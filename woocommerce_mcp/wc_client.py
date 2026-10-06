"""
Asynchronous WooCommerce REST API v3 Client for MCP Server.
Designed for Cloudflare Workers (Pyodide) using non-blocking asynchronous requests,
strict pagination enforcement (max 10-15 per page), and exponential backoff retry.
"""

import asyncio
import base64
import json
import logging
import random
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("woocommerce_mcp.client")


class WooCommerceAPIError(Exception):
    """Sanitized WooCommerce API error that is safe to expose to LLMs and MCP clients."""

    def __init__(self, message: str, status_code: Optional[int] = None, error_code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


class WooCommerceClient:
    """
    Fully asynchronous client for WooCommerce REST API v3.
    Uses non-blocking async network transport to prevent CPU limit crashes (Error 1102) in Workers.
    """

    # Maximum items per page allowed (WooCommerce REST API supports up to 100)
    MAX_PER_PAGE = 100
    DEFAULT_PER_PAGE = 10

    def __init__(
        self,
        store_url: str,
        consumer_key: str,
        consumer_secret: str,
        max_retries: int = 3,
        timeout_seconds: float = 15.0,
    ):
        self.store_url = store_url.rstrip("/")
        self._consumer_key = consumer_key.strip()
        self._consumer_secret = consumer_secret.strip()
        self.max_retries = max_retries
        self.timeout = timeout_seconds

        # Pre-compute HTTP Basic Auth header
        auth_bytes = f"{self._consumer_key}:{self._consumer_secret}".encode("utf-8")
        self._basic_auth_header = f"Basic {base64.b64encode(auth_bytes).decode('ascii')}"

    def is_transient_error(self, status_code: int) -> bool:
        """Determine if an HTTP status code indicates a transient failure eligible for retry."""
        return status_code == 429 or 500 <= status_code <= 599

    def _sanitize_log_url(self, url: str) -> str:
        """Strip query credentials if present from URLs for safe logging."""
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        safe_params = [
            (k, "***" if "secret" in k.lower() or "key" in k.lower() else v)
            for k, v in query_params
        ]
        sanitized_query = urllib.parse.urlencode(safe_params)
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, sanitized_query, parsed.fragment)
        )

    def _clamp_per_page(self, per_page: Optional[int]) -> int:
        """Enforce maximum pagination up to 100 items per page (WooCommerce max)."""
        if per_page is None:
            return self.DEFAULT_PER_PAGE
        try:
            val = int(per_page)
            return min(max(1, val), self.MAX_PER_PAGE)
        except (ValueError, TypeError):
            return self.DEFAULT_PER_PAGE

    def _build_url(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> str:
        clean_endpoint = endpoint.strip("/")
        base_api = f"{self.store_url}/wp-json/wc/v3/{clean_endpoint}"
        if not params:
            return base_api

        query_str = urllib.parse.urlencode(
            [(k, v) for k, v in params.items() if v is not None]
        )
        return f"{base_api}?{query_str}" if query_str else base_api

    async def _async_http_call(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
    ) -> Tuple[int, str, Dict[str, str]]:
        """
        Executes an asynchronous non-blocking HTTP request.
        Priority:
          1. Native Cloudflare Workers JS `fetch` (zero CPU overhead in Pyodide)
          2. `httpx.AsyncClient` (if installed)
          3. `asyncio.to_thread` / loop executor with urllib (fallback for standard Python tests)
        """
        method_upper = method.upper()

        # 1. Native Cloudflare Workers JS Fetch (runs on V8 event loop without blocking CPU)
        try:
            from js import fetch, Headers
            js_headers_list = [[k, v] for k, v in headers.items()]
            js_headers = Headers.new(js_headers_list)

            init_kwargs = {
                "method": method_upper,
                "headers": js_headers,
            }
            if body and method_upper in ("POST", "PUT", "PATCH", "DELETE"):
                init_kwargs["body"] = body

            js_resp = await fetch(url, **init_kwargs)
            status_code = int(js_resp.status)
            resp_text = str(await js_resp.text())

            resp_headers = {}
            for h in ("retry-after", "content-type", "x-wp-total", "x-wp-totalpages"):
                v = js_resp.headers.get(h)
                if v is not None:
                    resp_headers[h.lower()] = str(v)

            return status_code, resp_text, resp_headers
        except (ImportError, AttributeError):
            pass

        # 2. httpx (if installed in environment)
        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.request(
                    method=method_upper,
                    url=url,
                    headers=headers,
                    content=body.encode("utf-8") if body else None,
                )
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status_code, resp.text, hdrs
        except ImportError:
            pass

        # 3. Standard library non-blocking executor fallback
        def _sync_urlopen():
            import urllib.request
            import urllib.error
            import ssl

            ssl_ctx = ssl.create_default_context()
            data_bytes = body.encode("utf-8") if body else None
            req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method_upper)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_ctx) as r:
                    r_text = r.read().decode("utf-8")
                    h = {k.lower(): v for k, v in r.headers.items()}
                    return r.getcode(), r_text, h
            except urllib.error.HTTPError as e:
                err_text = ""
                try:
                    err_text = e.read().decode("utf-8")
                except Exception:
                    pass
                h = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
                return e.code, err_text, h

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _sync_urlopen)

    async def _execute_with_retry(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        return_headers: bool = False,
    ) -> Any:
        """
        Asynchronously executes an HTTP request to WooCommerce with retry and pagination enforcement.
        """
        if not self.store_url or not self._consumer_key or not self._consumer_secret:
            raise WooCommerceAPIError(
                "WooCommerce credentials are not configured on the server. Please set WOOCOMMERCE_STORE_URL, WOOCOMMERCE_CONSUMER_KEY, and WOOCOMMERCE_CONSUMER_SECRET.",
                status_code=500,
            )

        # Enforce pagination on GET requests
        clean_params = dict(params or {})
        if method.upper() == "GET":
            if "per_page" in clean_params:
                clean_params["per_page"] = self._clamp_per_page(clean_params["per_page"])
            elif any(seg in endpoint.lower() for seg in ["products", "orders"]):
                clean_params["per_page"] = self.DEFAULT_PER_PAGE

        full_url = self._build_url(endpoint, clean_params)
        body_str = json.dumps(data) if data is not None else None

        req_headers = {
            "Authorization": self._basic_auth_header,
            "Accept": "application/json",
            "User-Agent": "WooCommerce-MCP-AsyncServer/1.0",
        }
        if body_str is not None:
            req_headers["Content-Type"] = "application/json"

        attempt = 0
        backoff_delay = 1.0

        while True:
            attempt += 1
            safe_url = self._sanitize_log_url(full_url)

            try:
                status, resp_body, resp_headers = await self._async_http_call(
                    full_url, method=method, headers=req_headers, body=body_str
                )

                if 200 <= status < 300:
                    parsed_res: Any = {}
                    if resp_body.strip():
                        try:
                            parsed_res = json.loads(resp_body)
                        except json.JSONDecodeError:
                            parsed_res = {"raw_response": resp_body}
                    if return_headers:
                        return parsed_res, resp_headers
                    return parsed_res

                # Parse JSON error details from WooCommerce
                wc_code = None
                wc_msg = None
                if resp_body:
                    try:
                        parsed = json.loads(resp_body)
                        if isinstance(parsed, dict):
                            wc_code = parsed.get("code")
                            wc_msg = parsed.get("message")
                    except Exception:
                        pass

                # Handle 401 / 403 Authentication / Authorization failure
                if status in (401, 403):
                    msg = "Authentication failed with WooCommerce. Please check store credentials and permissions."
                    if wc_msg:
                        msg = f"WooCommerce authentication error: {wc_msg}"
                    raise WooCommerceAPIError(msg, status_code=status, error_code=wc_code)

                # Handle 404 Not Found
                if status == 404:
                    if endpoint and "variations" in endpoint:
                        resource_name = "Variation"
                    elif endpoint:
                        resource_name = endpoint.split("/")[0].capitalize()
                    else:
                        resource_name = "Resource"
                    raise WooCommerceAPIError(
                        f"Requested {resource_name} not found in WooCommerce.",
                        status_code=404,
                        error_code="not_found",
                    )

                # Handle 400 Bad Request
                if status == 400:
                    detail = wc_msg or "Invalid parameters supplied to WooCommerce."
                    raise WooCommerceAPIError(detail, status_code=400, error_code=wc_code)

                # Transient errors: 429 Too Many Requests or 5xx Server Errors
                is_transient = self.is_transient_error(status)
                if is_transient and attempt <= self.max_retries:
                    retry_after_hdr = resp_headers.get("retry-after")
                    sleep_time = backoff_delay + random.uniform(0.1, 0.4)
                    if retry_after_hdr:
                        try:
                            sleep_time = float(retry_after_hdr)
                        except (ValueError, TypeError):
                            pass

                    logger.warning(
                        "Transient HTTP %d from WooCommerce (%s). Awaiting %.2fs backoff (attempt %d/%d)...",
                        status, safe_url, sleep_time, attempt, self.max_retries
                    )
                    # Non-blocking async sleep yielding CPU to Cloudflare Workers event loop
                    await asyncio.sleep(sleep_time)
                    backoff_delay *= 2
                    continue

                if status == 429:
                    raise WooCommerceAPIError(
                        "WooCommerce rate limit was reached. Please retry later.",
                        status_code=429,
                        error_code="rate_limit_exceeded",
                    )
                else:
                    detail = wc_msg or f"WooCommerce server returned HTTP {status} error."
                    raise WooCommerceAPIError(detail, status_code=status, error_code=wc_code)

            except WooCommerceAPIError:
                raise
            except Exception as e:
                if attempt <= self.max_retries:
                    sleep_time = backoff_delay + random.uniform(0.1, 0.4)
                    logger.warning(
                        "Transient network failure connecting to WooCommerce (%s). Awaiting %.2fs (attempt %d/%d)...",
                        type(e).__name__, sleep_time, attempt, self.max_retries
                    )
                    await asyncio.sleep(sleep_time)
                    backoff_delay *= 2
                    continue

                raise WooCommerceAPIError(
                    "Network connection to WooCommerce store failed or timed out. Please check store URL and network connectivity.",
                    status_code=504,
                    error_code="network_timeout",
                )

    def _clean_html_text(self, text: Optional[str]) -> str:
        """Strip wrapping <p> and </p> tags for clean, consistent plain text output."""
        if not text:
            return ""
        t = str(text).strip()
        if t.startswith("<p>") and t.endswith("</p>"):
            t = t[3:-4].strip()
        return t

    # ------------------ High-Level WooCommerce Operations ------------------ #

    async def search_products(
        self,
        query: Optional[str] = None,
        category: Optional[int] = None,
        status: Optional[str] = "publish",
        min_price: Optional[str] = None,
        max_price: Optional[str] = None,
        sku: Optional[str] = None,
        page: int = 1,
        per_page: int = 10,
    ) -> Dict[str, Any]:
        """Asynchronously search products with filters and return pagination metadata and total counts."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }
        if query:
            params["search"] = query
        if sku:
            params["sku"] = sku
        if category is not None:
            params["category"] = category
        effective_status = status or "publish"
        if effective_status != "any":
            params["status"] = effective_status
        elif effective_status == "any":
            params["status"] = "any"
        if min_price:
            params["min_price"] = min_price
        if max_price:
            params["max_price"] = max_price

        raw_products, hdrs = await self._execute_with_retry(
            "products", method="GET", params=params, return_headers=True
        )
        products_list = []
        if isinstance(raw_products, list):
            products_list = [self._format_product(p) for p in raw_products]
            # Safety net: filter out nonexistent children from grouped products
            for p in products_list:
                if p.get("type") == "grouped" and p.get("grouped_products"):
                    p["grouped_products"] = await self._filter_existing_grouped_children(p["grouped_products"])

        total_count = len(products_list)
        total_pages = 1
        if isinstance(hdrs, dict):
            try:
                if "x-wp-total" in hdrs:
                    total_count = int(hdrs["x-wp-total"])
                if "x-wp-totalpages" in hdrs:
                    total_pages = int(hdrs["x-wp-totalpages"])
            except (ValueError, TypeError):
                pass

        return {
            "products": products_list,
            "total_count": total_count,
            "total_pages": total_pages,
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }

    async def get_product(
        self, product_id: Optional[int] = None, sku: Optional[str] = None
    ) -> Dict[str, Any]:
        """Asynchronously fetch product details by ID or SKU."""
        if product_id is not None:
            raw = await self._execute_with_retry(f"products/{product_id}", method="GET")
            formatted = self._format_product(raw)
            # Safety net: filter out nonexistent children from grouped products (R3)
            if formatted.get("type") == "grouped" and formatted.get("grouped_products"):
                formatted["grouped_products"] = await self._filter_existing_grouped_children(formatted["grouped_products"])
            return formatted
        elif sku:
            raw_list = await self._execute_with_retry(
                "products", method="GET", params={"sku": sku, "per_page": 1}
            )
            if isinstance(raw_list, list) and len(raw_list) > 0:
                formatted = self._format_product(raw_list[0])
                if formatted.get("type") == "grouped" and formatted.get("grouped_products"):
                    formatted["grouped_products"] = await self._filter_existing_grouped_children(formatted["grouped_products"])
                return formatted
            raise WooCommerceAPIError(f"Product with SKU '{sku}' was not found.", status_code=404)
        else:
            raise WooCommerceAPIError("Either 'product_id' or 'sku' must be provided.", status_code=400)

    async def list_products(
        self,
        stock_status: Optional[str] = None,
        category: Optional[int] = None,
        featured: Optional[bool] = None,
        page: int = 1,
        per_page: int = 10,
    ) -> Dict[str, Any]:
        """Asynchronously list products with inventory details, pagination metadata, and total counts."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }
        if stock_status:
            params["stock_status"] = stock_status
        if category is not None:
            params["category"] = category
        if featured is not None:
            params["featured"] = "true" if featured else "false"

        raw_products, hdrs = await self._execute_with_retry(
            "products", method="GET", params=params, return_headers=True
        )
        products_list = []
        if isinstance(raw_products, list):
            products_list = [self._format_product(p) for p in raw_products]
            # Safety net: filter out nonexistent children from grouped products (R3)
            for p in products_list:
                if p.get("type") == "grouped" and p.get("grouped_products"):
                    p["grouped_products"] = await self._filter_existing_grouped_children(p["grouped_products"])

        total_count = len(products_list)
        total_pages = 1
        if isinstance(hdrs, dict):
            try:
                if "x-wp-total" in hdrs:
                    total_count = int(hdrs["x-wp-total"])
                if "x-wp-totalpages" in hdrs:
                    total_pages = int(hdrs["x-wp-totalpages"])
            except (ValueError, TypeError):
                pass

        return {
            "products": products_list,
            "total_count": total_count,
            "total_pages": total_pages,
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }

    async def _filter_existing_grouped_children(
        self, children_ids: List[int], cache: Optional[Dict[int, bool]] = None
    ) -> List[int]:
        """Safety net: filters out IDs of products that no longer exist (R3)."""
        if not children_ids:
            return []
        if cache is None:
            cache = {}
        valid_ids: List[int] = []
        for cid in children_ids:
            if cid in cache:
                if cache[cid]:
                    valid_ids.append(cid)
                continue
            try:
                child = await self._execute_with_retry(f"products/{cid}", method="GET")
                if isinstance(child, dict) and child.get("id"):
                    cache[cid] = True
                    valid_ids.append(cid)
                else:
                    cache[cid] = False
            except WooCommerceAPIError as e:
                err_msg = (e.message or "").lower()
                if e.status_code == 404 or "not found" in err_msg or "invalid" in err_msg:
                    cache[cid] = False
                    continue
                cache[cid] = True
                valid_ids.append(cid)
            except Exception:
                cache[cid] = True
                valid_ids.append(cid)
        return valid_ids

    async def list_orders(
        self,
        status: Optional[str] = None,
        customer_id: Optional[int] = None,
        after: Optional[str] = None,
        before: Optional[str] = None,
        page: int = 1,
        per_page: int = 10,
    ) -> Dict[str, Any]:
        """Asynchronously list store orders with pagination metadata, total counts, and enforced pagination."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }
        if status and status != "any":
            params["status"] = status
        elif status == "any":
            params["status"] = "any"
        if customer_id is not None:
            params["customer"] = customer_id
        if after:
            params["after"] = after
        if before:
            params["before"] = before

        raw_orders, hdrs = await self._execute_with_retry(
            "orders", method="GET", params=params, return_headers=True
        )
        orders_list = []
        if isinstance(raw_orders, list):
            orders_list = [self._format_order(o) for o in raw_orders]
            if status != "trash":
                orders_list = [o for o in orders_list if o.get("status") != "trash"]

        total_count = len(orders_list)
        total_pages = 1
        if isinstance(hdrs, dict):
            try:
                if "x-wp-total" in hdrs:
                    total_count = int(hdrs["x-wp-total"])
                if "x-wp-totalpages" in hdrs:
                    total_pages = int(hdrs["x-wp-totalpages"])
            except (ValueError, TypeError):
                pass

        return {
            "orders": orders_list,
            "total_count": total_count,
            "total_pages": total_pages,
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }

    async def get_order(self, order_id: int) -> Dict[str, Any]:
        """Asynchronously fetch complete order details by order ID."""
        raw = await self._execute_with_retry(f"orders/{order_id}", method="GET")
        return self._format_order(raw)

    async def update_product_stock(
        self,
        product_id: int,
        stock_quantity: Optional[int] = None,
        stock_status: Optional[str] = None,
        manage_stock: Optional[bool] = None,
        backorders: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Asynchronously update inventory stock quantity and status for a product."""
        payload: Dict[str, Any] = {}
        if stock_quantity is not None:
            payload["stock_quantity"] = stock_quantity
            if manage_stock is None:
                payload["manage_stock"] = True
        if stock_status is not None:
            payload["stock_status"] = stock_status
        if manage_stock is not None:
            payload["manage_stock"] = manage_stock
        if backorders is not None:
            payload["backorders"] = backorders

        raw = await self._execute_with_retry(f"products/{product_id}", method="PUT", data=payload)
        return self._format_product(raw)

    async def create_product(
        self,
        name: str,
        type: str = "simple",
        regular_price: Optional[str] = None,
        sale_price: Optional[str] = None,
        description: str = "",
        short_description: str = "",
        sku: Optional[str] = None,
        manage_stock: bool = False,
        stock_quantity: Optional[int] = None,
        stock_status: str = "instock",
        backorders: str = "no",
        categories: Optional[List[int]] = None,
        status: str = "publish",
        featured: bool = False,
        images: Optional[List[Any]] = None,
        external_url: Optional[str] = None,
        button_text: Optional[str] = None,
        grouped_products: Optional[List[int]] = None,
        attributes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Asynchronously create a new product of any supported type."""
        payload: Dict[str, Any] = {
            "name": name,
            "type": type,
            "status": status,
            "manage_stock": manage_stock,
            "stock_status": stock_status,
            "backorders": backorders,
            "featured": featured,
        }
        if regular_price is not None:
            payload["regular_price"] = regular_price
        if sale_price is not None:
            payload["sale_price"] = sale_price
        if description:
            payload["description"] = description
        if short_description:
            payload["short_description"] = short_description
        if sku:
            payload["sku"] = sku
        if stock_quantity is not None:
            payload["stock_quantity"] = stock_quantity
            payload["manage_stock"] = True
        if categories:
            payload["categories"] = [{"id": cid} for cid in categories]
        if images:
            payload["images"] = [
                {"src": img} if isinstance(img, str) else img for img in images
            ]
        if external_url is not None:
            payload["external_url"] = external_url
        if button_text is not None:
            payload["button_text"] = button_text
        if grouped_products is not None:
            payload["grouped_products"] = grouped_products
        if attributes is not None:
            payload["attributes"] = attributes

        raw = await self._execute_with_retry("products", method="POST", data=payload)
        return self._format_product(raw)

    async def update_product(
        self,
        product_id: int,
        name: Optional[str] = None,
        regular_price: Optional[str] = None,
        sale_price: Optional[str] = None,
        description: Optional[str] = None,
        short_description: Optional[str] = None,
        sku: Optional[str] = None,
        status: Optional[str] = None,
        categories: Optional[List[int]] = None,
        featured: Optional[bool] = None,
        images: Optional[List[Any]] = None,
        manage_stock: Optional[bool] = None,
        stock_quantity: Optional[int] = None,
        stock_status: Optional[str] = None,
        backorders: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Asynchronously update fields of an existing product."""
        payload: Dict[str, Any] = {}
        if name is not None:
            payload["name"] = name
        if regular_price is not None:
            payload["regular_price"] = regular_price
        if sale_price is not None:
            payload["sale_price"] = sale_price
        if description is not None:
            payload["description"] = description
        if short_description is not None:
            payload["short_description"] = short_description
        if sku is not None:
            payload["sku"] = sku
        if status is not None:
            payload["status"] = status
        if categories is not None:
            payload["categories"] = [{"id": cid} for cid in categories]
        if featured is not None:
            payload["featured"] = featured
        if images is not None:
            payload["images"] = [
                {"src": img} if isinstance(img, str) else img for img in images
            ]
        if manage_stock is not None:
            payload["manage_stock"] = manage_stock
        if stock_quantity is not None:
            payload["stock_quantity"] = stock_quantity
            if manage_stock is None:
                payload["manage_stock"] = True
        if stock_status is not None:
            payload["stock_status"] = stock_status
        if backorders is not None:
            payload["backorders"] = backorders

        raw = await self._execute_with_retry(f"products/{product_id}", method="PUT", data=payload)
        return self._format_product(raw)

    async def _find_grouped_parents_referencing_child(self, child_id: int) -> List[Dict[str, Any]]:
        """Find all grouped products (including trashed and drafts) that reference child_id (R3)."""
        parents = []
        seen_parent_ids = set()
        for status_filter in ["any", "trash"]:
            try:
                page = 1
                while True:
                    raw_list = await self._execute_with_retry(
                        "products",
                        method="GET",
                        params={"type": "grouped", "status": status_filter, "page": page, "per_page": 50},
                    )
                    if not isinstance(raw_list, list) or not raw_list:
                        break
                    for p in raw_list:
                        p_id = p.get("id")
                        if p_id and p_id not in seen_parent_ids:
                            g_prods = p.get("grouped_products") or []
                            if child_id in g_prods:
                                parents.append(p)
                                seen_parent_ids.add(p_id)
                    if len(raw_list) < 50:
                        break
                    page += 1
            except Exception as e:
                logger.warning("Error fetching grouped products with status=%s: %s", status_filter, e)
        return parents

    async def delete_product(self, product_id: int, force: bool = False) -> Dict[str, Any]:
        """Asynchronously delete a product (trash by default, or permanent with force=True)."""
        updated_grouped_parents: List[int] = []

        # When delete_product runs with force=true on a product, remove its ID from the grouped_products list of every grouped product that references it (R3)
        if force:
            parents = await self._find_grouped_parents_referencing_child(product_id)
            for parent in parents:
                parent_id = parent["id"]
                current_children = parent.get("grouped_products", [])
                new_children = [cid for cid in current_children if cid != product_id]
                try:
                    await self._execute_with_retry(
                        f"products/{parent_id}",
                        method="PUT",
                        data={"grouped_products": new_children},
                    )
                    updated_grouped_parents.append(parent_id)
                except Exception as e:
                    logger.warning("Failed to update grouped parent %d after deleting child %d: %s", parent_id, product_id, e)

        raw = await self._execute_with_retry(
            f"products/{product_id}", method="DELETE", params={"force": "true" if force else "false"}
        )
        return {
            "id": raw.get("id", product_id),
            "name": raw.get("name", ""),
            "status": "trash" if not force else "deleted",
            "deleted": True,
            "message": f"Product {product_id} was {'permanently deleted' if force else 'moved to trash'}.",
            "updated_grouped_parents": updated_grouped_parents,
        }

    # ------------------ Product Variations ------------------ #

    async def list_variations(
        self, product_id: int, page: int = 1, per_page: int = 10
    ) -> Dict[str, Any]:
        """Asynchronously list variations for a variable product with pagination metadata."""
        params = {
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }
        raw_list, hdrs = await self._execute_with_retry(
            f"products/{product_id}/variations", method="GET", params=params, return_headers=True
        )
        variations_list = []
        if isinstance(raw_list, list):
            variations_list = [self._format_variation(v) for v in raw_list]

        total_count = len(variations_list)
        total_pages = 1
        if isinstance(hdrs, dict):
            try:
                if "x-wp-total" in hdrs:
                    total_count = int(hdrs["x-wp-total"])
                if "x-wp-totalpages" in hdrs:
                    total_pages = int(hdrs["x-wp-totalpages"])
            except (ValueError, TypeError):
                pass

        return {
            "variations": variations_list,
            "total_count": total_count,
            "total_pages": total_pages,
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }

    async def create_variation(
        self,
        product_id: int,
        regular_price: Optional[str] = None,
        sale_price: Optional[str] = None,
        sku: Optional[str] = None,
        stock_quantity: Optional[int] = None,
        manage_stock: Optional[bool] = None,
        stock_status: Optional[str] = None,
        backorders: Optional[str] = None,
        attributes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Asynchronously create a new variation for a variable product."""
        payload: Dict[str, Any] = {}
        if regular_price is not None:
            payload["regular_price"] = regular_price
        if sale_price is not None:
            payload["sale_price"] = sale_price
        if sku is not None:
            payload["sku"] = sku
        if stock_quantity is not None:
            payload["stock_quantity"] = stock_quantity
            payload["manage_stock"] = True
        elif manage_stock is not None:
            payload["manage_stock"] = manage_stock
        if stock_status is not None:
            payload["stock_status"] = stock_status
        if backorders is not None:
            payload["backorders"] = backorders
        if attributes is not None:
            payload["attributes"] = attributes

        raw = await self._execute_with_retry(
            f"products/{product_id}/variations", method="POST", data=payload
        )
        return self._format_variation(raw)

    async def update_variation(
        self,
        product_id: int,
        variation_id: int,
        regular_price: Optional[str] = None,
        sale_price: Optional[str] = None,
        sku: Optional[str] = None,
        stock_quantity: Optional[int] = None,
        manage_stock: Optional[bool] = None,
        stock_status: Optional[str] = None,
        backorders: Optional[str] = None,
        attributes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Asynchronously update a variation of a variable product."""
        payload: Dict[str, Any] = {}
        if regular_price is not None:
            payload["regular_price"] = regular_price
        if sale_price is not None:
            payload["sale_price"] = sale_price
        if sku is not None:
            payload["sku"] = sku
        if stock_quantity is not None:
            payload["stock_quantity"] = stock_quantity
            payload["manage_stock"] = True
        elif manage_stock is not None:
            payload["manage_stock"] = manage_stock
        if stock_status is not None:
            payload["stock_status"] = stock_status
        if backorders is not None:
            payload["backorders"] = backorders
        if attributes is not None:
            payload["attributes"] = attributes

        raw = await self._execute_with_retry(
            f"products/{product_id}/variations/{variation_id}", method="PUT", data=payload
        )
        return self._format_variation(raw)

    async def delete_variation(
        self, product_id: int, variation_id: int, force: bool = True
    ) -> Dict[str, Any]:
        """Asynchronously delete a variation."""
        raw = await self._execute_with_retry(
            f"products/{product_id}/variations/{variation_id}",
            method="DELETE",
            params={"force": "true" if force else "false"},
        )
        return {
            "id": raw.get("id", variation_id),
            "product_id": product_id,
            "deleted": True,
            "message": f"Variation {variation_id} of product {product_id} deleted successfully.",
        }

    # ------------------ Product Categories ------------------ #

    async def list_categories(
        self,
        page: int = 1,
        per_page: int = 10,
        search: Optional[str] = None,
        parent: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Asynchronously list product categories with pagination metadata."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }
        if search:
            params["search"] = search
        if parent is not None:
            params["parent"] = parent

        raw_list, hdrs = await self._execute_with_retry("products/categories", method="GET", params=params, return_headers=True)
        categories_list = []
        if isinstance(raw_list, list):
            categories_list = [self._format_category(c) for c in raw_list]

        total_count = len(categories_list)
        total_pages = 1
        if isinstance(hdrs, dict):
            try:
                if "x-wp-total" in hdrs:
                    total_count = int(hdrs["x-wp-total"])
                if "x-wp-totalpages" in hdrs:
                    total_pages = int(hdrs["x-wp-totalpages"])
            except (ValueError, TypeError):
                pass

        return {
            "categories": categories_list,
            "total_count": total_count,
            "total_pages": total_pages,
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }

    async def create_category(
        self,
        name: str,
        slug: Optional[str] = None,
        parent: Optional[int] = None,
        description: str = "",
        image: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Asynchronously create a product category."""
        payload: Dict[str, Any] = {"name": name, "description": description}
        if slug:
            payload["slug"] = slug
        if parent is not None:
            payload["parent"] = parent
        if image:
            payload["image"] = {"src": image}

        raw = await self._execute_with_retry("products/categories", method="POST", data=payload)
        return self._format_category(raw)

    async def update_category(
        self,
        category_id: int,
        name: Optional[str] = None,
        slug: Optional[str] = None,
        parent: Optional[int] = None,
        description: Optional[str] = None,
        image: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Asynchronously update an existing product category."""
        payload: Dict[str, Any] = {}
        if name is not None:
            payload["name"] = name
        if slug is not None:
            payload["slug"] = slug
        if parent is not None:
            payload["parent"] = parent
        if description is not None:
            payload["description"] = description
        if image is not None:
            payload["image"] = {"src": image}

        raw = await self._execute_with_retry(f"products/categories/{category_id}", method="PUT", data=payload)
        return self._format_category(raw)

    async def delete_category(
        self,
        category_id: int,
        force: bool = True,
    ) -> Dict[str, Any]:
        """Asynchronously delete a product category."""
        raw = await self._execute_with_retry(
            f"products/categories/{category_id}",
            method="DELETE",
            params={"force": "true" if force else "false"},
        )
        return {
            "id": raw.get("id", category_id),
            "deleted": True,
            "message": f"Category {category_id} deleted successfully.",
        }

    async def batch_update_categories(
        self,
        create: Optional[List[Dict[str, Any]]] = None,
        update: Optional[List[Dict[str, Any]]] = None,
        delete: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Asynchronously batch create, update, or delete product categories."""
        payload: Dict[str, Any] = {}
        if create:
            payload["create"] = create
        if update:
            payload["update"] = update
        if delete:
            payload["delete"] = delete

        raw = await self._execute_with_retry("products/categories/batch", method="POST", data=payload)
        res: Dict[str, Any] = {}
        if isinstance(raw, dict):
            if "create" in raw:
                res["create"] = [self._format_category(c) for c in raw["create"]]
            if "update" in raw:
                res["update"] = [self._format_category(c) for c in raw["update"]]
            if "delete" in raw:
                res["delete"] = [c.get("id") if isinstance(c, dict) else c for c in raw["delete"]]
        return res

    # ------------------ Order Writes & Refunds ------------------ #

    async def create_order(
        self,
        line_items: List[Dict[str, Any]],
        status: str = "pending",
        customer_id: Optional[int] = None,
        billing: Optional[Dict[str, Any]] = None,
        shipping: Optional[Dict[str, Any]] = None,
        customer_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Asynchronously create a new customer order."""
        payload: Dict[str, Any] = {
            "status": status,
            "line_items": line_items,
        }
        if customer_id is not None:
            payload["customer_id"] = customer_id
        if billing:
            payload["billing"] = billing
        if shipping:
            payload["shipping"] = shipping
        if customer_note:
            payload["customer_note"] = customer_note

        raw = await self._execute_with_retry("orders", method="POST", data=payload)
        return self._format_order(raw)

    async def update_order_status(self, order_id: int, status: str) -> Dict[str, Any]:
        """Asynchronously update order status. When status is 'trash', calls delete endpoint with force=false (R2)."""
        if status.lower() == "trash":
            raw = await self._execute_with_retry(
                f"orders/{order_id}", method="DELETE", params={"force": "false"}
            )
            formatted = self._format_order(raw)
            formatted["status"] = "trash"
            return formatted
        else:
            raw = await self._execute_with_retry(
                f"orders/{order_id}", method="PUT", data={"status": status}
            )
            return self._format_order(raw)

    async def create_refund(
        self,
        order_id: int,
        amount: str,
        reason: Optional[str] = None,
        api_refund: bool = True,
        line_items: Optional[List[Dict[str, Any]]] = None,
        restock_items: bool = False,
    ) -> Dict[str, Any]:
        """Asynchronously issue a refund against an order (R1)."""
        # Fetch current order to validate remaining refundable amount
        order_raw = await self._execute_with_retry(f"orders/{order_id}", method="GET")

        try:
            req_amount = float(amount)
            if req_amount <= 0:
                raise WooCommerceAPIError("Refund amount must be greater than zero.", status_code=400)
            order_total = float(order_raw.get("total", 0.0))
            refunds = order_raw.get("refunds", [])
            total_refunded = sum(abs(float(r.get("total", 0.0))) for r in refunds)
            remaining_refundable = max(0.0, round(order_total - total_refunded, 2))
            if req_amount > remaining_refundable:
                raise WooCommerceAPIError(
                    f"Refund amount {amount} exceeds the remaining refundable amount of {remaining_refundable:.2f} for order {order_id}.",
                    status_code=400,
                    error_code="invalid_refund_amount",
                )
        except (ValueError, TypeError):
            pass

        payload: Dict[str, Any] = {
            "amount": str(amount),
            "api_refund": api_refund,
        }
        if reason:
            payload["reason"] = reason
        if line_items is not None:
            payload["line_items"] = line_items
        if restock_items:
            payload["restock_items"] = True

        try:
            raw = await self._execute_with_retry(f"orders/{order_id}/refunds", method="POST", data=payload)
        except WooCommerceAPIError as e:
            err_lower = (e.message or "").lower()
            if "payment gateway" in err_lower and ("not exist" in err_lower or "unavailable" in err_lower or "not available" in err_lower or "missing" in err_lower):
                raise WooCommerceAPIError(
                    "The payment gateway for this order does not exist or is unavailable. Retry with api_refund=false for a manual refund.",
                    status_code=400,
                    error_code="gateway_not_found",
                )
            raise

        try:
            updated_order = await self._execute_with_retry(f"orders/{order_id}", method="GET")
            order_status = updated_order.get("status")
            order_total = updated_order.get("total")
        except Exception:
            order_status = order_raw.get("status")
            order_total = order_raw.get("total")

        order_gross_total = float(updated_order.get("total", order_raw.get("total", 0.0)))
        all_refunds = updated_order.get("refunds", [])
        total_refunded = sum(abs(float(r.get("total", 0.0))) for r in all_refunds)
        if total_refunded == 0.0 and float(amount) > 0:
            total_refunded = float(amount)
        net_total = max(0.0, round(order_gross_total - total_refunded, 2))

        return {
            "id": raw.get("id"),
            "order_id": order_id,
            "refund_amount": raw.get("amount", amount),
            "reason": raw.get("reason", reason or ""),
            "api_refund": api_refund,
            "order_status": order_status,
            "order_original_total": f"{order_gross_total:.2f}",
            "total_refunded": f"{total_refunded:.2f}",
            "net_total": f"{net_total:.2f}",
            "remaining_refundable": f"{net_total:.2f}",
            "date_created": raw.get("date_created"),
        }

    def _format_product(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize product representation into a clean, LLM-friendly structure."""
        categories = [
            {"id": c.get("id"), "name": c.get("name"), "slug": c.get("slug")}
            for c in raw.get("categories", [])
        ]
        images = [img.get("src") for img in raw.get("images", []) if "src" in img]

        res: Dict[str, Any] = {
            "id": raw.get("id"),
            "name": raw.get("name"),
            "slug": raw.get("slug"),
            "permalink": raw.get("permalink"),
            "status": raw.get("status"),
            "type": raw.get("type", "simple"),
            "price": raw.get("price"),
            "regular_price": raw.get("regular_price"),
            "sale_price": raw.get("sale_price"),
            "on_sale": raw.get("on_sale", False),
            "featured": raw.get("featured", False),
            "sku": raw.get("sku") or None,
            "manage_stock": raw.get("manage_stock", False),
            "stock_quantity": raw.get("stock_quantity"),
            "stock_status": raw.get("stock_status"),
            "backorders": raw.get("backorders", "no"),
            "categories": categories,
            "short_description": self._clean_html_text(raw.get("short_description")),
            "description": self._clean_html_text(raw.get("description")),
            "images": images,
        }

        # Include type-specific properties
        if raw.get("type") == "external":
            res["external_url"] = raw.get("external_url", "")
            res["button_text"] = raw.get("button_text", "")
        elif raw.get("type") == "grouped":
            res["grouped_products"] = raw.get("grouped_products", [])
        elif raw.get("type") == "variable":
            normalized_attributes = []
            for attr in raw.get("attributes", []):
                if isinstance(attr, dict):
                    attr_c = dict(attr)
                    slug_v = attr_c.get("slug") or attr_c.get("name") or ""
                    attr_c["slug"] = slug_v.lower()
                    normalized_attributes.append(attr_c)
                else:
                    normalized_attributes.append(attr)
            res["attributes"] = normalized_attributes
            res["variations"] = raw.get("variations", [])

        return res

    def _format_variation(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize variation representation with consistent lowercase attribute slugs."""
        raw_attrs = raw.get("attributes", [])
        norm_attrs = []
        for attr in raw_attrs:
            if isinstance(attr, dict):
                a_copy = dict(attr)
                slug_val = a_copy.get("slug") or a_copy.get("name") or ""
                a_copy["slug"] = slug_val.lower()
                norm_attrs.append(a_copy)
            else:
                norm_attrs.append(attr)

        return {
            "id": raw.get("id"),
            "parent_id": raw.get("parent_id"),
            "sku": raw.get("sku") or None,
            "price": raw.get("price"),
            "regular_price": raw.get("regular_price"),
            "sale_price": raw.get("sale_price"),
            "on_sale": raw.get("on_sale", False),
            "status": raw.get("status"),
            "manage_stock": raw.get("manage_stock", False),
            "stock_quantity": raw.get("stock_quantity"),
            "stock_status": raw.get("stock_status"),
            "backorders": raw.get("backorders", "no"),
            "attributes": norm_attrs,
            "description": self._clean_html_text(raw.get("description")),
        }

    def _format_category(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize product category representation."""
        img = raw.get("image")
        img_src = img.get("src") if isinstance(img, dict) else None
        return {
            "id": raw.get("id"),
            "name": raw.get("name"),
            "slug": raw.get("slug"),
            "parent": raw.get("parent", 0),
            "description": self._clean_html_text(raw.get("description")),
            "count": raw.get("count", 0),
            "image": img_src,
        }

    def _format_refund(self, raw: Dict[str, Any], order_id: int) -> Dict[str, Any]:
        """Normalize refund representation."""
        return {
            "id": raw.get("id"),
            "order_id": order_id,
            "amount": raw.get("amount"),
            "reason": raw.get("reason", ""),
            "date_created": raw.get("date_created"),
            "refunded_by": raw.get("refunded_by"),
        }

    def _format_order(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize order representation into a clean, LLM-friendly structure."""
        line_items = [
            {
                "id": item.get("id"),
                "product_id": item.get("product_id"),
                "name": item.get("name"),
                "quantity": item.get("quantity"),
                "price": item.get("price"),
                "subtotal": item.get("subtotal") or item.get("total"),
                "total": item.get("total"),
                "sku": item.get("sku") or None,
            }
            for item in raw.get("line_items", [])
        ]

        # Compute order subtotal accurately from line items (or total - shipping - taxes + discounts)
        subtotal_amt = 0.0
        has_subtotal = False
        for item in line_items:
            try:
                sub_val = item.get("subtotal") or item.get("total")
                if sub_val is not None:
                    subtotal_amt += float(sub_val)
                    has_subtotal = True
            except (ValueError, TypeError):
                pass

        if not has_subtotal:
            try:
                tot = float(raw.get("total") or 0.0)
                ship = float(raw.get("shipping_total") or 0.0)
                tax = float(raw.get("total_tax") or 0.0)
                disc = float(raw.get("discount_total") or 0.0)
                subtotal_amt = max(0.0, tot - ship - tax + disc)
            except (ValueError, TypeError):
                subtotal_amt = 0.0

        # Extract refunds and compute net amounts
        raw_refunds = raw.get("refunds", [])
        refunds_list = []
        total_refunded_amt = 0.0
        for r in raw_refunds:
            try:
                r_val = abs(float(r.get("total") or 0.0))
            except (ValueError, TypeError):
                r_val = 0.0
            total_refunded_amt += r_val
            refunds_list.append({
                "id": r.get("id"),
                "reason": r.get("reason", ""),
                "total": f"{r_val:.2f}",
            })

        order_gross_tot = 0.0
        try:
            order_gross_tot = float(raw.get("total") or 0.0)
        except (ValueError, TypeError):
            pass
        net_total_amt = max(0.0, order_gross_tot - total_refunded_amt)

        billing = raw.get("billing", {})
        shipping = raw.get("shipping", {})

        return {
            "id": raw.get("id"),
            "order_number": raw.get("number"),
            "status": raw.get("status"),
            "currency": raw.get("currency"),
            "total": f"{order_gross_tot:.2f}",
            "subtotal": f"{subtotal_amt:.2f}",
            "total_refunded": f"{total_refunded_amt:.2f}",
            "net_total": f"{net_total_amt:.2f}",
            "refunds": refunds_list,
            "discount_total": raw.get("discount_total", "0.00"),
            "total_tax": raw.get("total_tax"),
            "shipping_total": raw.get("shipping_total"),
            "payment_method_title": raw.get("payment_method_title"),
            "customer_id": raw.get("customer_id"),
            "date_created": raw.get("date_created"),
            "date_modified": raw.get("date_modified"),
            "customer_note": raw.get("customer_note"),
            "billing": {
                "first_name": billing.get("first_name"),
                "last_name": billing.get("last_name"),
                "email": billing.get("email"),
                "phone": billing.get("phone"),
                "city": billing.get("city"),
                "state": billing.get("state"),
                "country": billing.get("country"),
            },
            "shipping": {
                "first_name": shipping.get("first_name"),
                "last_name": shipping.get("last_name"),
                "address_1": shipping.get("address_1"),
                "city": shipping.get("city"),
                "state": shipping.get("state"),
                "country": shipping.get("country"),
            },
            "line_items": line_items,
        }
