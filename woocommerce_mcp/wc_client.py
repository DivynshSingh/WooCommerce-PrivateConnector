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

    # Maximum items per page allowed to protect Pyodide CPU limits
    MAX_PER_PAGE = 15
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
        """Strictly enforce maximum pagination of 10-15 items per page."""
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
            for h in ("retry-after", "content-type"):
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
                    if not resp_body.strip():
                        return {}
                    try:
                        return json.loads(resp_body)
                    except json.JSONDecodeError:
                        return {"raw_response": resp_body}

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
                    resource_name = endpoint.split("/")[0] if endpoint else "Resource"
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

    # ------------------ High-Level WooCommerce Operations ------------------ #

    async def search_products(
        self,
        query: Optional[str] = None,
        category: Optional[int] = None,
        status: Optional[str] = None,
        min_price: Optional[str] = None,
        max_price: Optional[str] = None,
        page: int = 1,
        per_page: int = 10,
    ) -> List[Dict[str, Any]]:
        """Asynchronously search products with filters and enforced pagination."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }
        if query:
            params["search"] = query
        if category is not None:
            params["category"] = category
        if status and status != "any":
            params["status"] = status
        if min_price:
            params["min_price"] = min_price
        if max_price:
            params["max_price"] = max_price

        raw_products = await self._execute_with_retry("products", method="GET", params=params)
        if isinstance(raw_products, list):
            return [self._format_product(p) for p in raw_products]
        return []

    async def get_product(
        self, product_id: Optional[int] = None, sku: Optional[str] = None
    ) -> Dict[str, Any]:
        """Asynchronously fetch product details by ID or SKU."""
        if product_id is not None:
            raw = await self._execute_with_retry(f"products/{product_id}", method="GET")
            return self._format_product(raw)
        elif sku:
            raw_list = await self._execute_with_retry(
                "products", method="GET", params={"sku": sku, "per_page": 1}
            )
            if isinstance(raw_list, list) and len(raw_list) > 0:
                return self._format_product(raw_list[0])
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
    ) -> List[Dict[str, Any]]:
        """Asynchronously list products with inventory details and enforced pagination."""
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

        raw_products = await self._execute_with_retry("products", method="GET", params=params)
        if isinstance(raw_products, list):
            return [self._format_product(p) for p in raw_products]
        return []

    async def list_orders(
        self,
        status: Optional[str] = None,
        customer_id: Optional[int] = None,
        after: Optional[str] = None,
        before: Optional[str] = None,
        page: int = 1,
        per_page: int = 10,
    ) -> List[Dict[str, Any]]:
        """Asynchronously list store orders with optional filters and enforced pagination."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": self._clamp_per_page(per_page),
        }
        if status and status != "any":
            params["status"] = status
        if customer_id is not None:
            params["customer"] = customer_id
        if after:
            params["after"] = after
        if before:
            params["before"] = before

        raw_orders = await self._execute_with_retry("orders", method="GET", params=params)
        if isinstance(raw_orders, list):
            return [self._format_order(o) for o in raw_orders]
        return []

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

        raw = await self._execute_with_retry(f"products/{product_id}", method="PUT", data=payload)
        return self._format_product(raw)

    async def create_product(
        self,
        name: str,
        regular_price: str,
        description: str = "",
        short_description: str = "",
        sku: Optional[str] = None,
        manage_stock: bool = False,
        stock_quantity: Optional[int] = None,
        stock_status: str = "instock",
        categories: Optional[List[int]] = None,
        status: str = "publish",
    ) -> Dict[str, Any]:
        """Asynchronously create a new product."""
        payload: Dict[str, Any] = {
            "name": name,
            "type": "simple",
            "regular_price": regular_price,
            "description": description,
            "short_description": short_description,
            "status": status,
            "manage_stock": manage_stock,
            "stock_status": stock_status,
        }
        if sku:
            payload["sku"] = sku
        if stock_quantity is not None:
            payload["stock_quantity"] = stock_quantity
            payload["manage_stock"] = True
        if categories:
            payload["categories"] = [{"id": cid} for cid in categories]

        raw = await self._execute_with_retry("products", method="POST", data=payload)
        return self._format_product(raw)

    def _format_product(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize product representation into a clean, LLM-friendly structure."""
        categories = [
            {"id": c.get("id"), "name": c.get("name"), "slug": c.get("slug")}
            for c in raw.get("categories", [])
        ]
        images = [img.get("src") for img in raw.get("images", []) if "src" in img]

        return {
            "id": raw.get("id"),
            "name": raw.get("name"),
            "slug": raw.get("slug"),
            "permalink": raw.get("permalink"),
            "status": raw.get("status"),
            "type": raw.get("type"),
            "price": raw.get("price"),
            "regular_price": raw.get("regular_price"),
            "sale_price": raw.get("sale_price"),
            "on_sale": raw.get("on_sale", False),
            "sku": raw.get("sku") or None,
            "manage_stock": raw.get("manage_stock", False),
            "stock_quantity": raw.get("stock_quantity"),
            "stock_status": raw.get("stock_status"),
            "categories": categories,
            "short_description": raw.get("short_description", "").strip(),
            "description": raw.get("description", "").strip(),
            "images": images,
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
                "total": item.get("total"),
                "sku": item.get("sku") or None,
            }
            for item in raw.get("line_items", [])
        ]

        billing = raw.get("billing", {})
        shipping = raw.get("shipping", {})

        return {
            "id": raw.get("id"),
            "order_number": raw.get("number"),
            "status": raw.get("status"),
            "currency": raw.get("currency"),
            "total": raw.get("total"),
            "subtotal": raw.get("discount_total"),
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
