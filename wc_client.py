import base64
import json
import logging
import random
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
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
    Client for WooCommerce REST API v3 with authentication, rate-limiting respect,
    and exponential backoff retry for transient failures.
    """

    def __init__(
        self,
        store_url: str,
        consumer_key: str,
        consumer_secret: str,
        max_retries: int = 3,
        timeout_seconds: float = 15.0,
    ):
        self.store_url = store_url.rstrip("/")
        self._consumer_key = consumer_key
        self._consumer_secret = consumer_secret
        self.max_retries = max_retries
        self.timeout = timeout_seconds

        # Pre-compute HTTP Basic Auth header
        auth_bytes = f"{self._consumer_key}:{self._consumer_secret}".encode("utf-8")
        self._basic_auth_header = f"Basic {base64.b64encode(auth_bytes).decode('ascii')}"

        # Standard SSL context
        self._ssl_context = ssl.create_default_context()

    def _sanitize_log_url(self, url: str) -> str:
        """Strip query credentials if present from URLs for safe logging."""
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        safe_params = [
            (k, "***" if "secret" in k.lower() or "key" in k.lower() else v)
            for k, v in query_params
        ]
        sanitized_query = urllib.parse.urlencode(safe_params)
        return urllib.parse.urlunparse(parsed._replace(query=sanitized_query))

    def _build_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> urllib.request.Request:
        """Constructs an authenticated urllib Request without leaking secrets in logs."""
        clean_endpoint = endpoint.lstrip("/")
        if not clean_endpoint.startswith("wp-json/"):
            url = f"{self.store_url}/wp-json/wc/v3/{clean_endpoint}"
        else:
            url = f"{self.store_url}/{clean_endpoint}"

        # Filter out None values in params
        if params:
            clean_params = {k: v for k, v in params.items() if v is not None}
            if clean_params:
                delimiter = "&" if "?" in url else "?"
                url += delimiter + urllib.parse.urlencode(clean_params, doseq=True)

        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", self._basic_auth_header)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "WooCommerce-MCP-Server/1.0")

        if data is not None:
            body_bytes = json.dumps(data).encode("utf-8")
            req.add_header("Content-Type", "application/json")
            req.data = body_bytes

        return req

    def _execute_with_retry(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Executes request with bounded exponential backoff on transient errors.
        Never retries 4xx permanent client errors.
        """
        if not self.store_url or not self._consumer_key or not self._consumer_secret:
            raise WooCommerceAPIError(
                "WooCommerce credentials are not configured on the server. Please set WOOCOMMERCE_STORE_URL, WOOCOMMERCE_CONSUMER_KEY, and WOOCOMMERCE_CONSUMER_SECRET.",
                status_code=500,
            )

        attempt = 0
        backoff_delay = 1.0

        while True:
            attempt += 1
            req = self._build_request(endpoint, method=method, params=params, data=data)
            safe_url = self._sanitize_log_url(req.full_url)

            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                    resp_body = resp.read().decode("utf-8")
                    if not resp_body.strip():
                        return {}
                    try:
                        return json.loads(resp_body)
                    except json.JSONDecodeError:
                        return {"raw_response": resp_body}

            except urllib.error.HTTPError as e:
                status = e.code
                error_body = ""
                try:
                    error_body = e.read().decode("utf-8")
                except Exception:
                    pass

                # Parse WooCommerce JSON error details if present
                wc_code = None
                wc_msg = None
                if error_body:
                    try:
                        parsed = json.loads(error_body)
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
                is_transient = status == 429 or 500 <= status <= 599

                if is_transient and attempt <= self.max_retries:
                    # Check for Retry-After header
                    retry_after_hdr = e.headers.get("Retry-After") if hasattr(e, "headers") else None
                    sleep_time = backoff_delay + random.uniform(0.1, 0.5)
                    if retry_after_hdr:
                        try:
                            sleep_time = max(float(retry_after_hdr), sleep_time)
                        except ValueError:
                            pass

                    logger.warning(
                        "Transient HTTP %s from WooCommerce for %s. Retrying in %.2fs (attempt %d/%d)...",
                        status, safe_url, sleep_time, attempt, self.max_retries
                    )
                    time.sleep(sleep_time)
                    backoff_delay *= 2
                    continue

                # Permanent or retries exhausted
                if status == 429:
                    raise WooCommerceAPIError(
                        "WooCommerce rate limit was reached. Please retry later.",
                        status_code=429,
                        error_code="rate_limit_exceeded",
                    )
                else:
                    detail = wc_msg or f"WooCommerce server returned HTTP {status} error."
                    raise WooCommerceAPIError(detail, status_code=status, error_code=wc_code)

            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionResetError) as e:
                if attempt <= self.max_retries:
                    sleep_time = backoff_delay + random.uniform(0.1, 0.5)
                    logger.warning(
                        "Transient network failure connecting to WooCommerce (%s). Retrying in %.2fs (attempt %d/%d)...",
                        type(e).__name__, sleep_time, attempt, self.max_retries
                    )
                    time.sleep(sleep_time)
                    backoff_delay *= 2
                    continue

                raise WooCommerceAPIError(
                    "Network connection to WooCommerce store failed or timed out. Please check store URL and network connectivity.",
                    status_code=504,
                    error_code="network_timeout",
                )

    # ------------------ High-Level WooCommerce Operations ------------------ #

    def search_products(
        self,
        query: Optional[str] = None,
        category: Optional[int] = None,
        status: Optional[str] = None,
        min_price: Optional[str] = None,
        max_price: Optional[str] = None,
        page: int = 1,
        per_page: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search products with filters."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": min(100, max(1, per_page)),
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

        raw_products = self._execute_with_retry("products", method="GET", params=params)
        if isinstance(raw_products, list):
            return [self._format_product(p) for p in raw_products]
        return []

    def get_product(
        self, product_id: Optional[int] = None, sku: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fetch product details by ID or SKU."""
        if product_id is not None:
            raw = self._execute_with_retry(f"products/{product_id}", method="GET")
            return self._format_product(raw)
        elif sku:
            raw_list = self._execute_with_retry("products", method="GET", params={"sku": sku})
            if isinstance(raw_list, list) and len(raw_list) > 0:
                return self._format_product(raw_list[0])
            raise WooCommerceAPIError(f"Product with SKU '{sku}' was not found.", status_code=404)
        else:
            raise WooCommerceAPIError("Either 'product_id' or 'sku' must be provided.", status_code=400)

    def list_products(
        self,
        stock_status: Optional[str] = None,
        category: Optional[int] = None,
        featured: Optional[bool] = None,
        page: int = 1,
        per_page: int = 10,
    ) -> List[Dict[str, Any]]:
        """List products with inventory details and filters."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": min(100, max(1, per_page)),
        }
        if stock_status:
            params["stock_status"] = stock_status
        if category is not None:
            params["category"] = category
        if featured is not None:
            params["featured"] = "true" if featured else "false"

        raw_products = self._execute_with_retry("products", method="GET", params=params)
        if isinstance(raw_products, list):
            return [self._format_product(p) for p in raw_products]
        return []

    def list_orders(
        self,
        status: Optional[str] = None,
        customer_id: Optional[int] = None,
        after: Optional[str] = None,
        before: Optional[str] = None,
        page: int = 1,
        per_page: int = 10,
    ) -> List[Dict[str, Any]]:
        """List store orders with optional filters."""
        params: Dict[str, Any] = {
            "page": max(1, page),
            "per_page": min(100, max(1, per_page)),
        }
        if status and status != "any":
            params["status"] = status
        if customer_id is not None:
            params["customer"] = customer_id
        if after:
            params["after"] = after
        if before:
            params["before"] = before

        raw_orders = self._execute_with_retry("orders", method="GET", params=params)
        if isinstance(raw_orders, list):
            return [self._format_order(o) for o in raw_orders]
        return []

    def get_order(self, order_id: int) -> Dict[str, Any]:
        """Fetch complete order details by order ID."""
        raw = self._execute_with_retry(f"orders/{order_id}", method="GET")
        return self._format_order(raw)

    def update_product_stock(
        self,
        product_id: int,
        stock_quantity: Optional[int] = None,
        stock_status: Optional[str] = None,
        manage_stock: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Update inventory stock quantity and status for a product."""
        payload: Dict[str, Any] = {}
        if stock_quantity is not None:
            payload["stock_quantity"] = stock_quantity
            # When stock quantity is updated, WooCommerce requires manage_stock to be True
            if manage_stock is None:
                payload["manage_stock"] = True
        if stock_status is not None:
            payload["stock_status"] = stock_status
        if manage_stock is not None:
            payload["manage_stock"] = manage_stock

        if not payload:
            raise WooCommerceAPIError("No inventory fields provided to update.", status_code=400)

        raw = self._execute_with_retry(f"products/{product_id}", method="PUT", data=payload)
        return self._format_product(raw)

    def create_product(
        self,
        name: str,
        type: str = "simple",
        regular_price: Optional[str] = None,
        description: Optional[str] = None,
        short_description: Optional[str] = None,
        manage_stock: Optional[bool] = None,
        stock_quantity: Optional[int] = None,
        sku: Optional[str] = None,
        categories: Optional[List[Dict[str, int]]] = None,
    ) -> Dict[str, Any]:
        """Create a new product in the store."""
        payload: Dict[str, Any] = {
            "name": name,
            "type": type,
        }
        if regular_price is not None:
            payload["regular_price"] = regular_price
        if description is not None:
            payload["description"] = description
        if short_description is not None:
            payload["short_description"] = short_description
        if manage_stock is not None:
            payload["manage_stock"] = manage_stock
        if stock_quantity is not None:
            payload["stock_quantity"] = stock_quantity
            payload["manage_stock"] = True
        if sku is not None:
            payload["sku"] = sku
        if categories:
            payload["categories"] = categories

        raw = self._execute_with_retry("products", method="POST", data=payload)
        return self._format_product(raw)

    # ------------------ Structured Response Formatters ------------------ #

    def _format_product(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Produce clean, structured product representation with relevant inventory & pricing."""
        if not isinstance(raw, dict):
            return {"raw": raw}
        return {
            "id": raw.get("id"),
            "name": raw.get("name"),
            "slug": raw.get("slug"),
            "permalink": raw.get("permalink"),
            "type": raw.get("type"),
            "status": raw.get("status"),
            "sku": raw.get("sku"),
            "price": raw.get("price"),
            "regular_price": raw.get("regular_price"),
            "sale_price": raw.get("sale_price"),
            "on_sale": raw.get("on_sale"),
            "stock_status": raw.get("stock_status"),
            "stock_quantity": raw.get("stock_quantity"),
            "manage_stock": raw.get("manage_stock"),
            "total_sales": raw.get("total_sales"),
            "categories": [
                {"id": c.get("id"), "name": c.get("name"), "slug": c.get("slug")}
                for c in raw.get("categories", [])
            ],
            "images": [
                {"id": img.get("id"), "src": img.get("src"), "alt": img.get("alt")}
                for img in raw.get("images", [])
            ],
            "short_description": raw.get("short_description", "").strip(),
        }

    def _format_order(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Produce clean, structured order representation."""
        if not isinstance(raw, dict):
            return {"raw": raw}
        return {
            "id": raw.get("id"),
            "number": raw.get("number"),
            "status": raw.get("status"),
            "currency": raw.get("currency"),
            "date_created": raw.get("date_created"),
            "total": raw.get("total"),
            "total_tax": raw.get("total_tax"),
            "customer_id": raw.get("customer_id"),
            "payment_method": raw.get("payment_method"),
            "payment_method_title": raw.get("payment_method_title"),
            "billing": raw.get("billing"),
            "shipping": raw.get("shipping"),
            "line_items": [
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "product_id": item.get("product_id"),
                    "variation_id": item.get("variation_id"),
                    "quantity": item.get("quantity"),
                    "subtotal": item.get("subtotal"),
                    "total": item.get("total"),
                    "sku": item.get("sku"),
                    "price": item.get("price"),
                }
                for item in raw.get("line_items", [])
            ],
        }
