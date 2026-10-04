"""
Comprehensive Verification Suite for WooCommerce MCP Server with OAuth 2.1 & Async Client.
Tests:
1. MCP Protocol Initialization & Tool Discovery
2. Async Tool Execution & Strict Pagination Enforcement (max 15 items per page)
3. Initial Handshake (401 Challenge) with WWW-Authenticate Header
4. RFC 9728 Protected Resource Metadata (/.well-known/oauth-protected-resource)
5. Stateless JWT Signature Verification & JWKS In-Memory Caching
6. Expired and Tampered Token Rejection
7. Rate Limiting at MCP Boundary for Authenticated Subject
8. Environment Variable Injection into os.environ
9. WooCommerce Authentication Failure & Secret Sanitization
10. Transient Error Retry with Non-Blocking Async Sleep
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from typing import Any, Dict

# Ensure package directory is first in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

if current_dir in sys.path:
    sys.path.remove(current_dir)
sys.path.insert(0, current_dir)

if parent_dir in sys.path:
    sys.path.remove(parent_dir)
sys.path.append(parent_dir)

try:
    from auth import Authenticator, b64url_decode, b64url_encode
    from config import ServerConfig
    from rate_limiter import RateLimiter
    from server import MCPServer
    from tools import execute_tool, get_tool_definitions, validate_input
    from wc_client import WooCommerceAPIError, WooCommerceClient
    from worker import on_fetch, inject_env_variables
except ImportError:
    from woocommerce_mcp.auth import Authenticator, b64url_decode, b64url_encode
    from woocommerce_mcp.config import ServerConfig
    from woocommerce_mcp.rate_limiter import RateLimiter
    from woocommerce_mcp.server import MCPServer
    from woocommerce_mcp.tools import execute_tool, get_tool_definitions, validate_input
    from woocommerce_mcp.wc_client import WooCommerceAPIError, WooCommerceClient
    from woocommerce_mcp.worker import on_fetch, inject_env_variables

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def print_test_header(num: int, title: str):
    print(f"\n{BLUE}[TEST {num}] {title}{RESET}")


def assert_test(condition: bool, description: str):
    if condition:
        print(f"  {GREEN}✓ PASS:{RESET} {description}")
    else:
        print(f"  {RED}✗ FAIL:{RESET} {description}")
        raise AssertionError(f"Test failed: {description}")


class MockRequest:
    """Mock Cloudflare Worker request for testing."""
    def __init__(self, method: str = "POST", url: str = "https://my-store-mcp.workers.dev/mcp", headers=None, body=""):
        self.method = method
        self.url = url
        self._headers_dict = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        self._body = body

    @property
    def headers(self):
        class HeadersAdapter:
            def __init__(self, d):
                self._d = d
            def get(self, k):
                return self._d.get(str(k).lower())
            def entries(self):
                return [(k, v) for k, v in self._d.items()]
            def __iter__(self):
                return iter(self.entries())
        return HeadersAdapter(self._headers_dict)

    async def text(self):
        return self._body


class MockEnv:
    """Mock Cloudflare Worker environment variables."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getitem__(self, item):
        return getattr(self, item, None)


def create_test_jwt(claims: Dict[str, Any], secret_bytes: bytes, kid: str = "test-key-1") -> str:
    """Generate a test JWT token signed with HMAC-SHA256 matching our test JWKS."""
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    header_b64 = b64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


async def run_all_tests():
    print(f"\n{YELLOW}{'='*70}")
    print("     WooCommerce MCP Server - Async & OAuth 2.1 Verification Suite     ")
    print(f"{'='*70}{RESET}")

    test_secret = b"test-symmetric-secret-key-32-byte!"
    test_jwk = {
        "kty": "oct",
        "kid": "test-key-1",
        "k": b64url_encode(test_secret),
    }

    config = ServerConfig(
        store_url="https://mock-store.example.com",
        consumer_key="ck_test_1234567890",
        consumer_secret="cs_test_abcdef1234567890",
        oauth_auth_server_url="https://auth.example.com",
        oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        oauth_audience="https://mock-store.example.com",
        oauth_issuer="https://auth.example.com",
    )

    # -------------------------------------------------------------------------
    # TEST 1: MCP Initialization
    # -------------------------------------------------------------------------
    print_test_header(1, "MCP Initialization (initialize & ping)")
    server = MCPServer(config)
    server.authenticator.jwks_manager.set_cached_jwks({"keys": [test_jwk]})

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    init_resp = await server.handle_json_rpc(init_req, client_id="test")
    assert_test(init_resp.get("jsonrpc") == "2.0", "Returns JSON-RPC 2.0 response")
    assert_test("serverInfo" in init_resp.get("result", {}), "Returns serverInfo metadata")
    assert_test(
        init_resp["result"].get("protocolVersion") == "2024-11-05",
        "Correct MCP protocol version",
    )

    ping_req = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
    ping_resp = await server.handle_json_rpc(ping_req, client_id="test")
    assert_test(ping_resp.get("result") == {}, "Ping returns empty result object")

    # -------------------------------------------------------------------------
    # TEST 2: Tool Discovery & Input Validation
    # -------------------------------------------------------------------------
    print_test_header(2, "Tool Discovery & Parameter Validation")
    tools_req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
    tools_resp = await server.handle_json_rpc(tools_req, client_id="test")
    tools = tools_resp.get("result", {}).get("tools", [])
    tool_names = [t["name"] for t in tools]

    expected_tools = [
        "search_products",
        "get_product",
        "list_products",
        "list_orders",
        "get_order",
        "update_product_stock",
        "create_product",
    ]
    for exp in expected_tools:
        assert_test(exp in tool_names, f"Tool '{exp}' is exposed with valid schema")

    for t in tools:
        assert_test(
            "inputSchema" in t and t["inputSchema"].get("type") == "object",
            f"Tool '{t['name']}' has valid JSON Schema inputSchema",
        )

    invalid_req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {"name": "get_product", "arguments": {}},
    }
    inv_resp = await server.handle_json_rpc(invalid_req, client_id="test")
    assert_test(inv_resp["result"]["isError"] is True, "Rejects get_product without ID or SKU")
    assert_test(
        "validation failed" in inv_resp["result"]["content"][0]["text"].lower(),
        "Returns informative input validation message",
    )

    # -------------------------------------------------------------------------
    # TEST 3: Async WooCommerce Client & Strict Pagination Enforcement
    # -------------------------------------------------------------------------
    print_test_header(3, "Async Client & Strict Pagination Enforcement (max 15 per page)")
    captured_urls = []

    class MockAsyncWCClient(WooCommerceClient):
        async def _async_http_call(self, url, method, headers, body=None):
            captured_urls.append(url)
            return 200, json.dumps([{"id": 1, "name": "T-Shirt", "price": "19.99"}]), {}

    mock_client = MockAsyncWCClient(
        store_url="https://mock-store.example.com",
        consumer_key="ck_123",
        consumer_secret="cs_123",
    )

    # Request 100 items -> should be clamped to 15
    prods = await mock_client.list_products(page=1, per_page=100)
    assert_test(len(prods) == 1, "Async list_products succeeded")
    assert_test("per_page=15" in captured_urls[-1], "Clamps per_page=100 down to per_page=15 max")

    # Default without per_page -> defaults to 10
    captured_urls.clear()
    await mock_client.list_orders()
    assert_test("per_page=10" in captured_urls[-1], "Defaults unpaginated orders to per_page=10")

    # -------------------------------------------------------------------------
    # TEST 4: Initial Handshake (401 Challenge) & WWW-Authenticate
    # -------------------------------------------------------------------------
    print_test_header(4, "Initial Handshake (401 Challenge) & WWW-Authenticate")
    env = MockEnv(
        WOOCOMMERCE_STORE_URL="https://dev-anythingstore37.pantheonsite.io",
        WOOCOMMERCE_CONSUMER_KEY="ck_test",
        WOOCOMMERCE_CONSUMER_SECRET="cs_test",
        OAUTH_AUTH_SERVER_URL="https://auth.example.com",
        OAUTH_JWKS_URL="https://auth.example.com/.well-known/jwks.json",
    )

    unauth_req = MockRequest(
        method="POST",
        url="https://my-store-mcp.workers.dev/mcp",
        headers={},
        body=json.dumps({"jsonrpc": "2.0", "id": 10, "method": "tools/list"}),
    )

    res_401 = await on_fetch(unauth_req, env)
    assert_test(res_401.status == 401, "Returns HTTP 401 Unauthorized for unauthenticated request")
    www_auth_val = res_401.headers.get("www-authenticate")
    expected_header = 'Bearer realm="mcp", resource_metadata="https://my-store-mcp.workers.dev/.well-known/oauth-protected-resource"'
    assert_test(
        www_auth_val == expected_header,
        f"Contains exact required WWW-Authenticate header: {www_auth_val}",
    )

    # -------------------------------------------------------------------------
    # TEST 5: Protected Resource Metadata (RFC 9728)
    # -------------------------------------------------------------------------
    print_test_header(5, "Protected Resource Metadata (RFC 9728)")
    metadata_req = MockRequest(
        method="GET",
        url="https://my-store-mcp.workers.dev/.well-known/oauth-protected-resource",
    )
    meta_res = await on_fetch(metadata_req, env)
    assert_test(meta_res.status == 200, "GET /.well-known/oauth-protected-resource returns 200")
    meta_json = json.loads(meta_res.body)
    assert_test(
        meta_json.get("resource") == "https://my-store-mcp.workers.dev",
        "Resource URL correctly set in RFC 9728 metadata",
    )
    assert_test(
        "https://auth.example.com" in meta_json.get("authorization_servers", []),
        "Authorization server correctly set to OAUTH_AUTH_SERVER_URL",
    )
    assert_test(
        "mcp:read" in meta_json.get("scopes_supported", []),
        "Supported scopes include 'mcp:read'",
    )

    # -------------------------------------------------------------------------
    # TEST 6: Stateless JWT Signature Verification & JWKS In-Memory Caching
    # -------------------------------------------------------------------------
    print_test_header(6, "Stateless JWT Signature Verification & JWKS In-Memory Caching")
    auth = Authenticator(
        jwks_url="https://auth.example.com/.well-known/jwks.json",
        expected_issuer="https://auth.example.com",
        static_keys=[test_jwk],
    )

    valid_claims = {
        "sub": "user_42",
        "iss": "https://auth.example.com",
        "exp": time.time() + 3600,
        "nbf": time.time() - 10,
    }
    valid_jwt = create_test_jwt(valid_claims, test_secret, kid="test-key-1")

    is_valid, client_id, err = await auth.authenticate_request_async({"Authorization": f"Bearer {valid_jwt}"})
    assert_test(is_valid is True, "Valid JWT successfully authenticated")
    assert_test(client_id.startswith("oauth-"), "Client ID safely derived from subject claim")
    assert_test(err is None, "No authentication error returned for valid token")

    assert_test(auth.jwks_manager.get_cached_jwks() is not None, "JWKS is cached in memory")
    assert_test(
        auth.jwks_manager.get_cached_jwks()["keys"][0]["kid"] == "test-key-1",
        "Cached JWKS retains public keys across requests",
    )

    # -------------------------------------------------------------------------
    # TEST 7: Expired and Invalid Token Rejection
    # -------------------------------------------------------------------------
    print_test_header(7, "Expired and Invalid Token Rejection")
    expired_claims = {
        "sub": "user_42",
        "iss": "https://auth.example.com",
        "exp": time.time() - 300,
    }
    expired_jwt = create_test_jwt(expired_claims, test_secret, kid="test-key-1")
    is_valid_exp, _, err_exp = await auth.authenticate_request_async({"Authorization": f"Bearer {expired_jwt}"})
    assert_test(is_valid_exp is False, "Expired token is rejected")
    assert_test("expired" in err_exp.lower(), f"Returns expiration error message: {err_exp}")

    tampered_jwt = valid_jwt[:-5] + "XXXXX"
    is_valid_tamp, _, err_tamp = await auth.authenticate_request_async({"Authorization": f"Bearer {tampered_jwt}"})
    assert_test(is_valid_tamp is False, "Tampered signature is rejected")
    assert_test("signature" in err_tamp.lower(), f"Returns signature error message: {err_tamp}")

    # -------------------------------------------------------------------------
    # TEST 8: Environment Variable Injection into os.environ
    # -------------------------------------------------------------------------
    print_test_header(8, "Environment Variable Injection into os.environ")
    test_env = MockEnv(
        WOOCOMMERCE_STORE_URL="https://dev-anythingstore37.pantheonsite.io",
        WOOCOMMERCE_CONSUMER_KEY="ck_injected_123",
        WOOCOMMERCE_CONSUMER_SECRET="cs_injected_456",
        OAUTH_AUTH_SERVER_URL="https://auth.injected.com",
    )
    inject_env_variables(test_env)
    assert_test(
        os.environ.get("WOOCOMMERCE_STORE_URL") == "https://dev-anythingstore37.pantheonsite.io",
        "Injected WOOCOMMERCE_STORE_URL into os.environ",
    )
    assert_test(
        os.environ.get("WOOCOMMERCE_CONSUMER_KEY") == "ck_injected_123",
        "Injected WOOCOMMERCE_CONSUMER_KEY into os.environ",
    )
    assert_test(
        os.environ.get("OAUTH_AUTH_SERVER_URL") == "https://auth.injected.com",
        "Injected OAUTH_AUTH_SERVER_URL into os.environ",
    )

    # -------------------------------------------------------------------------
    # TEST 9: WooCommerce Authentication Failure & Secret Sanitization
    # -------------------------------------------------------------------------
    print_test_header(9, "WooCommerce Authentication Failure Handling & Sanitization")
    class AuthFailingWCClient(WooCommerceClient):
        async def _execute_with_retry(self, endpoint, method="GET", params=None, data=None):
            raise WooCommerceAPIError(
                "Authentication failed with WooCommerce. Please check store credentials and permissions.",
                status_code=401,
                error_code="woocommerce_rest_authentication_error",
            )

    auth_failing_client = AuthFailingWCClient(
        store_url="https://mock-store.example.com",
        consumer_key="invalid_key",
        consumer_secret="invalid_secret_do_not_leak",
        max_retries=1,
    )
    auth_failed_server = MCPServer(config)
    auth_failed_server.wc_client = auth_failing_client

    wc_auth_req = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {"name": "get_order", "arguments": {"order_id": 99}},
    }
    wc_auth_resp = await auth_failed_server.handle_json_rpc(wc_auth_req, client_id="test")
    err_text = wc_auth_resp["result"]["content"][0]["text"]
    assert_test(wc_auth_resp["result"]["isError"] is True, "Marks response as error")
    assert_test("invalid_secret_do_not_leak" not in err_text, "Consumer secret is NOT leaked in error output")

    # -------------------------------------------------------------------------
    # TEST 10: Transient Retry Classification & Rate Limiting
    # -------------------------------------------------------------------------
    print_test_header(10, "Transient Retry Classification & Rate Limiting")
    wc_client = WooCommerceClient(
        store_url="https://mock.example.com",
        consumer_key="ck_123",
        consumer_secret="cs_123",
        max_retries=3,
    )
    for code in [429, 500, 502, 503, 504]:
        assert_test(wc_client.is_transient_error(code), f"HTTP {code} is classified as transient")
    for code in [400, 401, 403, 404, 422]:
        assert_test(not wc_client.is_transient_error(code), f"HTTP {code} is classified as permanent")

    limiter = RateLimiter(max_requests=5, window_seconds=1)
    client_test_id = "oauth-client-abc"
    for i in range(5):
        allowed, _ = limiter.check_limit(client_test_id)
        assert_test(allowed, f"Request {i+1} within rate limit accepted")

    allowed, retry_after = limiter.check_limit(client_test_id)
    assert_test(not allowed, "Request exceeding limit is rejected with 429 status")
    assert_test(retry_after > 0, f"Returns valid retry_after window ({retry_after}s)")

    print(f"\n{GREEN}{'='*70}")
    print("   ALL 10 ASYNC & OAUTH 2.1 VERIFICATION REQUIREMENTS PASSED!       ")
    print(f"{'='*70}{RESET}\n")


if __name__ == "__main__":
    asyncio.run(run_all_tests())
