"""
Comprehensive Verification Suite for WooCommerce MCP Server with Auth0 (DCR) & Dual-Layer Rate Limiting.
Tests:
1. MCP Protocol Initialization & Ping
2. Tool Discovery & Parameter Validation
3. Async Tool Execution & Strict Pagination Enforcement (max 15 items per page)
4. Initial Handshake (401 Challenge) with WWW-Authenticate Header pointing to metadata URL
5. RFC 9728 Protected Resource Metadata pointing to Auth0 Authorization Server
6. IP-Based Rate Limiting on GET /.well-known/oauth-protected-resource & Unauthenticated Handshakes
7. RS256 Stateless JWT Verification matching Auth0-Style JWKS & In-Memory Caching
8. Expired & Tampered Token Rejection
9. Authenticated Client Rate Limiting (Keyed by Token Subject Identifier)
10. Environment Variable Injection into os.environ
11. WooCommerce API Authentication Failure & Consumer Secret Sanitization
12. Transient Error Classification & Non-Blocking Async Retries
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
pkg_dir = os.path.join(current_dir, "woocommerce_mcp")

if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)

try:
    from auth import Authenticator, b64url_decode, b64url_encode, SHA256_DIGEST_INFO, verify_rs256
    from config import ServerConfig
    from rate_limiter import RateLimiter
    from server import MCPServer
    from tools import execute_tool, get_tool_definitions, validate_input
    from wc_client import WooCommerceAPIError, WooCommerceClient
    from worker import on_fetch, inject_env_variables
except ImportError:
    from woocommerce_mcp.auth import Authenticator, b64url_decode, b64url_encode, SHA256_DIGEST_INFO, verify_rs256
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


# Static 1024-bit RSA key pair for testing Auth0 RS256 signature verification completely offline
MOD_HEX = (
    "a8a4c2e31c78e055767a48ad72b27441c75c079e848bda0f0e3c662ad79d75c80fbc1d75e180"
    "b0c70d2a9b44f2b6bf4a1fd337b2082f3fb08a9c5e0d7e385917d057d2f9244b6ced259272ea"
    "b7c1dbceb52cb3939142f6f3de4b4b5ca243a520873cf24e7c9a6404b7883f94348bfa814c2d"
    "d9f9fed5b1fbbc6dab6c79cf5355"
)
D_HEX = (
    "a76c830a83cec1303762295b00de87aa72283c6c343cbf6c68feaf9362e1b0f7c01f4ac427ee"
    "e2118b51bc3a5417f78ab853b21c6e21b2422b2a17f99f5083a912079cd4940f74421885d315"
    "2e3f273389bd8c3a0356c21207e80c5ac142c3a50355a2c4682bf830b810b9c1bac4185076f4"
    "48be38b15ed525dc7b2517bfc541"
)

RSA_N = int(MOD_HEX, 16)
RSA_D = int(D_HEX, 16)
RSA_E = 65537
RSA_N_BYTES = bytes.fromhex(MOD_HEX)
RSA_E_BYTES = RSA_E.to_bytes((RSA_E.bit_length() + 7) // 8, "big")


def create_test_rs256_jwt(claims: Dict[str, Any], kid: str = "auth0-key-1") -> str:
    """Generate a valid Auth0-style RS256 JWT signed with test RSA private key."""
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    header_b64 = b64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # RSA PKCS#1 v1.5 padding with SHA-256 DigestInfo
    h = hashlib.sha256(signing_input).digest()
    t = SHA256_DIGEST_INFO + h
    k_len = len(RSA_N_BYTES)
    pad_len = k_len - len(t) - 3
    padded = b"\x00\x01" + (b"\xff" * pad_len) + b"\x00" + t
    padded_int = int.from_bytes(padded, "big")

    sig_int = pow(padded_int, RSA_D, RSA_N)
    sig_bytes = sig_int.to_bytes(k_len, "big")
    sig_b64 = b64url_encode(sig_bytes)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


async def run_all_tests():
    print(f"\n{YELLOW}{'='*70}")
    print("  WooCommerce MCP Server - Auth0 (DCR) & Dual-Layer Rate Limiting Suite  ")
    print(f"{'='*70}{RESET}")

    auth0_domain = "https://woocommerce-mcp-server.us.auth0.com"
    auth0_issuer = f"{auth0_domain}/"
    auth0_audience = "https://woocommerce-mcp-server.workers.dev"

    auth0_jwk = {
        "kty": "RSA",
        "kid": "auth0-key-1",
        "use": "sig",
        "n": b64url_encode(RSA_N_BYTES),
        "e": b64url_encode(RSA_E_BYTES),
        "alg": "RS256",
    }

    config = ServerConfig(
        store_url="https://mock-store.example.com",
        consumer_key="ck_test_1234567890",
        consumer_secret="cs_test_abcdef1234567890",
        oauth_auth_server_url=auth0_domain,
        oauth_jwks_url=f"{auth0_domain}/.well-known/jwks.json",
        oauth_audience=auth0_audience,
        oauth_issuer=auth0_issuer,
        unauth_rate_limit_max_requests=20,
        unauth_rate_limit_window_seconds=60,
    )

    # -------------------------------------------------------------------------
    # TEST 1: MCP Initialization
    # -------------------------------------------------------------------------
    print_test_header(1, "MCP Initialization (initialize & ping)")
    server = MCPServer(config)
    server.authenticator.jwks_manager.set_cached_jwks({"keys": [auth0_jwk]})

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "claude-desktop", "version": "1.0"},
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

    prods = await mock_client.list_products(page=1, per_page=100)
    assert_test(len(prods) == 1, "Async list_products succeeded")
    assert_test("per_page=15" in captured_urls[-1], "Clamps per_page=100 down to per_page=15 max")

    captured_urls.clear()
    await mock_client.list_orders()
    assert_test("per_page=10" in captured_urls[-1], "Defaults unpaginated orders to per_page=10")

    # -------------------------------------------------------------------------
    # TEST 4: Initial Handshake (401 Challenge) & WWW-Authenticate
    # -------------------------------------------------------------------------
    print_test_header(4, "Initial Handshake (401 Challenge) & WWW-Authenticate Header")
    env = MockEnv(
        WOOCOMMERCE_STORE_URL="https://dev-anythingstore37.pantheonsite.io",
        WOOCOMMERCE_CONSUMER_KEY="ck_test",
        WOOCOMMERCE_CONSUMER_SECRET="cs_test",
        OAUTH_AUTH_SERVER_URL=auth0_domain,
        OAUTH_JWKS_URL=f"{auth0_domain}/.well-known/jwks.json",
        OAUTH_ISSUER=auth0_issuer,
        OAUTH_AUDIENCE=auth0_audience,
        OAUTH_RESOURCE_SERVER_URL="https://my-store-mcp.workers.dev",
    )

    unauth_req = MockRequest(
        method="POST",
        url="https://my-store-mcp.workers.dev/mcp",
        headers={"cf-connecting-ip": "198.51.100.1"},
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
    # TEST 5: Protected Resource Metadata (RFC 9728) with Auth0
    # -------------------------------------------------------------------------
    print_test_header(5, "Protected Resource Metadata (RFC 9728) pointing to Auth0 DCR")
    metadata_req = MockRequest(
        method="GET",
        url="https://my-store-mcp.workers.dev/.well-known/oauth-protected-resource",
        headers={"cf-connecting-ip": "198.51.100.2"},
    )
    meta_res = await on_fetch(metadata_req, env)
    assert_test(meta_res.status == 200, "GET /.well-known/oauth-protected-resource returns 200")
    meta_json = json.loads(meta_res.body)
    assert_test(
        meta_json.get("resource") == "https://my-store-mcp.workers.dev",
        "Resource URL correctly set in RFC 9728 metadata",
    )
    assert_test(
        auth0_domain in meta_json.get("authorization_servers", []),
        f"Authorization server correctly set to Auth0 domain ({auth0_domain})",
    )
    assert_test(
        "mcp:read" in meta_json.get("scopes_supported", []) and "mcp:write" in meta_json.get("scopes_supported", []),
        "Supported scopes include 'mcp:read' and 'mcp:write'",
    )
    assert_test(
        meta_json.get("bearer_methods_supported") == ["header"],
        "Bearer methods supported set to ['header']",
    )

    # -------------------------------------------------------------------------
    # TEST 6: IP-Based Rate Limiting on Discovery Endpoint & Handshakes
    # -------------------------------------------------------------------------
    print_test_header(6, "IP-Based Rate Limiting on Discovery Endpoint")
    worker_server = MCPServer(config)
    worker_server.unauth_rate_limiter = RateLimiter(max_requests=5, window_seconds=1)
    spammer_ip = "203.0.113.99"

    for i in range(5):
        allowed, _ = worker_server.unauth_rate_limiter.check_limit(spammer_ip)
        assert_test(allowed, f"Discovery request {i+1} from IP within unauth limit accepted")

    allowed, retry_after = worker_server.unauth_rate_limiter.check_limit(spammer_ip)
    assert_test(not allowed, "Excessive unauthenticated discovery request rejected by IP limiter")
    assert_test(retry_after > 0, f"Returns valid retry-after window ({retry_after}s)")

    # -------------------------------------------------------------------------
    # TEST 7: Stateless RS256 JWT Verification matching Auth0 JWKS
    # -------------------------------------------------------------------------
    print_test_header(7, "Stateless RS256 JWT Verification (Auth0-Style Payload)")
    auth = Authenticator(
        jwks_url=f"{auth0_domain}/.well-known/jwks.json",
        expected_issuer=auth0_issuer,
        expected_audience=auth0_audience,
        static_keys=[auth0_jwk],
    )

    auth0_claims = {
        "iss": auth0_issuer,
        "sub": "auth0|64f2a1b3c8e9",
        "aud": [auth0_audience, f"{auth0_domain}/userinfo"],
        "azp": "claude-desktop-client-id",
        "scope": "mcp:read mcp:write",
        "exp": time.time() + 3600,
        "nbf": time.time() - 10,
    }
    valid_auth0_jwt = create_test_rs256_jwt(auth0_claims, kid="auth0-key-1")

    is_valid, client_id, err = await auth.authenticate_request_async(
        {"Authorization": f"Bearer {valid_auth0_jwt}"}
    )
    assert_test(is_valid is True, "Valid Auth0 RS256 JWT successfully authenticated")
    assert_test(client_id.startswith("oauth-"), f"Client ID derived from token subject: {client_id}")
    assert_test(err is None, "No authentication error for valid Auth0 token")
    assert_test(auth.jwks_manager.get_cached_jwks() is not None, "Auth0 JWKS cached in memory")
    assert_test(
        auth.jwks_manager.get_cached_jwks()["keys"][0]["kid"] == "auth0-key-1",
        "Cached JWKS retains Auth0 RSA public key across requests",
    )

    # -------------------------------------------------------------------------
    # TEST 8: Expired & Tampered Token Rejection
    # -------------------------------------------------------------------------
    print_test_header(8, "Expired & Tampered RS256 Token Rejection")
    expired_claims = dict(auth0_claims)
    expired_claims["exp"] = time.time() - 300
    expired_jwt = create_test_rs256_jwt(expired_claims, kid="auth0-key-1")

    is_valid_exp, _, err_exp = await auth.authenticate_request_async(
        {"Authorization": f"Bearer {expired_jwt}"}
    )
    assert_test(is_valid_exp is False, "Expired Auth0 token is rejected")
    assert_test("expired" in err_exp.lower(), f"Returns expiration error message: {err_exp}")

    tampered_jwt = valid_auth0_jwt[:-5] + "AAAAA"
    is_valid_tamp, _, err_tamp = await auth.authenticate_request_async(
        {"Authorization": f"Bearer {tampered_jwt}"}
    )
    assert_test(is_valid_tamp is False, "Tampered RS256 signature is rejected")
    assert_test("signature" in err_tamp.lower(), f"Returns signature error message: {err_tamp}")

    # -------------------------------------------------------------------------
    # TEST 9: Authenticated Client Rate Limiting (Keyed by Token Subject)
    # -------------------------------------------------------------------------
    print_test_header(9, "Authenticated Client Rate Limiting (Keyed by Subject)")
    auth_limiter = RateLimiter(max_requests=5, window_seconds=1)
    test_subject_client_id = client_id

    for i in range(5):
        allowed, _ = auth_limiter.check_limit(test_subject_client_id)
        assert_test(allowed, f"Authenticated request {i+1} from client within limit accepted")

    allowed, retry_after = auth_limiter.check_limit(test_subject_client_id)
    assert_test(not allowed, "Authenticated request exceeding limit is rejected with 429 status")
    assert_test(retry_after > 0, f"Returns valid retry_after window ({retry_after}s)")

    # -------------------------------------------------------------------------
    # TEST 10: Environment Variable Injection into os.environ
    # -------------------------------------------------------------------------
    print_test_header(10, "Environment Variable Injection into os.environ")
    test_env = MockEnv(
        WOOCOMMERCE_STORE_URL="https://dev-anythingstore37.pantheonsite.io",
        WOOCOMMERCE_CONSUMER_KEY="ck_injected_123",
        WOOCOMMERCE_CONSUMER_SECRET="cs_injected_456",
        OAUTH_AUTH_SERVER_URL=auth0_domain,
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
        os.environ.get("OAUTH_AUTH_SERVER_URL") == auth0_domain,
        f"Injected OAUTH_AUTH_SERVER_URL into os.environ: {auth0_domain}",
    )

    # -------------------------------------------------------------------------
    # TEST 11: WooCommerce Authentication Failure & Secret Sanitization
    # -------------------------------------------------------------------------
    print_test_header(11, "WooCommerce Authentication Failure Handling & Sanitization")
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
    # TEST 12: Transient Retry Classification & Rate Limiting
    # -------------------------------------------------------------------------
    print_test_header(12, "Transient Retry Classification")
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

    print(f"\n{GREEN}{'='*70}")
    print("   ALL 12 AUTH0 & DUAL-LAYER RATE LIMITING TESTS PASSED!          ")
    print(f"{'='*70}{RESET}\n")


if __name__ == "__main__":
    asyncio.run(run_all_tests())
