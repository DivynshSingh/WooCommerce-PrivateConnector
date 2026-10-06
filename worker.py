"""
Cloudflare Workers Python Entrypoint for WooCommerce MCP Server.
Implements non-blocking asynchronous WooCommerce REST client,
manual environment variable injection, OAuth 2.1 RFC 9728 Protected Resource Metadata,
RFC 7591 Dynamic Client Registration proxy, and JavaScript runtime sequence header compatibility.
"""

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse

_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

pkg_dir = os.path.join(_dir, "woocommerce_mcp")
if os.path.isdir(pkg_dir) and pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)

try:
    from config import ServerConfig
    from server import MCPServer
    from dcr import handle_dcr_registration
    from auth import b64url_encode, b64url_decode
except ImportError:
    from woocommerce_mcp.config import ServerConfig
    from woocommerce_mcp.server import MCPServer
    from woocommerce_mcp.dcr import handle_dcr_registration
    from woocommerce_mcp.auth import b64url_encode, b64url_decode

try:
    from fastapi import FastAPI
    app = FastAPI(redirect_slashes=False)
except ImportError:
    class FastAPI:
        """FastAPI-compatible stub ensuring redirect_slashes=False is set and accessible."""
        def __init__(self, *args, redirect_slashes: bool = False, **kwargs):
            self.redirect_slashes = redirect_slashes
            self.routes = []

        def get(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator

        def post(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator

        def options(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator

    app = FastAPI(redirect_slashes=False)

_server_instance = None


def inject_env_variables(env) -> None:
    """
    Manually injects Cloudflare Worker env secrets and variables into os.environ.
    Cloudflare Workers does not populate os.environ globally by default.
    """
    if env is None:
        return

    keys_to_inject = [
        "WOOCOMMERCE_STORE_URL",
        "WOOCOMMERCE_CONSUMER_KEY",
        "WOOCOMMERCE_CONSUMER_SECRET",
        "OAUTH_AUTH_SERVER_URL",
        "OAUTH_JWKS_URL",
        "OAUTH_RESOURCE_SERVER_URL",
        "OAUTH_AUDIENCE",
        "OAUTH_ISSUER",
        "OAUTH_JWKS_CACHE_TTL_SECONDS",
        "MCP_RATE_LIMIT_MAX_REQUESTS",
        "MCP_RATE_LIMIT_WINDOW_SECONDS",
        "WOOCOMMERCE_MAX_RETRIES",
        "WOOCOMMERCE_TIMEOUT_SECONDS",
    ]

    for key in keys_to_inject:
        val = None
        if hasattr(env, key):
            val = getattr(env, key)
        elif isinstance(env, dict) and key in env:
            val = env[key]

        if val is not None:
            os.environ[key] = str(val)


def get_server_for_env(env) -> MCPServer:
    """Initialize or reuse MCPServer instance configured with Cloudflare Worker env secrets."""
    global _server_instance

    inject_env_variables(env)

    def get_var(key: str, default: str = "") -> str:
        if key in os.environ and os.environ[key].strip():
            return os.environ[key].strip()
        if env is not None:
            if hasattr(env, key):
                val = getattr(env, key)
                if val is not None:
                    return str(val).strip()
            elif isinstance(env, dict) and key in env:
                val = env[key]
                if val is not None:
                    return str(val).strip()
        return default

    store_url = get_var("WOOCOMMERCE_STORE_URL", "").rstrip("/")
    consumer_key = get_var("WOOCOMMERCE_CONSUMER_KEY", "")
    consumer_secret = get_var("WOOCOMMERCE_CONSUMER_SECRET", "")

    # OAuth 2.1 Configuration (Auth0 with RFC 7591 Dynamic Client Registration)
    oauth_auth_server_url = get_var("OAUTH_AUTH_SERVER_URL", "").rstrip("/")
    oauth_jwks_url = get_var("OAUTH_JWKS_URL", "")
    if not oauth_jwks_url and oauth_auth_server_url:
        oauth_jwks_url = f"{oauth_auth_server_url}/.well-known/jwks.json"

    oauth_audience = get_var("OAUTH_AUDIENCE", "")
    oauth_issuer = get_var("OAUTH_ISSUER", "").rstrip("/")
    if not oauth_issuer and oauth_auth_server_url:
        oauth_issuer = oauth_auth_server_url
    if oauth_issuer and not oauth_issuer.endswith("/"):
        oauth_issuer += "/"
    oauth_resource_url = (
        get_var("OAUTH_RESOURCE_SERVER_URL", "").rstrip("/")
        or get_var("RESOURCE_SERVER_URL", "").rstrip("/")
    )

    try:
        jwks_ttl = int(get_var("OAUTH_JWKS_CACHE_TTL_SECONDS", "300"))
    except ValueError:
        jwks_ttl = 300

    try:
        rate_limit_max = int(get_var("MCP_RATE_LIMIT_MAX_REQUESTS", "50"))
    except ValueError:
        rate_limit_max = 50

    try:
        rate_limit_window = int(get_var("MCP_RATE_LIMIT_WINDOW_SECONDS", "10"))
    except ValueError:
        rate_limit_window = 10

    try:
        unauth_rate_limit_max = int(get_var("UNAUTH_RATE_LIMIT_MAX_REQUESTS", "20"))
    except ValueError:
        unauth_rate_limit_max = 20

    try:
        unauth_rate_limit_window = int(get_var("UNAUTH_RATE_LIMIT_WINDOW_SECONDS", "60"))
    except ValueError:
        unauth_rate_limit_window = 60

    try:
        wc_max_retries = int(get_var("WOOCOMMERCE_MAX_RETRIES", "3"))
    except ValueError:
        wc_max_retries = 3

    try:
        wc_timeout = float(get_var("WOOCOMMERCE_TIMEOUT_SECONDS", "15.0"))
    except ValueError:
        wc_timeout = 15.0

    # Re-use or instantiate server
    if _server_instance is not None:
        if (
            _server_instance.config.store_url == store_url
            and _server_instance.config.consumer_key == consumer_key
            and _server_instance.config.consumer_secret == consumer_secret
            and _server_instance.config.oauth_auth_server_url == oauth_auth_server_url
        ):
            return _server_instance

    config = ServerConfig(
        store_url=store_url,
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        oauth_auth_server_url=oauth_auth_server_url,
        oauth_jwks_url=oauth_jwks_url,
        oauth_audience=oauth_audience,
        oauth_issuer=oauth_issuer,
        oauth_resource_server_url=oauth_resource_url,
        jwks_cache_ttl_seconds=jwks_ttl,
        rate_limit_max_requests=rate_limit_max,
        rate_limit_window_seconds=rate_limit_window,
        unauth_rate_limit_max_requests=unauth_rate_limit_max,
        unauth_rate_limit_window_seconds=unauth_rate_limit_window,
        wc_max_retries=wc_max_retries,
        wc_timeout_seconds=wc_timeout,
    )
    _server_instance = MCPServer(config)
    return _server_instance


async def on_fetch(request, env):
    """Cloudflare Worker request handler with async transport and sequence-based headers."""
    try:
        from js import Response, Headers
    except ImportError:
        class Headers:
            def __init__(self, pairs):
                self._pairs = list(pairs)
                self._dict = {str(k).lower(): str(v) for k, v in pairs}
            @classmethod
            def new(cls, pairs):
                return cls(pairs)
            def get(self, k):
                return self._dict.get(str(k).lower())

        class Response:
            def __init__(self, body, status=200, headers=None):
                self.body = body
                self.status = status
                self.headers = headers
            @classmethod
            def new(cls, body, status=200, headers=None):
                return cls(body, status=status, headers=headers)

    # 1. Environment Variable Injection into os.environ before initializing server
    inject_env_variables(env)

    method = str(request.method).upper()
    url_str = str(request.url)

    path = "/" + url_str.split("/", 3)[-1].split("?")[0] if "/" in url_str else "/"
    query_str = url_str.split("?", 1)[1] if "?" in url_str else ""

    # Normalize trailing slash directly without 307 Temporary Redirects (preserves POST body)
    norm_path = path.rstrip("/") if len(path) > 1 and path.endswith("/") else path

    server = get_server_for_env(env)
    configured_resource_url = server.config.oauth_resource_server_url

    if configured_resource_url:
        worker_origin = configured_resource_url
    elif "://" in url_str:
        scheme, rest = url_str.split("://", 1)
        host = rest.split("/")[0]
        worker_origin = f"{scheme}://{host}"
    else:
        host_header = ""
        try:
            if hasattr(request, "headers") and request.headers:
                host_header = request.headers.get("host", "") or request.headers.get("Host", "")
        except Exception:
            pass
        worker_origin = f"https://{host_header}" if host_header else "http://localhost:3000"

    resource_metadata_url = f"{worker_origin}/.well-known/oauth-protected-resource"
    www_auth_challenge = f'Bearer realm="mcp", resource_metadata="{resource_metadata_url}"'

    # Configure authenticator worker_origin for JWT validation
    server.authenticator.worker_origin = worker_origin
    if not server.authenticator.expected_audience:
        server.authenticator.expected_audience = worker_origin

    # JS sequence of sequences for Web API Headers compatibility (avoids Sequence TypeErrors)
    cors_headers_list = [
        ["Access-Control-Allow-Origin", "*"],
        ["Access-Control-Allow-Methods", "GET, POST, OPTIONS"],
        ["Access-Control-Allow-Headers", "Authorization, Content-Type"],
    ]

    def create_json_headers(extra_pairs=None):
        pairs = [["Content-Type", "application/json"]] + cors_headers_list
        if extra_pairs:
            pairs.extend(extra_pairs)
        return Headers.new(pairs)

    # 2. CORS Preflight
    if method == "OPTIONS":
        return Response.new(
            "",
            status=204,
            headers=Headers.new(cors_headers_list),
        )

    # Extract incoming headers safely via Web API
    req_headers = {}
    for h in ("authorization", "content-type", "user-agent", "cf-connecting-ip", "x-forwarded-for", "x-real-ip"):
        try:
            val = request.headers.get(h)
            if val is not None:
                req_headers[h] = str(val)
        except Exception:
            pass

    try:
        if hasattr(request.headers, "entries"):
            for entry in request.headers.entries():
                k = str(entry[0]).lower()
                v = str(entry[1])
                req_headers[k] = v
    except Exception:
        pass

    def extract_client_ip() -> str:
        ip = req_headers.get("cf-connecting-ip")
        if not ip:
            xff = req_headers.get("x-forwarded-for")
            if xff:
                ip = xff.split(",")[0].strip()
        if not ip:
            ip = req_headers.get("x-real-ip")
        if not ip and hasattr(request, "headers"):
            try:
                ip = request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for")
                if ip and "," in str(ip):
                    ip = str(ip).split(",")[0].strip()
            except Exception:
                pass
        return str(ip).strip() if ip else "127.0.0.1"

    # 3. RFC 9728 Protected Resource Metadata endpoint
    if method == "GET" and norm_path == "/.well-known/oauth-protected-resource":
        # Unauthenticated / IP-based rate limiting on discovery endpoint
        client_ip = extract_client_ip()
        allowed, retry_after = server.unauth_rate_limiter.check_limit(client_ip)
        if not allowed:
            err_body = json.dumps({
                "error": "too_many_requests",
                "message": f"Rate limit exceeded for discovery endpoint. Retry after {retry_after} seconds.",
            })
            return Response.new(
                err_body,
                status=429,
                headers=create_json_headers([["Retry-After", str(retry_after)]]),
            )

        auth_servers = []
        if server.config.oauth_auth_server_url:
            auth_servers.append(server.config.oauth_auth_server_url)

        protected_resource_metadata = {
            "resource": worker_origin,
            "authorization_servers": auth_servers,
            "registration_endpoint": f"{worker_origin}/oauth/register",
            "scopes_supported": [
                "mcp:read",
                "mcp:write",
            ],
            "bearer_methods_supported": [
                "header",
            ],
            "resource_documentation": "https://modelcontextprotocol.io",
        }
        return Response.new(
            json.dumps(protected_resource_metadata),
            status=200,
            headers=create_json_headers(),
        )

    # 3b. RFC 8414 OAuth Authorization Server Metadata & OpenID Configuration
    # Intercepts discovery to force AI clients to register through the worker DCR proxy
    if method == "GET" and norm_path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        client_ip = extract_client_ip()
        allowed, retry_after = server.unauth_rate_limiter.check_limit(client_ip)
        if not allowed:
            err_body = json.dumps({
                "error": "too_many_requests",
                "message": f"Rate limit exceeded. Retry after {retry_after} seconds.",
            })
            return Response.new(
                err_body,
                status=429,
                headers=create_json_headers([["Retry-After", str(retry_after)]]),
            )

        auth_server_base = (server.config.oauth_auth_server_url or "").rstrip("/")
        as_metadata = {
            "issuer": server.config.oauth_issuer or f"{auth_server_base}/",
            "authorization_endpoint": f"{auth_server_base}/authorize",
            "token_endpoint": f"{auth_server_base}/oauth/token",
            "jwks_uri": server.config.oauth_jwks_url or f"{auth_server_base}/.well-known/jwks.json",
            "registration_endpoint": f"{worker_origin}/oauth/register",
            "scopes_supported": [
                "mcp:read",
                "mcp:write",
                "offline_access",
            ],
            "response_types_supported": [
                "code",
            ],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
            ],
            "code_challenge_methods_supported": [
                "S256",
            ],
            "token_endpoint_auth_methods_supported": [
                "none",
            ],
        }
        return Response.new(
            json.dumps(as_metadata),
            status=200,
            headers=create_json_headers(),
        )

    # 3c. OAuth 2.1 Authorization Endpoint Forwarder
    # Forwards directly to Auth0's Universal Login page with human authentication
    if method == "GET" and norm_path == "/oauth/authorize":
        auth_server_base = (server.config.oauth_auth_server_url or "").rstrip("/")
        if not auth_server_base:
            err_body = json.dumps({
                "error": "server_misconfiguration",
                "error_description": "OAUTH_AUTH_SERVER_URL environment variable is not configured.",
            })
            return Response.new(err_body, status=500, headers=create_json_headers())
        target = f"{auth_server_base}/authorize"
        if query_str:
            target += f"?{query_str}"
        return Response.new(
            "",
            status=302,
            headers=[["Location", target]],
        )

    # 3d. Direct OAuth 2.1 Token Exchange Notification
    if method == "POST" and norm_path == "/oauth/token":
        auth_server_base = (server.config.oauth_auth_server_url or "").rstrip("/")
        err_body = json.dumps({
            "error": "invalid_request",
            "error_description": f"Token exchange must be performed directly at the Auth0 token endpoint: {auth_server_base}/oauth/token",
        })
        return Response.new(
            err_body,
            status=400,
            headers=create_json_headers(),
        )

    # 3e. RFC 7591 Dynamic Client Registration (DCR) Proxy Endpoint
    if method == "POST" and norm_path == "/oauth/register":
        # Unauthenticated / IP-based rate limiting on registration endpoint
        client_ip = extract_client_ip()
        allowed, retry_after = server.unauth_rate_limiter.check_limit(client_ip)
        if not allowed:
            err_body = json.dumps({
                "error": "too_many_requests",
                "message": f"Rate limit exceeded for client registration. Retry after {retry_after} seconds.",
            })
            return Response.new(
                err_body,
                status=429,
                headers=create_json_headers([["Retry-After", str(retry_after)]]),
            )

        try:
            body_text = await request.text()
            payload = json.loads(body_text) if body_text else {}
        except Exception:
            err_body = json.dumps({
                "error": "invalid_request",
                "error_description": "Request body must be valid JSON.",
            })
            return Response.new(
                err_body,
                status=400,
                headers=create_json_headers(),
            )

        status_code, dcr_resp = await handle_dcr_registration(
            payload,
            auth_server_url=server.config.oauth_auth_server_url,
            audience=server.config.oauth_audience,
        )
        return Response.new(
            json.dumps(dcr_resp),
            status=status_code,
            headers=create_json_headers(),
        )

    # 4. Health and status route
    if method == "GET" and norm_path in ("/", "/health", "/status"):
        body = json.dumps({
            "status": "healthy",
            "service": "WooCommerce MCP Server (Async Cloudflare Worker)",
            "version": "1.0.0",
            "protocol": "mcp-2024-11-05",
            "auth_type": "OAuth 2.1 (Stateless JWT)",
            "auth_server": server.config.oauth_auth_server_url or None,
            "store_url": server.config.store_url or None,
            "woocommerce_configured": server.config.has_woocommerce_credentials,
            "protected_resource_metadata": resource_metadata_url,
        })
        return Response.new(
            body,
            status=200,
            headers=create_json_headers(),
        )

    # 5. MCP Route check
    if method != "POST" or norm_path not in ("/mcp", "/"):
        body = json.dumps({"error": "Not Found. Send MCP POST requests to /mcp"})
        return Response.new(
            body,
            status=404,
            headers=create_json_headers(),
        )

    # 6. OAuth 2.1 Stateless JWT Authentication with WWW-Authenticate 401 challenge
    is_auth, client_id, auth_err = await server.authenticator.authenticate_request_async(
        req_headers
    )

    if not is_auth:
        # Pre-auth handshake: rate-limited by client IP
        client_ip = extract_client_ip()
        allowed, retry_after = server.unauth_rate_limiter.check_limit(client_ip)
        if not allowed:
            err_res = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32001,
                    "message": f"Too many unauthenticated requests from IP. Retry after {retry_after} seconds.",
                },
            }
            return Response.new(
                json.dumps(err_res),
                status=429,
                headers=create_json_headers([["Retry-After", str(retry_after)]]),
            )

        err_res = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": auth_err or "Unauthorized: Valid OAuth 2.1 Bearer token required.",
            },
        }
        body = json.dumps(err_res)
        return Response.new(
            body,
            status=401,
            headers=create_json_headers([
                ["WWW-Authenticate", www_auth_challenge],
            ]),
        )

    # 7. Check Authenticated Client Rate Limit (keyed by client_id = oauth-<sha256(sub)[:12]>)
    allowed, retry_after = server.rate_limiter.check_limit(client_id or "unknown")
    if not allowed:
        err_res = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32001,
                "message": f"MCP client exceeded the server rate limit. Retry after {retry_after} seconds.",
            },
        }
        body = json.dumps(err_res)
        return Response.new(
            body,
            status=429,
            headers=create_json_headers([["Retry-After", str(retry_after)]]),
        )

    # 8. Read and parse JSON-RPC request body
    try:
        body_text = await request.text()
        rpc_req = json.loads(body_text) if body_text else None
    except Exception:
        err_res = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error: Invalid JSON"}}
        body = json.dumps(err_res)
        return Response.new(
            body,
            status=400,
            headers=create_json_headers(),
        )

    if rpc_req is None:
        err_res = {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request: Empty body"}}
        body = json.dumps(err_res)
        return Response.new(
            body,
            status=400,
            headers=create_json_headers(),
        )

    # 9. Handle Batch vs Single JSON-RPC with async await
    if isinstance(rpc_req, list):
        results = []
        for item in rpc_req:
            res = await server.handle_json_rpc(item, client_id=client_id or "default")
            if res is not None:
                results.append(res)
        body = json.dumps(results)
        return Response.new(
            body,
            status=200,
            headers=create_json_headers(),
        )

    resp = await server.handle_json_rpc(rpc_req, client_id=client_id or "default")
    if resp is not None:
        body = json.dumps(resp)
        return Response.new(
            body,
            status=200,
            headers=create_json_headers(),
        )
    else:
        return Response.new(
            "",
            status=204,
            headers=Headers.new(cors_headers_list),
        )
