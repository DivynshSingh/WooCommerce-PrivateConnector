"""
Cloudflare Workers Python Entrypoint for WooCommerce MCP Server.
"""

import json
from .config import ServerConfig
from .server import MCPServer


_server_instance = None


def get_server_for_env(env) -> MCPServer:
    """Initialize or reuse MCPServer instance configured with Cloudflare Worker env secrets."""
    global _server_instance
    if _server_instance is not None:
        return _server_instance

    def get_var(key: str, default: str = "") -> str:
        if hasattr(env, key):
            val = getattr(env, key)
            return str(val) if val is not None else default
        return default

    store_url = get_var("WOOCOMMERCE_STORE_URL", "").rstrip("/")
    consumer_key = get_var("WOOCOMMERCE_CONSUMER_KEY", "")
    consumer_secret = get_var("WOOCOMMERCE_CONSUMER_SECRET", "")

    tokens = []
    single_token = get_var("MCP_AUTH_TOKEN", "")
    raw_config = get_var("MCP_AUTH_CONFIGURATION", "")
    if single_token:
        tokens.append(single_token)
    if raw_config:
        try:
            parsed = json.loads(raw_config)
            if isinstance(parsed, list):
                tokens.extend([str(t) for t in parsed])
            elif isinstance(parsed, dict):
                tokens.extend([str(v) for v in parsed.values()])
        except Exception:
            tokens.extend([t.strip() for t in raw_config.split(",") if t.strip()])

    try:
        rate_limit_max = int(get_var("MCP_RATE_LIMIT_MAX_REQUESTS", "50"))
    except ValueError:
        rate_limit_max = 50

    try:
        rate_limit_window = int(get_var("MCP_RATE_LIMIT_WINDOW_SECONDS", "10"))
    except ValueError:
        rate_limit_window = 10

    try:
        wc_max_retries = int(get_var("WOOCOMMERCE_MAX_RETRIES", "3"))
    except ValueError:
        wc_max_retries = 3

    try:
        wc_timeout = float(get_var("WOOCOMMERCE_TIMEOUT_SECONDS", "15.0"))
    except ValueError:
        wc_timeout = 15.0

    config = ServerConfig(
        store_url=store_url,
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        valid_auth_tokens=tokens,
        rate_limit_max_requests=rate_limit_max,
        rate_limit_window_seconds=rate_limit_window,
        wc_max_retries=wc_max_retries,
        wc_timeout_seconds=wc_timeout,
    )
    _server_instance = MCPServer(config)
    return _server_instance


async def on_fetch(request, env):
    """Cloudflare Worker request handler."""
    from js import Response, Headers

    method = request.method
    url_str = str(request.url)
    
    path = "/" + url_str.split("/", 3)[-1].split("?")[0] if "/" in url_str else "/"
    query_str = url_str.split("?", 1)[1] if "?" in url_str else ""

    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, X-API-Key",
        "Content-Type": "application/json",
    }

    if method == "OPTIONS":
        return Response.new("", headers=cors_headers, status=204)

    server = get_server_for_env(env)

    if method == "GET" and path in ("/", "/health", "/status"):
        body = {
            "status": "healthy",
            "service": "WooCommerce MCP Server (Cloudflare Worker)",
            "version": "1.0.0",
            "protocol": "mcp-2024-11-05",
            "woocommerce_configured": server.config.has_woocommerce_credentials,
            "auth_required": server.authenticator.is_auth_required,
        }
        return Response.new(json.dumps(body), headers=cors_headers, status=200)

    if method != "POST" or path not in ("/mcp", "/"):
        return Response.new(
            json.dumps({"error": "Not Found. Send MCP POST requests to /mcp"}),
            headers=cors_headers,
            status=404,
        )

    req_headers = {}
    for entry in request.headers.entries():
        req_headers[str(entry[0]).lower()] = str(entry[1])

    query_token = None
    if "token=" in query_str:
        for param in query_str.split("&"):
            if param.startswith("token="):
                query_token = param.split("=", 1)[1]

    is_auth, client_id, auth_err = server.authenticator.authenticate_request(
        req_headers, query_token=query_token
    )

    if not is_auth:
        err_res = {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": auth_err or "Unauthorized MCP client"},
        }
        return Response.new(json.dumps(err_res), headers=cors_headers, status=401)

    allowed, retry_after = server.rate_limiter.check_limit(client_id or "unknown")
    if not allowed:
        headers_with_retry = dict(cors_headers)
        headers_with_retry["Retry-After"] = str(retry_after)
        err_res = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32001,
                "message": f"MCP client exceeded the server rate limit. Retry after {retry_after} seconds.",
            },
        }
        return Response.new(json.dumps(err_res), headers=headers_with_retry, status=429)

    try:
        body_text = await request.text()
        rpc_req = json.loads(body_text)
    except Exception:
        err_res = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error: Invalid JSON"}}
        return Response.new(json.dumps(err_res), headers=cors_headers, status=400)

    if isinstance(rpc_req, list):
        results = [server.handle_json_rpc(item, client_id=client_id or "default") for item in rpc_req]
        results = [r for r in results if r is not None]
        return Response.new(json.dumps(results), headers=cors_headers, status=200)

    resp = server.handle_json_rpc(rpc_req, client_id=client_id or "default")
    if resp is not None:
        return Response.new(json.dumps(resp), headers=cors_headers, status=200)
    else:
        return Response.new("", headers=cors_headers, status=204)
