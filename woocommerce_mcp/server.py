import asyncio
import http.server
import json
import logging
import socketserver
import sys
import threading
import urllib.parse
from typing import Any, Dict, Optional, Tuple

import os

_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from auth import Authenticator
from config import ServerConfig
from rate_limiter import RateLimiter
from tools import execute_tool, get_tool_definitions
from wc_client import WooCommerceClient

logger = logging.getLogger("woocommerce_mcp")


class MCPServer:
    """
    Model Context Protocol (MCP) server for WooCommerce.
    Handles MCP JSON-RPC protocol, authentication, rate-limiting, and tool dispatching.
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_INFO = {
        "name": "woocommerce-mcp-server",
        "version": "1.0.0",
    }

    def __init__(self, config: ServerConfig):
        self.config = config
        self.authenticator = Authenticator(
            jwks_url=config.oauth_jwks_url,
            auth_server_url=config.oauth_auth_server_url,
            expected_issuer=config.oauth_issuer,
            expected_audience=config.oauth_audience,
            cache_ttl_seconds=config.jwks_cache_ttl_seconds,
        )
        self.rate_limiter = RateLimiter(
            max_requests=config.rate_limit_max_requests,
            window_seconds=config.rate_limit_window_seconds,
        )
        self.wc_client = WooCommerceClient(
            store_url=config.store_url,
            consumer_key=config.consumer_key,
            consumer_secret=config.consumer_secret,
            max_retries=config.wc_max_retries,
            timeout_seconds=config.wc_timeout_seconds,
        )

    async def handle_json_rpc(self, rpc_request: Dict[str, Any], client_id: str = "default") -> Optional[Dict[str, Any]]:
        """
        Process a single MCP JSON-RPC 2.0 message.
        """
        req_id = rpc_request.get("id")
        method = rpc_request.get("method")
        params = rpc_request.get("params") or {}

        # Notification messages (like notifications/initialized) have no ID and do not get responses
        is_notification = req_id is None

        if not method:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: missing method"},
            }

        # 1. MCP Initialization
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {
                            "listChanged": False
                        }
                    },
                    "serverInfo": self.SERVER_INFO,
                },
            }

        # 2. Initialized notification
        if method == "notifications/initialized":
            logger.info("MCP client initialized notification received.")
            return None

        # 3. Ping
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        # 4. Tool Discovery
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": get_tool_definitions()
                },
            }

        # 5. Tool Execution
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}

            if not tool_name:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Missing 'name' in tool call parameters"},
                }

            # Check rate limiting for this client
            allowed, retry_after = self.rate_limiter.check_limit(client_id)
            if not allowed:
                logger.warning("Rate limit exceeded for client %s. Retry after %ds.", client_id, retry_after)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"MCP client exceeded the server rate limit. Please retry in {retry_after} seconds.",
                            }
                        ],
                        "isError": True,
                    },
                }

            # Asynchronously execute tool with validation and WooCommerce backend
            result = await execute_tool(tool_name, arguments, self.wc_client)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }

        # Method not found
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        }


class MCPHTTPHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP server handler supporting authenticated remote MCP clients.
    Serves /mcp endpoint for JSON-RPC tool calls, /sse for streaming, and /health.
    """

    server_instance: MCPServer

    # Disable default BaseHTTPRequestHandler verbose console access logs
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send_json_response(self, status_code: int, data: Any, extra_headers: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Health / Status check (unauthenticated for load balancers and diagnostics)
        if path in ("/", "/health", "/status"):
            status_data = {
                "status": "healthy",
                "service": "WooCommerce MCP Server",
                "version": "1.0.0",
                "protocol": "mcp-2024-11-05",
                "woocommerce_configured": self.server_instance.config.has_woocommerce_credentials,
                "auth_required": self.server_instance.authenticator.is_auth_required,
                "endpoints": {
                    "mcp_rpc": "/mcp",
                    "health": "/health"
                }
            }
            self._send_json_response(200, status_data)
            return

        self._send_json_response(404, {"error": "Endpoint not found"})

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path not in ("/mcp", "/"):
            self._send_json_response(404, {"error": "Endpoint not found. Use /mcp for MCP requests."})
            return

        # 1. Authenticate MCP Client
        headers_dict = {k: v for k, v in self.headers.items()}
        query_params = urllib.parse.parse_qs(parsed_url.query)
        query_token = query_params.get("token", [None])[0] or query_params.get("auth_token", [None])[0]

        is_auth, client_id, auth_err = self.server_instance.authenticator.authenticate_request(
            headers_dict, query_token=query_token
        )

        if not is_auth:
            self._send_json_response(401, {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": auth_err or "Unauthorized MCP client",
                }
            })
            return

        # 2. Rate limit check at server HTTP boundary
        allowed, retry_after = self.server_instance.rate_limiter.check_limit(client_id or "unknown")
        if not allowed:
            self._send_json_response(
                429,
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32001,
                        "message": f"MCP client exceeded the server rate limit. Retry after {retry_after} seconds.",
                    }
                },
                extra_headers={"Retry-After": str(retry_after)},
            )
            return

        # 3. Read body
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            rpc_data = json.loads(body)
        except Exception:
            self._send_json_response(400, {
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "Parse error: Invalid JSON"},
            })
            return

        # 4. Handle RPC message
        if isinstance(rpc_data, list):
            # Batch RPC
            responses = []
            for item in rpc_data:
                resp = asyncio.run(self.server_instance.handle_json_rpc(item, client_id=client_id or "default"))
                if resp is not None:
                    responses.append(resp)
            self._send_json_response(200, responses)
        else:
            resp = asyncio.run(self.server_instance.handle_json_rpc(rpc_data, client_id=client_id or "default"))
            if resp is not None:
                self._send_json_response(200, resp)
            else:
                # Notification handled, no content
                self.send_response(204)
                self.end_headers()


def run_http_server(config: ServerConfig, host: str = "0.0.0.0", port: int = 3000) -> None:
    """Optional local HTTP runner for testing before Cloudflare Worker deployment."""
    server_instance = MCPServer(config)

    class CustomHandler(MCPHTTPHandler):
        pass

    CustomHandler.server_instance = server_instance

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, CustomHandler)

    print(f"WooCommerce MCP Server listening on http://{host}:{port}/mcp", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...", file=sys.stderr)
        httpd.server_close()


def run_stdio_server(config: ServerConfig) -> None:
    """Start local stdio MCP server for Claude Desktop / CLI clients."""
    server_instance = MCPServer(config)
    print("WooCommerce MCP Server started in STDIO mode.", file=sys.stderr)

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            rpc_req = json.loads(line)
            resp = asyncio.run(server_instance.handle_json_rpc(rpc_req, client_id="stdio-client"))
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except KeyboardInterrupt:
            break
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
