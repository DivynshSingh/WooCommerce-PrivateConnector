"""
RFC 7591 Dynamic Client Registration (DCR) Proxy for WooCommerce MCP Server.

Provides a standards-compliant DCR intermediary endpoint for AI clients (such as
Claude Desktop, Cursor, and ChatGPT) connecting to the MCP Server via Auth0.
Ensures critical parser fields (such as 'response_types': ['code'], 'grant_types': ['authorization_code'],
and 'token_endpoint_auth_method': 'none') are explicitly included in registration responses.

Supports:
1. Static Public Native Client ID (industry-standard for desktop AI clients with Auth0 PKCE,
   preventing tenant application ceiling errors).
2. Dynamic upstream client registration via Auth0's RFC 7591 /oidc/register endpoint.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("woocommerce_mcp.dcr")


def log_console_error(message: str) -> None:
    """Log error to Python logger and JavaScript console (in Cloudflare Workers / browser)."""
    logger.error(message)
    try:
        from js import console
        console.error(message)
    except Exception:
        pass


def validate_dcr_payload(payload: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate RFC 7591 dynamic client registration payload.
    Ensures 'redirect_uris' is present, is a non-empty list of valid URIs.
    """
    if not isinstance(payload, dict):
        return False, "Request body must be a JSON object."

    redirect_uris = payload.get("redirect_uris")
    if not redirect_uris:
        return False, "The 'redirect_uris' parameter is required and must not be empty."

    if not isinstance(redirect_uris, list):
        return False, "The 'redirect_uris' parameter must be a JSON array of URI strings."

    for uri in redirect_uris:
        if not isinstance(uri, str) or not uri.strip():
            return False, "Each entry in 'redirect_uris' must be a non-empty string."
        try:
            parsed = urlparse(uri.strip())
            # Support http, https, and custom scheme URIs used by desktop/native clients
            if not parsed.scheme:
                return False, f"Invalid URI format in 'redirect_uris': '{uri}'."
        except Exception:
            return False, f"Failed to parse URI in 'redirect_uris': '{uri}'."

    return True, None


async def _async_http_post(
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout_seconds: float = 10.0,
) -> Tuple[int, str]:
    """
    Send an asynchronous HTTP POST request.
    Uses Web API 'fetch' when running in Cloudflare Workers / Pyodide,
    and falls back to urllib.request when running in standard Python.
    """
    body_str = json.dumps(payload)

    # 1. Pyodide / Web API fetch
    try:
        from js import fetch, Headers, Object
        h = Headers.new([[str(k), str(v)] for k, v in headers.items()])
        init = Object()
        init.method = "POST"
        init.headers = h
        init.body = body_str

        resp = await fetch(url, init)
        status = int(resp.status)
        text = str(await resp.text())
        return status, text
    except Exception:
        pass

    # 2. Standard library urllib fallback
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            url,
            data=body_str.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = int(resp.status)
            text = resp.read().decode("utf-8")
            return status, text
    except urllib.error.HTTPError as he:
        err_body = he.read().decode("utf-8") if he.fp else str(he)
        return int(he.code), err_body
    except Exception as exc:
        return 0, str(exc)


async def handle_dcr_registration(
    payload: Dict[str, Any],
    auth_server_url: str = "",
    audience: str = "",
    timeout_seconds: float = 10.0,
) -> Tuple[int, Dict[str, Any]]:
    """
    Handles RFC 7591 Dynamic Client Registration Proxy for Auth0:
    1. Validates and sanitizes incoming client registration payload from Claude / MCP client.
    2. Registers dynamically upstream with Auth0 at /oidc/register.
    3. Guarantees 'response_types': ['code'], 'grant_types': ['authorization_code'],
       and 'token_endpoint_auth_method': 'none' in the response so Claude's client parser succeeds.

    Returns:
        (status_code: int, response_body: dict)
    """
    # 1. Validate incoming request
    is_valid, err_msg = validate_dcr_payload(payload)
    if not is_valid:
        return 400, {
            "error": "invalid_client_metadata",
            "error_description": err_msg or "Invalid client metadata in registration request.",
        }

    client_name = str(payload.get("client_name") or "Claude MCP Client").strip()
    redirect_uris = [str(u).strip() for u in payload.get("redirect_uris", [])]
    token_auth_method = str(payload.get("token_endpoint_auth_method") or "none").strip()
    app_type = str(payload.get("application_type") or "native").strip()

    # Upstream Auth0 Dynamic Client Registration (/oidc/register)
    auth0_dcr_url = f"{auth_server_url.rstrip('/')}/oidc/register" if auth_server_url else ""
    if not auth0_dcr_url:
        return 500, {
            "error": "server_error",
            "error_description": "OAUTH_AUTH_SERVER_URL is not configured on the server.",
        }

    upstream_payload = {
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": token_auth_method,
        "response_types": ["code"],
        "grant_types": ["authorization_code"],
        "application_type": app_type,
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "WooCommerce-MCP-DCR-Proxy/1.0",
    }
    status, resp_text = await _async_http_post(
        auth0_dcr_url, headers, upstream_payload, timeout_seconds=timeout_seconds
    )

    upstream_data: Optional[Dict[str, Any]] = None
    if status in (200, 201):
        try:
            parsed = json.loads(resp_text)
            if isinstance(parsed, dict) and "client_id" in parsed:
                upstream_data = parsed
        except Exception as json_err:
            log_console_error(f"[Auth0 DCR] Failed to parse Auth0 response JSON: {json_err}")

    if upstream_data and "client_id" in upstream_data:
        client_id = str(upstream_data["client_id"])
        client_secret = upstream_data.get("client_secret")

        response_body = {
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": token_auth_method,
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "application_type": app_type,
            "client_id_issued_at": int(time.time()),
        }
        if client_secret:
            response_body["client_secret"] = str(client_secret)
        return 201, response_body

    # If upstream registration failed, return error with clear message
    err_desc = f"Auth0 dynamic registration failed (HTTP {status}): {resp_text}"
    log_console_error(f"[Auth0 DCR] {err_desc}")
    return (status if status in (400, 401, 403, 429) else 400), {
        "error": "registration_failed",
        "error_description": err_desc,
    }
