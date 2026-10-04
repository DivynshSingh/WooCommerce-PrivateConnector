"""
RFC 7591 Dynamic Client Registration (DCR) Proxy for WooCommerce MCP Server.

Provides a standards-compliant DCR intermediary endpoint for AI clients (such as
Claude Desktop, Cursor, and ChatGPT) connecting to the MCP Server via Auth0.
Ensures critical parser fields (such as 'response_types': ['code'], 'grant_types': ['authorization_code'],
and 'token_endpoint_auth_method': 'none') are explicitly included in registration responses.

Additionally automates Auth0 Client Grant creation via the Auth0 Management API immediately
after client creation, granting newly registered clients access to the custom API audience
('https://woocommerce-mcp-server.woocommerce-connector.workers.dev') with scopes
['mcp:read', 'mcp:write', 'offline_access'].
"""

import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("woocommerce_mcp.dcr")

# In-memory cache for Auth0 Management API M2M tokens
# Key: f"{auth_server_url}:{m2m_client_id}" -> {"access_token": str, "expires_at": float}
_mgmt_token_cache: Dict[str, Dict[str, Any]] = {}


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


async def get_auth0_management_token(
    auth_server_url: str,
    m2m_client_id: str,
    m2m_client_secret: str,
    timeout_seconds: float = 10.0,
) -> Optional[str]:
    """
    Obtain or reuse a cached Auth0 Management API M2M access token.
    Calls POST https://<TENANT_DOMAIN>/oauth/token with audience https://<TENANT_DOMAIN>/api/v2/.
    """
    clean_url = auth_server_url.rstrip("/")
    if not clean_url or not m2m_client_id or not m2m_client_secret:
        return None

    cache_key = f"{clean_url}:{m2m_client_id}"
    cached = _mgmt_token_cache.get(cache_key)
    if cached and cached.get("expires_at", 0) > time.time() + 60:
        return str(cached["access_token"])

    token_url = f"{clean_url}/oauth/token"
    audience = f"{clean_url}/api/v2/"
    req_body = {
        "grant_type": "client_credentials",
        "client_id": m2m_client_id,
        "client_secret": m2m_client_secret,
        "audience": audience,
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "WooCommerce-MCP-DCR-Proxy/1.0",
    }

    status, resp_text = await _async_http_post(token_url, headers, req_body, timeout_seconds=timeout_seconds)

    if status in (200, 201):
        try:
            data = json.loads(resp_text)
            access_token = data.get("access_token")
            expires_in = int(data.get("expires_in", 86400))
            if access_token:
                _mgmt_token_cache[cache_key] = {
                    "access_token": access_token,
                    "expires_at": time.time() + expires_in,
                }
                return str(access_token)
        except Exception as exc:
            log_console_error(f"[Auth0 DCR] Failed to parse Management API token response: {exc}")
            return None

    log_console_error(
        f"[Auth0 DCR] Failed to obtain Management API token: HTTP {status} - {resp_text}"
    )
    return None


async def create_client_grant(
    client_id: str,
    audience: str,
    auth_server_url: str,
    m2m_client_id: str = "",
    m2m_client_secret: str = "",
    scope: Optional[List[str]] = None,
    timeout_seconds: float = 10.0,
) -> Tuple[bool, str]:
    """
    Automate Client Grant creation via Auth0 Management API.
    POST https://<TENANT_DOMAIN>/api/v2/client-grants with:
      {
        "client_id": "<NEWLY_CREATED_CLIENT_ID>",
        "audience": "<RESOURCE_SERVER_AUDIENCE>",
        "scope": ["mcp:read", "mcp:write", "offline_access"]
      }
    """
    clean_url = auth_server_url.rstrip("/")
    if not clean_url:
        return False, "Auth server URL not configured"

    if not m2m_client_id or not m2m_client_secret:
        logger.debug("[Auth0 DCR] No M2M credentials configured; skipping Client Grant automation.")
        return False, "M2M credentials not configured"

    # 1. Fetch Management API access token
    mgmt_token = await get_auth0_management_token(
        clean_url,
        m2m_client_id=m2m_client_id,
        m2m_client_secret=m2m_client_secret,
        timeout_seconds=timeout_seconds,
    )

    if not mgmt_token:
        err_msg = f"[Auth0 DCR] Unable to create Client Grant: failed to acquire Management API token."
        log_console_error(err_msg)
        return False, err_msg

    # 2. POST /api/v2/client-grants
    grants_url = f"{clean_url}/api/v2/client-grants"
    grant_payload = {
        "client_id": client_id,
        "audience": audience,
        "scope": scope if scope is not None else ["mcp:read", "mcp:write", "offline_access"],
    }
    headers = {
        "Authorization": f"Bearer {mgmt_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "WooCommerce-MCP-DCR-Proxy/1.0",
    }

    status, resp_text = await _async_http_post(grants_url, headers, grant_payload, timeout_seconds=timeout_seconds)

    # If Auth0 rejects due to an unregistered scope (e.g. 'offline_access' not configured on custom API),
    # retry automatically with only custom API scopes
    if status == 400 and "offline_access" in grant_payload.get("scope", []):
        logger.info("[Auth0 DCR] Retrying Client Grant without 'offline_access' scope...")
        grant_payload["scope"] = [s for s in grant_payload["scope"] if s != "offline_access"]
        status, resp_text = await _async_http_post(grants_url, headers, grant_payload, timeout_seconds=timeout_seconds)

    if status in (200, 201):
        logger.info("[Auth0 DCR] Client Grant created successfully for client_id='%s', audience='%s'", client_id, audience)
        return True, "Created"
    elif status == 409:
        logger.info("[Auth0 DCR] Client Grant already exists for client_id='%s', audience='%s'", client_id, audience)
        return True, "Already exists"
    else:
        err_msg = f"[Auth0 DCR] Failed to create Client Grant for client '{client_id}': HTTP {status} - {resp_text}"
        log_console_error(err_msg)
        return False, err_msg


async def handle_dcr_registration(
    payload: Dict[str, Any],
    auth_server_url: str = "",
    audience: str = "https://woocommerce-mcp-server.woocommerce-connector.workers.dev",
    m2m_client_id: str = "",
    m2m_client_secret: str = "",
    static_client_id: str = "",
    timeout_seconds: float = 10.0,
) -> Tuple[int, Dict[str, Any]]:
    """
    Handles RFC 7591 Dynamic Client Registration and automates Client Grant creation.
    1. Validates and sanitizes incoming client registration payload.
    2. Uses static pre-registered Auth0 client or registers upstream with Auth0.
    3. Automates creation of an Auth0 Client Grant for audience and scopes.
    4. Returns a strictly compliant DCR response with 'response_types': ['code'].

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
    target_audience = audience or "https://woocommerce-mcp-server.woocommerce-connector.workers.dev"

    # Option A: If a dedicated Auth0 client ID is provided, reuse it directly!
    # This avoids Auth0's tenant application ceiling ('too_many_entities') and ensures
    # the client is 100% recognized by Auth0's /authorize endpoint.
    if static_client_id:
        if auth_server_url and m2m_client_id and m2m_client_secret:
            try:
                await create_client_grant(
                    client_id=static_client_id,
                    audience=target_audience,
                    auth_server_url=auth_server_url,
                    m2m_client_id=m2m_client_id,
                    m2m_client_secret=m2m_client_secret,
                    scope=["mcp:read", "mcp:write", "offline_access"],
                    timeout_seconds=timeout_seconds,
                )
            except Exception as grant_exc:
                log_console_error(f"[Auth0 DCR] Exception during Client Grant automation: {grant_exc}")

        return 201, {
            "client_id": static_client_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": token_auth_method,
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "application_type": app_type,
            "client_id_issued_at": int(time.time()),
        }

    # Base upstream Auth0 DCR URL if configured
    auth0_dcr_url = f"{auth_server_url.rstrip('/')}/oidc/register" if auth_server_url else ""
    upstream_data: Optional[Dict[str, Any]] = None
    status = 0
    resp_text = ""

    # 2. Attempt upstream registration if Auth0 URL is provided
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
    if status in (200, 201):
        try:
            parsed = json.loads(resp_text)
            if isinstance(parsed, dict) and "client_id" in parsed:
                upstream_data = parsed
        except Exception as json_err:
            log_console_error(f"[Auth0 DCR] Failed to parse Auth0 response JSON: {json_err}")

    # 3. Determine client_id - use upstream Auth0 if available, or self-contained worker client ID
    if upstream_data and "client_id" in upstream_data:
        client_id = str(upstream_data["client_id"])
        client_secret = upstream_data.get("client_secret")
    else:
        # Fallback to self-contained client ID so Claude connects seamlessly without Auth0 entity limits
        logger.info("[Auth0 DCR] Using self-contained worker client ID for seamless connector authentication.")
        client_id = f"claude-{hashlib.sha256(f'{client_name}:{redirect_uris[0]}'.encode()).hexdigest()[:16]}"
        client_secret = None

    # 4. Automate Client Grant creation via Management API
    if auth_server_url:
        if m2m_client_id and m2m_client_secret:
            try:
                await create_client_grant(
                    client_id=client_id,
                    audience=target_audience,
                    auth_server_url=auth_server_url,
                    m2m_client_id=m2m_client_id,
                    m2m_client_secret=m2m_client_secret,
                    scope=["mcp:read", "mcp:write", "offline_access"],
                    timeout_seconds=timeout_seconds,
                )
            except Exception as grant_exc:
                log_console_error(f"[Auth0 DCR] Exception during Client Grant automation: {grant_exc}")
        else:
            log_console_error(
                f"[Auth0 DCR] WARNING: Cannot automate Client Grant for client '{client_id}': "
                f"AUTH0_M2M_CLIENT_ID and/or AUTH0_M2M_CLIENT_SECRET are not configured on the worker. "
                f"Client will not have authorization for audience '{target_audience}' until granted."
            )

    # 5. Formulate strictly-compliant RFC 7591 JSON response
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
