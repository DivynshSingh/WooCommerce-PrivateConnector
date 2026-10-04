# WooCommerce MCP Server (Auth0 DCR Proxy, Automated Client Grants & Dual-Layer Rate Limiting)

A Model Context Protocol (MCP) server for WooCommerce REST API v3, deployable directly as a Cloudflare Worker (Python/Pyodide) or run locally.

## Features
- **Integrated RFC 7591 Dynamic Client Registration (DCR) Proxy**: Exposes `POST /oauth/register` directly on the worker. Normalizes registration responses to strictly include `"response_types": ["code"]`, `"grant_types": ["authorization_code"]`, and `"token_endpoint_auth_method": "none"`, preventing parser crashes in strict AI clients (e.g., Claude Desktop, Cursor).
- **Automated Client Grants via Auth0 Management API**: When dynamic clients register, the proxy automatically creates a Client Grant on Auth0 (`POST https://<TENANT>/api/v2/client-grants`) for audience `https://woocommerce-mcp-server.woocommerce-connector.workers.dev` and scopes `['mcp:read', 'mcp:write', 'offline_access']`. This permanently eliminates subsequent login authorization failures.
- **RFC 9728 Protected Resource Server**: Points `registration_endpoint` directly to the worker's internal proxy route (`https://<WORKER_ORIGIN>/oauth/register`).
- **Dual-Layer Rate Limiting**:
  - **Unauthenticated / IP Limiter**: Limits unauthenticated hits to `/.well-known/oauth-protected-resource`, `POST /oauth/register`, and pre-auth handshakes (Default: 20 requests / 60s).
  - **Authenticated Client Limiter**: Keyed by token subject identifier (`oauth-<sha256(sub)[:12]>`) for MCP tool execution (Default: 50 requests / 10s).
- **Stateless RS256 JWT Verification**: Validates Auth0 standard access tokens against Auth0 JWKS (`/.well-known/jwks.json`) with in-memory caching.
- **Asynchronous Execution & Strict Pagination**: Non-blocking client (`wc_client.py`) with pagination clamping (max 15/page).

## Deploying to Cloudflare Workers

Navigate into this folder and run:
```bash
wrangler deploy
```

Configure your sensitive WooCommerce consumer secrets and Auth0 M2M credentials via Cloudflare Dashboard or Wrangler:
```bash
wrangler secret put WOOCOMMERCE_CONSUMER_KEY
wrangler secret put WOOCOMMERCE_CONSUMER_SECRET
wrangler secret put AUTH0_M2M_CLIENT_ID
wrangler secret put AUTH0_M2M_CLIENT_SECRET
```

## Running Verification Tests
```bash
python3 test_mcp.py
```
*(All 13 verification tests pass cleanly)*
