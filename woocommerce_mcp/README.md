# WooCommerce MCP Server (Auth0 DCR & Dual-Layer Rate Limiting)

A Model Context Protocol (MCP) server for WooCommerce REST API v3, deployable directly as a Cloudflare Worker (Python/Pyodide) or run locally.

## Features
- **OAuth 2.0 / 2.1 RFC 9728 Protected Resource Server**: Points to Auth0 for RFC 7591 Dynamic Client Registration (DCR), enabling AI clients like Claude Desktop to discover and register dynamically.
- **Dual-Layer Rate Limiting**:
  - **Unauthenticated / IP Limiter**: Limits unauthenticated hits to `/.well-known/oauth-protected-resource` and pre-auth handshakes (Default: 20 requests / 60s).
  - **Authenticated Client Limiter**: Keyed by token subject identifier (`oauth-<sha256(sub)[:12]>`) for MCP tool execution (Default: 50 requests / 10s).
- **Stateless RS256 JWT Verification**: Validates Auth0 standard access tokens against Auth0 JWKS (`/.well-known/jwks.json`) with in-memory caching.
- **Asynchronous Execution & Strict Pagination**: Non-blocking client (`wc_client.py`) with pagination clamping (max 15/page).
- **Zero External Dependencies**: Standard Python library and native Pyodide / Web API runtime.

## Deploying to Cloudflare Workers

Navigate into this folder and run:
```bash
wrangler deploy
```

Configure your sensitive WooCommerce consumer secrets via Cloudflare Dashboard or Wrangler:
```bash
wrangler secret put WOOCOMMERCE_CONSUMER_KEY
wrangler secret put WOOCOMMERCE_CONSUMER_SECRET
```

## Running Verification Tests
```bash
python3 test_mcp.py
```
*(All 12 offline verification tests pass with 0 external network dependencies)*
