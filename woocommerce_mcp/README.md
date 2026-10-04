# WooCommerce MCP Server (Self-Contained Backend)

A Model Context Protocol (MCP) server for WooCommerce REST API v3, deployable directly as a Cloudflare Worker (Python/Pyodide) or run locally.

## Features
- **OAuth 2.1 RFC 9728**: Resource server authentication using Supabase Auth JWTs.
- **Asynchronous Execution**: Fully async network client (`wc_client.py`) utilizing native Cloudflare Worker non-blocking I/O.
- **Strict Pagination**: Clamps catalog responses (max 15/page) to prevent CPU limit timeouts.
- **Zero External Dependencies**: Runs entirely on Python 3 standard library and native Pyodide WebCrypto.

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
