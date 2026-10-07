# WooCommerce MCP Server — Submission & Quickstart

## Quick Setup & How to Run

### 1. Clone & install dependencies
```bash
git clone <repo-url>
cd woocommerce_mcp
pip install -r requirements.txt
```

### 2. Configure environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Fill in your store & OAuth credentials:
- `WOOCOMMERCE_STORE_URL`: Your store URL (e.g. `https://your-store.example.com`)
- `WOOCOMMERCE_CONSUMER_KEY` & `WOOCOMMERCE_CONSUMER_SECRET`: Generated with Read/Write permissions in **WooCommerce > Settings > Advanced > REST API**
- `OAUTH_AUTH_SERVER_URL`: Your Auth0 / OAuth 2.1 tenant domain
- `OAUTH_AUDIENCE`: Your MCP server public URL

### 3. Run the server

- **Local HTTP (Port 3000):**
  ```bash
  python3 -m server --http --host 0.0.0.0 --port 3000
  ```
  Accessible at `http://localhost:3000/mcp`.

- **Local STDIO (Claude Desktop direct):**
  ```bash
  python3 -m server --stdio
  ```

- **Cloudflare Workers (Edge deployment):**
  ```bash
  npx wrangler secret put WOOCOMMERCE_CONSUMER_KEY
  npx wrangler secret put WOOCOMMERCE_CONSUMER_SECRET
  npx wrangler deploy
  ```

### 4. Run tests
To run the full test suite (covering all 21 tools across 24 test suites):
```bash
python3 test_mcp.py
```

*(Note: For a detailed architectural breakdown, DCR setup, and hosting alternatives, see `setup.md`.)*

---

## Assumptions & Practical Limitations

- **Store-Managed Business Logic vs. Server Layer:** Some behaviors strictly belong to WooCommerce's internal lifecycle rather than the MCP server. For example:
  - When inventory drops to 0, WooCommerce itself should handle the transition from `instock` to `outofstock` based on store catalog settings. While the MCP server guards against invalid inputs, it delegates catalog lifecycle side-effects to WooCommerce.
  - On variable products, stock status is derived from variations—attempting to force `instock` on a parent variable product whose variants are all out of stock is ignored by WooCommerce (and our server returns warnings accordingly).
- **Colocated DCR Proxy on the Worker:** The dynamic client registration endpoint (`/oauth/register`) is hosted right on the Cloudflare Worker alongside the MCP server code, acting as an intermediary proxy to Auth0's `/oidc/register`. In enterprise architectures, the authorization server handles DCR directly. However, because desktop AI clients (like Claude) require specific fields (`response_types: ['code']`, `token_endpoint_auth_method: 'none'`) that Auth0 doesn't format out of the box without manual app patching, this proxy bridges the gap and prevents desktop clients from hitting Auth0 tenant application ceilings.
- **Manual vs. Gateway Refunds:** WooCommerce's API rejects automated refund requests if the order was placed without an online payment gateway (or with cash on delivery/test checkouts). To handle this without crashing tool calls, manual refunds require passing `api_refund=false`, which records the refund on WooCommerce ledger without querying a non-existent payment processor.
- **Orphaned IDs in Grouped Products:** WooCommerce's core REST API does not automatically scrub child IDs from grouped parent products when a child item is deleted. The MCP server actively tracks parent references on permanent deletes and scrubs dangling IDs as a safety net.
- **Trashing Orders via DELETE Endpoint:** WooCommerce doesn't allow setting an order status to `"trash"` via the update (`PUT`) endpoint (it throws `Invalid parameter(s): status`). To trash an order through `update_order_status`, the server routes the call to WooCommerce's `DELETE /wp-json/wc/v3/orders/<id>?force=false` endpoint under the hood.
- **HTML Cleanup on Text Outputs:** WooCommerce stores rich product descriptions wrapped in WordPress `<p>` and formatting tags. The server strips raw wrapping tags to deliver clean markdown text to LLMs without consuming excess prompt tokens.
