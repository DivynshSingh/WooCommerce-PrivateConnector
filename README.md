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
Fill in your credentials:
- **`WOOCOMMERCE_STORE_URL`**: Your store URL (e.g., `https://your-store.example.com`).
- **`WOOCOMMERCE_CONSUMER_KEY`** & **`WOOCOMMERCE_CONSUMER_SECRET`**: Generated with Read/Write permissions under **WooCommerce > Settings > Advanced > REST API**.
- **`OAUTH_AUTH_SERVER_URL`**: Your OAuth 2.1 provider base URL (e.g. Auth0 tenant, Keycloak, or Zitadel).
- **`OAUTH_AUDIENCE`**: Your MCP server's public identifier URL.

### 3. Run the server

Choose whichever runtime suits your setup:

- **Local HTTP (Port 3000):**
  ```bash
  python3 -m server --http --host 0.0.0.0 --port 3000
  ```
  The MCP JSON-RPC endpoint is live at `http://localhost:3000/mcp`.

- **Local STDIO (Claude Desktop direct):**
  ```bash
  python3 -m server --stdio
  ```

- **Cloudflare Workers (Edge deployment):**
  Set secrets via Wrangler:
  ```bash
  npx wrangler secret put WOOCOMMERCE_CONSUMER_KEY
  npx wrangler secret put WOOCOMMERCE_CONSUMER_SECRET
  npx wrangler deploy
  ```

### 4. Run tests
To verify all 24 tool, authentication, DCR, and catalog tests:
```bash
python3 test_mcp.py
```

*(Note: For an in-depth architectural breakdown, RFC 9728 discovery setup, Auth0/Keycloak configuration details, and hosting alternatives, please check `setup.md`.)*

---

## Assumptions & Limitations

- **WooCommerce REST API:** Assumes the WooCommerce REST API v3 is enabled with valid Read/Write consumer keys.
- **Stateless OAuth Verification:** Assumes incoming Bearer JWT tokens are signed with RS256/ES256 and verifiable against the authorization server's public JWKS endpoint (`/.well-known/jwks.json`).
- **Payment Gateways & Refunds:** Automated gateway refunds require an active payment gateway configured on the order. For orders created without a payment gateway (or offline orders), `create_refund` should be called with `api_refund=false` to record a manual refund.
- **Variable Product Stock:** In WooCommerce, stock status on variable parent products is derived from child variations; stock adjustments should target individual variations.
- **Credentials & Git Hygiene:** Live API keys, passwords, and `.env` files are excluded from version control via `.gitignore`. Placeholders and variable documentation are maintained in `.env.example`.
