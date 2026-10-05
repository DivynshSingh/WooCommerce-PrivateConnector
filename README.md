# WooCommerce MCP Server with Real Auth0 Authentication (OAuth 2.1 & PKCE)

A production-grade, remote Model Context Protocol (MCP) server that provides an AI-facing interface to a WooCommerce store hosted on WordPress (e.g. Pantheon). 

It implements the official OAuth 2.1 specification for MCP servers (RFC 9728 Protected Resource Metadata, RFC 8414 Authorization Server Discovery, and RFC 7591 Dynamic Client Registration Proxy), delegating **human user authentication to an Auth0 Universal Login page**.

---

## 🏗️ Architecture Overview

```text
  [ Claude Desktop / AI Agent ]
                 │
  Step 1: POST /mcp (Unauthenticated)
                 ▼
  [ Cloudflare Worker ] ──► Returns 401 with WWW-Authenticate:
                            realm="mcp", resource_metadata="https://<worker>/.well-known/oauth-protected-resource"
                 │
  Step 2: GET /.well-known/oauth-authorization-server
                 ▼
  [ Cloudflare Worker ] ──► Returns Auth Server Metadata:
                            • authorization_endpoint: "https://<tenant>.auth0.com/authorize"
                            • token_endpoint: "https://<tenant>.auth0.com/oauth/token"
                            • jwks_uri: "https://<tenant>.auth0.com/.well-known/jwks.json"
                            • registration_endpoint: "https://<worker>/oauth/register"
                 │
  Step 3: POST /oauth/register (RFC 7591 DCR Proxy)
                 ▼
  [ Cloudflare Worker ] ──► Returns compliant Native Client ID with response_types: ["code"],
                            grant_types: ["authorization_code"], token_endpoint_auth_method: "none".
                 │
  Step 4: Browser opens Auth0 Universal Login
                 ▼
  ┌────────────────────────────────────────────────────────┐
  │              Auth0 Universal Login Page                │
  │  • Real human enters email/password or SSO             │
  │  • User approves access to WooCommerce MCP API         │
  └────────────────────────────────────────────────────────┘
                 │
  Step 5: Auth0 redirects back to Claude:
          http://localhost:<port>/callback?code=AUTH0_CODE&state=...
                 │
  Step 6: Claude calls Auth0 Token Endpoint directly:
          POST https://<tenant>.auth0.com/oauth/token (with PKCE code_verifier)
                 ▼
  [ Auth0 Token Endpoint ] ──► Issues signed RS256 JWT access_token
                 │
  Step 7: Claude sends authenticated MCP JSON-RPC tool calls:
          POST https://<worker>/mcp with Authorization: Bearer <RS256 JWT>
                 ▼
  ┌────────────────────────────────────────────────────────┐
  │                 Cloudflare Worker                      │
  │  • Verifies RS256 JWT signature via Auth0 JWKS         │
  │  • Enforces audience & issuer validation               │
  │  • Applies sliding-window rate limiting per subject    │
  │  • Executes WooCommerce tool via non-blocking fetch    │
  └────────────────────────────────────────────────────────┘
                 │
                 ▼ HTTPS Basic Auth (ck_... / cs_...)
  ┌────────────────────────────────────────────────────────┐
  │             WooCommerce Store (Pantheon)               │
  │                WordPress REST API v3                   │
  └────────────────────────────────────────────────────────┘
```

---

## 🛠️ Step-by-Step Auth0 Setup Guide

Follow these exact steps in your new Auth0 account to enable human login:

### Step 1: Create an API in Auth0
1. In your Auth0 Dashboard, navigate to **Applications > APIs**.
2. Click **Create API**:
   - **Name**: `WooCommerce MCP Server API`
   - **Identifier (Audience)**: `https://woocommerce-mcp-server.woocommerce-connector.workers.dev`  
     *(or your custom Cloudflare Worker URL, e.g. `https://my-store-mcp.<subdomain>.workers.dev`)*
   - **Signing Algorithm**: `RS256`
3. Click **Create**.
4. In the **Permissions** tab of your new API, optionally add:
   - `mcp:read` (Read products and orders)
   - `mcp:write` (Update stock and create products)

### Step 2: Configure the Default Audience (CRITICAL)
> **Why this is required:** Standard desktop OAuth clients like Claude Desktop do not pass Auth0's custom `audience` query parameter during the `/authorize` request. Without a Default Audience configured, Auth0 issues an opaque string token rather than an RS256 JWT for your API.

1. In your Auth0 Dashboard, click **Settings** (top-right tenant dropdown or left menu).
2. Go to the **General** tab.
3. Scroll down to **API Authorization Settings**.
4. Set **Default Audience** to the exact Identifier you created in Step 1:
   ```text
   https://woocommerce-mcp-server.woocommerce-connector.workers.dev
   ```
5. Click **Save**.

### Step 3: Create a Native Application for Claude Desktop
1. In your Auth0 Dashboard, navigate to **Applications > Applications**.
2. Click **Create Application**:
   - **Name**: `Claude Desktop WooCommerce Connector`
   - **Application Type**: **Native**
3. In the application **Settings** tab:
   - **Token Endpoint Authentication Method**: `None` *(Public Client using PKCE)*
   - **Application Login URI**: Leave blank
   - **Allowed Callback URLs**:
     ```text
     http://localhost, http://localhost:*, https://claude.ai/oauth/callback
     ```
   - **Allowed Web Origins**:
     ```text
     http://localhost, http://localhost:*, https://claude.ai
     ```
   - **Allowed Origins (CORS)**:
     ```text
     http://localhost, http://localhost:*, https://claude.ai
     ```
4. In **Advanced Settings > Grant Types** (at the bottom):
   - Ensure **Authorization Code** and **Refresh Token** are checked.
5. Click **Save Changes**.
6. Copy your **Client ID** (e.g. `aBcDeFgHiJkLmNoPqRsTuVwXyZ123456`).

---

## ☁️ Step-by-Step Cloudflare Worker Setup Guide

### 1. Configure `wrangler.toml`
Update the `[vars]` block in `wrangler.toml` with your new Auth0 tenant details:

```toml
name = "woocommerce-mcp-server"
main = "woocommerce_mcp/worker.py"
compatibility_date = "2024-09-23"
compatibility_flags = ["python_workers"]

[vars]
# Your WooCommerce store URL (e.g. hosted on Pantheon)
WOOCOMMERCE_STORE_URL = "https://dev-anythingstore37.pantheonsite.io"

# Your Auth0 Tenant Configuration
OAUTH_AUTH_SERVER_URL = "https://<YOUR_TENANT>.us.auth0.com"
OAUTH_JWKS_URL = "https://<YOUR_TENANT>.us.auth0.com/.well-known/jwks.json"
OAUTH_ISSUER = "https://<YOUR_TENANT>.us.auth0.com/"
OAUTH_AUDIENCE = "https://woocommerce-mcp-server.woocommerce-connector.workers.dev"
OAUTH_JWKS_CACHE_TTL_SECONDS = "300"

# The Native Client ID you created in Step 3 (bypasses tenant application limits)
AUTH0_STATIC_CLIENT_ID = "<YOUR_AUTH0_CLIENT_ID>"

# Rate Limiting
MCP_RATE_LIMIT_MAX_REQUESTS = "50"
MCP_RATE_LIMIT_WINDOW_SECONDS = "10"
UNAUTH_RATE_LIMIT_MAX_REQUESTS = "20"
UNAUTH_RATE_LIMIT_WINDOW_SECONDS = "60"

# WooCommerce API Request Resilience
WOOCOMMERCE_MAX_RETRIES = "3"
WOOCOMMERCE_TIMEOUT_SECONDS = "15"
```

### 2. Configure Sensitive Secrets in Cloudflare
Set your WooCommerce REST API keys in Cloudflare Worker secrets:

```bash
# WooCommerce Consumer Key (from WordPress Admin > WooCommerce > Settings > Advanced > REST API)
npx wrangler secret put WOOCOMMERCE_CONSUMER_KEY

# WooCommerce Consumer Secret
npx wrangler secret put WOOCOMMERCE_CONSUMER_SECRET
```

### 3. Deploy to Cloudflare
```bash
npx wrangler deploy
```

Once deployed, note your worker URL:
`https://woocommerce-mcp-server.<your-subdomain>.workers.dev`

---

## 🧪 Testing with Claude Desktop

1. In Claude Desktop, configure the remote MCP connector:
   - **Server Name**: `WooCommerce Store`
   - **Server URL**: `https://<your-worker-subdomain>.workers.dev/mcp`
2. When Claude initiates connection:
   - Claude performs discovery via `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-authorization-server`.
   - Claude registers via the DCR proxy (`POST /oauth/register`), receiving your public client ID.
   - Claude automatically opens your browser to:
     `https://<your-tenant>.us.auth0.com/authorize?...`
   - You log in with your Auth0 account credentials and grant access.
   - Auth0 redirects back to Claude's local callback handler.
   - Claude exchanges the authorization code for an RS256 JWT access token directly at Auth0.
   - Claude is now connected and can run queries!

### Sample Commands to Try in Claude:
- *"Show me all available products in my store."*
- *"Search for any items in the catalog that are low on stock."*
- *"What were the most recent orders placed in the store?"*
- *"Update the stock of product ID 42 to 20 units."*

---

## 🔬 Local Verification Suite

Run the included verification suite to validate all 13 security, protocol, and rate-limiting tests:

```bash
python3 test_mcp.py
```

All 13 tests verify:
1. MCP Protocol Initialization & Ping
2. Tool Discovery & Schema Validation
3. Async Transport & Strict Pagination Enforcement (max 15 items per page)
4. Initial 401 Handshake with `WWW-Authenticate` pointing to Protected Resource Metadata
5. RFC 9728 Discovery pointing to Auth0
6. RFC 7591 Dynamic Client Registration proxying & Claude parser compatibility
7. Unauthenticated IP-based rate limiting on discovery routes
8. RS256 Stateless JWT Verification matching Auth0's public JWKS
9. Expired & Tampered Token Rejection
10. Authenticated Subject Rate Limiting
11. Safe Environment Variable Injection into `os.environ`
12. WooCommerce Authentication Failure Handling & Secret Sanitization
13. Transient vs. Permanent Error Classification with Exponential Backoff
