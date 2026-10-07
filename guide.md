# WooCommerce MCP Server - Setup & Deployment Guide

This guide walks you through setting up, configuring, and running the **WooCommerce Model Context Protocol (MCP) Server**. README.md is the first choice, this .md is only for a deeper dive.

---

## Table of Contents
1. [Architecture Overview](#1-architecture-overview)
2. [Vendor Lock-in Analysis (Auth0 & Cloudflare)](#2-vendor-lock-in-analysis)
3. [Prerequisites](#3-prerequisites)
4. [Setting Up WooCommerce Credentials](#4-setting-up-woocommerce-credentials)
5. [Setting Up the Auth Server (Auth0 or Alternatives)](#5-setting-up-the-auth-server)
6. [Hosting & Deployment Options](#6-hosting--deployment-options)
   - [Option A: Cloudflare Workers (Serverless Edge)](#option-a-cloudflare-workers-serverless-edge)
   - [Option B: Self-Hosted Docker / VPS / Local HTTP](#option-b-self-hosted-docker--vps--local-http)
7. [Connecting Your AI Client (Claude Desktop, Cursor, ChatGPT)](#7-connecting-your-ai-client)
8. [Testing & Verification](#8-testing--verification)

---

## 1. Architecture Overview

The WooCommerce MCP Server is a connector LLM clients to your WooCommerce store catalog:

```
┌──────────────────┐               ┌─────────────────────────────────┐               ┌─────────────────────┐
│  AI Client       │  MCP JSON-RPC │  WooCommerce MCP Server         │  REST API     │  WooCommerce Store  │
│  (Claude, etc.)  ├──────────────►│  - OAuth 2.1 RFC 9728 Discovery │──────────────►│  (WordPress REST v3)│
└────────┬─────────┘  Bearer Token │  - RFC 7591 DCR Proxy           │  CK / CS Auth └─────────────────────┘
         │                         │  - Rate Limiter & Tools Engine  │
         │                         └────────────────┬────────────────┘
         │                                          │
         │ Authorize / Exchange Code                │ Verify JWKS / Public Key
         ▼                                          ▼
┌────────────────────────────────────────────────────────┐
│ OAuth 2.0 / 2.1 Authorization Server (Auth0, etc.)     │
└────────────────────────────────────────────────────────┘
```

---

## 2. Vendor Lock-in Analysis

### Is there any lock-in to Auth0?
**No.** The server uses standard **OAuth 2.0 / 2.1 specifications**:
- **RFC 9728 (Protected Resource Metadata)**: Advertises resource metadata, supported scopes (`mcp:read`, `mcp:write`), and the authorization server's URL.
- **RFC 8414 / OpenID Connect Discovery**: Resolves endpoints via `/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server`.
- **RFC 7517 (JWKS)**: Validates incoming Bearer JWT tokens using public RSA/EC keys from `/.well-known/jwks.json`.
- **RFC 7591 (Dynamic Client Registration - DCR)**: The server includes an optional DCR proxy endpoint (`/oauth/register`). For Auth0, this forwards to `/oidc/register`. If you use Keycloak, Zitadel etc this is either configured directly or pointed to their RFC 7591 endpoint.
- **Any OIDC / OAuth 2.1 Provider works**: You can swap Auth0 for **Keycloak, Zitadel, etc** simply by changing `OAUTH_AUTH_SERVER_URL` in your `wrangler.toml`.

### Is there any lock-in to Cloudflare Workers?
**No.** While `worker.py` provides bindings for Cloudflare Workers (Pyodide edge runtime), the core codebase is standard Python:
- `server.py` contains standalone HTTP (`run_http_server`) and STDIO (`run_stdio_server`) runners using Python's standard library (`http.server`).
- You can host it on **AWS (Lambda, ECS, EC2)**, **Google Cloud Run**, **DigitalOcean**, **Hetzner**, or a local Raspberry Pi.
- In Cloudflare Workers, `worker.py` wraps standard asynchronous requests; on traditional Python servers, `wc_client.py` uses `urllib.request` / `asyncio` without external binary dependencies.

---

## 3. Prerequisites

- **Python 3.10+**
- **Node.js 18+ & npm** (only needed if deploying to Cloudflare Workers via Wrangler)
- A working **WooCommerce Store** (with REST API enabled)
- An **OAuth 2.0 / 2.1 provider** (such as an Auth0 free tenant)

---

## 4. Setting Up WooCommerce Credentials

1. Log in to your WordPress Admin dashboard.
2. Go to **WooCommerce > Settings > Advanced > REST API**.
3. Click **Add key**.
   - **Description**: `MCP Server Integration`
   - **User**: Select an admin or shop manager user.
   - **Permissions**: `Read/Write`.
4. Click **Generate API Key**.
5. Copy both the `Consumer Key` and `Consumer Secret`.
   *(Save these as WooCommerce will not show them again).*

---

## 5. Setting Up the Auth Server

### Using Auth0

1. Create a account at [auth0.com](https://auth0.com).
2. **Create an API (Resource Server)**:
   - Navigate to **Applications > APIs > Create API**.
   - **Name**: `WooCommerce MCP Server`
   - **Identifier (Audience)**: `https://your-mcp-server-domain.com` (or your Cloudflare worker URL `https://<name>.<subdomain>.workers.dev`).
   - **Signing Algorithm**: `RS256`.
   - In the API settings, add permissions (scopes):
     - `mcp:read` (Read access to store products and orders)
     - `mcp:write` (Write/update access to store catalog and orders)
3. **Enable Dynamic Client Registration (DCR)** *(if using dynamic registration)*:
   - Navigate to **Settings > Advanced > Dynamic Client Registration**.
   - Enable **Dynamic Client Registration**
4. **Ensure Default Connection is Enabled**:
   - Navigate to **Authentication > Database**
   - In your Settings tab, ensure `Promote Connection to Domain Level` is enabled, this gives the tenant this current database as the default authentication connection method.
5. **Create User Cred**:
   - goto User Management > Users and create a user, save email and password for this created user as it will be used by you while authorizing your MCP client.


### You can use another OAuth 2.0 Provider too(Keycloak / Zitadel / Ory)
1. Create a client with Authorization Code Flow + PKCE (`S256`).
2. Set the audience / resource identifier to your MCP Server URL.
3. Configure `OAUTH_AUTH_SERVER_URL` to point to the base URL of your provider (e.g., `https://auth.example.com/realms/myrealm`).
4. The MCP server automatically fetches keys from `{OAUTH_AUTH_SERVER_URL}/.well-known/jwks.json`.

---

## 6. Hosting & Deployment

### Cloudflare Workers (Serverless Edge)

Cloudflare Workers runs the Python worker globally with zero cold starts.

1. Navigate to the project directory:

2. Copy `.example.wrangler.toml` to create your local config:
   ```bash
   cp .example.wrangler.toml wrangler.toml
   ```

3. Update `wrangler.toml` with your public URLs:
   ```toml
   name = "woocommerce-mcp-server"
   main = "worker.py"
   compatibility_date = "2024-09-23"
   compatibility_flags = ["python_workers"]

   [vars]
   WOOCOMMERCE_STORE_URL = "https://your-store.example.com"
   OAUTH_AUTH_SERVER_URL = "https://your-tenant.us.auth0.com"
   OAUTH_AUDIENCE = "https://woocommerce-mcp-server.<your-subdomain>.workers.dev"
   ```

4. Store sensitive secrets securely in Cloudflare:
   ```bash
   npx wrangler secret put WOOCOMMERCE_CONSUMER_KEY
   # Enter your ck_... when prompted

   npx wrangler secret put WOOCOMMERCE_CONSUMER_SECRET
   # Enter your cs_... when prompted
   ```

5. Deploy:
   ```bash
   npx wrangler deploy
   ```

---

### you can go ahead with Self-Hosted Docker / VPS / Local HTTP

To host on a standard Linux server, Docker container, or virtual machine:

1. Clone repo:
   ```bash
   git clone <your-repo-url>
   cd <your-repo-name>/woocommerce_mcp
   ```

2. Create virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Configure `wrangler.toml`:
   ```bash
   cp .example.wrangler.toml wrangler.toml
   ```
   Edit `wrangler.toml` and fill in:
   - `WOOCOMMERCE_STORE_URL`
   - `WOOCOMMERCE_CONSUMER_KEY`
   - `WOOCOMMERCE_CONSUMER_SECRET`
   - `OAUTH_AUTH_SERVER_URL`
   - `OAUTH_AUDIENCE`

4. Run the HTTP server:
   ```bash
   python3 -m server --http --host 0.0.0.0 --port 3000
   ```
   The MCP endpoint is accessible at `http://your-server-ip:3000/mcp`.

---



## 7. Connecting Your AI Client

1. **Add Remote MCP Server**:
   - URL: `https://URL-of-your-hosted-mcp-server`
2. **Handshake flow**:
   - The AI client makes an unauthenticated call to `/mcp`.
   - The server responds with `HTTP 401 Unauthorized` and includes:
     ```http
     WWW-Authenticate: Bearer resource_metadata="https://<your-worker-subdomain>.workers.dev/.well-known/oauth-protected-resource"
     ```
   - The client fetches `/.well-known/oauth-protected-resource` and dynamically discovers Auth0.
   - The client prompts you to authorize via browser.
   - Once authorized, all tool calls are signed with an RS256 Bearer JWT.

---

## 8. Testing & Verification

The repository includes a test suite covering all 24 security, OAuth, and WooCommerce API operations, to test before deploying:

```bash
# Run the test suite
python3 test_mcp.py
```

Expected output:
```
======================================================================
   ALL 24 TESTS (DCR, WORKER, BUGFIXES, R1-R3, STORE FIXES, METADATA & CATEGORIES) PASSED! 
======================================================================
```
