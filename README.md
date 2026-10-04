# WooCommerce MCP Server

A production-grade, remote Model Context Protocol (MCP) server that acts as an AI-facing interface to a WooCommerce store. It translates standard MCP tool calls from AI clients (Claude, Cursor, Windsurf, custom agents) into authenticated WooCommerce REST API v3 operations.

```text
AI Agent (Claude / Agent Client)
       │
       │ MCP Protocol (HTTP POST / SSE / STDIO)
       ▼
  [ MCP Client ]
       │
       │ Authenticated MCP connection (Bearer Token / API Key)
       ▼
┌────────────────────────────────────────────────────────┐
│               WooCommerce MCP Server                   │
│                                                        │
│  • MCP Protocol Handler (JSON-RPC 2.0)                 │
│  • Client Authentication & Validation                  │
│  • Sliding-Window Rate Limiter (e.g. 50 req / 10s)     │
│  • Input Schema Validation (Pre-call validation)       │
│  • WooCommerce REST API Client                         │
│  • Bounded Exponential Backoff Retries (429 & 5xx)     │
│  • Secret Sanitization (Zero credential leakage)       │
└────────────────────────────────────────────────────────┘
       │
       │ Authenticated HTTPS (Basic Auth)
       ▼
┌────────────────────────────────────────────────────────┐
│                 WooCommerce Store                      │
│            WordPress /wp-json/wc/v3/                   │
└────────────────────────────────────────────────────────┘
```

---

## Features

- **Standard MCP Protocol**: Implements `initialize`, `ping`, `tools/list`, and `tools/call` conforming to specification `2024-11-05`.
- **Dual Transport Modes**: Supports remote HTTP JSON-RPC endpoint (`/mcp`) and local STDIO mode for Claude Desktop.
- **Robust Client Authentication**: Validates clients via `Authorization: Bearer <token>` or `X-API-Key: <token>`.
- **Server-Side Rate Limiter**: Enforces rate limits (default: 50 requests per 10 seconds per client) before forwarding requests to WooCommerce.
- **Smart Retry & Backoff**: Automatically retries transient failures (HTTP 429, 500, 502, 503, 504, network timeouts) with exponential backoff and jitter, while immediately rejecting permanent client errors (400, 401, 403, 404).
- **Strict Security & Sanitization**: Never leaks store keys, secrets, or internal stack traces in tool outputs or server logs.
- **Deployable to Cloudflare Workers**: Includes `wrangler.toml` and `worker.py` for serverless deployment on Cloudflare's global edge network.
- **Zero Heavy Dependencies**: Built with Python 3.10+ standard library.

---

## Available MCP Tools

| Tool Name | Description | Key Parameters |
|:---|:---|:---|
| `search_products` | Search store products by keyword, category, status, or price range | `query` (str), `category` (int), `status` (str), `min_price`, `max_price`, `page`, `per_page` |
| `get_product` | Retrieve complete product details, inventory count, SKU, variations, and pricing | `product_id` (int) or `sku` (str) |
| `list_products` | List catalog products with stock status and category filtering | `stock_status` (`instock`, `outofstock`, `onbackorder`), `category` (int), `page`, `per_page` |
| `list_orders` | Retrieve store orders with status, customer, and date range filters | `status` (`pending`, `processing`, `completed`, etc.), `customer_id` (int), `after`, `before` |
| `get_order` | Fetch complete details for a specific order (line items, shipping/billing, totals) | `order_id` (int, required) |
| `update_product_stock` | Safely update inventory quantity, stock status, or stock management settings | `product_id` (int, required), `stock_quantity` (int), `stock_status` (str), `manage_stock` (bool) |
| `create_product` | Create a new simple or variable product in the WooCommerce catalog | `name` (str, required), `type`, `regular_price`, `description`, `stock_quantity`, `sku` |

---

## Environment Variables

All configuration is provided via environment variables (or `.env` file):

| Variable | Required | Default | Description |
|:---|:---:|:---:|:---|
| `WOOCOMMERCE_STORE_URL` | Yes | - | URL of your WooCommerce store (e.g. `https://example.com`) |
| `WOOCOMMERCE_CONSUMER_KEY` | Yes | - | WooCommerce REST API Consumer Key (`ck_...`) |
| `WOOCOMMERCE_CONSUMER_SECRET` | Yes | - | WooCommerce REST API Consumer Secret (`cs_...`) |
| `MCP_AUTH_TOKEN` | Yes | - | Secret token required from MCP clients |
| `MCP_AUTH_CONFIGURATION` | Optional | - | JSON array or comma-separated tokens for multiple clients |
| `MCP_RATE_LIMIT_MAX_REQUESTS` | No | `50` | Maximum requests allowed per client in window |
| `MCP_RATE_LIMIT_WINDOW_SECONDS` | No | `10` | Rate limit sliding window duration in seconds |
| `WOOCOMMERCE_MAX_RETRIES` | No | `3` | Maximum retry attempts for transient errors |
| `WOOCOMMERCE_TIMEOUT_SECONDS` | No | `15.0` | Timeout per WooCommerce HTTP request |

---

## WooCommerce Setup

1. Log into your WordPress / WooCommerce Admin Dashboard.
2. Navigate to **WooCommerce > Settings > Advanced > REST API**.
3. Click **Add Key**:
   - **Description**: `MCP Server Integration`
   - **User**: Select an admin or shop manager user
   - **Permissions**: `Read/Write` (or `Read` for read-only access)
4. Click **Generate API Key**.
5. Copy the **Consumer Key** (`ck_...`) and **Consumer Secret** (`cs_...`) immediately into your `.env` file.

---

## Local Setup & Running Locally

### 1. Clone & Configure
```bash
git clone <repo-url>
cd woocommerce-mcp-server

# Copy example environment configuration
cp .env.example .env

# Edit .env with your WooCommerce store URL and keys
nano .env
```

### 2. Run the Verification Suite
Before starting the server, run the 10-point test suite:
```bash
python3 test_mcp.py
```

### 3. Run Remote HTTP MCP Server
```bash
python3 server.py --port 3000
```
The server will start listening at:
`http://localhost:3000/mcp`

### 4. Run in STDIO Mode (Claude Desktop)
For local desktop integration with Claude Desktop, edit `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "woocommerce": {
      "command": "python3",
      "args": ["-m", "woocommerce_mcp", "--stdio"],
      "env": {
        "WOOCOMMERCE_STORE_URL": "https://your-store.com",
        "WOOCOMMERCE_CONSUMER_KEY": "ck_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "WOOCOMMERCE_CONSUMER_SECRET": "cs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      }
    }
  }
}
```

---

## Connecting Remote MCP Clients (Claude, Cursor, Windsurf)

To connect an AI agent or MCP client to the remote HTTP server:

- **Endpoint URL**: `https://<your-server-host>/mcp`
- **HTTP Method**: `POST`
- **Headers**:
  ```http
  Authorization: Bearer <YOUR_MCP_AUTH_TOKEN>
  Content-Type: application/json
  ```

### Example MCP JSON-RPC Request:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "search_products",
    "arguments": {
      "query": "shirt",
      "per_page": 5
    }
  }
}
```

### Example Structured Response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[\n  {\n    \"id\": 42,\n    \"name\": \"Classic T-Shirt\",\n    \"sku\": \"TSHIRT-01\",\n    \"price\": \"29.99\",\n    \"stock_status\": \"instock\",\n    \"stock_quantity\": 15\n  }\n]"
      }
    ],
    "isError": false
  }
}
```

---

## Cloudflare Workers Deployment

The server is architected to deploy as a serverless Cloudflare Python Worker using `wrangler.toml` and `worker.py`.

### 1. Install Wrangler CLI
```bash
npm install -g wrangler
```

### 2. Authenticate with Cloudflare
```bash
wrangler login
```

### 3. Configure Secrets in Cloudflare
```bash
wrangler secret put WOOCOMMERCE_STORE_URL
wrangler secret put WOOCOMMERCE_CONSUMER_KEY
wrangler secret put WOOCOMMERCE_CONSUMER_SECRET
wrangler secret put MCP_AUTH_TOKEN
```

### 4. Deploy to Cloudflare
```bash
wrangler deploy
```

Your MCP server will be live globally at:
`https://woocommerce-mcp-server.<your-subdomain>.workers.dev/mcp`

The URL remains stable across subsequent deployments.

---

## Manual Testing Instructions

Use the included CLI client `mcp_client.py` to verify each capability:

```bash
# 1. Test MCP initialization
python3 mcp_client.py --token <YOUR_TOKEN> init

# 2. List available tools
python3 mcp_client.py --token <YOUR_TOKEN> tools

# 3. Search products
python3 mcp_client.py --token <YOUR_TOKEN> search "shoes"

# 4. Get product details
python3 mcp_client.py --token <YOUR_TOKEN> product 101

# 5. List recent orders
python3 mcp_client.py --token <YOUR_TOKEN> orders

# 6. Update product stock level
python3 mcp_client.py --token <YOUR_TOKEN> stock 101 25

# 7. Test invalid auth token (Verifies 401 Unauthorized rejection)
python3 mcp_client.py --token WRONG_TOKEN tools

# 8. Test parameter validation (Verifies error response without calling WooCommerce)
python3 mcp_client.py --token <YOUR_TOKEN> call get_order '{}'
```

---

## Architecture & Codebase Structure

```text
├── .env.example              # Environment variables template
├── README.md                 # Complete documentation
├── pyproject.toml            # Python package metadata
├── requirements.txt          # Python requirements
├── server.py                 # Direct execution entrypoint
├── worker.py                 # Cloudflare Worker Python handler
├── wrangler.toml             # Cloudflare Workers configuration
├── test_mcp.py               # 10-requirement verification test suite
├── mcp_client.py             # CLI MCP client for manual inspection
└── woocommerce_mcp/
    ├── __init__.py           # Package initializer
    ├── __main__.py           # CLI runner (python3 -m woocommerce_mcp)
    ├── auth.py               # Client authentication and identity hashing
    ├── config.py             # Environment configuration parser
    ├── rate_limiter.py       # Sliding-window rate limiting engine
    ├── tools.py              # MCP tool schemas, validation, dispatch
    ├── wc_client.py          # WooCommerce REST API v3 client with retry/backoff
    └── server.py             # HTTP JSON-RPC & STDIO server runtime
```

---

## License

MIT License. Designed for production AI-agent integration with WooCommerce stores.
