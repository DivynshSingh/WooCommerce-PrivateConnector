## Submission: 3. Build a Private Connector for a Mercahnt/ Tool 

## WooCommerce MCP Server

### Quick Setup & How to Run
We need an authorization server and a place to host the mcp. I used `Auth0` as authorization server and `Cloudflare worker` to host the mcp server.
There is no vendor lock-in but setting up authorization server is a hassle sometimes, hence it would be faster to use `Auth0` as I will provide detailed steps to set it up correctly.

### 1. Setup steps
 - Create a Cloudflare and a Auth0 Account.
 - Clone this repository on your laptop.
    ```bash
        git clone https://github.com/DivynshSingh/WooCommerce-PrivateConnector.git
        pip install -r requirements.txt
    ```
 - Create wrangler.toml. This is config for CloudFlare worker:
    ```bash
        cp .example.wrangler.toml wrangler.toml
    ```
 - Fill in your store & OAuth credentials:
  - `WOOCOMMERCE_STORE_URL`: Your store URL
  - `OAUTH_AUTH_SERVER_URL`: Your Auth0 / OAuth 2.1 tenant domain. Skip this for now we will add it later as we need to host the MCP server first to use it as audience in auth0 setup.
  - `OAUTH_AUDIENCE`: MCP server's own public URL. This is Optional. Skip this too, hosted MCP server will finds this value by looking up its own origin URL.
  - set other rate limiting parameters, or you can let them be; they are already set to real values.
  -  Run command to host:
     ```bash
         npx wrangler deploy
     ```
  - After following all the prompted instructions after above command, you will see the URL to hosted resource at the end, this url is the audience which consumes the access token given by authorization server.
  - Now We setup the auth0 server.
    - MCP clients need DCR enabled in OAuth: goto Auth0 management Dashboard > Settings / Tenant Settings > Advanced > Scroll down to `settings` section and enable `Dynamic Client Registration (DCR)`
    - Now Go to auth0 dashboard > Applications > APIs:
      - Click Create API; the identifier field here is your MCP server URL(do not include a trailing slash, it may cause issues such as resource not found).
    - After creating the API, go to the permissions tab and create `mcp:read` and `mcp:write` under `Add a Permission`.
      - go to `Settings` tab, scroll to bottom and find `Application Access Policy`
      - Under `Application Access Policy` set `User-delegated Access` to all apps allowed.
      - Under `Default Permissions for third-party applications` set `User-delegated Access` to `Authorized - Pick and choose permissions.` pick `mcp:read` and `mcp:write`.
  - Create credentials for Authorization flow now.
      - In Management Dashboard goto Authentication > Database > Settings > Scroll to bottom to find `Promote Connection to Domain Level` and enable this setting.
      - Now we create an entry in our auth database. In management dashboard go to `User Management` > `Users`. Creat a User with mail and password, save this credential it will be used to authorize MCP client to mcp server.

  - Come back to the MCP codebase now. Add the `OAUTH_AUTH_SERVER_URL` to `wrangler.toml`. `OAUTH_AUTH_SERVER_URL` is the url to auth0 server we just created.
    Your OAUTH_AUTH_SERVER url is `https://{your-tenant-name}.auth0.com/` and you can see your tenant name on the left top corner or in settings / tenant-settings.
  - setup SECRET API keys for MCP server:
    - Goto your wordpress site admin page then to > `WooCommerce` > `Settings` > `Advanced` > `REST API`, and generate consumer key and secret. Copy and save the key and secret, it will not be shown again.
    - Run:
        ```bash
         npx wrangler secret put WOOCOMMERCE_CONSUMER_KEY
        ```
      It will ask you to enter the value for this secret, paste the `WOOCOMMERCE_CONSUMER_KEY` you just generated in WordPress site / wp-admin page.
        ```bash
         npx wrangler secret put WOOCOMMERCE_CONSUMER_SECRET
        ```
      Add the consumer secret when prompted.
  -  Run command to Redeploy:
     ```bash
         npx wrangler deploy
     ```

### 2. Connect to MCP server
  - Goto your agent and connect to MCP server, authorization page will ask for the authorization credentials that we created in above steps.

Let your agent Use and test the MCP server.

### 3. Local tests
To run the full test suite (covering all 21 tools across 24 test suites):
```bash
python3 test_mcp.py
```

---

*(Note: For a detailed architectural breakdown, DCR setup, and hosting alternatives, see `guide.md`.)*

---

## Assumptions & Practical Limitations

- **Store-Managed Business Logic vs. Server Layer:** Some behaviors strictly belong to WooCommerce's internal lifecycle rather than the MCP server. For example:
  - When inventory drops to 0, WooCommerce itself should handle the transition from `instock` to `outofstock` based on store catalog settings. While the MCP server guards against invalid inputs, it delegates catalog lifecycle side-effects to WooCommerce.
  - On variable products, stock status is derived from variations—attempting to force `instock` on a parent variable product whose variants are all out of stock is ignored by WooCommerce (and the mcp server returns warnings accordingly).
- **Colocated DCR Proxy on the Worker:** The dynamic client registration endpoint (`/oauth/register`) is hosted right on the Cloudflare Worker alongside the MCP server code, acting as an intermediary proxy to Auth0's `/oidc/register`. In enterprise architectures, the authorization server handles DCR directly. However, because desktop AI clients (like Claude) require specific fields (`response_types: ['code']`, `token_endpoint_auth_method: 'none'`) that Auth0 doesn't format out of the box without manual app patching, this proxy bridges the gap and prevents desktop clients failed connection setup.
- **Manual vs. Gateway Refunds:** WooCommerce's API rejects automated refund requests if the order was placed without an online payment gateway (or with cash on delivery/test checkouts). To handle this without crashing tool calls, manual refunds require passing `api_refund=false`, which records the refund on WooCommerce ledger without querying a non-existent payment processor.
- **Orphaned IDs in Grouped Products:** WooCommerce's core REST API does not automatically scrub child IDs from grouped parent products when a child item is deleted. The MCP server actively tracks parent references on permanent deletes and scrubs dangling IDs as a safety net.
- **Trashing Orders via DELETE Endpoint:** WooCommerce doesn't allow setting an order status to `"trash"` via the update (`PUT`) endpoint (it throws `Invalid parameter(s): status`). To trash an order through `update_order_status`, the server routes the call to WooCommerce's `DELETE /wp-json/wc/v3/orders/<id>?force=false` endpoint under the hood.
- **HTML Cleanup on Text Outputs:** WooCommerce stores rich product descriptions wrapped in WordPress `<p>` and formatting tags. The server strips raw wrapping tags to deliver clean markdown text to LLMs without consuming excess prompt tokens.
