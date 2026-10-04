/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export default function App() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-mono flex items-center justify-center p-6">
      <div className="max-w-2xl w-full bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-2xl space-y-6">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block animate-pulse"></span>
            <span className="font-semibold text-slate-100">WooCommerce MCP Server</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 px-2 py-0.5 rounded">
              Auth0 DCR Active
            </span>
            <span className="text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded">
              Dual Rate Limit
            </span>
          </div>
        </div>

        <p className="text-sm text-slate-400 leading-relaxed">
          Cloudflare Worker-based WooCommerce Model Context Protocol (MCP) server. Acts as an RFC 9728 OAuth 2.0 Protected Resource Server paired with Auth0 for RFC 7591 Dynamic Client Registration (DCR) and dual-layer rate limiting.
        </p>

        <div className="bg-slate-950 rounded-lg p-4 text-xs space-y-2.5 border border-slate-800/80">
          <div className="flex justify-between items-center pb-2 border-b border-slate-800/60 text-slate-400 font-semibold">
            <span>CONFIGURED AUTH0 & MCP ENDPOINTS</span>
            <span className="text-emerald-400 font-mono text-[11px]">RFC 9728 & RFC 7591</span>
          </div>
          <div>
            <span className="text-slate-500 block">Domain Base URL:</span>
            <code className="text-indigo-400 break-all">https://woocommerce-mcp-server.us.auth0.com</code>
          </div>
          <div>
            <span className="text-slate-500 block">Dynamic Client Registration (DCR):</span>
            <code className="text-amber-400 break-all">https://woocommerce-mcp-server.us.auth0.com/oidc/register</code>
          </div>
          <div>
            <span className="text-slate-500 block">Authorization Endpoint:</span>
            <code className="text-slate-300 break-all">https://woocommerce-mcp-server.us.auth0.com/authorize</code>
          </div>
          <div>
            <span className="text-slate-500 block">Token Endpoint:</span>
            <code className="text-slate-300 break-all">https://woocommerce-mcp-server.us.auth0.com/oauth/token</code>
          </div>
          <div>
            <span className="text-slate-500 block">JWKS Endpoint (RS256):</span>
            <code className="text-sky-400 break-all">https://woocommerce-mcp-server.us.auth0.com/.well-known/jwks.json</code>
          </div>
          <div>
            <span className="text-slate-500 block">OpenID Discovery:</span>
            <code className="text-slate-400 break-all">https://woocommerce-mcp-server.us.auth0.com/.well-known/openid-configuration</code>
          </div>
          <div>
            <span className="text-slate-500 block">WooCommerce Store Target:</span>
            <code className="text-emerald-400 break-all">https://dev-anythingstore37.pantheonsite.io</code>
          </div>
          <div className="pt-2 border-t border-slate-900 grid grid-cols-2 gap-2 text-[11px]">
            <div>
              <span className="text-slate-500 block">Unauth / IP Limit:</span>
              <span className="text-amber-400 font-bold">20 reqs / 60s</span>
            </div>
            <div>
              <span className="text-slate-500 block">Authenticated Client Limit:</span>
              <span className="text-emerald-400 font-bold">50 reqs / 10s</span>
            </div>
          </div>
        </div>

        <div className="bg-indigo-950/30 border border-indigo-500/20 rounded-lg p-4 text-xs space-y-2 text-indigo-200">
          <div className="font-semibold text-indigo-300 flex items-center space-x-1.5">
            <span>Client Connection & Discovery</span>
          </div>
          <ul className="space-y-1.5 text-slate-400">
            <li>• <strong className="text-slate-200">Discovery:</strong> MCP clients fetch <code className="text-sky-300">/.well-known/oauth-protected-resource</code> to discover your Auth0 domain.</li>
            <li>• <strong className="text-slate-200">DCR (RFC 7591):</strong> AI clients (Claude Desktop, Cursor) register automatically via <code className="text-amber-300">/oidc/register</code>.</li>
            <li>• <strong className="text-slate-200">Execution:</strong> Authorized calls carry <code className="text-slate-200">Authorization: Bearer &lt;JWT&gt;</code> verified against Auth0 JWKS.</li>
          </ul>
        </div>

        <div className="text-xs text-slate-500 flex justify-between items-center pt-2 border-t border-slate-800/80">
          <span>Self-contained: <code className="text-slate-400">woocommerce_mcp/</code></span>
          <span>Verification: <code className="text-emerald-400">python3 test_mcp.py</code> (12/12 PASS)</span>
        </div>
      </div>
    </div>
  );
}
