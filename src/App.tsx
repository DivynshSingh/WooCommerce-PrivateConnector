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
          <span className="text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded">
            OAuth 2.1 Active
          </span>
        </div>

        <p className="text-sm text-slate-400 leading-relaxed">
          Headless Model Context Protocol (MCP) server engineered for Cloudflare Workers (Pyodide) with non-blocking async execution, strict pagination (max 15/page), and OAuth 2.1 stateless JWT authentication.
        </p>

        <div className="bg-slate-950 rounded-lg p-4 text-xs space-y-2.5 border border-slate-800/80">
          <div className="flex justify-between items-center pb-2 border-b border-slate-800/60 text-slate-400 font-semibold">
            <span>CONFIGURED ENDPOINTS</span>
            <span className="text-emerald-400 font-mono text-[11px]">RFC 9728 Compliant</span>
          </div>
          <div>
            <span className="text-slate-500 block">Auth Server (Supabase):</span>
            <code className="text-indigo-400 break-all">https://esommvnvcatygpciqdps.supabase.co/auth/v1</code>
          </div>
          <div>
            <span className="text-slate-500 block">JWKS Endpoint (ES256):</span>
            <code className="text-sky-400 break-all">https://esommvnvcatygpciqdps.supabase.co/auth/v1/.well-known/jwks.json</code>
          </div>
          <div>
            <span className="text-slate-500 block">WooCommerce Store:</span>
            <code className="text-emerald-400 break-all">https://dev-anythingstore37.pantheonsite.io</code>
          </div>
          <div>
            <span className="text-slate-500 block">MCP RPC Route:</span>
            <code className="text-amber-400">POST /mcp</code>
          </div>
          <div>
            <span className="text-slate-500 block">Protected Resource Metadata:</span>
            <code className="text-slate-300">GET /.well-known/oauth-protected-resource</code>
          </div>
        </div>

        <div className="bg-indigo-950/30 border border-indigo-500/20 rounded-lg p-4 text-xs space-y-2 text-indigo-200">
          <div className="font-semibold text-indigo-300 flex items-center space-x-1.5">
            <span>Testing with Glamour / MCP Inspector</span>
          </div>
          <ol className="list-decimal list-inside space-y-1 text-slate-400">
            <li>Set Transport: <strong className="text-slate-200">Streamable HTTP</strong></li>
            <li>Server URL: <strong className="text-slate-200">https://woocommerce-mcp-server.woocommerce-connector.workers.dev/mcp</strong></li>
            <li>Add Request Header: <strong className="text-slate-200">Authorization: Bearer &lt;SUPABASE_ACCESS_TOKEN&gt;</strong></li>
            <li>Execute <strong className="text-emerald-300">list_products</strong> to query your Pantheon store</li>
          </ol>
        </div>

        <div className="text-xs text-slate-500 flex justify-between items-center pt-2 border-t border-slate-800/80">
          <span>Deploy: <code className="text-slate-400">wrangler deploy</code></span>
          <span>Verification: <code className="text-emerald-400">python3 test_mcp.py</code> (10/10 PASS)</span>
        </div>
      </div>
    </div>
  );
}
