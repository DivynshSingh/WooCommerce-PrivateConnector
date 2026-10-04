#!/usr/bin/env python3
"""
WooCommerce Model Context Protocol (MCP) Server.
Run directly with:
    python3 server.py
or
    python3 server.py --stdio
"""

import os
import sys

_pkg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "woocommerce_mcp")
if _pkg not in sys.path:
    sys.path.insert(0, _pkg)

from woocommerce_mcp.server import MCPServer, run_http_server, run_stdio_server
from woocommerce_mcp.__main__ import main

if __name__ == "__main__":
    main()
