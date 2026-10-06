#!/usr/bin/env python3
"""
Simple CLI MCP Client for manual testing and inspection of the WooCommerce MCP Server.
Usage:
    python3 mcp_client.py --token <TOKEN> [--url http://localhost:3000/mcp] <command> [args...]

Commands:
    init                        Send initialize handshake
    tools                       List available tools (tools/list)
    call <tool_name> '<json>'   Execute tool call
    search <query>              Convenience product search
    product <id>                Get product details
    orders                      List recent orders
    order <id>                  Get specific order details
    stock <id> <quantity>       Update product stock
"""

import argparse
import json
import sys
import urllib.request
import urllib.error


def send_mcp_request(url: str, token: str, method: str, params: dict = None, req_id: int = 1) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params or {},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return {"http_status": e.code, "error": json.loads(body)}
        except Exception:
            return {"http_status": e.code, "error": body}


def main():
    parser = argparse.ArgumentParser(description="WooCommerce MCP Client CLI")
    parser.add_argument("--url", default="http://localhost:3000/mcp", help="Remote MCP endpoint URL")
    parser.add_argument("--token", default="", help="MCP auth token")
    parser.add_argument("command", help="Command (init, tools, call, search, product, orders, order, stock)")
    parser.add_argument("cmd_args", nargs="*", help="Arguments for the command")

    args = parser.parse_args()

    if args.command == "init":
        res = send_mcp_request(args.url, args.token, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "cli-client", "version": "1.0"},
        })
        print(json.dumps(res, indent=2))

    elif args.command == "tools":
        res = send_mcp_request(args.url, args.token, "tools/list")
        print(json.dumps(res, indent=2))

    elif args.command == "call":
        if len(args.cmd_args) < 1:
            print("Usage: call <tool_name> [json_arguments]")
            sys.exit(1)
        tool_name = args.cmd_args[0]
        arguments = json.loads(args.cmd_args[1]) if len(args.cmd_args) > 1 else {}
        res = send_mcp_request(args.url, args.token, "tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })
        print(json.dumps(res, indent=2))

    elif args.command == "search":
        query = args.cmd_args[0] if args.cmd_args else ""
        res = send_mcp_request(args.url, args.token, "tools/call", {
            "name": "search_products",
            "arguments": {"query": query},
        })
        print(json.dumps(res, indent=2))

    elif args.command == "product":
        if not args.cmd_args:
            print("Usage: product <id>")
            sys.exit(1)
        res = send_mcp_request(args.url, args.token, "tools/call", {
            "name": "get_product",
            "arguments": {"product_id": int(args.cmd_args[0])},
        })
        print(json.dumps(res, indent=2))

    elif args.command == "orders":
        res = send_mcp_request(args.url, args.token, "tools/call", {
            "name": "list_orders",
            "arguments": {"per_page": 5},
        })
        print(json.dumps(res, indent=2))

    elif args.command == "order":
        if not args.cmd_args:
            print("Usage: order <id>")
            sys.exit(1)
        res = send_mcp_request(args.url, args.token, "tools/call", {
            "name": "get_order",
            "arguments": {"order_id": int(args.cmd_args[0])},
        })
        print(json.dumps(res, indent=2))

    elif args.command == "stock":
        if len(args.cmd_args) < 2:
            print("Usage: stock <product_id> <quantity>")
            sys.exit(1)
        res = send_mcp_request(args.url, args.token, "tools/call", {
            "name": "update_product_stock",
            "arguments": {"product_id": int(args.cmd_args[0]), "stock_quantity": int(args.cmd_args[1])},
        })
        print(json.dumps(res, indent=2))

    else:
        print(f"Unknown command: {args.command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
