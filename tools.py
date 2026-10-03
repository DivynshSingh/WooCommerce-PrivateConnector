import json
from typing import Any, Dict, List, Optional, Tuple
from .wc_client import WooCommerceClient, WooCommerceAPIError

# Definition of available MCP tools according to MCP Specification
TOOLS_METADATA = [
    {
        "name": "search_products",
        "description": "Search products in the WooCommerce store by keyword query, category, status, and price range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search keyword for product title or content."
                },
                "category": {
                    "type": "integer",
                    "description": "Category ID to limit results to."
                },
                "status": {
                    "type": "string",
                    "enum": ["any", "publish", "draft", "pending", "private"],
                    "description": "Product publication status.",
                    "default": "publish"
                },
                "min_price": {
                    "type": "string",
                    "description": "Minimum product price filter."
                },
                "max_price": {
                    "type": "string",
                    "description": "Maximum product price filter."
                },
                "page": {
                    "type": "integer",
                    "description": "Page number (1-indexed).",
                    "default": 1
                },
                "per_page": {
                    "type": "integer",
                    "description": "Number of products per page (1-100).",
                    "default": 10
                }
            }
        }
    },
    {
        "name": "get_product",
        "description": "Retrieve detailed information for a specific product by its ID or SKU, including stock quantity, price, variations, and status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The unique WooCommerce product ID."
                },
                "sku": {
                    "type": "string",
                    "description": "The unique product SKU code."
                }
            }
        }
    },
    {
        "name": "list_products",
        "description": "List products and check inventory levels with optional stock status and category filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "stock_status": {
                    "type": "string",
                    "enum": ["instock", "outofstock", "onbackorder"],
                    "description": "Filter by stock status."
                },
                "category": {
                    "type": "integer",
                    "description": "Category ID filter."
                },
                "featured": {
                    "type": "boolean",
                    "description": "Filter featured products."
                },
                "page": {
                    "type": "integer",
                    "description": "Page number (1-indexed).",
                    "default": 1
                },
                "per_page": {
                    "type": "integer",
                    "description": "Number of products per page (1-100).",
                    "default": 10
                }
            }
        }
    },
    {
        "name": "list_orders",
        "description": "Retrieve orders from the WooCommerce store with optional status, customer, and date range filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["any", "pending", "processing", "on-hold", "completed", "cancelled", "refunded", "failed"],
                    "description": "Order status filter.",
                    "default": "any"
                },
                "customer_id": {
                    "type": "integer",
                    "description": "Filter orders for a specific customer ID."
                },
                "after": {
                    "type": "string",
                    "description": "Limit response to resources published after a given ISO8601 compliant date (e.g. 2026-01-01T00:00:00)."
                },
                "before": {
                    "type": "string",
                    "description": "Limit response to resources published before a given ISO8601 compliant date."
                },
                "page": {
                    "type": "integer",
                    "description": "Page number (1-indexed).",
                    "default": 1
                },
                "per_page": {
                    "type": "integer",
                    "description": "Number of orders per page (1-100).",
                    "default": 10
                }
            }
        }
    },
    {
        "name": "get_order",
        "description": "Retrieve complete details for a specific order by order ID, including line items, customer billing/shipping details, and totals.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "integer",
                    "description": "The unique WooCommerce order ID."
                }
            },
            "required": ["order_id"]
        }
    },
    {
        "name": "update_product_stock",
        "description": "Update inventory stock quantity, stock status, or stock management settings for a product.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The unique WooCommerce product ID."
                },
                "stock_quantity": {
                    "type": "integer",
                    "description": "The updated inventory stock count."
                },
                "stock_status": {
                    "type": "string",
                    "enum": ["instock", "outofstock", "onbackorder"],
                    "description": "The updated stock status."
                },
                "manage_stock": {
                    "type": "boolean",
                    "description": "Enable or disable stock management at product level."
                }
            },
            "required": ["product_id"]
        }
    },
    {
        "name": "create_product",
        "description": "Create a new product in the WooCommerce catalog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Product name / title."
                },
                "type": {
                    "type": "string",
                    "enum": ["simple", "variable", "grouped", "external"],
                    "default": "simple",
                    "description": "Product type."
                },
                "regular_price": {
                    "type": "string",
                    "description": "Product regular price (e.g. '19.99')."
                },
                "description": {
                    "type": "string",
                    "description": "Full product description."
                },
                "short_description": {
                    "type": "string",
                    "description": "Product short description."
                },
                "manage_stock": {
                    "type": "boolean",
                    "description": "Enable stock management."
                },
                "stock_quantity": {
                    "type": "integer",
                    "description": "Initial stock quantity."
                },
                "sku": {
                    "type": "string",
                    "description": "Unique SKU identifier."
                }
            },
            "required": ["name"]
        }
    }
]


def get_tool_definitions() -> List[Dict[str, Any]]:
    """Return tool schemas formatted for MCP tools/list."""
    return TOOLS_METADATA


def validate_input(tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validates input arguments against the tool schema before calling WooCommerce.
    Rejects malformed inputs early.
    """
    if not isinstance(arguments, dict):
        return False, "Tool arguments must be a JSON object."

    if tool_name == "get_product":
        if "product_id" not in arguments and "sku" not in arguments:
            return False, "Either 'product_id' or 'sku' must be provided."
        if "product_id" in arguments and not isinstance(arguments["product_id"], int):
            return False, "Argument 'product_id' must be an integer."

    elif tool_name == "get_order":
        if "order_id" not in arguments:
            return False, "Required parameter 'order_id' is missing."
        if not isinstance(arguments["order_id"], int):
            return False, "Argument 'order_id' must be an integer."

    elif tool_name == "update_product_stock":
        if "product_id" not in arguments:
            return False, "Required parameter 'product_id' is missing."
        if not isinstance(arguments["product_id"], int):
            return False, "Argument 'product_id' must be an integer."
        if "stock_quantity" in arguments and not isinstance(arguments["stock_quantity"], int):
            return False, "Argument 'stock_quantity' must be an integer."
        if "stock_status" in arguments:
            allowed = ["instock", "outofstock", "onbackorder"]
            if arguments["stock_status"] not in allowed:
                return False, f"Argument 'stock_status' must be one of {allowed}."

    elif tool_name == "create_product":
        if "name" not in arguments or not str(arguments["name"]).strip():
            return False, "Required parameter 'name' is missing or empty."
        if "type" in arguments:
            allowed = ["simple", "variable", "grouped", "external"]
            if arguments["type"] not in allowed:
                return False, f"Argument 'type' must be one of {allowed}."

    elif tool_name in ("search_products", "list_products", "list_orders"):
        if "page" in arguments and (not isinstance(arguments["page"], int) or arguments["page"] < 1):
            return False, "Argument 'page' must be a positive integer."
        if "per_page" in arguments and (not isinstance(arguments["per_page"], int) or arguments["per_page"] < 1 or arguments["per_page"] > 100):
            return False, "Argument 'per_page' must be an integer between 1 and 100."

    return True, None


def execute_tool(
    tool_name: str, arguments: Dict[str, Any], wc_client: WooCommerceClient
) -> Dict[str, Any]:
    """
    Executes tool with input validation, error handling, and structured MCP output.
    Returns standard MCP tool result dictionary:
    {"content": [{"type": "text", "text": "..."}], "isError": bool}
    """
    # 1. Validate inputs before calling WooCommerce
    is_valid, validation_err = validate_input(tool_name, arguments)
    if not is_valid:
        return {
            "content": [{"type": "text", "text": f"Input validation failed: {validation_err}"}],
            "isError": True,
        }

    try:
        # 2. Dispatch to WooCommerce Client
        if tool_name == "search_products":
            res = wc_client.search_products(
                query=arguments.get("query"),
                category=arguments.get("category"),
                status=arguments.get("status"),
                min_price=arguments.get("min_price"),
                max_price=arguments.get("max_price"),
                page=arguments.get("page", 1),
                per_page=arguments.get("per_page", 10),
            )
        elif tool_name == "get_product":
            res = wc_client.get_product(
                product_id=arguments.get("product_id"),
                sku=arguments.get("sku"),
            )
        elif tool_name == "list_products":
            res = wc_client.list_products(
                stock_status=arguments.get("stock_status"),
                category=arguments.get("category"),
                featured=arguments.get("featured"),
                page=arguments.get("page", 1),
                per_page=arguments.get("per_page", 10),
            )
        elif tool_name == "list_orders":
            res = wc_client.list_orders(
                status=arguments.get("status"),
                customer_id=arguments.get("customer_id"),
                after=arguments.get("after"),
                before=arguments.get("before"),
                page=arguments.get("page", 1),
                per_page=arguments.get("per_page", 10),
            )
        elif tool_name == "get_order":
            res = wc_client.get_order(order_id=arguments["order_id"])
        elif tool_name == "update_product_stock":
            res = wc_client.update_product_stock(
                product_id=arguments["product_id"],
                stock_quantity=arguments.get("stock_quantity"),
                stock_status=arguments.get("stock_status"),
                manage_stock=arguments.get("manage_stock"),
            )
        elif tool_name == "create_product":
            res = wc_client.create_product(
                name=arguments["name"],
                type=arguments.get("type", "simple"),
                regular_price=arguments.get("regular_price"),
                description=arguments.get("description"),
                short_description=arguments.get("short_description"),
                manage_stock=arguments.get("manage_stock"),
                stock_quantity=arguments.get("stock_quantity"),
                sku=arguments.get("sku"),
                categories=arguments.get("categories"),
            )
        else:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: '{tool_name}'."}],
                "isError": True,
            }

        return {
            "content": [{"type": "text", "text": json.dumps(res, indent=2)}],
            "isError": False,
        }

    except WooCommerceAPIError as e:
        return {
            "content": [{"type": "text", "text": f"WooCommerce Error: {e.message}"}],
            "isError": True,
        }
    except Exception as e:
        # Generic error with no sensitive stack trace or credential leaks
        return {
            "content": [{"type": "text", "text": f"Unexpected error executing {tool_name}: {str(e)}"}],
            "isError": True,
        }
