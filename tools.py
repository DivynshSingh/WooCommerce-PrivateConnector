import json
from typing import Any, Dict, List, Optional, Tuple
import os
import sys

_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from wc_client import WooCommerceClient, WooCommerceAPIError

# Definition of available MCP tools according to Model Context Protocol specification
TOOLS_METADATA = [
    {
        "name": "search_products",
        "description": "Search products in the WooCommerce store by keyword query (matches product title, description, and SKU), category, status, and price range. Note: to filter specifically by category, use the 'category' parameter.",
        "readOnlyHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search keyword for product title or content."
                },
                "sku": {
                    "type": "string",
                    "description": "Direct SKU search filter."
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
        "description": "Retrieve detailed information for a specific product by its ID or SKU, including stock quantity, price, variations, attributes, and status.",
        "readOnlyHint": True,
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
        "description": "List products and check inventory levels with optional stock status, category, and featured filters.",
        "readOnlyHint": True,
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
        "readOnlyHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["any", "pending", "processing", "on-hold", "completed", "cancelled", "refunded", "failed", "trash"],
                    "description": "Order status filter.",
                    "default": "any"
                },
                "customer_id": {
                    "type": "integer",
                    "description": "Filter orders for a specific customer ID."
                },
                "after": {
                    "type": "string",
                    "description": "Limit response to resources published after a given ISO8601 date."
                },
                "before": {
                    "type": "string",
                    "description": "Limit response to resources published before a given ISO8601 date."
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
        "readOnlyHint": True,
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
        "name": "create_product",
        "description": "Create a new product in the WooCommerce catalog. Supports simple, variable, grouped, and external types with type-specific validation.",
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
                    "description": "Product type. Required fields: 'external' needs external_url; 'grouped' needs grouped_products; 'variable' needs attributes."
                },
                "regular_price": {
                    "type": "string",
                    "description": "Product regular price (e.g. '19.99')."
                },
                "sale_price": {
                    "type": "string",
                    "description": "Product sale price (e.g. '14.99')."
                },
                "description": {
                    "type": "string",
                    "description": "Full product description."
                },
                "short_description": {
                    "type": "string",
                    "description": "Product short description."
                },
                "sku": {
                    "type": "string",
                    "description": "Unique SKU identifier."
                },
                "manage_stock": {
                    "type": "boolean",
                    "description": "Enable stock management at product level."
                },
                "stock_quantity": {
                    "type": "integer",
                    "description": "Initial stock quantity (must be non-negative unless backorders is 'yes' or 'notify')."
                },
                "stock_status": {
                    "type": "string",
                    "enum": ["instock", "outofstock", "onbackorder"],
                    "description": "Stock status."
                },
                "backorders": {
                    "type": "string",
                    "enum": ["no", "notify", "yes"],
                    "description": "Allow backorders policy ('no', 'notify', or 'yes').",
                    "default": "no"
                },
                "categories": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of category IDs to assign the product to."
                },
                "status": {
                    "type": "string",
                    "enum": ["publish", "draft", "pending", "private"],
                    "default": "publish",
                    "description": "Product publication status."
                },
                "featured": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether the product is featured."
                },
                "images": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of image URLs."
                },
                "external_url": {
                    "type": "string",
                    "description": "Required if type='external'. URL for the external product."
                },
                "button_text": {
                    "type": "string",
                    "description": "Optional for type='external'. Text for the external buy button."
                },
                "grouped_products": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Required if type='grouped'. List of child product IDs."
                },
                "attributes": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Required if type='variable'. List of product attributes."
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "update_product",
        "description": "General edit tool to update fields of an existing product. Only specified fields are changed; omitted fields remain untouched.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The unique WooCommerce product ID to update."
                },
                "name": {
                    "type": "string",
                    "description": "Updated product name."
                },
                "regular_price": {
                    "type": "string",
                    "description": "Updated regular price."
                },
                "sale_price": {
                    "type": "string",
                    "description": "Updated sale price."
                },
                "description": {
                    "type": "string",
                    "description": "Updated product description."
                },
                "short_description": {
                    "type": "string",
                    "description": "Updated short description."
                },
                "sku": {
                    "type": "string",
                    "description": "Updated SKU code."
                },
                "status": {
                    "type": "string",
                    "enum": ["publish", "draft", "pending", "private"],
                    "description": "Updated product publication status."
                },
                "categories": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Updated list of category IDs."
                },
                "featured": {
                    "type": "boolean",
                    "description": "Mark product as featured or unfeatured."
                },
                "images": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Updated list of product image URLs."
                },
                "manage_stock": {
                    "type": "boolean",
                    "description": "Enable or disable product-level stock management."
                },
                "stock_quantity": {
                    "type": "integer",
                    "description": "Updated inventory stock quantity (cannot be negative unless backorders is enabled)."
                },
                "stock_status": {
                    "type": "string",
                    "enum": ["instock", "outofstock", "onbackorder"],
                    "description": "Updated stock status."
                },
                "backorders": {
                    "type": "string",
                    "enum": ["no", "notify", "yes"],
                    "description": "Allow backorders setting."
                }
            },
            "required": ["product_id"]
        }
    },
    {
        "name": "update_product_stock",
        "description": "Update inventory stock quantity, stock status, backorder policy, or stock management settings for a product.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The unique WooCommerce product ID."
                },
                "stock_quantity": {
                    "type": "integer",
                    "description": "The updated inventory stock count (cannot be negative unless backorders is 'yes' or 'notify')."
                },
                "stock_status": {
                    "type": "string",
                    "enum": ["instock", "outofstock", "onbackorder"],
                    "description": "The updated stock status."
                },
                "manage_stock": {
                    "type": "boolean",
                    "description": "Enable or disable stock management at product level."
                },
                "backorders": {
                    "type": "string",
                    "enum": ["no", "notify", "yes"],
                    "description": "Backorder policy ('no', 'notify', or 'yes')."
                }
            },
            "required": ["product_id"]
        }
    },
    {
        "name": "delete_product",
        "description": "Delete a product from the store. By default moves the product to trash; set force=true to permanently delete it.",
        "destructiveHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The unique WooCommerce product ID to delete."
                },
                "force": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether to permanently delete the product (true) or move it to trash (false)."
                }
            },
            "required": ["product_id"]
        }
    },
    {
        "name": "list_variations",
        "description": "List all variations of a variable product.",
        "readOnlyHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The parent variable product ID."
                },
                "page": {
                    "type": "integer",
                    "default": 1,
                    "description": "Page number (1-indexed)."
                },
                "per_page": {
                    "type": "integer",
                    "default": 10,
                    "description": "Number of variations per page (1-100)."
                }
            },
            "required": ["product_id"]
        }
    },
    {
        "name": "create_variation",
        "description": "Create a new variation for an existing variable product.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The parent variable product ID."
                },
                "regular_price": {
                    "type": "string",
                    "description": "Regular price for this variation."
                },
                "sale_price": {
                    "type": "string",
                    "description": "Sale price for this variation."
                },
                "sku": {
                    "type": "string",
                    "description": "Unique SKU for this variation."
                },
                "manage_stock": {
                    "type": "boolean",
                    "description": "Enable stock management for this variation."
                },
                "stock_quantity": {
                    "type": "integer",
                    "description": "Stock quantity for this variation."
                },
                "stock_status": {
                    "type": "string",
                    "enum": ["instock", "outofstock", "onbackorder"],
                    "description": "Stock status for this variation."
                },
                "backorders": {
                    "type": "string",
                    "enum": ["no", "notify", "yes"],
                    "description": "Backorder policy."
                },
                "attributes": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Variation attributes defining this variant (e.g. [{'name': 'Size', 'option': 'Large'}])."
                }
            },
            "required": ["product_id"]
        }
    },
    {
        "name": "update_variation",
        "description": "Update pricing, SKU, stock, or attributes for a specific variation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The parent variable product ID."
                },
                "variation_id": {
                    "type": "integer",
                    "description": "The unique variation ID to update."
                },
                "regular_price": {
                    "type": "string",
                    "description": "Updated regular price."
                },
                "sale_price": {
                    "type": "string",
                    "description": "Updated sale price."
                },
                "sku": {
                    "type": "string",
                    "description": "Updated SKU."
                },
                "manage_stock": {
                    "type": "boolean",
                    "description": "Enable stock management."
                },
                "stock_quantity": {
                    "type": "integer",
                    "description": "Updated stock quantity."
                },
                "stock_status": {
                    "type": "string",
                    "enum": ["instock", "outofstock", "onbackorder"],
                    "description": "Updated stock status."
                },
                "backorders": {
                    "type": "string",
                    "enum": ["no", "notify", "yes"],
                    "description": "Updated backorder setting."
                },
                "attributes": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Updated variation attributes."
                }
            },
            "required": ["product_id", "variation_id"]
        }
    },
    {
        "name": "delete_variation",
        "description": "Permanently delete a product variation.",
        "destructiveHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_id": {
                    "type": "integer",
                    "description": "The parent variable product ID."
                },
                "variation_id": {
                    "type": "integer",
                    "description": "The unique variation ID to delete."
                },
                "force": {
                    "type": "boolean",
                    "default": True,
                    "description": "Force permanent deletion (default true for variations)."
                }
            },
            "required": ["product_id", "variation_id"]
        }
    },
    {
        "name": "list_categories",
        "description": "List all product categories in the store with IDs, slugs, and item counts.",
        "readOnlyHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "page": {
                    "type": "integer",
                    "default": 1,
                    "description": "Page number (1-indexed)."
                },
                "per_page": {
                    "type": "integer",
                    "default": 10,
                    "description": "Number of categories per page (1-100)."
                },
                "search": {
                    "type": "string",
                    "description": "Search keyword for category name."
                },
                "parent": {
                    "type": "integer",
                    "description": "Filter by parent category ID."
                }
            }
        }
    },
    {
        "name": "create_category",
        "description": "Create a new product category in the store.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Category name."
                },
                "slug": {
                    "type": "string",
                    "description": "Optional category slug."
                },
                "parent": {
                    "type": "integer",
                    "description": "Optional parent category ID."
                },
                "description": {
                    "type": "string",
                    "description": "Optional category description."
                },
                "image": {
                    "type": "string",
                    "description": "Optional category image URL."
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "update_category",
        "description": "Update an existing product category in the store.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category_id": {
                    "type": "integer",
                    "description": "Category ID to update."
                },
                "name": {
                    "type": "string",
                    "description": "New category name."
                },
                "slug": {
                    "type": "string",
                    "description": "New category slug."
                },
                "parent": {
                    "type": "integer",
                    "description": "New parent category ID."
                },
                "description": {
                    "type": "string",
                    "description": "New category description."
                },
                "image": {
                    "type": "string",
                    "description": "New category image URL."
                }
            },
            "required": ["category_id"]
        }
    },
    {
        "name": "delete_category",
        "description": "Delete a product category by ID, with optional force permanent delete.",
        "destructiveHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "category_id": {
                    "type": "integer",
                    "description": "Category ID to delete."
                },
                "force": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to permanently delete the category (default true)."
                }
            },
            "required": ["category_id"]
        }
    },
    {
        "name": "batch_update_categories",
        "description": "Perform batch create, update, and delete operations on product categories in a single call.",
        "destructiveHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "create": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of categories to create, e.g. [{'name': 'Shoes', 'description': 'Footwear'}]."
                },
                "update": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of categories to update, e.g. [{'id': 19, 'name': 'Apparel & Accessories'}]."
                },
                "delete": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of category IDs to delete."
                }
            }
        }
    },
    {
        "name": "create_order",
        "description": "Create a new customer order with line items, billing, and shipping details.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "line_items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "product_id": {"type": "integer"},
                            "quantity": {"type": "integer"}
                        },
                        "required": ["product_id", "quantity"]
                    },
                    "description": "List of line items in the order."
                },
                "status": {
                    "type": "string",
                    "enum": ["pending", "processing", "on-hold", "completed", "cancelled", "refunded", "failed"],
                    "default": "pending",
                    "description": "Initial order status."
                },
                "customer_id": {
                    "type": "integer",
                    "description": "User ID of the customer."
                },
                "billing": {
                    "type": "object",
                    "description": "Billing address details (first_name, last_name, email, phone, city, state, country)."
                },
                "shipping": {
                    "type": "object",
                    "description": "Shipping address details (first_name, last_name, address_1, city, state, country)."
                },
                "customer_note": {
                    "type": "string",
                    "description": "Customer note or special instructions."
                }
            },
            "required": ["line_items"]
        }
    },
    {
        "name": "update_order_status",
        "description": "Update the lifecycle status of an existing order (e.g. mark completed, processing, or cancelled).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "integer",
                    "description": "The unique WooCommerce order ID."
                },
                "status": {
                    "type": "string",
                    "enum": ["pending", "processing", "on-hold", "completed", "cancelled", "refunded", "failed", "trash"],
                    "description": "The updated order status."
                }
            },
            "required": ["order_id", "status"]
        }
    },
    {
        "name": "create_refund",
        "description": "Issue a financial refund against an order. Set api_refund=false for a manual refund on orders without a payment gateway.",
        "destructiveHint": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "integer",
                    "description": "The unique WooCommerce order ID."
                },
                "amount": {
                    "type": "string",
                    "description": "Refund amount (e.g. '15.00')."
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for issuing the refund."
                },
                "api_refund": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to refund through the payment gateway (default true). Set to false to record a manual refund on the order without contacting a gateway."
                },
                "line_items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer", "description": "Line item ID to refund."},
                            "quantity": {"type": "integer", "description": "Quantity to refund."},
                            "refund_total": {"type": "string", "description": "Refund total for this item."}
                        },
                        "required": ["id"]
                    },
                    "description": "Optional list of line items to target specific items for refund."
                },
                "restock_items": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether to restock refunded items."
                }
            },
            "required": ["order_id", "amount"]
        }
    }
]


def get_tool_definitions() -> List[Dict[str, Any]]:
    """Return tool schemas formatted for MCP tools/list."""
    return TOOLS_METADATA


def validate_input(tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validates input arguments against the tool schema before calling WooCommerce.
    Rejects malformed inputs early with clear field-naming errors.
    """
    if not isinstance(arguments, dict):
        return False, "Tool arguments must be a JSON object."

    # Validate stock quantity across all tools that accept it (BUG-2)
    if "stock_quantity" in arguments:
        qty = arguments["stock_quantity"]
        if not isinstance(qty, int):
            return False, "Argument 'stock_quantity' must be an integer."
        backorders = arguments.get("backorders")
        if qty < 0 and backorders not in ("yes", "notify"):
            return False, "Argument 'stock_quantity' cannot be negative unless 'backorders' is set to 'yes' or 'notify'."

    if tool_name == "get_product":
        if "product_id" not in arguments and "sku" not in arguments:
            return False, "Either 'product_id' or 'sku' must be provided."
        if "product_id" in arguments and not isinstance(arguments["product_id"], int):
            return False, "Argument 'product_id' must be an integer."

    elif tool_name in ("get_order", "update_order_status", "create_refund"):
        if "order_id" not in arguments:
            return False, "Required parameter 'order_id' is missing."
        if not isinstance(arguments["order_id"], int):
            return False, "Argument 'order_id' must be an integer."

        if tool_name == "update_order_status":
            if "status" not in arguments or not str(arguments["status"]).strip():
                return False, "Required parameter 'status' is missing."
            allowed = ["pending", "processing", "on-hold", "completed", "cancelled", "refunded", "failed", "trash"]
            if arguments["status"] not in allowed:
                return False, f"Argument 'status' must be one of {allowed}."

        if tool_name == "create_refund":
            if "amount" not in arguments or not str(arguments["amount"]).strip():
                return False, "Required parameter 'amount' is missing."
            try:
                amt = float(arguments["amount"])
                if amt <= 0:
                    return False, "Refund amount must be greater than zero."
            except (ValueError, TypeError):
                return False, "Argument 'amount' must be a valid numeric amount."
            if "api_refund" in arguments and not isinstance(arguments["api_refund"], bool):
                return False, "Argument 'api_refund' must be a boolean."
            if "line_items" in arguments:
                if not isinstance(arguments["line_items"], list):
                    return False, "Argument 'line_items' must be a list of objects."
            if "restock_items" in arguments and not isinstance(arguments["restock_items"], bool):
                return False, "Argument 'restock_items' must be a boolean."

    elif tool_name in ("update_product_stock", "update_product", "delete_product"):
        if "product_id" not in arguments:
            return False, "Required parameter 'product_id' is missing."
        if not isinstance(arguments["product_id"], int):
            return False, "Argument 'product_id' must be an integer."

        if "stock_status" in arguments:
            allowed = ["instock", "outofstock", "onbackorder"]
            if arguments["stock_status"] not in allowed:
                return False, f"Argument 'stock_status' must be one of {allowed}."

        if "categories" in arguments:
            cats = arguments["categories"]
            if not isinstance(cats, list) or any(not isinstance(c, int) for c in cats):
                return False, "Argument 'categories' must be a list of integer category IDs."

    elif tool_name == "create_product":
        if "name" not in arguments or not str(arguments["name"]).strip():
            return False, "Required parameter 'name' is missing or empty."

        p_type = str(arguments.get("type", "simple")).strip()
        allowed_types = ["simple", "variable", "grouped", "external"]
        if p_type not in allowed_types:
            return False, f"Argument 'type' must be one of {allowed_types}."

        # BUG-1: Per-type requirements validation
        if p_type == "external":
            ext_url = arguments.get("external_url")
            if not ext_url or not isinstance(ext_url, str) or not ext_url.strip():
                return False, "Missing required parameter 'external_url' for product of type 'external'."

        elif p_type == "grouped":
            grp_prods = arguments.get("grouped_products")
            if not grp_prods or not isinstance(grp_prods, list) or len(grp_prods) == 0:
                return False, "Missing required parameter 'grouped_products' (non-empty list of child product IDs) for product of type 'grouped'."
            if any(not isinstance(cid, int) for cid in grp_prods):
                return False, "All items in 'grouped_products' must be integer product IDs."

        elif p_type == "variable":
            attrs = arguments.get("attributes")
            if not attrs or not isinstance(attrs, list) or len(attrs) == 0:
                return False, "Missing required parameter 'attributes' (list of attribute specifications) for product of type 'variable'."

        if "categories" in arguments:
            cats = arguments["categories"]
            if not isinstance(cats, list) or any(not isinstance(c, int) for c in cats):
                return False, "Argument 'categories' must be a list of integer category IDs."

    elif tool_name in ("list_variations", "create_variation", "update_variation", "delete_variation"):
        if "product_id" not in arguments:
            return False, "Required parameter 'product_id' is missing."
        if not isinstance(arguments["product_id"], int):
            return False, "Argument 'product_id' must be an integer."

        if tool_name in ("update_variation", "delete_variation"):
            if "variation_id" not in arguments:
                return False, "Required parameter 'variation_id' is missing."
            if not isinstance(arguments["variation_id"], int):
                return False, "Argument 'variation_id' must be an integer."

    elif tool_name == "create_category":
        if "name" not in arguments or not str(arguments["name"]).strip():
            return False, "Required parameter 'name' is missing or empty."

    elif tool_name in ("update_category", "delete_category"):
        if "category_id" not in arguments:
            return False, "Required parameter 'category_id' is missing."
        if not isinstance(arguments["category_id"], int):
            return False, "Argument 'category_id' must be an integer."

    elif tool_name == "batch_update_categories":
        has_any = False
        for op in ("create", "update", "delete"):
            if op in arguments:
                has_any = True
                if not isinstance(arguments[op], list):
                    return False, f"Argument '{op}' must be a list."
        if not has_any:
            return False, "At least one operation ('create', 'update', or 'delete') must be provided."

    elif tool_name == "create_order":
        items = arguments.get("line_items")
        if not items or not isinstance(items, list) or len(items) == 0:
            return False, "Required parameter 'line_items' must be a non-empty list of items."
        for idx, item in enumerate(items):
            if not isinstance(item, dict) or "product_id" not in item or "quantity" not in item:
                return False, f"Line item at index {idx} must be an object with 'product_id' and 'quantity'."

    elif tool_name in ("search_products", "list_products", "list_orders", "list_variations", "list_categories"):
        if "page" in arguments and (not isinstance(arguments["page"], int) or arguments["page"] < 1):
            return False, "Argument 'page' must be a positive integer."
        if "per_page" in arguments and (not isinstance(arguments["per_page"], int) or arguments["per_page"] < 1 or arguments["per_page"] > 100):
            return False, "Argument 'per_page' must be an integer between 1 and 100."

    return True, None


async def execute_tool(
    tool_name: str, arguments: Dict[str, Any], wc_client: WooCommerceClient
) -> Dict[str, Any]:
    """
    Asynchronously executes tool with input validation, error handling, warning tracking,
    and structured MCP output.
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

    # 2. Track potential parameter ignored warnings (BUG-3)
    warnings: List[str] = []
    stock_status = arguments.get("stock_status")
    stock_qty = arguments.get("stock_quantity")
    backorders = arguments.get("backorders")

    if stock_status == "onbackorder" and stock_qty == 0 and backorders in (None, "", "no"):
        warnings.append(
            "stock_status 'onbackorder' was requested with 0 stock but backorders is 'no'. "
            "In WooCommerce, status will revert to 'outofstock' unless backorders is set to 'yes' or 'notify'."
        )

    try:
        # 3. Dispatch to WooCommerce Client
        if tool_name == "search_products":
            res = await wc_client.search_products(
                query=arguments.get("query"),
                sku=arguments.get("sku"),
                category=arguments.get("category"),
                status=arguments.get("status") or "publish",
                min_price=arguments.get("min_price"),
                max_price=arguments.get("max_price"),
                page=arguments.get("page", 1),
                per_page=min(int(arguments.get("per_page", 10)), 100),
            )
        elif tool_name == "get_product":
            res = await wc_client.get_product(
                product_id=arguments.get("product_id"),
                sku=arguments.get("sku"),
            )
        elif tool_name == "list_products":
            res = await wc_client.list_products(
                stock_status=arguments.get("stock_status"),
                category=arguments.get("category"),
                featured=arguments.get("featured"),
                page=arguments.get("page", 1),
                per_page=min(int(arguments.get("per_page", 10)), 100),
            )
        elif tool_name == "list_orders":
            res = await wc_client.list_orders(
                status=arguments.get("status"),
                customer_id=arguments.get("customer_id"),
                after=arguments.get("after"),
                before=arguments.get("before"),
                page=arguments.get("page", 1),
                per_page=min(int(arguments.get("per_page", 10)), 100),
            )
        elif tool_name == "get_order":
            res = await wc_client.get_order(order_id=arguments["order_id"])
        elif tool_name == "update_product_stock":
            res = await wc_client.update_product_stock(
                product_id=arguments["product_id"],
                stock_quantity=arguments.get("stock_quantity"),
                stock_status=arguments.get("stock_status"),
                manage_stock=arguments.get("manage_stock"),
                backorders=arguments.get("backorders"),
            )
            if isinstance(res, dict) and res.get("type") == "variable" and not res.get("manage_stock") and stock_status:
                warnings.append("stock_status on variable product is derived from its variations.")
        elif tool_name == "create_product":
            res = await wc_client.create_product(
                name=arguments["name"],
                type=arguments.get("type", "simple"),
                regular_price=arguments.get("regular_price"),
                sale_price=arguments.get("sale_price"),
                description=arguments.get("description", ""),
                short_description=arguments.get("short_description", ""),
                sku=arguments.get("sku"),
                manage_stock=arguments.get("manage_stock", False),
                stock_quantity=arguments.get("stock_quantity"),
                stock_status=arguments.get("stock_status", "instock"),
                backorders=arguments.get("backorders", "no"),
                categories=arguments.get("categories"),
                status=arguments.get("status", "publish"),
                featured=arguments.get("featured", False),
                images=arguments.get("images"),
                external_url=arguments.get("external_url"),
                button_text=arguments.get("button_text"),
                grouped_products=arguments.get("grouped_products"),
                attributes=arguments.get("attributes"),
            )
        elif tool_name == "update_product":
            res = await wc_client.update_product(
                product_id=arguments["product_id"],
                name=arguments.get("name"),
                regular_price=arguments.get("regular_price"),
                sale_price=arguments.get("sale_price"),
                description=arguments.get("description"),
                short_description=arguments.get("short_description"),
                sku=arguments.get("sku"),
                status=arguments.get("status"),
                categories=arguments.get("categories"),
                featured=arguments.get("featured"),
                images=arguments.get("images"),
                manage_stock=arguments.get("manage_stock"),
                stock_quantity=arguments.get("stock_quantity"),
                stock_status=arguments.get("stock_status"),
                backorders=arguments.get("backorders"),
            )
            if isinstance(res, dict) and res.get("type") == "variable" and not res.get("manage_stock") and stock_status:
                warnings.append("stock_status on variable product is derived from its variations.")
        elif tool_name == "delete_product":
            res = await wc_client.delete_product(
                product_id=arguments["product_id"],
                force=arguments.get("force", False),
            )
        elif tool_name == "list_variations":
            res = await wc_client.list_variations(
                product_id=arguments["product_id"],
                page=arguments.get("page", 1),
                per_page=min(int(arguments.get("per_page", 10)), 100),
            )
        elif tool_name == "create_variation":
            res = await wc_client.create_variation(
                product_id=arguments["product_id"],
                regular_price=arguments.get("regular_price"),
                sale_price=arguments.get("sale_price"),
                sku=arguments.get("sku"),
                stock_quantity=arguments.get("stock_quantity"),
                manage_stock=arguments.get("manage_stock"),
                stock_status=arguments.get("stock_status"),
                backorders=arguments.get("backorders"),
                attributes=arguments.get("attributes"),
            )
        elif tool_name == "update_variation":
            res = await wc_client.update_variation(
                product_id=arguments["product_id"],
                variation_id=arguments["variation_id"],
                regular_price=arguments.get("regular_price"),
                sale_price=arguments.get("sale_price"),
                sku=arguments.get("sku"),
                stock_quantity=arguments.get("stock_quantity"),
                manage_stock=arguments.get("manage_stock"),
                stock_status=arguments.get("stock_status"),
                backorders=arguments.get("backorders"),
                attributes=arguments.get("attributes"),
            )
        elif tool_name == "delete_variation":
            res = await wc_client.delete_variation(
                product_id=arguments["product_id"],
                variation_id=arguments["variation_id"],
                force=arguments.get("force", True),
            )
        elif tool_name == "list_categories":
            res = await wc_client.list_categories(
                page=arguments.get("page", 1),
                per_page=min(int(arguments.get("per_page", 10)), 100),
                search=arguments.get("search"),
                parent=arguments.get("parent"),
            )
        elif tool_name == "create_category":
            res = await wc_client.create_category(
                name=arguments["name"],
                slug=arguments.get("slug"),
                parent=arguments.get("parent"),
                description=arguments.get("description", ""),
                image=arguments.get("image"),
            )
        elif tool_name == "update_category":
            res = await wc_client.update_category(
                category_id=arguments["category_id"],
                name=arguments.get("name"),
                slug=arguments.get("slug"),
                parent=arguments.get("parent"),
                description=arguments.get("description"),
                image=arguments.get("image"),
            )
        elif tool_name == "delete_category":
            res = await wc_client.delete_category(
                category_id=arguments["category_id"],
                force=arguments.get("force", True),
            )
        elif tool_name == "batch_update_categories":
            res = await wc_client.batch_update_categories(
                create=arguments.get("create"),
                update=arguments.get("update"),
                delete=arguments.get("delete"),
            )
        elif tool_name == "create_order":
            res = await wc_client.create_order(
                line_items=arguments["line_items"],
                status=arguments.get("status", "pending"),
                customer_id=arguments.get("customer_id"),
                billing=arguments.get("billing"),
                shipping=arguments.get("shipping"),
                customer_note=arguments.get("customer_note"),
            )
        elif tool_name == "update_order_status":
            res = await wc_client.update_order_status(
                order_id=arguments["order_id"],
                status=arguments["status"],
            )
        elif tool_name == "create_refund":
            res = await wc_client.create_refund(
                order_id=arguments["order_id"],
                amount=str(arguments["amount"]),
                reason=arguments.get("reason"),
                api_refund=arguments.get("api_refund", True),
                line_items=arguments.get("line_items"),
                restock_items=arguments.get("restock_items", False),
            )
        else:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: '{tool_name}'."}],
                "isError": True,
            }

        # Attach warnings if any ignored parameters were detected (BUG-3)
        if warnings and isinstance(res, dict):
            res["warnings"] = warnings

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
        return {
            "content": [{"type": "text", "text": f"Unexpected error executing {tool_name}: {str(e)}"}],
            "isError": True,
        }
