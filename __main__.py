import argparse
import logging
import sys

from .config import ServerConfig
from .server import run_http_server, run_stdio_server


def main():
    parser = argparse.ArgumentParser(description="WooCommerce MCP Server")
    parser.add_argument("--stdio", action="store_true", help="Run in stdio mode for Claude Desktop / CLI clients")
    parser.add_argument("--port", type=int, default=None, help="Port to listen on in HTTP mode")
    parser.add_argument("--host", type=str, default=None, help="Host to bind in HTTP mode")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    config = ServerConfig.from_env()

    if args.stdio:
        run_stdio_server(config)
    else:
        run_http_server(config, host=args.host or "0.0.0.0", port=args.port or 3000)


if __name__ == "__main__":
    main()
