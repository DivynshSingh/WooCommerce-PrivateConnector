import os
import json
from dataclasses import dataclass
from typing import List, Optional


def load_env_file(filepath: str = ".env") -> None:
    """Simple .env file parser so zero external dependencies are required."""
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


@dataclass
class ServerConfig:
    store_url: str
    consumer_key: str
    consumer_secret: str
    valid_auth_tokens: List[str]
    rate_limit_max_requests: int = 50
    rate_limit_window_seconds: int = 10
    wc_max_retries: int = 3
    wc_timeout_seconds: float = 15.0

    @property
    def has_woocommerce_credentials(self) -> bool:
        return bool(self.store_url and self.consumer_key and self.consumer_secret)

    @classmethod
    def from_env(cls) -> "ServerConfig":
        # Load local .env if present
        load_env_file(".env")

        store_url = os.environ.get("WOOCOMMERCE_STORE_URL", "").strip().rstrip("/")
        consumer_key = os.environ.get("WOOCOMMERCE_CONSUMER_KEY", "").strip()
        consumer_secret = os.environ.get("WOOCOMMERCE_CONSUMER_SECRET", "").strip()

        # Parse MCP client auth tokens
        tokens: List[str] = []
        raw_mcp_auth = os.environ.get("MCP_AUTH_CONFIGURATION", "").strip()
        single_token = os.environ.get("MCP_AUTH_TOKEN", "").strip()

        if raw_mcp_auth:
            try:
                parsed = json.loads(raw_mcp_auth)
                if isinstance(parsed, list):
                    tokens.extend([str(t).strip() for t in parsed if str(t).strip()])
                elif isinstance(parsed, dict):
                    if "tokens" in parsed and isinstance(parsed["tokens"], list):
                        tokens.extend([str(t).strip() for t in parsed["tokens"]])
                    else:
                        tokens.extend([str(v).strip() for v in parsed.values() if str(v).strip()])
            except json.JSONDecodeError:
                tokens.extend([t.strip() for t in raw_mcp_auth.split(",") if t.strip()])

        if single_token and single_token not in tokens:
            tokens.append(single_token)

        try:
            rate_limit_max = int(os.environ.get("MCP_RATE_LIMIT_MAX_REQUESTS", "50"))
        except ValueError:
            rate_limit_max = 50

        try:
            rate_limit_window = int(os.environ.get("MCP_RATE_LIMIT_WINDOW_SECONDS", "10"))
        except ValueError:
            rate_limit_window = 10

        try:
            wc_max_retries = int(os.environ.get("WOOCOMMERCE_MAX_RETRIES", "3"))
        except ValueError:
            wc_max_retries = 3

        try:
            wc_timeout = float(os.environ.get("WOOCOMMERCE_TIMEOUT_SECONDS", "15.0"))
        except ValueError:
            wc_timeout = 15.0

        return cls(
            store_url=store_url,
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            valid_auth_tokens=tokens,
            rate_limit_max_requests=rate_limit_max,
            rate_limit_window_seconds=rate_limit_window,
            wc_max_retries=wc_max_retries,
            wc_timeout_seconds=wc_timeout,
        )
