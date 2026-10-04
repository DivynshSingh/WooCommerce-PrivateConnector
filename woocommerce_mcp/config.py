import os
import json
from dataclasses import dataclass, field
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
    oauth_auth_server_url: str = ""
    oauth_jwks_url: str = ""
    oauth_audience: str = ""
    oauth_issuer: str = ""
    oauth_resource_server_url: str = ""
    jwks_cache_ttl_seconds: int = 300
    rate_limit_max_requests: int = 50
    rate_limit_window_seconds: int = 10
    unauth_rate_limit_max_requests: int = 20
    unauth_rate_limit_window_seconds: int = 60
    wc_max_retries: int = 3
    wc_timeout_seconds: float = 15.0
    auth0_m2m_client_id: str = ""
    auth0_m2m_client_secret: str = ""

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

        # OAuth 2.1 Configuration (Auth0 with RFC 7591 Dynamic Client Registration)
        oauth_auth_server_url = (
            os.environ.get("OAUTH_AUTH_SERVER_URL", "").strip().rstrip("/")
            or "https://woocommerce-mcp-server.us.auth0.com"
        )
        oauth_jwks_url = (
            os.environ.get("OAUTH_JWKS_URL", "").strip()
            or f"{oauth_auth_server_url}/.well-known/jwks.json"
        )
        oauth_audience = (
            os.environ.get("OAUTH_AUDIENCE", "").strip()
            or "https://woocommerce-mcp-server.woocommerce-connector.workers.dev"
        )
        oauth_issuer = (
            os.environ.get("OAUTH_ISSUER", "").strip().rstrip("/")
            or oauth_auth_server_url
        )
        if not oauth_issuer.endswith("/"):
            oauth_issuer += "/"
        oauth_resource_url = (
            os.environ.get("OAUTH_RESOURCE_SERVER_URL", "").strip().rstrip("/")
            or os.environ.get("RESOURCE_SERVER_URL", "").strip().rstrip("/")
        )

        auth0_m2m_client_id = (
            os.environ.get("AUTH0_M2M_CLIENT_ID", "").strip()
            or os.environ.get("AUTH0_CLIENT_ID", "").strip()
            or os.environ.get("AUTH0_MGMT_CLIENT_ID", "").strip()
        )
        auth0_m2m_client_secret = (
            os.environ.get("AUTH0_M2M_CLIENT_SECRET", "").strip()
            or os.environ.get("AUTH0_CLIENT_SECRET", "").strip()
            or os.environ.get("AUTH0_MGMT_CLIENT_SECRET", "").strip()
        )

        try:
            jwks_ttl = int(os.environ.get("OAUTH_JWKS_CACHE_TTL_SECONDS", "300"))
        except ValueError:
            jwks_ttl = 300

        try:
            rate_limit_max = int(os.environ.get("MCP_RATE_LIMIT_MAX_REQUESTS", "50"))
        except ValueError:
            rate_limit_max = 50

        try:
            rate_limit_window = int(os.environ.get("MCP_RATE_LIMIT_WINDOW_SECONDS", "10"))
        except ValueError:
            rate_limit_window = 10

        try:
            unauth_rate_limit_max = int(os.environ.get("UNAUTH_RATE_LIMIT_MAX_REQUESTS", "20"))
        except ValueError:
            unauth_rate_limit_max = 20

        try:
            unauth_rate_limit_window = int(os.environ.get("UNAUTH_RATE_LIMIT_WINDOW_SECONDS", "60"))
        except ValueError:
            unauth_rate_limit_window = 60

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
            oauth_auth_server_url=oauth_auth_server_url,
            oauth_jwks_url=oauth_jwks_url,
            oauth_audience=oauth_audience,
            oauth_issuer=oauth_issuer,
            oauth_resource_server_url=oauth_resource_url,
            jwks_cache_ttl_seconds=jwks_ttl,
            rate_limit_max_requests=rate_limit_max,
            rate_limit_window_seconds=rate_limit_window,
            unauth_rate_limit_max_requests=unauth_rate_limit_max,
            unauth_rate_limit_window_seconds=unauth_rate_limit_window,
            wc_max_retries=wc_max_retries,
            wc_timeout_seconds=wc_timeout,
            auth0_m2m_client_id=auth0_m2m_client_id,
            auth0_m2m_client_secret=auth0_m2m_client_secret,
        )
