import hashlib
import hmac
from typing import Optional, Tuple, Dict, Any, List


class Authenticator:
    """
    Validates MCP client authentication tokens and extracts client identities.
    """

    def __init__(self, allowed_tokens: List[str]):
        self.allowed_tokens = set(t.strip() for t in allowed_tokens if t.strip())

    @property
    def is_auth_required(self) -> bool:
        return len(self.allowed_tokens) > 0

    def extract_token_from_headers(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract token from Authorization (Bearer) or X-API-Key headers (case-insensitive)."""
        # Normalize header keys to lowercase
        norm_headers = {k.lower(): v for k, v in headers.items()}

        auth_val = norm_headers.get("authorization", "")
        if auth_val:
            parts = auth_val.strip().split(" ", 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                return parts[1].strip()
            # If plain token was provided
            if len(parts) == 1:
                return parts[0].strip()

        api_key = norm_headers.get("x-api-key", "")
        if api_key:
            return api_key.strip()

        return None

    def authenticate_request(
        self, headers: Dict[str, str], query_token: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validates request authentication.
        Returns:
            (is_authenticated: bool, client_identifier: Optional[str], error_message: Optional[str])
        """
        # If no tokens are configured, warn that server requires setup
        if not self.allowed_tokens:
            return False, None, "MCP server authentication is not configured. Set MCP_AUTH_TOKEN in environment."

        token = self.extract_token_from_headers(headers)
        if not token and query_token:
            token = query_token.strip()

        if not token:
            return False, None, "Missing authentication credential. Provide 'Authorization: Bearer <token>' or 'X-API-Key'."

        # Constant-time comparison to prevent timing attacks
        for allowed in self.allowed_tokens:
            if hmac.compare_digest(token, allowed):
                # Derive an opaque client identifier for rate-limiting (never exposes raw token)
                client_id = f"client-{hashlib.sha256(token.encode()).hexdigest()[:12]}"
                return True, client_id, None

        return False, None, "Invalid authentication credential."
