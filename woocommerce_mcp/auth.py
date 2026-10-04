"""
OAuth 2.1 Stateless JWT Authentication for WooCommerce MCP Server.
Implements RFC 9728 Protected Resource authentication and JWKS signature verification.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("woocommerce_mcp.auth")

# ASN.1 prefix for SHA-256 in PKCS#1 v1.5 padding (RFC 8017 / RFC 3447)
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def b64url_decode(s: str) -> bytes:
    """Decode base64url string with missing padding handling."""
    s = s.strip()
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def b64url_encode(b: bytes) -> str:
    """Encode bytes into base64url string without trailing equals."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# NIST P-256 (secp256r1) curve constants for ES256 verification
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _mod_inv(k: int, m: int = _P256_P) -> int:
    return pow(k, m - 2, m)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        l = (3 * x1 * x1 + _P256_A) * _mod_inv(2 * y1, _P256_P) % _P256_P
    else:
        l = (y2 - y1) * _mod_inv(x2 - x1, _P256_P) % _P256_P
    x3 = (l * l - x1 - x2) % _P256_P
    y3 = (l * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _ec_mul(k: int, point):
    res = None
    cur = point
    while k > 0:
        if k & 1:
            res = _ec_add(res, cur)
        cur = _ec_add(cur, cur)
        k >>= 1
    return res


def verify_es256(signing_input: bytes, sig_bytes: bytes, qx_bytes: bytes, qy_bytes: bytes) -> bool:
    """
    Stateless ECDSA P-256 SHA-256 signature verification in standard Python.
    Used for Supabase Auth, Auth0, and modern OAuth 2.1 IdPs with EC ES256 keys.
    """
    try:
        if len(sig_bytes) != 64:
            return False
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        if not (1 <= r < _P256_N and 1 <= s < _P256_N):
            return False

        qx = int.from_bytes(qx_bytes, "big")
        qy = int.from_bytes(qy_bytes, "big")

        e = int.from_bytes(hashlib.sha256(signing_input).digest(), "big")
        w = pow(s, _P256_N - 2, _P256_N)
        u1 = (e * w) % _P256_N
        u2 = (r * w) % _P256_N

        p1 = _ec_mul(u1, (_P256_GX, _P256_GY))
        p2 = _ec_mul(u2, (qx, qy))
        res_pt = _ec_add(p1, p2)
        if res_pt is None:
            return False
        return (res_pt[0] % _P256_N) == r
    except Exception as exc:
        logger.debug("ES256 verification exception: %s", exc)
        return False


def verify_rs256(signing_input: bytes, sig_bytes: bytes, n_bytes: bytes, e_bytes: bytes) -> bool:
    """
    Stateless RSA PKCS#1 v1.5 SHA-256 signature verification in standard Python.
    Uses pow(sig, e, n) for high-speed, zero-dependency validation in Pyodide/Cloudflare Workers.
    """
    try:
        n_int = int.from_bytes(n_bytes, "big")
        e_int = int.from_bytes(e_bytes, "big")
        sig_int = int.from_bytes(sig_bytes, "big")
        k_len = len(n_bytes)

        # RSA decrypt signature
        decrypted_int = pow(sig_int, e_int, n_int)
        decrypted_bytes = decrypted_int.to_bytes(k_len, "big")

        # Compute SHA-256 of header.payload
        h = hashlib.sha256(signing_input).digest()
        t = SHA256_DIGEST_INFO + h

        # Build expected PKCS#1 v1.5 padding: 0x00 0x01 [0xFF...] 0x00 [DigestInfo]
        expected_padding = b"\x00\x01" + (b"\xff" * (k_len - len(t) - 3)) + b"\x00" + t
        return hmac.compare_digest(decrypted_bytes, expected_padding)
    except Exception as exc:
        logger.debug("RSA verification exception: %s", exc)
        return False


def verify_hs256(signing_input: bytes, sig_bytes: bytes, key_bytes: bytes) -> bool:
    """Verify HMAC-SHA256 signature for symmetric keys (used in mock/test setups)."""
    try:
        expected = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
        return hmac.compare_digest(sig_bytes, expected)
    except Exception:
        return False


class JWKSManager:
    """
    Manages fetching and in-memory caching of the IdP's JSON Web Key Set (JWKS).
    Avoids spamming the IdP on every request.
    """

    def __init__(self, jwks_url: str = "", cache_ttl_seconds: int = 300):
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl_seconds
        self._cached_jwks: Optional[Dict[str, Any]] = None
        self._cached_at: float = 0.0

    def get_cached_jwks(self) -> Optional[Dict[str, Any]]:
        """Return cached JWKS if not expired."""
        if self._cached_jwks and (time.time() - self._cached_at) < self.cache_ttl:
            return self._cached_jwks
        return None

    def set_cached_jwks(self, jwks: Dict[str, Any]) -> None:
        """Cache JWKS in memory."""
        self._cached_jwks = jwks
        self._cached_at = time.time()

    async def fetch_jwks_async(self, jwks_url: Optional[str] = None) -> Dict[str, Any]:
        """Fetch JWKS asynchronously with Cloudflare Worker JS fetch support."""
        cached = self.get_cached_jwks()
        if cached:
            return cached

        url = (jwks_url or self.jwks_url).strip()
        if not url:
            return {"keys": []}

        # In Cloudflare Worker environment, use js.fetch
        try:
            from js import fetch
            resp = await fetch(url)
            text = await resp.text()
            data = json.loads(str(text))
            if isinstance(data, dict) and "keys" in data:
                self.set_cached_jwks(data)
                return data
        except Exception:
            pass

        return self.fetch_jwks_sync(url)

    def fetch_jwks_sync(self, jwks_url: Optional[str] = None) -> Dict[str, Any]:
        """Fetch JWKS synchronously via urllib.request with caching."""
        cached = self.get_cached_jwks()
        if cached:
            return cached

        url = (jwks_url or self.jwks_url).strip()
        if not url:
            return {"keys": []}

        try:
            import urllib.request
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "WooCommerce-MCP-ResourceServer/1.0",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, dict) and "keys" in data:
                    self.set_cached_jwks(data)
                    return data
        except Exception as exc:
            logger.error("Failed to fetch JWKS from %s: %s", url, exc)

        return {"keys": []}


class Authenticator:
    """
    OAuth 2.1 Resource Server Authenticator.
    Validates incoming Bearer JWT tokens against the IdP's public JWKS.
    """

    def __init__(
        self,
        jwks_url: str = "",
        auth_server_url: str = "",
        expected_issuer: str = "",
        expected_audience: str = "",
        cache_ttl_seconds: int = 300,
        static_keys: Optional[List[Dict[str, Any]]] = None,
    ):
        self.jwks_url = jwks_url.strip()
        self.auth_server_url = auth_server_url.strip()
        self.expected_issuer = expected_issuer.strip()
        self.expected_audience = expected_audience.strip()
        self.jwks_manager = JWKSManager(self.jwks_url, cache_ttl_seconds=cache_ttl_seconds)

        if static_keys:
            self.jwks_manager.set_cached_jwks({"keys": static_keys})

    @property
    def is_auth_required(self) -> bool:
        """Resource Server always requires OAuth 2.1 authentication when configured."""
        return bool(self.jwks_url or self.auth_server_url or self.jwks_manager._cached_jwks)

    def extract_token_from_headers(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract JWT exclusively from Authorization: Bearer <token> per OAuth 2.1."""
        norm_headers = {k.lower(): str(v) for k, v in headers.items()}
        auth_val = norm_headers.get("authorization", "").strip()
        if auth_val:
            parts = auth_val.split(" ", 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                return parts[1].strip()
        return None

    def verify_jwt(
        self, token: str, jwks: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[Dict[str, Any]]]:
        """
        Stateless JWT verification:
        1. Validates structure (header.payload.signature)
        2. Validates expiration (exp) and not-before (nbf)
        3. Validates issuer (iss) and audience (aud) if configured
        4. Matches key in JWKS and verifies cryptographic signature

        Returns:
            (is_valid: bool, client_identifier: Optional[str], error_message: Optional[str], claims: Optional[dict])
        """
        parts = token.strip().split(".")
        if len(parts) != 3:
            return False, None, "Invalid JWT format. Must contain 3 period-separated segments.", None

        # 1. Parse header
        try:
            header_bytes = b64url_decode(parts[0])
            header = json.loads(header_bytes.decode("utf-8"))
        except Exception:
            return False, None, "Failed to decode JWT header.", None

        # 2. Parse payload
        try:
            payload_bytes = b64url_decode(parts[1])
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return False, None, "Failed to decode JWT payload.", None

        # 3. Check expiration (exp) and not before (nbf)
        now = time.time()
        if "exp" in payload:
            try:
                exp_ts = float(payload["exp"])
                if now > exp_ts:
                    return False, None, "Token has expired.", payload
            except (ValueError, TypeError):
                return False, None, "Malformed 'exp' claim in JWT.", payload

        if "nbf" in payload:
            try:
                nbf_ts = float(payload["nbf"])
                if now < nbf_ts:
                    return False, None, "Token is not yet active (nbf).", payload
            except (ValueError, TypeError):
                return False, None, "Malformed 'nbf' claim in JWT.", payload

        # 4. Check issuer if configured
        if self.expected_issuer:
            token_iss = payload.get("iss", "").rstrip("/")
            expected_iss = self.expected_issuer.rstrip("/")
            if token_iss != expected_iss:
                return (
                    False,
                    None,
                    f"Token issuer mismatch: expected '{self.expected_issuer}', got '{payload.get('iss')}'.",
                    payload,
                )

        # 5. Check audience if configured
        if self.expected_audience:
            token_aud = payload.get("aud")
            aud_valid = False
            if isinstance(token_aud, list):
                aud_valid = self.expected_audience in token_aud
            elif isinstance(token_aud, str):
                aud_valid = token_aud == self.expected_audience
            if not aud_valid:
                return (
                    False,
                    None,
                    f"Token audience mismatch: expected '{self.expected_audience}'.",
                    payload,
                )

        # 6. Cryptographic signature verification against JWKS
        alg = header.get("alg", "RS256").upper()
        kid = header.get("kid")
        keys = jwks.get("keys", [])

        if not keys:
            return False, None, "No public keys available in JWKS to verify token.", payload

        # Find matching key by kid, or fallback to first compatible key
        matching_key = None
        if kid:
            for k in keys:
                if k.get("kid") == kid:
                    matching_key = k
                    break

        if not matching_key and len(keys) == 1:
            matching_key = keys[0]

        if not matching_key:
            return False, None, f"No matching public key found in JWKS for kid '{kid}'.", payload

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        try:
            sig_bytes = b64url_decode(parts[2])
        except Exception:
            return False, None, "Failed to decode JWT signature.", payload

        sig_valid = False
        kty = matching_key.get("kty", "").upper()

        if (alg == "ES256" or kty == "EC") and kty in ("EC", "OKP"):
            x_val = matching_key.get("x")
            y_val = matching_key.get("y")
            if not x_val or not y_val:
                return False, None, "JWK is missing EC coordinates 'x' or 'y'.", payload
            qx_bytes = b64url_decode(x_val)
            qy_bytes = b64url_decode(y_val)
            sig_valid = verify_es256(signing_input, sig_bytes, qx_bytes, qy_bytes)

        elif alg == "RS256" and kty == "RSA":
            n_val = matching_key.get("n")
            e_val = matching_key.get("e", "AQAB")
            if not n_val:
                return False, None, "JWK is missing RSA modulus 'n'.", payload
            n_bytes = b64url_decode(n_val)
            e_bytes = b64url_decode(e_val)
            sig_valid = verify_rs256(signing_input, sig_bytes, n_bytes, e_bytes)

        elif alg == "HS256" and kty in ("OCT", "OCTET"):
            k_val = matching_key.get("k", "")
            if not k_val:
                return False, None, "JWK is missing symmetric key 'k'.", payload
            key_bytes = b64url_decode(k_val)
            sig_valid = verify_hs256(signing_input, sig_bytes, key_bytes)

        else:
            return False, None, f"Unsupported key/algorithm combination: kty={kty}, alg={alg}.", payload

        if not sig_valid:
            return False, None, "Invalid JWT signature.", payload

        # Derive opaque client/subject identifier for rate limiting
        sub = payload.get("sub") or payload.get("client_id") or payload.get("azp") or "oauth_client"
        client_id = f"oauth-{hashlib.sha256(str(sub).encode('utf-8')).hexdigest()[:12]}"
        return True, client_id, None, payload

    def _needs_jwks_refresh(self, token: str) -> bool:
        """Check if token kid is missing from currently cached JWKS (key rotation)."""
        if not self.jwks_url:
            return False
        cached = self.jwks_manager.get_cached_jwks()
        if not cached:
            return True
        try:
            parts = token.strip().split(".")
            header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
            kid = header.get("kid")
            if not kid:
                return False
            cached_kids = {k.get("kid") for k in cached.get("keys", [])}
            return kid not in cached_kids
        except Exception:
            return False

    async def authenticate_request_async(
        self, headers: Dict[str, str], query_token: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Asynchronously validate incoming request using cached/fetched JWKS."""
        token = self.extract_token_from_headers(headers)
        if not token and query_token:
            token = query_token.strip()

        if not token:
            return False, None, "Missing Bearer token in Authorization header."

        jwks = await self.jwks_manager.fetch_jwks_async()
        is_valid, client_id, err, _ = self.verify_jwt(token, jwks)

        # Only refresh JWKS if key ID is unknown (to handle IdP key rotation)
        if not is_valid and self._needs_jwks_refresh(token):
            self.jwks_manager._cached_jwks = None
            jwks = await self.jwks_manager.fetch_jwks_async()
            is_valid, client_id, err, _ = self.verify_jwt(token, jwks)

        return is_valid, client_id, err

    def authenticate_request(
        self, headers: Dict[str, str], query_token: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Synchronously validate incoming request using cached JWKS."""
        token = self.extract_token_from_headers(headers)
        if not token and query_token:
            token = query_token.strip()

        if not token:
            return False, None, "Missing Bearer token in Authorization header."

        jwks = self.jwks_manager.fetch_jwks_sync()
        is_valid, client_id, err, _ = self.verify_jwt(token, jwks)

        # Only refresh JWKS if key ID is unknown (to handle IdP key rotation)
        if not is_valid and self._needs_jwks_refresh(token):
            self.jwks_manager._cached_jwks = None
            jwks = self.jwks_manager.fetch_jwks_sync()
            is_valid, client_id, err, _ = self.verify_jwt(token, jwks)

        return is_valid, client_id, err
