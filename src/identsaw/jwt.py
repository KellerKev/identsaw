"""Self-contained HS256 JWT (no external deps) — sign and verify session/API
tokens. Mirrors sqladal's helper so identsaw's core needs nothing but stdlib."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _key(secret) -> bytes:
    return secret if isinstance(secret, bytes) else str(secret).encode("utf-8")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict, secret, *, exp=None, now=None) -> str:
    """Encode an HS256 JWT. ``exp`` = seconds-from-now TTL."""
    body = dict(payload)
    if exp is not None:
        body["exp"] = int((time.time() if now is None else now) + exp)
    segs = [_b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()),
            _b64u(json.dumps(body, separators=(",", ":")).encode())]
    sig = hmac.new(_key(secret), ".".join(segs).encode("ascii"), hashlib.sha256).digest()
    return ".".join(segs) + "." + _b64u(sig)


def jwt_decode(token: str, secret, *, verify_exp: bool = True, now=None) -> dict:
    """Verify + decode an HS256 JWT; raise ``ValueError`` if invalid/expired."""
    try:
        h, p, s = token.split(".")
    except ValueError:
        raise ValueError("malformed token")
    good = _b64u(hmac.new(_key(secret), ("%s.%s" % (h, p)).encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(s, good):
        raise ValueError("bad signature")
    payload = json.loads(_b64u_dec(p))
    if verify_exp and "exp" in payload:
        if (time.time() if now is None else now) > payload["exp"]:
            raise ValueError("token expired")
    return payload


__all__ = ["jwt_encode", "jwt_decode"]
