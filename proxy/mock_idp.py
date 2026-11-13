#!/usr/bin/env python3
"""
Mock CIAM IdP for the Token Federation PoC.

Stands in for the customer's real Customer Identity Access Management
provider (Auth0, Okta CIC, AWS Cognito, Azure AD B2C, etc.) Provides
the three OIDC primitives Databricks needs to validate JWTs:

  - /.well-known/openid-configuration  → OIDC discovery
  - /.well-known/jwks.json             → JSON Web Key Set (public RSA key)
  - /mint?user=<email>                 → returns a freshly signed JWT

The /mint endpoint takes the place of a real interactive OAuth flow.
In production this is never exposed — the user gets their JWT by
authenticating through their CIAM's standard login.

JWT signing: RS256 (RSA 2048). Token claims include iss / aud / sub /
email / upn / iat / nbf / exp — adjust as needed for your federation
policy's `subject_claim`.

Environment / CLI:
  --port <int>      port to listen on (default 8080)
  --issuer <url>    public issuer URL written into the JWTs and the
                    discovery doc. Must match what Databricks fetches.
                    Default: http://localhost:<port> (only useful locally).
  --audience <str>  audience claim (default "databricks")
"""

import argparse
import base64
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
KEY_PATH = os.path.join(KEY_DIR, "rsa_key.pem")
KID = "mock-idp-key-1"


def _load_or_create_key():
    os.makedirs(KEY_DIR, exist_ok=True)
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend(),
            )
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend(),
    )
    with open(KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"Generated new RSA key at {KEY_PATH}")
    return key


PRIVATE_KEY = _load_or_create_key()
PUBLIC_KEY = PRIVATE_KEY.public_key()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_b64url(n: int) -> str:
    return _b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def make_jwks() -> dict:
    pub = PUBLIC_KEY.public_numbers()
    return {
        "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
            "n": _int_to_b64url(pub.n),
            "e": _int_to_b64url(pub.e),
        }]
    }


def mint_jwt(issuer: str, audience: str, user_email: str, ttl_seconds: int = 3600) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": user_email,
        "email": user_email,
        "upn": user_email,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
    }
    enc_h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    enc_c = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig_input = f"{enc_h}.{enc_c}".encode()
    signature = PRIVATE_KEY.sign(sig_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{enc_h}.{enc_c}.{_b64url(signature)}"


class Handler(BaseHTTPRequestHandler):
    issuer: str = ""
    audience: str = ""

    def _json(self, code: int, payload: dict):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)

        if path == "/":
            return self._json(200, {
                "name": "Mock CIAM IdP",
                "issuer": Handler.issuer,
                "audience": Handler.audience,
                "endpoints": {
                    "discovery": f"{Handler.issuer}/.well-known/openid-configuration",
                    "jwks":      f"{Handler.issuer}/.well-known/jwks.json",
                    "mint":      f"{Handler.issuer}/mint?user=<email>",
                },
            })

        if path == "/.well-known/openid-configuration":
            return self._json(200, {
                "issuer": Handler.issuer,
                "jwks_uri": f"{Handler.issuer}/.well-known/jwks.json",
                "id_token_signing_alg_values_supported": ["RS256"],
                "subject_types_supported": ["public"],
                "response_types_supported": ["id_token"],
            })

        if path == "/.well-known/jwks.json":
            return self._json(200, make_jwks())

        if path == "/mint":
            user = qs.get("user", [None])[0]
            if not user:
                return self._json(400, {"error": "missing ?user=<email>"})
            ttl = int(qs.get("ttl", ["3600"])[0])
            token = mint_jwt(Handler.issuer, Handler.audience, user, ttl)
            return self._json(200, {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": ttl,
                "user": user,
            })

        self._json(404, {"error": "not found"})

    def do_POST(self):
        return self.do_GET()

    def log_message(self, fmt: str, *args):
        print(f"[mock-idp] {self.address_string()} {fmt % args}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=int(os.environ.get("MOCK_IDP_PORT", 8080)))
    p.add_argument("--issuer", default=os.environ.get("MOCK_IDP_ISSUER", ""))
    p.add_argument("--audience", default=os.environ.get("MOCK_IDP_AUDIENCE", "databricks"))
    args = p.parse_args()

    Handler.issuer = args.issuer or f"http://localhost:{args.port}"
    Handler.audience = args.audience

    print(f"Mock CIAM IdP listening on port {args.port}")
    print(f"  issuer:   {Handler.issuer}")
    print(f"  audience: {Handler.audience}")
    print(f"  discovery: {Handler.issuer}/.well-known/openid-configuration")
    print(f"  jwks:      {Handler.issuer}/.well-known/jwks.json")
    print(f"  mint:      {Handler.issuer}/mint?user=<email>")
    print()
    HTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
