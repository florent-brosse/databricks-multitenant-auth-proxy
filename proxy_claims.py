#!/usr/bin/env python3
"""
Transparent auth proxy for multi-tenant apps on Databricks, using OAuth custom identity claims.

Who the Databricks token belongs to:

  before: CIAM JWT --RFC 8693--> token of a Databricks USER (1 user per end user, SCIM)
  now:    CIAM JWT --validated by the proxy--> token of ONE service principal
          carrying custom_claim=<end user id>, read in SQL with
          current_oauth_custom_identity_claim()

Because the proxy now chooses the claim, it MUST validate the CIAM JWT itself
(signature against the CIAM JWKS, iss, aud, exp). Databricks signs whatever
claim the proxy asks for.

The proxy still does NOT parse the request path, body, or content type.

Environment variables:
  TFP_PORT            port to listen on (default 9443)
  TFP_DBX_WORKSPACE   https://<workspace>
  TFP_SP_CLIENT_ID    application id of the shared service principal
  TFP_SP_SECRET       its OAuth secret (prod: secret manager, or replace the
                      client_credentials call by a token exchange of the
                      proxy's own workload identity token)
  CIAM_ISSUER         expected iss (JWKS read from <iss>/.well-known/jwks.json)
  CIAM_AUDIENCE       expected aud
  CIAM_USER_CLAIM     JWT claim that identifies the end user (default "sub")
  TFP_TLS_CERT/KEY    optional, serve HTTPS directly (Thrift clients need TLS)
"""

import base64
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt  # PyJWT[crypto]

PORT = int(os.environ.get("TFP_PORT", "9443"))
DBX_WORKSPACE = os.environ["TFP_DBX_WORKSPACE"].rstrip("/")
SP_CLIENT_ID = os.environ["TFP_SP_CLIENT_ID"]
SP_SECRET = os.environ["TFP_SP_SECRET"]
CIAM_ISSUER = os.environ["CIAM_ISSUER"].rstrip("/")
CIAM_AUDIENCE = os.environ["CIAM_AUDIENCE"]
CIAM_USER_CLAIM = os.environ.get("CIAM_USER_CLAIM", "sub")

_jwks = jwt.PyJWKClient(f"{CIAM_ISSUER}/.well-known/jwks.json", cache_keys=True)

# The claim ends up in an HTTP header and in SQL comparisons. Observed on
# DBSQL 2026.45: non-ASCII is turned into '?', empty/blank claims are accepted
# and read as '' (not NULL), control chars make every query fail. So we only
# allow a plain ASCII identifier and refuse everything else at the edge.
_CLAIM_OK = re.compile(r"^[A-Za-z0-9._@+\-|:]{1,256}$")


class AuthError(Exception):
    pass


def validate_ciam_jwt(token: str) -> str:
    """Return the end-user id from a valid CIAM JWT, or raise AuthError."""
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token, key, algorithms=["RS256"], audience=CIAM_AUDIENCE,
            issuer=CIAM_ISSUER, options={"require": ["exp", "iss", "aud", CIAM_USER_CLAIM]},
        )
    except Exception as e:  # bad signature, expired, wrong iss/aud, unknown kid...
        raise AuthError(f"invalid CIAM JWT: {type(e).__name__}: {e}")
    user_id = str(payload[CIAM_USER_CLAIM])
    if not _CLAIM_OK.match(user_id):
        raise AuthError(f"user id not usable as a claim: {user_id!r}")
    return user_id


# {end user id -> (DBX token, expiry)}. Keyed by user, not by JWT: a user who
# refreshes his CIAM JWT keeps the same Databricks token until it expires.
_CACHE: dict[str, tuple[str, float]] = {}
_LOCK = threading.Lock()


def dbx_token_for(user_id: str) -> str:
    now = time.time()
    with _LOCK:
        hit = _CACHE.get(user_id)
        if hit and hit[1] > now + 60:
            return hit[0]
    form = urllib.parse.urlencode({
        "grant_type": "client_credentials", "scope": "all-apis", "custom_claim": user_id,
    }).encode()
    req = urllib.request.Request(f"{DBX_WORKSPACE}/oidc/v1/token", data=form, method="POST")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{SP_CLIENT_ID}:{SP_SECRET}".encode()).decode())
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.loads(r.read())
    with _LOCK:
        _CACHE[user_id] = (d["access_token"], now + int(d.get("expires_in", 3600)))
    return d["access_token"]


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, needed for Thrift (ODBC/JDBC)

    def _send(self, code, body, ct="application/json"):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ciam_jwt(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        if auth.startswith("Basic "):  # Simba ODBC: user "token", pwd = JWT
            try:
                return base64.b64decode(auth[6:].strip()).decode().split(":", 1)[1]
            except Exception:
                return None
        return None

    def _forward(self, method, body):
        token = self._ciam_jwt()
        if not token:
            return self._send(401, '{"error_code":"MISSING_TOKEN"}')
        try:
            user_id = validate_ciam_jwt(token)
        except AuthError as e:
            print(f"[proxy] REJECT {method} {self.path}: {e}", flush=True)
            return self._send(401, json.dumps({"error_code": "INVALID_CIAM_TOKEN", "message": str(e)}))
        try:
            dbx = dbx_token_for(user_id)
        except Exception as e:
            return self._send(502, json.dumps({"error_code": "TOKEN_MINT_FAILED", "message": str(e)[:300]}))

        # Audit: Databricks query history shows the SP, so the proxy records
        # which end user sent which request.
        print(f"[audit] user={user_id} {method} {self.path}", flush=True)

        req = urllib.request.Request(f"{DBX_WORKSPACE}{self.path}", data=body, method=method)
        req.add_header("Authorization", f"Bearer {dbx}")
        for k, v in self.headers.items():
            if k.lower() not in {"authorization", "host", "content-length", "connection"}:
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                self._send(r.status, r.read(), r.headers.get("Content-Type", "application/json"))
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read(), e.headers.get("Content-Type", "application/json"))
        except urllib.error.URLError as e:
            self._send(502, json.dumps({"error_code": "UPSTREAM_UNREACHABLE", "message": str(e.reason)}))

    def _body(self):
        n = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(n) if n else None

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/healthz":
            return self._send(200, '{"status":"ok"}')
        self._forward("GET", None)

    def do_POST(self): self._forward("POST", self._body())
    def do_PUT(self): self._forward("PUT", self._body())
    def do_PATCH(self): self._forward("PATCH", self._body())
    def do_DELETE(self): self._forward("DELETE", None)

    def log_message(self, fmt, *args):
        pass  # the [audit] line above is enough


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), ProxyHandler)
    cert, key = os.environ.get("TFP_TLS_CERT"), os.environ.get("TFP_TLS_KEY")
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"claims proxy on {'https' if cert else 'http'}://0.0.0.0:{PORT} -> {DBX_WORKSPACE} as SP {SP_CLIENT_ID}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
