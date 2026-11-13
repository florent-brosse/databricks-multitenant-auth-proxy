#!/usr/bin/env python3
"""
Token Federation Proxy — a transparent HTTP forwarder.

Listens on PORT, accepts any HTTP request, swaps the Authorization header
from a CIAM JWT to a Databricks OAuth token (via RFC 8693 token exchange),
then forwards the request verbatim to the configured Databricks workspace.

The proxy:
  - does NOT parse the request path, body, or content type
  - does NOT validate the JWT signature (Databricks does that against the
    federation policy + JWKS, returning an error — observed 4xx/5xx — if
    the token is invalid; the proxy maps any exchange failure to 401)
  - only swaps the Authorization header
  - caches the exchanged DBX token (per CIAM JWT) for 5 minutes to avoid
    one /oidc/v1/token call per upstream request

Supported auth schemes on the way in:
  - Authorization: Bearer <CIAM JWT>
  - Authorization: Basic base64(token:<CIAM JWT>)  (used by Simba ODBC / Thrift)

Environment variables:
  TFP_PORT             port to listen on (default 9090)
  TFP_DBX_WORKSPACE    base URL of the target Databricks workspace
                       (default: must be set; no sensible default)
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

PORT = int(os.environ.get("TFP_PORT", "9090"))
DBX_WORKSPACE = os.environ.get("TFP_DBX_WORKSPACE", "").rstrip("/")
if not DBX_WORKSPACE:
    sys.exit("TFP_DBX_WORKSPACE is required (e.g. https://your.cloud.databricks.com)")


# ---------------------------------------------------------------------------
# Token cache
# ---------------------------------------------------------------------------

# {CIAM JWT  →  (DBX token, expiry_unix_seconds)}
_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
SAFETY_MARGIN = 30  # seconds


def _exchange_jwt_for_dbx_token(ciam_jwt: str) -> tuple[str, int]:
    """RFC 8693 OAuth Token Exchange."""
    body = urllib.parse.urlencode({
        "subject_token": ciam_jwt,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "scope": "all-apis",
    }).encode()
    req = urllib.request.Request(
        f"{DBX_WORKSPACE}/oidc/v1/token", data=body, method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
    return data["access_token"], int(data.get("expires_in", 3600))


def _get_dbx_token(ciam_jwt: str) -> str:
    now = time.time()
    cached = _TOKEN_CACHE.get(ciam_jwt)
    if cached and cached[1] > now + SAFETY_MARGIN:
        return cached[0]
    # Drop expired entries so the cache doesn't grow unbounded (one entry per
    # distinct JWT seen). Cheap to do on every miss for a PoC-sized cache.
    for jwt, (_tok, exp) in list(_TOKEN_CACHE.items()):
        if exp <= now:
            _TOKEN_CACHE.pop(jwt, None)  # pop() is safe if another thread won the race
    dbx_token, expires_in = _exchange_jwt_for_dbx_token(ciam_jwt)
    _TOKEN_CACHE[ciam_jwt] = (dbx_token, now + expires_in)
    return dbx_token


# ---------------------------------------------------------------------------
# HTTP handler — transparent forwarder
# ---------------------------------------------------------------------------

class ProxyHandler(BaseHTTPRequestHandler):

    # HTTP/1.1 so the client connection stays alive across requests. Thrift
    # (Simba ODBC/JDBC) does many sequential round-trips on one connection —
    # under HTTP/1.0 each would reconnect, which is correct but very slow.
    # Every response sets Content-Length (see _send), so keep-alive is safe.
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, body: bytes | str, content_type: str = "application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _extract_ciam_jwt(self) -> str | None:
        """Pull the CIAM JWT out of either Bearer or Basic auth."""
        auth = self.headers.get("Authorization", "")
        if not auth:
            return None
        if auth.startswith("Bearer "):
            return auth[len("Bearer "):].strip()
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[len("Basic "):].strip()).decode("utf-8")
                # Simba ODBC sends user="token", pwd=<the JWT>
                if ":" in decoded:
                    _user, pwd = decoded.split(":", 1)
                    return pwd
            except Exception:
                return None
        return None

    def _forward(self, method: str, path: str, body: bytes | None):
        ciam_jwt = self._extract_ciam_jwt()
        if not ciam_jwt:
            return self._send(401, json.dumps({
                "error_code": "MISSING_TOKEN",
                "message": "Authorization: Bearer <CIAM JWT>  or  Basic token:<CIAM JWT>  required",
            }))

        try:
            dbx_token = _get_dbx_token(ciam_jwt)
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
            return self._send(401, json.dumps({
                "error_code": "TOKEN_EXCHANGE_FAILED",
                "message": f"Token Federation exchange failed: HTTP {e.code}",
                "upstream": err_body[:500],
            }))
        except Exception as e:
            return self._send(401, json.dumps({
                "error_code": "TOKEN_EXCHANGE_FAILED",
                "message": f"Token Federation exchange failed: {type(e).__name__}: {e}",
            }))

        # Build upstream request. Forward every client header verbatim,
        # except the ones the proxy must own (auth, host, content-length, connection).
        url = f"{DBX_WORKSPACE}{path}"
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Authorization", f"Bearer {dbx_token}")
        skip = {"authorization", "host", "content-length", "connection"}
        for h_name, h_val in self.headers.items():
            if h_name.lower() not in skip:
                req.add_header(h_name, h_val)

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_body = resp.read()
                resp_ct = resp.headers.get("Content-Type", "application/json")
                self._send(resp.status, resp_body, resp_ct)
        except urllib.error.HTTPError as e:
            # Upstream returned a 4xx/5xx — forward it verbatim.
            err_body = e.read()
            err_ct = e.headers.get("Content-Type", "application/json")
            self._send(e.code, err_body, err_ct)
        except urllib.error.URLError as e:
            # Couldn't reach the workspace at all (DNS, connect timeout, TLS).
            self._send(502, json.dumps({
                "error_code": "UPSTREAM_UNREACHABLE",
                "message": f"Could not reach Databricks workspace: {e.reason}",
            }))

    def _is_health(self) -> bool:
        return self.path.split("?", 1)[0] == "/healthz"

    # The proxy is method-agnostic — any verb that hits it is forwarded.
    def do_GET(self):
        # Liveness probe for the container / reverse proxy. Databricks has no
        # /healthz route, so intercepting it can't shadow a real upstream call.
        # Answered locally, without auth or a token exchange.
        if self._is_health():
            return self._send(200, json.dumps({"status": "ok"}))
        self._forward("GET", self.path, None)

    def do_HEAD(self):
        if self._is_health():
            return self._send(200, b"")
        self._forward("HEAD", self.path, None)
    def do_DELETE(self): self._forward("DELETE", self.path, None)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else None
        self._forward("POST", self.path, body)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else None
        self._forward("PUT", self.path, body)

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else None
        self._forward("PATCH", self.path, body)

    def log_message(self, fmt: str, *args):
        # flush so logs appear promptly even when stdout is redirected to a
        # file/pipe (block-buffered) rather than a TTY.
        print(f"[proxy] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    print(f"Token Federation Proxy listening on http://0.0.0.0:{PORT}")
    print(f"  forwarding to: {DBX_WORKSPACE}")
    print(f"  auth: Bearer or Basic('token':<JWT>)")
    print()
    # Threaded so a long-poll request (wait_timeout up to 50s) or a slow
    # client doesn't block every other connection — matters for BI tools
    # that open several connections at once.
    ThreadingHTTPServer(("0.0.0.0", PORT), ProxyHandler).serve_forever()


if __name__ == "__main__":
    main()
