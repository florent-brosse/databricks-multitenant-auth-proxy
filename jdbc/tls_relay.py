#!/usr/bin/env python3
"""Local TLS terminator -> plaintext relay, for testing JDBC/ODBC clients
against the proxy WITHOUT a public HTTPS tunnel.

JDBC/ODBC drivers require TLS. In production the proxy sits behind a real
reverse proxy / managed cert (or a cloudflared tunnel) on 443 — point the
client straight at that and you don't need this. For purely local testing,
this terminates TLS on :9443 with a self-signed cert and forwards raw bytes
to the proxy on :9092. It is protocol-agnostic (a byte pipe), so it preserves
the proxy's own HTTP keep-alive behavior end to end.

Pair with AllowSelfSignedCerts=1 (JDBC) / the equivalent ODBC option.

Env:
  RELAY_PORT     default 9443
  BACKEND_PORT   default 9092
"""
import os
import socket
import ssl
import subprocess
import threading

RELAY_PORT = int(os.environ.get("RELAY_PORT", "9443"))
BACKEND = ("127.0.0.1", int(os.environ.get("BACKEND_PORT", "9092")))
HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "relay_cert.pem")
KEY = os.path.join(HERE, "relay_key.pem")


def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    print("Generating self-signed cert for the relay...")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", KEY,
         "-out", CERT, "-days", "7", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client):
    try:
        backend = socket.create_connection(BACKEND, timeout=60)
    except OSError:
        client.close()
        return
    t1 = threading.Thread(target=pump, args=(client, backend), daemon=True)
    t2 = threading.Thread(target=pump, args=(backend, client), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    client.close(); backend.close()


def main():
    ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", RELAY_PORT))
    srv.listen(50)
    print(f"TLS relay on https://127.0.0.1:{RELAY_PORT} -> {BACKEND[0]}:{BACKEND[1]}", flush=True)
    while True:
        raw, _ = srv.accept()
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            continue
        threading.Thread(target=handle, args=(tls,), daemon=True).start()


if __name__ == "__main__":
    main()
