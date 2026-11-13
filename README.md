# Databricks Token Federation Proxy — B2B2C ISV pattern

A proof-of-concept showing how an ISV serving many customer tenants on
Databricks SQL can replace a heavy custom proxy (with query translation,
custom token vending, per-protocol parsing, etc.) by a **thin
HTTP-transparent forwarder** that swaps an external IdP JWT for a
Databricks OAuth token via [RFC 8693 Token Federation](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation-exchange).

Unity Catalog row filters, column masks and GRANTs do the per-user and
per-tenant enforcement natively. The proxy never decodes the payload —
it only swaps the `Authorization` header.

> **New: custom identity claims mode** ([`custom-claims/`](custom-claims/README.md)). One service
> principal for all end users: the proxy adds `custom_claim=<end user id>` to the SP token and Unity
> Catalog filters on `current_oauth_custom_identity_claim()`. No Databricks identity per end user.
> Includes ABAC, token exchange, and per-tenant LLM budgets with Unity Gateway.

---

## Architecture

```
Customer end-user
   │
   │ logs in to the customer IdP (CIAM)        ← any OIDC IdP
   ▼
CIAM issues a signed JWT (RS256 or ES256)
   │
   │ Client (PowerBI, ADBC tool, Excel, anything HTTP-speaking)
   │ sends the JWT as Bearer or HTTP Basic to the proxy
   ▼
┌───────────────────────────────────────────────────────────────┐
│  Token Federation Proxy  (~200 lines of Python stdlib)         │
│  - reads the JWT from the incoming auth header                 │
│  - calls Databricks /oidc/v1/token (RFC 8693) to exchange      │
│    the JWT for a DBX OAuth token tied to the federated user    │
│  - forwards the request verbatim with the swapped auth header  │
│  - the proxy never inspects path, method, body or content type │
└───────────────────────────────────────────────────────────────┘
   │
   ▼
Databricks workspace
   │
   │ The federation policy (created once at account level) tells
   │ DBX to trust JWTs from this IdP, and which claim maps to the
   │ Databricks user identity.
   │
   ▼
Unity Catalog enforces row filters, column masks and GRANTs based on
`current_user()` resolved from the federated identity.
```

---

## Why the proxy works for every protocol

All Databricks SQL access protocols share **HTTP/HTTPS** as the
transport. The proxy doesn't care about the payload — it only cares
about the auth header.

| Client / driver           | Wire protocol on top of HTTPS                | Endpoint(s) the proxy forwards |
|---------------------------|----------------------------------------------|--------------------------------|
| JDBC / ODBC (Simba/Hardy) | Thrift binary                                | `POST /sql/1.0/warehouses/<id>` |
| ADBC Databricks (new)     | REST + Arrow IPC payloads                    | `POST /api/2.0/sql/statements`, `GET /api/2.0/sql/statements/<id>` |
| OSS JDBC v2 (Thrift=off)  | REST + Arrow IPC                             | same as ADBC |
| Power BI Desktop          | Uses Simba Thrift today, ADBC default 2026   | both supported simultaneously |
| Tableau, DBeaver, etc.    | JDBC under the hood                          | same as JDBC |

Because the proxy is a **transparent HTTP forwarder**, every Databricks
HTTP API call works without modification:

- **OIDC / token exchange** — `POST /oidc/v1/token`
- **Statement execution** — `POST /api/2.0/sql/statements`
- **Polling and chunk retrieval** — `GET /api/2.0/sql/statements/<id>/result/chunks/<n>`
- **Cancellation** — `POST /api/2.0/sql/statements/<id>/cancel`
- **Identity** — `GET /api/2.0/preview/scim/v2/Me`
- **Catalog / warehouse metadata** — UC and warehouse APIs
- **Cloud Fetch** — Databricks returns presigned S3 / Azure Blob URLs;
  the client fetches data plane chunks **directly from object storage**,
  bypassing the proxy. The proxy sees only the control plane response
  (the manifest), never the data bytes themselves.
- **Pagination** — multi-chunk results are just additional HTTP calls
  the proxy forwards verbatim (or, for EXTERNAL_LINKS, fetched directly
  by the client).
- **Long-poll** — `wait_timeout` up to 50 s is just a long-held HTTP
  request the proxy forwards transparently.

---

## What this PoC validates

End-to-end demonstrated on a Databricks workspace with PowerBI Desktop
(Simba ODBC Thrift), via the Python `databricks-sql-connector`
(Arrow-native, same engine as ADBC), and via raw `curl`:

| Scenario | Result |
|----------|--------|
| Four federated personas across two tenants | Each sees only their allowed rows, with column masks applied where appropriate |
| Cross-tenant access attempt                | Denied by UC GRANTs (`INSUFFICIENT_PERMISSIONS`, SQLSTATE 42501) |
| Token Federation exchange (RFC 8693)       | Single curl call, no admin SP needed in the runtime |
| Cloud Fetch with EXTERNAL_LINKS            | Manifest comes through proxy, data chunks fetched directly from S3 |
| Pagination (synthetic multi-chunk result)  | All chunks fetched, UC filters preserved across chunks |
| REST + Arrow through the proxy             | Larger EXTERNAL_LINKS query runs through the proxy; data plane verified bypassing it (Arrow fetched straight from object storage) |
| Thrift / JDBC through the proxy            | OSS Databricks JDBC driver (`com.databricks:databricks-jdbc`, `AuthMech=3` → Basic `token:<JWT>`) and `databricks-sql-connector` both return the same RLS + masked rows over the **Thrift** endpoint (`/sql/1.0/warehouses/…`); needs HTTP/1.1 keep-alive on the proxy (else correct but slower) |
| PowerBI Desktop end-to-end                 | Same RLS, same column masks visible in the Navigator preview |

See the `notebook.py` for a runnable showcase of the whole pattern,
including the EXTERNAL_LINKS / chunked retrieval inspection.

---

## Status

| Component                              | Maturity |
|----------------------------------------|----------|
| Proxy core (HTTP forwarding + token swap) | ✅ PoC working — single binary, no deps beyond stdlib |
| Token Federation (RFC 8693)            | ✅ GA on Databricks (AWS, Azure, GCP) |
| UC row filters / column masks / GRANTs | ✅ GA |
| Mock CIAM (RS256 + JWKS + discovery)    | ✅ For demo; production swaps in the real CIAM |
| ADBC + Simba ODBC compatibility        | ✅ Both validated through the proxy |
| Cloud Fetch transparency               | ✅ Validated (manifest passes through, data plane bypasses proxy) |
| Multi-tenant data isolation            | ✅ Per-tenant catalogs / schemas + UC GRANTs |
| Production-ready proxy                 | ⚠️ See "Improvements" |

---

## Recommended improvements before production

The PoC proxy is intentionally minimal to make the pattern obvious.
For a real deployment the following are recommended.

| Concern | PoC behavior | Recommended for production |
|---------|--------------|----------------------------|
| TLS termination | cloudflared quick tunnel | ✅ Real reverse proxy with managed certs + HTTP/2 — see [Docker deployment](#docker-deployment-caddy-tls-edge) (Caddy edge, `tls internal` self-signed locally → one-line switch to Let's Encrypt) |
| Runtime | Python `ThreadingHTTPServer`, **HTTP/1.1 keep-alive** (required for Thrift/ODBC — see note) | Async runtime (aiohttp, FastAPI + uvicorn) or a real reverse proxy front-end (the [Docker setup](#docker-deployment-caddy-tls-edge) fronts it with Caddy: HTTP/2 + HTTP/3, keep-alive pool, active health checks) |
| Connection pooling | Client→proxy keep-alive on; one new socket per upstream (proxy→DBX) call | HTTP/2 keep-alive pool to Databricks; reuse TLS sessions |
| JWT signature validation | Delegated to Databricks (federation policy) | Optional **defense in depth**: validate signature locally before exchange to short-circuit obvious junk |
| JWKS caching | Implicit (Databricks caches) | Local JWKS cache with periodic refresh (don't refetch on every request) |
| DBX token caching | In-memory per-process, 5 min TTL | Shared cache (Redis / cluster cache) so multiple proxy replicas hit the same cache |
| Streaming of large responses | Buffered fully in memory | Stream the response chunk by chunk; for Cloud Fetch the client bypasses the proxy anyway |
| **Audit logs + telemetry** | stdout debug | **Send structured JSON events to a Delta table via [Zerobus](https://docs.databricks.com/aws/en/ingestion/zerobus/) (Databricks low-latency streaming ingestion). Then everything is queryable, governed by Unity Catalog, and stays in the lakehouse without extra infrastructure (no Splunk / Dynatrace / etc).** |
| Metrics | stdout debug | Prometheus / OpenMetrics endpoint, scraped by your monitoring stack |
| Health checks | None | ✅ `/healthz` liveness endpoint added (answered locally, no auth/exchange); wired into the Docker `HEALTHCHECK` and Caddy active health checks. Readiness with an actual `/oidc/v1/token` probe is still a TODO. |
| Error mapping | Forward DBX 4xx/5xx as-is | Translate common errors into client-friendly payloads where useful (e.g. token expiry → 401 with explicit error code) |
| Multi-tenant routing | One DBX workspace hardcoded | If you front multiple workspaces, route by tenant claim in the JWT |
| Multi-region | Single instance | Deploy per-region close to your customers; latency for the auth swap < 50 ms |
| Configuration | env vars hardcoded in source | Standard 12-factor (env, config file, secrets manager) |

---

## What's in this repo

```
.
├── README.md                ← this file
├── notebook.py              ← Databricks notebook end-to-end showcase
├── proxy/
│   ├── proxy.py             ← the ~200-line transparent forwarder (+ /healthz)
│   └── mock_idp.py          ← mock CIAM for the demo (RS256 + OIDC discovery + JWKS)
├── docker/                  ← production-shaped deployment (Caddy TLS edge)
│   ├── Dockerfile           ← non-root proxy image (stdlib only), HEALTHCHECK
│   ├── Caddyfile            ← TLS termination, HTTP/2+3, health checks, keep-alive
│   ├── docker-compose.yml   ← proxy (internal) + Caddy (edge) on a private net
│   └── .env.example         ← TFP_DBX_WORKSPACE + TFP_SITE_ADDRESS
└── setup/
    ├── setup.py             ← idempotent setup: users, workspace assignment,
    │                          entitlements, federation policy, SQL fixtures
    └── poc.sql              ← multi-tenant SQL: catalogs, schemas, row filters,
                               column masks, GRANTs
```

---

## Quickstart

```bash
# 1. Install dependencies (mock IdP needs `cryptography`; proxy is stdlib only)
python3 -m venv .venv && source .venv/bin/activate
pip install cryptography databricks-sdk

# 2. Run the mock IdP and expose it publicly via cloudflared
python3 proxy/mock_idp.py --port 8080 &
cloudflared tunnel --url http://localhost:8080 &
# Capture the public tunnel URL (https://*.trycloudflare.com)

# 3. Run setup (creates users, assigns to workspace, grants entitlements,
#    creates federation policy, runs the SQL fixtures)
export ACCOUNT_PROFILE=<your-databricks-account-cli-profile>
export WORKSPACE_PROFILE=<your-databricks-workspace-cli-profile>
export WORKSPACE_ID=<workspace_id>
export CATALOG=<workspace-default-catalog>
export WAREHOUSE_ID=<sql-warehouse-id>
export MOCK_IDP_ISSUER=<https://your-cloudflared-tunnel.trycloudflare.com>
python3 setup/setup.py

# 4. Start the proxy
export TFP_DBX_WORKSPACE=<https://your-workspace.cloud.databricks.com>
python3 proxy/proxy.py &
cloudflared tunnel --url http://localhost:9090 &
# Capture the proxy public tunnel URL

# 5. Upload notebook.py to your workspace and run it (it queries via the
#    federation flow as each persona and shows the filtered results).

# 6. Point PowerBI Desktop at the proxy tunnel URL:
#      Server hostname: <proxy-tunnel>.trycloudflare.com
#      HTTP path:       /sql/1.0/warehouses/<warehouse-id>
#      Auth:            Personal Access Token (paste a fresh CIAM JWT)
```

---

## Docker deployment (Caddy TLS edge)

For a deployment closer to production than the cloudflared quick tunnel, the
`docker/` directory runs the proxy behind **[Caddy](https://caddyserver.com/)**
as a TLS-terminating reverse proxy. Two containers on a private network:

```
client ──HTTPS (HTTP/2, HTTP/3)──▶  Caddy edge  ──HTTP──▶  Token Federation Proxy  ──▶  Databricks
         :443 (TLS terminated)       (cert mgmt,            :9090 (internal only)
                                      h2/h3, health
                                      checks, logs)
```

Caddy handles what the README's improvements table asks for: managed certs,
HTTP/2 **and** HTTP/3, an HTTP→HTTPS redirect, a warm keep-alive pool to the
backend (needed for Thrift/ODBC), response streaming (for long-polls), and
active health checks against the proxy's `/healthz`. The Python proxy runs as a
non-root user and is never published to the host — all traffic comes through
Caddy.

```bash
cd docker
cp .env.example .env
#   set TFP_DBX_WORKSPACE   = https://your-workspace.cloud.databricks.com
#   leave TFP_SITE_ADDRESS  = localhost   (local self-signed demo)
docker compose up -d --build

# Verify (self-signed cert, so -k):
curl -sk https://localhost/healthz                 # {"status": "ok"}, HTTP/2
curl -sk -H "Authorization: Bearer <CIAM JWT>" \
     https://localhost/api/2.0/sql/statements -d '{...}'
```

**TLS — local vs production.** With `TFP_SITE_ADDRESS=localhost`, Caddy serves a
self-signed cert from its own internal CA (`tls internal` in the `Caddyfile`),
so clients must trust or skip verification. To hand the CA to a BI tool/driver:

```bash
docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt
```

To go to **real managed certs**: point a public domain's DNS at the host, set
`TFP_SITE_ADDRESS=tfp.example.com`, open ports 80/443, and delete the
`tls internal` line in `docker/Caddyfile` — Caddy then provisions and renews
Let's Encrypt certificates automatically. No other changes.

> Run `docker compose` commands from inside `docker/` so the adjacent `.env` is
> picked up. `docker/.env` is git-ignored (it holds your workspace URL).

---

## ⚠️ Security note about the mock IdP

While the demo is running, `mock_idp.py`'s `/mint?user=<email>` endpoint is
exposed publicly through the cloudflared tunnel and mints a **validly signed
JWT for any email, with no authentication**. Because the account federation
policy trusts that issuer, anyone who discovers the tunnel URL can mint a
token for e.g. `alice@acme.test` and exchange it for a real Databricks OAuth
token tied to that identity.

This is fine for a short-lived, throwaway PoC, but:

- Keep the tunnel URL private and the demo window short.
- When you're done, **delete the federation policy** and stop the tunnel so
  the trust relationship no longer exists:
  ```bash
  databricks account federation-policy delete tokenfed-mock-idp -p $ACCOUNT_PROFILE
  ```
- In production the CIAM is never exposed this way — users obtain their JWT
  through the CIAM's standard interactive login, and there is no open `/mint`.

---

## Key references

- [Databricks OAuth Token Federation (RFC 8693 exchange)](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation-exchange)
- [Federation policy registration](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation-policy)
- [Unity Catalog row filters and column masks](https://docs.databricks.com/aws/en/data-governance/unity-catalog/filters-and-masks/)
- [Databricks ADBC driver for Power BI](https://docs.databricks.com/aws/en/partners/bi/power-bi-adbc)
- [Statement Execution API](https://docs.databricks.com/aws/en/dev-tools/sql-execution-tutorial) — Arrow IPC, EXTERNAL_LINKS / Cloud Fetch
- [Zerobus streaming ingestion](https://docs.databricks.com/aws/en/ingestion/zerobus/) — recommended for audit / telemetry log ingestion into Delta
