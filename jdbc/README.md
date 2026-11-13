# JDBC (Thrift) test through the proxy

Proves the **classic JDBC/ODBC wire protocol — Thrift over HTTP** —  works
through the Token Federation Proxy, from a real **external** client. This is
the path Power BI (today) and Simba ODBC use, distinct from the REST + Arrow
path that ADBC and the notebook's Steps 7–9 exercise.

> Run this from a laptop / external host — **not** from a Databricks notebook.
> The proxy exists for external ISV clients; driving it from inside Databricks
> would be an unnatural Databricks→proxy→Databricks loop. The notebook's
> Step 10 already demonstrates the same Thrift path in-notebook via
> `databricks-sql-connector`.

## What it showed

- Driver: **OSS Databricks JDBC driver** (`com.databricks:databricks-jdbc`,
  Apache-2.0) — *not* the legacy Simba/Magnitude driver. The class name
  `com.databricks.client.jdbc.Driver` is only a compatibility shim; the
  implementation lives under `com.databricks.jdbc.*`.
- Auth: `AuthMech=3; UID=token; PWD=<CIAM JWT>` → the driver sends HTTP
  `Basic(token:<JWT>)`, which the proxy unwraps (`_extract_ciam_jwt`).
- The driver connected over the **Thrift** endpoint (`POST
  /sql/1.0/warehouses/<id>`), and Unity Catalog applied the same row filter +
  column mask: `dave@contoso.test` saw 2 sales rows with masked SSN.
- Timing (local relay → proxy → serverless warehouse): ~1.5s connect + a
  couple seconds query. The proxy itself is not the bottleneck (it forwarded a
  handful of fast Thrift POSTs). Requires **HTTP/1.1 keep-alive** on the proxy
  (already set) — under HTTP/1.0 every Thrift round-trip reconnects.
- **Cloud Fetch + multi-chunk fetch work through the proxy.** A 900,000-row
  result (`acme.employees` ⨯ a 300k sequence, RLS-filtered to Bob's 3 of 4
  employees) came back correctly. Total bytes *through the proxy*: **~7.5 KB**
  (control plane only — `OpenSession`, `ExecuteStatement`, several
  `FetchResults` round-trips returning presigned chunk URLs). The ~30 MB of
  Arrow was downloaded by the driver **directly from object storage**, never
  touching the proxy — identical to the REST EXTERNAL_LINKS behavior. RLS is
  preserved across all chunks (900k rows, not 1.2M). Reproduce with:
  ```bash
  SQL="SELECT e.employee_id, e.name, e.department, s.idx AS row_id \
       FROM <catalog>.acme.employees e \
       CROSS JOIN (SELECT explode(sequence(1,300000)) AS idx) s" \
  MAX_PRINT=0 USER_EMAIL=bob@acme.test \
  HTTP_PATH=/sql/1.0/warehouses/<id> CATALOG=<catalog> bash jdbc/run.sh
  ```

## Run it

Prereqs: the mock IdP (`:8082`) and proxy (`:9092`) running (see the repo
root README), and Java on PATH.

JDBC drivers need TLS. Two options:

**A — local (no public tunnel):** use the bundled TLS relay.
```bash
# 1. start the relay (terminates TLS on :9443 -> proxy :9092)
python3 jdbc/tls_relay.py &

# 2. run the test (downloads the driver, mints a JWT, compiles, runs)
HTTP_PATH=/sql/1.0/warehouses/<your-warehouse-id> \
CATALOG=<your-catalog> \
bash jdbc/run.sh
```

**B — against a real HTTPS tunnel on 443** (e.g. cloudflared in front of the proxy):
```bash
PROXY_HOST=<your-proxy-tunnel-host> PROXY_PORT=443 ALLOW_SELF_SIGNED=0 \
HTTP_PATH=/sql/1.0/warehouses/<your-warehouse-id> CATALOG=<your-catalog> \
bash jdbc/run.sh
```

### Getting the driver inside Databricks
Maven Central is blocked on the Databricks corp network; use the mirror:
```bash
DRIVER_URL=https://repo1.maven.org/maven2/com/databricks/databricks-jdbc/3.4.1/databricks-jdbc-3.4.1.jar \
bash jdbc/run.sh
```

## Files
- `JdbcTest.java` — the JDBC client (env-configurable).
- `run.sh` — fetch driver + mint JWT + compile + run.
- `tls_relay.py` — local TLS terminator for option A.
