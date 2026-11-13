# Databricks notebook source
# MAGIC %md
# MAGIC # OAuth Token Federation showcase
# MAGIC
# MAGIC This notebook demonstrates the end-to-end **OAuth Token Federation** pattern
# MAGIC for customer-facing analytics on Databricks:
# MAGIC
# MAGIC ```
# MAGIC Customer end-user (Carol@Contoso)
# MAGIC   → the customer CIAM (mocked here)         → signed RS256 JWT
# MAGIC   → the ISV proxy / direct exchange    → POST /oidc/v1/token (RFC 8693)
# MAGIC   → Databricks OAuth token (Carol's identity)
# MAGIC   → Databricks SQL                   → Unity Catalog row filters + masks
# MAGIC ```
# MAGIC
# MAGIC Same query, same warehouse, **different identity → different result set**.
# MAGIC No application-layer SQL rewriting — Unity Catalog enforces filtering
# MAGIC natively based on `current_user()`.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration
# MAGIC
# MAGIC Edit these to match the running mock IdP tunnel + workspace.

# COMMAND ----------

import json
import ssl
import urllib.parse
import urllib.request
import pandas as pd

# Mock CIAM (the customer CIAM substitute) exposed via cloudflared
CIAM_TUNNEL = "https://<YOUR-MOCK-IDP-TUNNEL>.trycloudflare.com"

# Databricks workspace
DBX_WORKSPACE = "https://<YOUR-WORKSPACE>.cloud.databricks.com"
WAREHOUSE_ID = "<YOUR-WAREHOUSE-ID>"
CATALOG = "<YOUR_CATALOG>"

# The token-federation proxy, exposed via its own cloudflared tunnel.
# Steps 3-8 emulate the proxy inline (direct RFC 8693 exchange) to teach the
# pattern; Step 9 sends traffic through the REAL proxy to prove the transparent
# forwarder — including Cloud Fetch — works end to end.
PROXY_URL = "https://<YOUR-PROXY-TUNNEL>.trycloudflare.com"

print("Mock CIAM issuer:", CIAM_TUNNEL)
print("Databricks workspace:", DBX_WORKSPACE)
print("Proxy URL:", PROXY_URL)
print("Catalog under test:", CATALOG)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1 — Define the auth helpers
# MAGIC
# MAGIC Two short functions emulate what the ISV proxy does in production:
# MAGIC
# MAGIC 1. `mint_ciam_jwt(user)` — calls the mock CIAM to obtain a signed JWT for
# MAGIC    a given customer end-user. In production this would be the customer
# MAGIC    completing OAuth flow against the customer CIAM.
# MAGIC 2. `exchange_for_dbx_token(jwt)` — calls Databricks `/oidc/v1/token` with
# MAGIC    the JWT as `subject_token` (RFC 8693). Databricks validates the JWT
# MAGIC    against the federation policy and returns a Databricks OAuth token
# MAGIC    bearing the federated user identity.

# COMMAND ----------

def mint_ciam_jwt(user_email: str) -> str:
    """Get a signed RS256 JWT for a user from the mock CIAM."""
    url = f"{CIAM_TUNNEL}/mint?user={urllib.parse.quote(user_email)}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


def exchange_for_dbx_token(ciam_jwt: str) -> str:
    """Exchange a CIAM JWT for a Databricks OAuth token (RFC 8693)."""
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
        return json.loads(resp.read())["access_token"]


def run_sql_as(user_email: str, sql: str) -> pd.DataFrame:
    """Query Databricks SQL as a federated user. Returns a DataFrame."""
    ciam_jwt = mint_ciam_jwt(user_email)
    dbx_token = exchange_for_dbx_token(ciam_jwt)

    body = json.dumps({
        "warehouse_id": WAREHOUSE_ID,
        "statement": sql,
        "wait_timeout": "30s",
    }).encode()
    req = urllib.request.Request(
        f"{DBX_WORKSPACE}/api/2.0/sql/statements",
        data=body, method="POST",
    )
    req.add_header("Authorization", f"Bearer {dbx_token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())

    status = data.get("status", {}).get("state")
    if status != "SUCCEEDED":
        err = data.get("status", {}).get("error", {}).get("message", "")
        raise RuntimeError(f"[{status}] {err}")

    cols = [c["name"] for c in data["manifest"]["schema"]["columns"]]
    rows = data.get("result", {}).get("data_array", []) or []
    return pd.DataFrame(rows, columns=cols)


print("Helpers ready.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2 — Query as Carol (Contoso HR admin)
# MAGIC
# MAGIC Carol is mapped with `allowed_dept = NULL` → she has full visibility on
# MAGIC the Contoso employees table, and SSN is shown in clear.

# COMMAND ----------

print(">>> Calling mock CIAM, exchanging JWT, querying as carol@contoso.test ...")
df_carol = run_sql_as(
    "carol@contoso.test",
    f"SELECT employee_id, name, department, salary, ssn FROM {CATALOG}.contoso.employees ORDER BY employee_id"
)
display(df_carol)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3 — Same query as Dave (Contoso sales-only)
# MAGIC
# MAGIC Dave is mapped with `allowed_dept = 'sales'` → row filter excludes the
# MAGIC HR row, column mask hides the SSN.
# MAGIC
# MAGIC **Same query, same warehouse, different identity → 2 rows, masked SSN.**

# COMMAND ----------

print(">>> Calling mock CIAM, exchanging JWT, querying as dave@contoso.test ...")
df_dave = run_sql_as(
    "dave@contoso.test",
    f"SELECT employee_id, name, department, salary, ssn FROM {CATALOG}.contoso.employees ORDER BY employee_id"
)
display(df_dave)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4 — Cross-tenant denied
# MAGIC
# MAGIC Carol (Contoso) tries to read the Acme tenant data. Unity Catalog GRANTs
# MAGIC are restricted to her tenant only, so this fails at the database, not
# MAGIC at the application layer.

# COMMAND ----------

try:
    df_xtenant = run_sql_as(
        "carol@contoso.test",
        f"SELECT * FROM {CATALOG}.acme.employees"
    )
    display(df_xtenant)
except RuntimeError as e:
    print("❌ As expected — Carol blocked from Acme:")
    print(str(e)[:400])

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5 — Bonus: Alice (Acme HR) for comparison
# MAGIC
# MAGIC To show the same pattern on the other tenant — Alice has full visibility
# MAGIC on the Acme employees, with SSN in clear.

# COMMAND ----------

print(">>> Same exchange flow, this time as alice@acme.test on the Acme tenant ...")
df_alice = run_sql_as(
    "alice@acme.test",
    f"SELECT employee_id, name, department, salary, ssn FROM {CATALOG}.acme.employees ORDER BY employee_id"
)
display(df_alice)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6 — And Bob (Acme dept head) for the row-filter contrast
# MAGIC
# MAGIC Bob is mapped with `allowed_dept IN ('engineering','design')` →
# MAGIC HR row filtered out, SSN masked.

# COMMAND ----------

df_bob = run_sql_as(
    "bob@acme.test",
    f"SELECT employee_id, name, department, salary, ssn FROM {CATALOG}.acme.employees ORDER BY employee_id"
)
display(df_bob)

# COMMAND ----------

# MAGIC %md
# MAGIC ## What just happened
# MAGIC
# MAGIC | User | Tenant | Rows returned | SSN | Reason |
# MAGIC |---|---|---|---|---|
# MAGIC | `carol@contoso.test` | contoso | 3 (all) | clear | HR admin, `allowed_dept=NULL` |
# MAGIC | `dave@contoso.test` | contoso | 2 (sales only) | masked `XXX-XX-…` | `allowed_dept='sales'` |
# MAGIC | `carol@contoso.test` → acme | — | `INSUFFICIENT_PERMISSIONS` | — | No `USE SCHEMA` grant on acme |
# MAGIC | `alice@acme.test` | acme | 4 (all) | clear | HR admin |
# MAGIC | `bob@acme.test` | acme | 3 (eng+design) | masked | dept head |
# MAGIC
# MAGIC Every query in this notebook went through the same auth chain:
# MAGIC
# MAGIC 1. Mock CIAM signs a JWT for the user.
# MAGIC 2. Databricks `/oidc/v1/token` validates the JWT against the federation
# MAGIC    policy and returns a DBX OAuth token tied to the user's identity.
# MAGIC 3. Statement Execution API runs the SQL — `current_user()` resolves to
# MAGIC    the federated user, Unity Catalog applies row filters + column masks
# MAGIC    + GRANTs natively.
# MAGIC
# MAGIC The application code (this notebook, or the ISV proxy in production)
# MAGIC does no SQL rewriting, no per-user filtering, no token-vending magic.
# MAGIC Just a single RFC 8693 token exchange per session.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 7 — Observe Cloud Fetch / chunked retrieval
# MAGIC
# MAGIC With `disposition=EXTERNAL_LINKS`, Databricks returns **presigned URLs**
# MAGIC for large results — the client downloads chunks directly from object
# MAGIC storage, **bypassing the proxy** for the actual data transfer.
# MAGIC
# MAGIC The proxy sees only the control plane (the query + the manifest); the
# MAGIC bytes themselves don't transit through it.

# COMMAND ----------

def submit_external_links(user_email: str, sql: str) -> dict:
    """Submit a statement with EXTERNAL_LINKS disposition and return the raw response."""
    ciam_jwt = mint_ciam_jwt(user_email)
    dbx_token = exchange_for_dbx_token(ciam_jwt)

    body = json.dumps({
        "warehouse_id": WAREHOUSE_ID,
        "statement": sql,
        "wait_timeout": "30s",
        "disposition": "EXTERNAL_LINKS",
        "format": "ARROW_STREAM",
    }).encode()
    req = urllib.request.Request(
        f"{DBX_WORKSPACE}/api/2.0/sql/statements",
        data=body, method="POST",
    )
    req.add_header("Authorization", f"Bearer {dbx_token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


# Run a query as Carol — same Token Federation flow, just EXTERNAL_LINKS this time
response = submit_external_links(
    "carol@contoso.test",
    f"SELECT employee_id, name, department FROM {CATALOG}.contoso.employees"
)

manifest = response.get("manifest", {})
result = response.get("result", {})

print("State:", response.get("status", {}).get("state"))
print("Format:", manifest.get("format"))
print("Total rows:", manifest.get("total_row_count"))
print("Total chunks:", manifest.get("total_chunk_count"))
print()

# Show the chunk URLs — these are presigned S3/Azure URLs the client uses to
# fetch data directly from object storage. (Step 9 routes this same query
# through the real proxy and confirms the fetch bypasses it.)
for chunk in result.get("external_links", []):
    url = chunk.get("external_link", "")
    print(f"  chunk {chunk.get('chunk_index')}: {chunk.get('row_count')} rows")
    print(f"    presigned URL: {url[:100]}...")
    print(f"    expiry: {chunk.get('expiration')}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 8 — Showing pagination via chunks
# MAGIC
# MAGIC For larger results the response includes multiple chunks. Each chunk is
# MAGIC fetched via a separate HTTP GET — either to the presigned URL (when
# MAGIC `EXTERNAL_LINKS`) or via `/api/2.0/sql/statements/<id>/result/chunks/<n>`
# MAGIC (when `INLINE`).
# MAGIC
# MAGIC Every chunk fetch is **just another HTTP request** — for the URL-based
# MAGIC path it bypasses the proxy, for the inline path the proxy forwards it
# MAGIC verbatim. No state in the proxy, no protocol parsing.

# COMMAND ----------

# Build a synthetically larger result to demonstrate multi-chunk paths.
# We use a CROSS JOIN of the small acme.employees with a generated series.
big_sql = f"""
SELECT e.employee_id, e.name, e.department, s.idx AS row_id
FROM {CATALOG}.acme.employees e
CROSS JOIN (SELECT explode(sequence(1, 1000)) AS idx) s
ORDER BY row_id, employee_id
"""

# Bob is restricted to engineering+design — so the synthetic 4000 rows become
# ~3000 (3 of the 4 employees match the filter). Same UC filtering applies
# even on chunked / EXTERNAL_LINKS results.
big_response = submit_external_links("bob@acme.test", big_sql)

big_manifest = big_response.get("manifest", {})
big_result = big_response.get("result", {})
print(f"Bob — large query — rows returned: {big_manifest.get('total_row_count')}")
print(f"  Chunks: {big_manifest.get('total_chunk_count')}")
print(f"  Format: {big_manifest.get('format')}")
print()
print("First chunk metadata (proxy sees this; data lives on S3 / Blob):")
chunks = big_result.get("external_links", [])
if chunks:
    c = chunks[0]
    print(f"  index={c.get('chunk_index')} rows={c.get('row_count')} byte_count={c.get('byte_count')}")
    print(f"  external_link: {c.get('external_link', '')[:120]}...")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 9 — Now do it for real, THROUGH the proxy
# MAGIC
# MAGIC Steps 3-8 emulated the proxy: the notebook did the RFC 8693 exchange
# MAGIC itself and called Databricks directly. That proves the **Unity Catalog**
# MAGIC half of the story but never touches the proxy.
# MAGIC
# MAGIC Here the client holds **only the CIAM JWT** and talks **only to the
# MAGIC proxy** (`PROXY_URL`). The proxy swaps `Authorization: Bearer <CIAM JWT>`
# MAGIC for a Databricks token and forwards verbatim. We run the **larger
# MAGIC EXTERNAL_LINKS query through the proxy** and then fetch a data chunk
# MAGIC **directly from object storage**, proving the data plane bypasses the
# MAGIC proxy while UC filtering is still applied.

# COMMAND ----------

def submit_via_proxy(user_email: str, sql: str, external_links: bool = False) -> dict:
    """Submit a statement THROUGH the proxy. The only credential the client
    holds is the CIAM JWT — never a Databricks token."""
    ciam_jwt = mint_ciam_jwt(user_email)  # in prod: the user's CIAM login

    payload = {"warehouse_id": WAREHOUSE_ID, "statement": sql, "wait_timeout": "50s"}
    if external_links:
        payload["disposition"] = "EXTERNAL_LINKS"
        payload["format"] = "ARROW_STREAM"

    req = urllib.request.Request(
        f"{PROXY_URL}/api/2.0/sql/statements",
        data=json.dumps(payload).encode(), method="POST",
    )
    # Raw CIAM JWT — NOT a Databricks token. The proxy does the exchange.
    req.add_header("Authorization", f"Bearer {ciam_jwt}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


# Same large query as Step 8, but routed through the proxy this time.
proxied = submit_via_proxy("bob@acme.test", big_sql, external_links=True)
p_manifest = proxied.get("manifest", {})
p_result = proxied.get("result", {})

print("Submitted to PROXY_URL — client never saw a Databricks token.")
print(f"  state:  {proxied.get('status', {}).get('state')}")
print(f"  rows:   {p_manifest.get('total_row_count')}  (Bob's RLS still applied through the proxy)")
print(f"  chunks: {p_manifest.get('total_chunk_count')}  format={p_manifest.get('format')}")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Step 9b — Fetch a chunk directly from storage (data plane bypasses proxy)
# MAGIC
# MAGIC The manifest came back *through* the proxy. The chunk bytes do not: the
# MAGIC presigned link points at object storage, and we fetch it with no proxy
# MAGIC and no `Authorization` header at all.

# COMMAND ----------

links = p_result.get("external_links", [])
if links:
    link = links[0]["external_link"]
    link_host = urllib.parse.urlparse(link).netloc
    proxy_host = urllib.parse.urlparse(PROXY_URL).netloc
    print(f"Proxy host (control plane): {proxy_host}")
    print(f"Chunk host  (data plane):  {link_host}")
    print()

    # Fetch the chunk DIRECTLY — no proxy, no auth header (the URL is presigned).
    with urllib.request.urlopen(urllib.request.Request(link, method="GET"), timeout=60) as r:
        chunk_bytes = r.read()
    arrow_magic = b"\xff\xff\xff\xff"  # Arrow IPC stream continuation marker
    is_arrow = chunk_bytes[:4] == arrow_magic
    print(f"Fetched {len(chunk_bytes):,} bytes straight from {link_host}")
    print(f"Arrow IPC stream: {is_arrow}")
    print()
    print("→ Control plane (query + manifest) went through the proxy.")
    print("→ Data plane (the actual rows) came straight from object storage.")
else:
    print("No external_links in result (small result may have been returned inline).")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 10 — The JDBC/ODBC (Thrift) path through the proxy
# MAGIC
# MAGIC Steps 3-9 used the REST Statement Execution API (what ADBC and OSS JDBC
# MAGIC v2 use). The classic Simba ODBC/JDBC drivers — and Power BI today —
# MAGIC instead speak **Thrift binary over HTTP** to `/sql/1.0/warehouses/<id>`.
# MAGIC That's a different wire protocol, so it deserves its own proof.
# MAGIC
# MAGIC `databricks-sql-connector` speaks exactly that Thrift-over-HTTP protocol,
# MAGIC so we point it at the **proxy** and authenticate with the **raw CIAM
# MAGIC JWT**. The proxy swaps the header; Unity Catalog enforces the same RLS
# MAGIC and masks. Two findings worth knowing (both handled):
# MAGIC
# MAGIC 1. **Keep-alive matters.** Thrift does many sequential round-trips on one
# MAGIC    connection. The proxy must speak **HTTP/1.1** (it does) or every
# MAGIC    round-trip reconnects — correct but ~2.5x slower (measured 36s → 15s).
# MAGIC 2. **The connector has its own token federation.** It first tries to
# MAGIC    exchange the token at `PROXY_URL/oidc/v1/token`. That request carries
# MAGIC    no `Authorization` header, so the proxy returns `401 MISSING_TOKEN`;
# MAGIC    the connector then logs *"Token exchange failed, using external
# MAGIC    token"* and sends the raw CIAM JWT — which is exactly what the proxy
# MAGIC    wants. The warning is benign.

# COMMAND ----------

# MAGIC %pip install -q databricks-sql-connector
# MAGIC # NOTE: %pip restarts the Python interpreter. After it finishes, run the
# MAGIC # Configuration cell (and the auth-helpers cell) again before this step,
# MAGIC # or just Run All a second time.

# COMMAND ----------

from databricks import sql

def query_via_thrift(user_email: str, statement: str):
    """Query through the proxy over the Thrift (JDBC/ODBC) wire protocol."""
    ciam_jwt = mint_ciam_jwt(user_email)        # raw CIAM JWT; proxy does the swap
    proxy_host = urllib.parse.urlparse(PROXY_URL).netloc
    with sql.connect(
        server_hostname=proxy_host,
        http_path=f"/sql/1.0/warehouses/{WAREHOUSE_ID}",
        access_token=ciam_jwt,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(statement)
            cols = [c[0] for c in cur.description]
            rows = cur.fetchall()
    return cols, rows


cols, rows = query_via_thrift(
    "dave@contoso.test",
    f"SELECT employee_id, name, department, salary, ssn "
    f"FROM {CATALOG}.contoso.employees ORDER BY employee_id",
)
print("Columns:", cols)
for r in rows:
    print(" ", tuple(r))
print()
print("Expected: 2 rows (sales only), SSN masked XXX-XX-#### — same UC enforcement,")
print("this time proven over the Thrift/JDBC/ODBC wire protocol through the proxy.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Recap of what was demonstrated
# MAGIC
# MAGIC | Step | Path | Through proxy? | What it proves |
# MAGIC |---|---|---|---|
# MAGIC | 3-6 | `/api/2.0/sql/statements` JSON_ARRAY | No (direct exchange) | Per-user RLS + column mask + cross-tenant denial |
# MAGIC | 7   | ARROW_STREAM + EXTERNAL_LINKS | No (direct exchange) | Cloud Fetch manifest shape — presigned links to storage |
# MAGIC | 8   | Multi-chunk EXTERNAL_LINKS | No (direct exchange) | UC filtering preserved on chunked results |
# MAGIC | 9   | REST EXTERNAL_LINKS **through `PROXY_URL`** | **Yes** | Transparent forwarder works: manifest via proxy, **data plane fetched directly from object storage**, RLS still applied |
# MAGIC | 10  | **Thrift / JDBC / ODBC** through `PROXY_URL` | **Yes** | Classic Simba wire protocol works through the proxy too; needs HTTP/1.1 keep-alive |
# MAGIC
# MAGIC **The proxy never decodes the query or the result.** It forwards HTTP,
# MAGIC swaps the auth header, that's it. JDBC / ODBC / ADBC / Cloud Fetch /
# MAGIC pagination — all transparent because they're all HTTP underneath.
# MAGIC Steps 9-10 are the ones that actually exercise the proxy end to end,
# MAGIC over both the REST+Arrow and the Thrift wire protocols.
