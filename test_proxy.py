"""End-to-end through proxy_claims.py: client sends a CIAM JWT, the proxy validates it and sets the claim.
Run first:  python mock_idp.py --port 8080 --issuer http://localhost:8080 --audience claims-proxy
            (env for proxy_claims.py: see its docstring; CIAM_ISSUER=http://localhost:8080 CIAM_AUDIENCE=claims-proxy)
Env: DATABRICKS_HOST, WAREHOUSE_ID, CLAIMS_SCHEMA, PROXY_PORT (default 9443)."""
import base64, json, os, ssl, urllib.parse, urllib.request
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as pyjwt
from databricks import sql
from common import SCHEMA, WAREHOUSE_ID, rest_sql

IDP = "http://localhost:8080"
PORT = int(os.environ.get("PROXY_PORT", "9443"))
PROXY = f"https://localhost:{PORT}"
CTX = ssl._create_unverified_context()  # local self-signed cert
Q_WHO = "SELECT current_user(), current_oauth_custom_identity_claim()"
Q_DATA = f"SELECT tenant_id, department, full_name, salary FROM {SCHEMA}.hr_employees ORDER BY employee_id"

def mint(user, ttl=3600):
    return json.loads(urllib.request.urlopen(f"{IDP}/mint?user={urllib.parse.quote(user)}&ttl={ttl}").read())["access_token"]

def thrift(jwt_token, stmt):
    with sql.connect(server_hostname="localhost", _port=PORT, http_path=f"/sql/1.0/warehouses/{WAREHOUSE_ID}",
                     access_token=jwt_token, _tls_no_verify=True) as c, c.cursor() as cur:
        cur.execute(stmt); return [list(r) for r in cur.fetchall()]

print("== Thrift through the proxy (Bearer CIAM JWT)")
for u in ["alice@acme.test", "bob@acme.test", "carol@globex.test", "mallory@unknown.test"]:
    j = mint(u); who = thrift(j, Q_WHO)[0]; rows = thrift(j, Q_DATA)
    print(f"  {u:22} current_user={who[0][:8]}... claim={who[1]} -> {len(rows)} rows")

print("\n== REST through the proxy, Basic token:<JWT> (ODBC style)")
basic = "Basic " + base64.b64encode(f"token:{mint('bob@acme.test')}".encode()).decode()
print("  bob ->", rest_sql(PROXY, basic, Q_DATA, ctx=CTX))

print("\n== Bad tokens (must be refused by the proxy)")
fake = rsa.generate_private_key(public_exponent=65537, key_size=2048)
real = mint("alice@acme.test")
forged = pyjwt.encode({**pyjwt.decode(real, options={"verify_signature": False}), "sub": "carol@globex.test"},
                      fake, algorithm="RS256", headers={"kid": pyjwt.get_unverified_header(real)["kid"]})
for label, tok in [("forged signature", forged), ("expired", mint("alice@acme.test", ttl=-120)),
                   ("non-ASCII user id", mint("andré@acme.test"))]:
    print(f"  {label:18} ->", rest_sql(PROXY, f"Bearer {tok}", Q_DATA, ctx=CTX))
