"""
Custom claim + RFC 8693 token exchange (service principal federation policy), and why the
policy must trust ONLY the proxy's own identity.

  SAFE : subject = "claims-proxy"        -> only the proxy's JWT can be exchanged for the SP
  RISKY: subject_claim = "azp" (app id)  -> ANY end user's JWT matches: a user can ask for
                                            someone else's custom_claim and read their data

Policies use inline jwks_json, so Databricks never needs to reach the (mock) IdP.
Needs account admin (federation policies are account-level).

Usage: python token_exchange.py setup|test
Env:   DATABRICKS_HOST, WAREHOUSE_ID, CLAIMS_SCHEMA, WS_PROFILE, ACCOUNT_PROFILE (Databricks CLI profiles)
"""
import json, os, subprocess, sys, time, urllib.error, urllib.parse, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))
import mock_idp                                    # generates/loads proxy/keys/rsa_key.pem (git-ignored)
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from common import HOST, SCHEMA, rest_sql, jwt_payload

ISSUER, AUD = "https://ciam.example.com", "databricks-claims"
WS_P, ACCT_P = os.environ.get("WS_PROFILE"), os.environ.get("ACCOUNT_PROFILE")
STATE = "token_exchange_state.json"


def cli(*args, profile):
    out = subprocess.run(["databricks", *args, "-p", profile, "-o", "json"], capture_output=True, text=True)
    if out.returncode:
        raise SystemExit(f"CLI error: {out.stderr.strip()[:300]}")
    return json.loads(out.stdout) if out.stdout.strip() else {}


def mint(sub, ttl=3600):
    now = int(time.time())  # real CIAM tokens carry the app client id (azp) for every user
    return pyjwt.encode({"iss": ISSUER, "aud": AUD, "sub": sub, "azp": "claims-app", "iat": now, "exp": now + ttl},
                        mock_idp.PRIVATE_KEY, algorithm="RS256", headers={"kid": mock_idp.KID})


def setup():
    jwks = json.dumps(mock_idp.make_jwks())
    policies = {"safe": {"subject": "claims-proxy"}, "risky": {"subject_claim": "azp", "subject": "claims-app"}}
    st = {}
    for name, extra in policies.items():
        sp = cli("service-principals", "create", "--display-name", f"claims-tokenfed-{name}",
                 "--json", json.dumps({"entitlements": [{"value": "databricks-sql-access"}]}), profile=WS_P)
        cli("account", "service-principal-federation-policy", "create", str(sp["id"]), "--json",
            json.dumps({"oidc_policy": {"issuer": ISSUER, "audiences": [AUD], "jwks_json": jwks, **extra}}), profile=ACCT_P)
        st[name] = sp["applicationId"]
        print(f"{name}: SP {sp['applicationId']} + federation policy {extra}")
    json.dump(st, open(STATE, "w"))
    print("Now grant both SPs USE CATALOG / USE SCHEMA / SELECT on the demo table and CAN USE on the warehouse.")


def exchange(sp, subject_token, claim=None):
    form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "client_id": sp, "scope": "all-apis",
            "subject_token": subject_token, "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"}
    if claim:
        form["custom_claim"] = claim
    req = urllib.request.Request(f"{HOST}/oidc/v1/token", data=urllib.parse.urlencode(form).encode(), method="POST")
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=15).read())["access_token"]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:160]


def run(label, sp, subject_token, claim):
    code, tok = exchange(sp, subject_token, claim)
    if code != 200:
        return print(f"  {label:52} -> REFUSED (HTTP {code}) {tok[:110]}")
    rows = rest_sql(HOST, tok, f"SELECT tenant_id, full_name, salary FROM {SCHEMA}.hr_employees ORDER BY employee_id")
    print(f"  {label:52} -> claim={jwt_payload(tok).get('custom')} rows={rows}")


def test():
    st = json.load(open(STATE))
    proxy_jwt, bob_jwt = mint("claims-proxy"), mint("bob@acme.test")
    forged = pyjwt.encode(pyjwt.decode(proxy_jwt, options={"verify_signature": False}),
                          rsa.generate_private_key(public_exponent=65537, key_size=2048),
                          algorithm="RS256", headers={"kid": mock_idp.KID})
    print("== SAFE policy (subject = claims-proxy)")
    run("proxy JWT + custom_claim=bob@acme.test", st["safe"], proxy_jwt, "bob@acme.test")
    run("Bob's own JWT (calls Databricks directly)", st["safe"], bob_jwt, "bob@acme.test")
    run("forged proxy JWT", st["safe"], forged, "carol@globex.test")
    print("\n== RISKY policy (subject_claim = azp, identical for every user)")
    run("Bob's JWT + custom_claim=carol@globex.test", st["risky"], bob_jwt, "carol@globex.test")


if __name__ == "__main__":
    {"setup": setup, "test": test}[sys.argv[1]]()
