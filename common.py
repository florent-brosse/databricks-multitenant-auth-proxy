"""Shared helpers. Configuration comes from environment variables only."""
import base64, json, os, urllib.error, urllib.parse, urllib.request

HOST = os.environ["DATABRICKS_HOST"].rstrip("/")          # https://<workspace>.cloud.databricks.com
WAREHOUSE_ID = os.environ.get("WAREHOUSE_ID", "")
SCHEMA = os.environ.get("CLAIMS_SCHEMA", "main.claims_demo")
SP_CLIENT_ID = os.environ.get("SP_CLIENT_ID", "")         # shared service principal (application id)
SP_CLIENT_SECRET = os.environ.get("SP_CLIENT_SECRET", "")


def sp_token(claim=None, client_id=None, secret=None):
    """client_credentials token for the shared SP, optionally carrying a custom identity claim."""
    form = {"grant_type": "client_credentials", "scope": "all-apis"}
    if claim is not None:
        form["custom_claim"] = claim
    req = urllib.request.Request(f"{HOST}/oidc/v1/token", data=urllib.parse.urlencode(form).encode(), method="POST")
    cred = f"{client_id or SP_CLIENT_ID}:{secret or SP_CLIENT_SECRET}"
    req.add_header("Authorization", "Basic " + base64.b64encode(cred.encode()).decode())
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())["access_token"]


def rest_sql(base, bearer, stmt, ctx=None):
    body = json.dumps({"statement": stmt, "warehouse_id": WAREHOUSE_ID, "wait_timeout": "50s"}).encode()
    req = urllib.request.Request(f"{base}/api/2.0/sql/statements", data=body, method="POST")
    req.add_header("Authorization", bearer if " " in bearer else f"Bearer {bearer}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=70, context=ctx) as r:
            d = json.loads(r.read())
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.read().decode()[:160]}"
    if d["status"]["state"] != "SUCCEEDED":
        return f"{d['status']['state']}: {d['status'].get('error', {}).get('message', '')[:160]}"
    return d.get("result", {}).get("data_array", [])


def jwt_payload(tok):
    p = tok.split(".")[1]; p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))
