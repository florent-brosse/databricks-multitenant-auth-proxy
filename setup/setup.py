#!/usr/bin/env python3
"""
Idempotent setup for the Token Federation PoC.

Creates / updates:
  - Four federated users at the account level: alice/bob @acme.test,
    carol/dave @contoso.test
  - Workspace assignment + databricks-sql-access entitlement for each
  - A federation policy on the account pointing at the configured
    mock CIAM issuer
  - All SQL fixtures from setup/poc.sql (catalogs, schemas, row filter,
    column mask, GRANTs)

Requires the Databricks CLI to be authenticated:
  - One account-level profile (account admin)
  - One workspace-level profile (workspace admin)

Environment variables (or pass via CLI):
  ACCOUNT_PROFILE       CLI profile pointing at https://accounts.cloud.databricks.com
  WORKSPACE_PROFILE     CLI profile pointing at the target workspace
  WORKSPACE_ID          numeric workspace id (e.g. 1234567890123456)
  CATALOG               workspace default catalog to use for the fixtures
  WAREHOUSE_ID          SQL warehouse id to run the SQL on
  MOCK_IDP_ISSUER       public HTTPS URL of the mock IdP (cloudflared tunnel)

Usage:
  python3 setup/setup.py
"""

import argparse
import json
import os
import subprocess
import sys
from string import Template


USERS = [
    ("alice@acme.test",   "Alice Martin (Acme HR)"),
    ("bob@acme.test",     "Bob Durand (Acme Eng)"),
    ("carol@contoso.test", "Carol Park (Contoso HR)"),
    ("dave@contoso.test",  "Dave King (Contoso Sales)"),
]
POLICY_ID = "tokenfed-mock-idp"
ENTITLEMENTS = ["databricks-sql-access", "workspace-access"]


def run(cmd: list[str], capture=True) -> tuple[int, str, str]:
    """Run a subprocess; return (returncode, stdout, stderr)."""
    p = subprocess.run(cmd, capture_output=capture, text=True)
    return p.returncode, p.stdout, p.stderr


def databricks(args: list[str], profile: str, json_body: dict | None = None) -> dict | str:
    cmd = ["databricks", *args, "-p", profile]
    if json_body is not None:
        cmd += ["--json", json.dumps(json_body)]
    rc, out, err = run(cmd)
    if rc != 0:
        raise RuntimeError(f"databricks {args} failed:\n{err or out}")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def get_account_id(account_profile: str) -> str:
    cmd = ["databricks", "auth", "describe", "-p", account_profile, "-o", "json"]
    rc, out, _ = run(cmd)
    if rc == 0:
        try:
            return json.loads(out).get("details", {}).get("account_id", "")
        except Exception:
            pass
    # Fallback: parse ~/.databrickscfg
    cfg = os.path.expanduser("~/.databrickscfg")
    in_section = False
    if os.path.exists(cfg):
        with open(cfg) as f:
            for line in f:
                if line.strip() == f"[{account_profile}]":
                    in_section = True
                    continue
                if in_section and line.startswith("["):
                    break
                if in_section and "account_id" in line:
                    return line.split("=", 1)[1].strip()
    raise RuntimeError(f"Could not find account_id for profile {account_profile}")


def provision_users(account_profile: str) -> dict[str, str]:
    """Create the 4 users at account level, return {email: user_id}."""
    user_ids: dict[str, str] = {}
    for email, display in USERS:
        try:
            d = databricks(
                ["account", "users", "create"],
                account_profile,
                {
                    "userName": email,
                    "displayName": display,
                    "active": True,
                    "emails": [{"value": email, "primary": True, "type": "work"}],
                },
            )
            user_ids[email] = d["id"]
            print(f"  created {email}  id={d['id']}")
        except RuntimeError as e:
            # User likely already exists — fetch and skip
            if "already" in str(e).lower() or "duplicate" in str(e).lower():
                # Find by listing — quick and dirty
                listing = databricks(
                    ["account", "users", "list", "--filter", f"userName eq '{email}'"],
                    account_profile,
                )
                if isinstance(listing, dict):
                    listing = listing.get("Resources", [])
                if listing and isinstance(listing, list):
                    user_ids[email] = listing[0]["id"]
                    print(f"  exists  {email}  id={listing[0]['id']}")
            else:
                raise
    return user_ids


def assign_to_workspace(account_profile: str, workspace_id: str, user_ids: dict[str, str]):
    for email, uid in user_ids.items():
        databricks(
            ["account", "workspace-assignment", "update", workspace_id, uid],
            account_profile,
            {"permissions": ["USER"]},
        )
        print(f"  assigned {email} to workspace {workspace_id}")


def grant_entitlements(workspace_profile: str, user_ids: dict[str, str]):
    for email, uid in user_ids.items():
        databricks(
            ["api", "patch", f"/api/2.0/preview/scim/v2/Users/{uid}"],
            workspace_profile,
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{
                    "op": "add",
                    "path": "entitlements",
                    "value": [{"value": e} for e in ENTITLEMENTS],
                }],
            },
        )
        print(f"  granted {ENTITLEMENTS} to {email}")


def create_or_update_federation_policy(account_profile: str, account_id: str, issuer: str):
    full_name = f"accounts/{account_id}/federationPolicies/{POLICY_ID}"
    payload = {
        "oidc_policy": {
            "issuer": issuer,
            "audiences": ["databricks"],
            "subject_claim": "email",
        },
    }

    # Try to update first; if it doesn't exist, create.
    try:
        databricks(
            ["account", "federation-policy", "update", POLICY_ID,
             "--update-mask", "oidc_policy"],
            account_profile,
            payload,
        )
        print(f"  updated federation policy {POLICY_ID} → {issuer}")
        return
    except RuntimeError as e:
        msg = str(e).lower()
        not_found = "not found" in msg or "not_found" in msg or "does not exist" in msg
        if not not_found:
            # A real error (auth, bad payload, ...) — don't mask it by
            # blindly falling through to create.
            raise

    payload["name"] = full_name
    databricks(
        ["account", "federation-policy", "create"],
        account_profile,
        payload,
    )
    print(f"  created federation policy {POLICY_ID} → {issuer}")


def run_sql_fixtures(workspace_profile: str, warehouse_id: str, catalog: str):
    sql_path = os.path.join(os.path.dirname(__file__), "poc.sql")
    with open(sql_path) as f:
        template = f.read()
    sql = Template(template).safe_substitute(CATALOG=catalog)

    # Split on ';' (naïve but fine for this fixture). Strip comments.
    statements = []
    for stmt in sql.split(";"):
        clean = "\n".join(l for l in stmt.split("\n") if not l.strip().startswith("--"))
        if clean.strip():
            statements.append(clean.strip())

    print(f"  running {len(statements)} SQL statements...")
    ok = 0
    for i, stmt in enumerate(statements):
        try:
            d = databricks(
                ["api", "post", "/api/2.0/sql/statements"],
                workspace_profile,
                {"warehouse_id": warehouse_id, "statement": stmt, "wait_timeout": "50s"},
            )
            state = d.get("status", {}).get("state")
            if state == "SUCCEEDED":
                ok += 1
            else:
                err = d.get("status", {}).get("error", {}).get("message", state)
                print(f"    [{i+1}/{len(statements)}] FAIL: {err[:200]}")
        except Exception as e:
            print(f"    [{i+1}/{len(statements)}] ERR: {e}")
    print(f"  {ok}/{len(statements)} statements succeeded")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--account-profile", default=os.environ.get("ACCOUNT_PROFILE"))
    p.add_argument("--workspace-profile", default=os.environ.get("WORKSPACE_PROFILE"))
    p.add_argument("--workspace-id", default=os.environ.get("WORKSPACE_ID"))
    p.add_argument("--catalog", default=os.environ.get("CATALOG"))
    p.add_argument("--warehouse-id", default=os.environ.get("WAREHOUSE_ID"))
    p.add_argument("--issuer", default=os.environ.get("MOCK_IDP_ISSUER"))
    args = p.parse_args()

    missing = [k for k, v in vars(args).items() if not v]
    if missing:
        sys.exit(f"Missing required args: {missing}")

    account_id = get_account_id(args.account_profile)
    print(f"Account id: {account_id}")

    print("\n[1/5] Provisioning users...")
    user_ids = provision_users(args.account_profile)

    print("\n[2/5] Assigning users to workspace...")
    assign_to_workspace(args.account_profile, args.workspace_id, user_ids)

    print("\n[3/5] Granting workspace entitlements...")
    grant_entitlements(args.workspace_profile, user_ids)

    print("\n[4/5] Configuring federation policy...")
    create_or_update_federation_policy(args.account_profile, account_id, args.issuer)

    print("\n[5/5] Running SQL fixtures...")
    run_sql_fixtures(args.workspace_profile, args.warehouse_id, args.catalog)

    print("\n✅ Setup complete.")
    print()
    print("Now:")
    print("  1. Start the proxy:  TFP_DBX_WORKSPACE=<workspace-url> python3 proxy/proxy.py")
    print("  2. Expose it via cloudflared: cloudflared tunnel --url http://localhost:9090")
    print("  3. Open notebook.py in your Databricks workspace and Run All.")


if __name__ == "__main__":
    main()
