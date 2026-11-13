"""
Per-tenant monthly $ cap for LLM calls with ONE shared service principal (Unity Gateway).

The custom claim is NOT used by Unity Gateway budgets (they key on the Databricks principal or on
model-service tags). Pattern: one model service per tenant (same model behind), tagged tenant=<id>,
plus one Unity Gateway budget per tenant filtered on that tag with BLOCK_USAGE.
Request tags (header Databricks-Ai-Gateway-Request-Tags) carry tenant/end user for attribution only.

Usage: python ai_gateway_budget.py setup|test
Env:   DATABRICKS_HOST, WS_PROFILE, ACCOUNT_PROFILE, WORKSPACE_ID, AI_SCHEMA (catalog.schema),
       AI_SP_CLIENT_ID, AI_SP_CLIENT_SECRET (SP with workspace-access entitlement),
       MODEL (default models/system.ai.databricks-claude-sonnet-4-6), BUDGET_USD (default 0.20)
"""
import json, os, subprocess, sys, time, urllib.error, urllib.request
from common import HOST, sp_token

WS_P, ACCT_P = os.environ.get("WS_PROFILE"), os.environ.get("ACCOUNT_PROFILE")
SCHEMA = os.environ.get("AI_SCHEMA", "main.ai_tenants")
MODEL = os.environ.get("MODEL", "models/system.ai.databricks-claude-sonnet-4-6")
SP_ID, SP_SECRET = os.environ.get("AI_SP_CLIENT_ID"), os.environ.get("AI_SP_CLIENT_SECRET")
TENANTS = ["acme", "globex"]


def cli(*args, profile):
    out = subprocess.run(["databricks", *args, "-p", profile, "-o", "json"], capture_output=True, text=True)
    if out.returncode:
        raise SystemExit(f"CLI error: {out.stderr.strip()[:300]}")
    return json.loads(out.stdout) if out.stdout.strip() else {}


def setup():
    for t in TENANTS:
        cli("ai-gateway", "create-model-service", f"schemas/{SCHEMA}", f"tenant_{t}", "--json", json.dumps(
            {"comment": f"model service for tenant {t}", "config": {"routing": {"destinations": [{
                "name": "primary", "destination_type": "DESTINATION_TYPE_PAY_PER_TOKEN_FOUNDATION_MODEL",
                "pay_per_token_config": {"model": MODEL}, "traffic_percentage": 100}]}}}), profile=WS_P)
        cli("entity-tag-assignments", "create", f"{SCHEMA}.tenant_{t}", "tenant", "model-services",
            "--tag-value", t, profile=WS_P)
        cli("grants", "update", "model-service", f"{SCHEMA}.tenant_{t}", "--json",
            json.dumps({"changes": [{"principal": SP_ID, "add": ["EXECUTE"]}]}), profile=WS_P)
        print(f"model service {SCHEMA}.tenant_{t} (tag tenant={t}, EXECUTE for the SP)")
    # Budget for the first tenant only, so the second one shows it is not affected.
    b = cli("account", "budgets", "create", "--json", json.dumps({"budget": {
        "display_name": f"tenant-{TENANTS[0]}-llm-monthly", "resource_type": "BUDGET_RESOURCE_TYPE_UNITY_AI_GATEWAY",
        "filter": {"workspace_id": {"operator": "IN", "values": [int(os.environ["WORKSPACE_ID"])]},
                   "tags": [{"key": "tenant", "value": {"operator": "IN", "values": [TENANTS[0]]}}]},
        "alert_configurations": [{"time_period": "MONTH", "trigger_type": "CUMULATIVE_SPENDING_EXCEEDED",
            "quantity_type": "LIST_PRICE_DOLLARS_USD", "quantity_threshold": os.environ.get("BUDGET_USD", "0.20"),
            "scope_type": "ALERT_CONFIGURATION_SCOPE_TYPE_SHARED", "action_configurations": [{"action_type": "BLOCK_USAGE"}]}]}}),
        profile=ACCT_P)
    print("budget", b.get("budget", b).get("budget_configuration_id"), f"(tenant={TENANTS[0]}, BLOCK_USAGE)")
    print("Also grant the SP USE CATALOG / USE SCHEMA on", SCHEMA)


def call(tenant, user, max_tokens=1500):
    body = json.dumps({"model": f"{SCHEMA}.tenant_{tenant}", "max_tokens": max_tokens,
                       "messages": [{"role": "user", "content": "Write a detailed 1000-word essay about alpine lakes."}]}).encode()
    req = urllib.request.Request(f"{HOST}/ai-gateway/mlflow/v1/chat/completions", data=body, method="POST")
    req.add_header("Authorization", f"Bearer {sp_token(user, SP_ID, SP_SECRET)}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Databricks-Ai-Gateway-Request-Tags", json.dumps({"tenant": tenant, "end_user": user}))
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return 200, json.loads(r.read()).get("usage", {}).get("completion_tokens", 0), ""
    except urllib.error.HTTPError as e:
        return e.code, 0, e.read().decode()[:200]


def test():
    out = 0
    for i in range(1, 80):
        code, n, err = call(TENANTS[0], f"alice@{TENANTS[0]}.test"); out += n
        print(f"{time.strftime('%H:%M:%S')} {TENANTS[0]} #{i}: HTTP {code} (~${out * 15 / 1e6:.2f}) {err}", flush=True)
        if code != 200 or out * 15 / 1e6 > 1.0:
            break
        time.sleep(5)
    code, _, err = call(TENANTS[1], f"carol@{TENANTS[1]}.test", 50)
    print(f"{TENANTS[1]} (same SP, no budget hit): HTTP {code} {err}")


if __name__ == "__main__":
    {"setup": setup, "test": test}[sys.argv[1]]()
