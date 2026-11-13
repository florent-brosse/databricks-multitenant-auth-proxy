# Databricks multi-tenant auth proxy (OAuth custom identity claims)

Serve many end users of a multi-tenant (B2B2C) app through **one service principal**, while each
user only sees their own data. No Databricks identity per end user.

The proxy validates the end user's IdP JWT, requests a token for the shared service principal with
`custom_claim=<end user id>`, and forwards the request. Unity Catalog reads the claim with
[`current_oauth_custom_identity_claim()`](https://docs.databricks.com/aws/en/sql/language-manual/functions/current_oauth_custom_identity_claim)
in row filters, column masks and ABAC policies.
Docs: [OAuth custom identity claims](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-custom-identity-claims).

```
end user ──IdP JWT──▶ proxy_claims.py
                        1. validates the JWT (JWKS signature, iss, aud, exp)
                        2. reads the user id (sub), checks it is a plain ASCII id
                        3. POST /oidc/v1/token  client_credentials (shared SP) + custom_claim=<user id>
                        4. forwards the request with the SP token (cached per user)
Databricks SQL ──▶ row filter / mask / ABAC: mapping table  user → tenant, scope, rights
```

## Options

| | Token federation, 1 Databricks user per end user | Custom claim + SP secret | Custom claim + token exchange |
|---|---|---|---|
| What Databricks validates | the end user's IdP JWT | the SP secret | the proxy's own JWT |
| Who vouches for the end user | Databricks | the proxy | the proxy |
| Databricks identity per end user | yes | no | no |
| Secret in the proxy | none | SP OAuth secret | none on the Databricks side |

Token exchange only removes the Databricks secret: useful if the proxy has a secretless identity
(Kubernetes service account, cloud workload identity). Otherwise keep it simple with the SP secret.

## Quick start

```bash
pip install -r requirements.txt
# 1. run sql/01_rls_mask.sql (adapt catalog.schema, grant the SP as commented at the end)
# 2. direct test, REST + Thrift
export DATABRICKS_HOST=https://<workspace> WAREHOUSE_ID=<id> SP_CLIENT_ID=<app id> SP_CLIENT_SECRET=<secret>
python test_direct.py
# 3. through the proxy
python mock_idp.py --port 8080 --issuer http://localhost:8080 --audience claims-proxy &
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj /CN=localhost
TFP_DBX_WORKSPACE=$DATABRICKS_HOST TFP_SP_CLIENT_ID=$SP_CLIENT_ID TFP_SP_SECRET=$SP_CLIENT_SECRET \
CIAM_ISSUER=http://localhost:8080 CIAM_AUDIENCE=claims-proxy TFP_TLS_CERT=cert.pem TFP_TLS_KEY=key.pem \
python proxy_claims.py &
python test_proxy.py
```

Tested on AWS (SQL warehouse, Nov 2026): REST (Statement Execution API) and Thrift (the ODBC/JDBC
protocol), directly and through the proxy; ABAC; token exchange; per-tenant LLM budgets.
Not tested: Power BI Desktop, ADBC. Officially supported surfaces: JDBC, SQL Statement Execution API,
Genie Agents API.

## Security notes

1. The proxy chooses the claim, so it **must validate the IdP JWT**. Databricks signs whatever claim is requested.
2. The SP credential opens every tenant: secret manager, rotation, IP access list or Private Link.
3. **Never let an SP federation policy accept end-user JWTs** (for example `subject_claim=azp`): a user could
   request someone else's claim. `token_exchange.py` shows it. Trust only the proxy's identity.
4. Use a **plain ASCII, non-empty id** as claim (IdP user id rather than email). Write filters with plain `=`
   so a NULL claim matches nothing.
5. ABAC: an **untagged table is fully visible** to the SP. The tag is the security boundary.
6. Query history shows the SP: log `user → request` in the proxy. For strong isolation, use one SP per tenant
   and the claim for per-user rights inside the tenant.

## LLM costs per tenant (Unity Gateway)

[Unity Gateway budgets](https://docs.databricks.com/aws/en/ai-gateway/budgets) don't use the claim. They key
on the principal or on **model service tags**. For a monthly $ cap per tenant with one SP:
one model service per tenant (same model behind) tagged `tenant=<id>`, plus one budget per tenant on that tag
with block usage (`ai_gateway_budget.py`). Tested: the tenant is blocked about a minute after crossing its
threshold, other tenants keep working. Call `POST /ai-gateway/mlflow/v1/chat/completions` (legacy
`/serving-endpoints` calls aren't covered) and send `Databricks-Ai-Gateway-Request-Tags` for attribution.

## Files

| File | |
|---|---|
| `proxy_claims.py` | the proxy |
| `mock_idp.py` | local IdP that mints test JWTs |
| `sql/01_rls_mask.sql`, `sql/02_abac.sql` | demo tables, mapping table, filters, masks, ABAC |
| `test_direct.py`, `test_proxy.py` | personas without and with the proxy |
| `token_exchange.py` | safe vs risky SP federation policy (account admin) |
| `ai_gateway_budget.py` | per-tenant model services + budget |

Proof of concept, not an official Databricks project.
