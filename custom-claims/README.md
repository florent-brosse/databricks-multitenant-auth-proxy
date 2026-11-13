# Custom identity claims mode: one service principal, many end users

The main proxy in this repo exchanges each end user's IdP JWT for a token of a **Databricks user**
(one Databricks identity per end user, provisioned via SCIM). That works, but every end user has to
exist in Databricks: provisioning, lifecycle, and the account identity limits.

[OAuth custom identity claims](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-custom-identity-claims)
remove that step. The proxy requests a token for **one service principal** and adds
`custom_claim=<end user id>`. Databricks signs the value into the token, and SQL reads it with
[`current_oauth_custom_identity_claim()`](https://docs.databricks.com/aws/en/sql/language-manual/functions/current_oauth_custom_identity_claim)
in row filters, column masks, dynamic views and ABAC policies.

```
end user ──IdP JWT──▶ proxy_claims.py
                        1. validates the JWT itself (JWKS signature, iss, aud, exp)
                        2. reads the user id (sub) and checks it is a plain ASCII id
                        3. POST /oidc/v1/token  grant_type=client_credentials (shared SP)
                                                custom_claim=<user id>
                        4. forwards the request with the SP token (cached per user)
Databricks SQL ──▶ current_user() = the SP, current_oauth_custom_identity_claim() = <user id>
                ──▶ row filter / mask / ABAC joins a mapping table user → tenant, scope, rights
```

## Which mode?

| | User-level exchange (main proxy) | Custom claim + SP secret | Custom claim + token exchange |
|---|---|---|---|
| What Databricks validates | the end user's IdP JWT, and that the user exists | the SP secret | the proxy's own JWT (SP federation policy) |
| Who vouches for the end user | Databricks | the proxy | the proxy |
| Databricks identity per end user | yes | no | no |
| Secret stored in the proxy | none | SP OAuth secret | none on the Databricks side |
| `current_user()` / query history | the end user | the SP | the SP |

Token exchange only removes the Databricks secret. It is worth it when the proxy runs on a platform
that gives it a secretless identity (Kubernetes service account token, cloud workload identity).
Otherwise the secret just moves to the IdP.

## What was tested (AWS, SQL warehouse, Nov 2026)

- Row filter + column mask driven by the claim and a mapping table (`sql/01_rls_mask.sql`):
  each user sees only their tenant and scope, a token without claim or an unknown user gets 0 rows,
  the SP has no access to the mapping table.
- Same results over **REST** (Statement Execution API) and **Thrift** (databricks-sql-connector, the
  protocol used by ODBC/JDBC drivers), directly and through `proxy_claims.py` (Bearer and Basic `token:<JWT>`).
- **ABAC** (`sql/02_abac.sql`): one schema-level policy covers every tagged table; policies target only
  the SP so data owners keep full access.
- **Token exchange** (`token_exchange.py`): the proxy exchanges its own JWT and gets a token with the
  claim; an end user presenting their own JWT is refused (`TOKEN_SUBJECT_INVALID`).
- **LLM cost cap per tenant** with one SP (`ai_gateway_budget.py`), see below.

Not tested: Power BI Desktop itself, the ADBC driver, Cloud Fetch on large results. The custom claims
doc lists JDBC, the SQL Statement Execution API and the Genie Agents API as supported surfaces.

## Security notes

1. **The proxy chooses the claim, so it must validate the IdP JWT itself.** Databricks signs whatever
   `custom_claim` the token request contains.
2. **The SP credential opens every tenant.** Keep it in a secret manager, rotate it, and restrict
   Databricks access to the proxy (IP access lists or front-end Private Link).
3. **Never let an SP federation policy accept end-user JWTs.** With `subject_claim` set to a claim that
   is identical for all users (for example the app client id `azp`), any user can exchange their own
   JWT and ask for someone else's claim: `token_exchange.py` shows a user reading another tenant's rows.
   Trust only the proxy's identity (`subject = <proxy id>`).
4. **Use a plain ASCII, non-empty identifier as claim** (the IdP's opaque user id rather than an email).
   In our tests non-ASCII characters were not preserved and an empty claim was read as `''`, not NULL.
   `proxy_claims.py` rejects anything else.
5. **Write filters so a NULL claim matches nothing**: plain `=`, no `IS NULL`, `coalesce` or `<=>`.
6. **ABAC: an untagged table is fully visible to the SP.** The tag is the security boundary.
7. **Audit**: query history shows the SP. Log `user → request` in the proxy (`[audit]` lines).
8. For strong tenant isolation (for example HR data), consider one SP per tenant (hard boundary with
   GRANTs) and the claim for per-user rights inside the tenant.

## LLM costs with Unity Gateway

Unity Gateway [budgets](https://docs.databricks.com/aws/en/ai-gateway/budgets) (monthly USD, optional
**block usage**) key on the Databricks principal or on **model service tags**. The custom claim and
request tags do not affect budget matching, so with one SP and one endpoint all tenants share one budget.

Per-tenant cap with one SP, tested:

- one model service per tenant (same model behind), tagged `tenant=<id>`;
- one Unity Gateway budget per tenant filtered on that tag, with block usage;
- the proxy routes each tenant to its model service:
  `POST /ai-gateway/mlflow/v1/chat/completions` with `"model": "<catalog>.<schema>.tenant_<id>"`.

Result with a $0.20 threshold: the tenant was blocked at about $0.25, about a minute after crossing
the threshold (`403 PERMISSION_DENIED: Budget ... has reached its limit`), the other tenant on the same
SP kept working, and the email alert arrived at the same time. Enforcement is approximate by design,
treat it as a guardrail.

- Attribution per tenant / end user: send `Databricks-Ai-Gateway-Request-Tags: {"tenant": "...", "end_user": "..."}`.
- Per end user caps: count tokens from each response in the proxy.
- Calls to legacy `/serving-endpoints/...` URLs are not covered by Unity Gateway budgets.
- The SP calling models needs the `workspace-access` entitlement (`databricks-sql-access` is enough for SQL):
  a separate SP for LLM calls keeps the SQL one minimal.
- Tags work the same way per project (`project=<x>`): one budget can cover several model services sharing a tag.

## Files

| File | What it does |
|---|---|
| `proxy_claims.py` | transparent forwarder: validates the IdP JWT, mints SP token with `custom_claim`, forwards |
| `sql/01_rls_mask.sql` | demo table, mapping table, row filter and column mask on the claim |
| `sql/02_abac.sql` | ABAC variant with governed tags |
| `test_direct.py` | personas over REST and Thrift, no proxy |
| `test_proxy.py` | same through the proxy + forged / expired / non-ASCII tokens |
| `token_exchange.py` | SAFE vs RISKY SP federation policy (needs account admin) |
| `ai_gateway_budget.py` | per-tenant model services + tag budget with block usage |

Environment variables are listed at the top of each script. The mock IdP is `../proxy/mock_idp.py`.

This is a proof of concept, not an official Databricks project.
