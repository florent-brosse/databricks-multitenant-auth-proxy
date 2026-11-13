"""One shared SP, one token per end user (custom_claim). REST and Thrift, no proxy.
Env: DATABRICKS_HOST, WAREHOUSE_ID, SP_CLIENT_ID, SP_CLIENT_SECRET, CLAIMS_SCHEMA."""
from common import *
from databricks import sql

Q_DATA = f"SELECT tenant_id, department, full_name, salary FROM {SCHEMA}.hr_employees ORDER BY employee_id"
USERS = ["alice@acme.test", "bob@acme.test", "carol@globex.test", "mallory@unknown.test", None]

print("JWT 'custom' field:", jwt_payload(sp_token("alice@acme.test")).get("custom"))
for proto in ("REST (Statement Execution API)", "Thrift (databricks-sql-connector, same protocol as ODBC/JDBC)"):
    print(f"\n== {proto}")
    for claim in USERS:
        at = sp_token(claim)
        if proto.startswith("REST"):
            rows = rest_sql(HOST, at, Q_DATA)
        else:
            with sql.connect(server_hostname=HOST.split("//")[1], http_path=f"/sql/1.0/warehouses/{WAREHOUSE_ID}",
                             access_token=at) as c, c.cursor() as cur:
                cur.execute(Q_DATA); rows = [list(r) for r in cur.fetchall()]
        print(f"  claim={str(claim):22} -> {len(rows) if isinstance(rows, list) else rows} rows {rows if isinstance(rows, list) else ''}")

at = sp_token("alice@acme.test")
print("\nSP reads the mapping table directly:", rest_sql(HOST, at, f"SELECT * FROM {SCHEMA}.user_access"))
