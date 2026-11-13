/*
 * JDBC (Thrift over HTTP) smoke test through the Token Federation Proxy.
 *
 * Represents a real EXTERNAL ISV client (a BI tool / Java app on the customer
 * side) — NOT something you'd run inside a Databricks notebook. The client
 * holds only the CIAM JWT and points at the proxy; the proxy swaps the auth
 * header and Unity Catalog enforces RLS + masks.
 *
 * Auth: AuthMech=3 with UID=token, PWD=<CIAM JWT>. The OSS Databricks JDBC
 * driver sends this as HTTP Basic(token:<JWT>), which the proxy understands
 * (see proxy.py _extract_ciam_jwt). This is the same scheme Simba ODBC / older
 * Power BI use.
 *
 * Config via env vars (all optional except the JWT arg):
 *   PROXY_HOST          default 127.0.0.1
 *   PROXY_PORT          default 9443   (local TLS relay; use 443 for a tunnel)
 *   HTTP_PATH           default /sql/1.0/warehouses/<warehouse-id>
 *   CATALOG             default tokenfed_poc
 *   ALLOW_SELF_SIGNED   default 1      (set 0 when pointing at a real cert/tunnel)
 *
 * Usage: java -cp databricks-jdbc-<ver>.jar:. JdbcTest <CIAM_JWT>
 */
import java.sql.*;

public class JdbcTest {

    static String env(String k, String d) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? d : v;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: JdbcTest <CIAM_JWT>");
            System.exit(2);
        }
        String jwt = args[0];
        String host = env("PROXY_HOST", "127.0.0.1");
        String port = env("PROXY_PORT", "9443");
        String httpPath = env("HTTP_PATH", "/sql/1.0/warehouses/<warehouse-id>");
        String catalog = env("CATALOG", "tokenfed_poc");
        boolean selfSigned = env("ALLOW_SELF_SIGNED", "1").equals("1");
        // Optional: override the query (e.g. a large result to exercise Cloud
        // Fetch / multi-chunk) and cap how many rows are printed.
        String sqlOverride = env("SQL", "");
        int maxPrint = Integer.parseInt(env("MAX_PRINT", "50"));

        String url = "jdbc:databricks://" + host + ":" + port + "/default"
            + ";transportMode=http;ssl=1"
            + ";httpPath=" + httpPath
            + ";AuthMech=3;UID=token;PWD=" + jwt
            + ";LogLevel=0"
            + (selfSigned ? ";AllowSelfSignedCerts=1" : "");

        System.out.println("Driver: "
            + DriverManager.getDriver("jdbc:databricks://x").getClass().getName());

        long t0 = System.currentTimeMillis();
        try (Connection conn = DriverManager.getConnection(url)) {
            long c1 = System.currentTimeMillis();
            System.out.printf("Connected in %d ms%n", c1 - t0);
            String sql = sqlOverride.isEmpty()
                ? "SELECT employee_id, name, department, salary, ssn FROM "
                    + catalog + ".contoso.employees ORDER BY employee_id"
                : sqlOverride;
            try (Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery(sql)) {
                long c2 = System.currentTimeMillis();
                System.out.printf("Query returned in %d ms%n%n", c2 - c1);
                int cols = rs.getMetaData().getColumnCount();
                int n = 0;
                while (rs.next()) {           // iterate ALL rows -> forces every chunk/fetch
                    n++;
                    if (n <= maxPrint) {
                        StringBuilder sb = new StringBuilder("  ");
                        for (int i = 1; i <= cols; i++) {
                            if (i > 1) sb.append(" | ");
                            sb.append(rs.getString(i));
                        }
                        System.out.println(sb);
                    }
                }
                long c3 = System.currentTimeMillis();
                System.out.printf("%n%d rows (fetched all in %d ms).%n", n, c3 - c2);
            }
        }
    }
}
