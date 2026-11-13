#!/usr/bin/env bash
# Run the JDBC (Thrift) test through the Token Federation Proxy as an EXTERNAL
# client. Downloads the OSS Databricks JDBC driver, mints a CIAM JWT from the
# mock IdP, compiles JdbcTest.java, and runs it.
#
# Requires: Java (javac/java) on PATH, the mock IdP + proxy running, and either
#   (a) a TLS path to the proxy (the included tls_relay.py for local testing, or
#   (b) the proxy behind a real HTTPS tunnel on 443 — then set PROXY_PORT=443
#       ALLOW_SELF_SIGNED=0 PROXY_HOST=<tunnel-host>).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

DRIVER_VERSION="${DRIVER_VERSION:-3.4.1}"
# Default: Maven Central. Inside Databricks (Central is blocked) use the mirror:
#   DRIVER_URL=https://repo1.maven.org/maven2/com/databricks/databricks-jdbc/$DRIVER_VERSION/databricks-jdbc-$DRIVER_VERSION.jar
DRIVER_URL="${DRIVER_URL:-https://repo1.maven.org/maven2/com/databricks/databricks-jdbc/$DRIVER_VERSION/databricks-jdbc-$DRIVER_VERSION.jar}"
JAR="$HERE/databricks-jdbc-$DRIVER_VERSION.jar"

IDP="${IDP:-http://localhost:8082}"
USER_EMAIL="${USER_EMAIL:-dave@contoso.test}"

# These are read by JdbcTest.java (exported so they reach the JVM):
export PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
export PROXY_PORT="${PROXY_PORT:-9443}"
export HTTP_PATH="${HTTP_PATH:-/sql/1.0/warehouses/<warehouse-id>}"
export CATALOG="${CATALOG:-tokenfed_poc}"
export ALLOW_SELF_SIGNED="${ALLOW_SELF_SIGNED:-1}"

if [ ! -f "$JAR" ]; then
  echo "Downloading Databricks JDBC driver $DRIVER_VERSION ..."
  curl -fsSL "$DRIVER_URL" -o "$JAR"
fi

echo "Minting CIAM JWT for $USER_EMAIL ..."
JWT="$(curl -fsS "$IDP/mint?user=$USER_EMAIL" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')"

javac -d "$HERE" "$HERE/JdbcTest.java"
java -cp "$JAR:$HERE" JdbcTest "$JWT"
