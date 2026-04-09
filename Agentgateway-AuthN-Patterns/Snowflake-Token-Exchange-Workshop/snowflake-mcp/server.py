from http.server import BaseHTTPRequestHandler, HTTPServer
import json, os, sys, urllib.request, urllib.parse

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak.keycloak.svc.cluster.local:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "snowflake-workshop")
INTROSPECT_CLIENT_ID = os.environ.get("INTROSPECT_CLIENT_ID", "agw-exchange")
INTROSPECT_CLIENT_SECRET = os.environ.get("INTROSPECT_CLIENT_SECRET", "agw-exchange-secret")

INTROSPECT_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"

MOCK_SALES = [
    {"region": "WEST", "total_sales": 142500, "quarter": "Q1"},
    {"region": "EAST", "total_sales": 198300, "quarter": "Q1"},
    {"region": "CENTRAL", "total_sales": 167800, "quarter": "Q1"},
]

MOCK_TABLES = [
    {"schema": "SALES", "name": "ORDERS", "row_count": 15420},
    {"schema": "SALES", "name": "CUSTOMERS", "row_count": 3200},
    {"schema": "ANALYTICS", "name": "DAILY_REVENUE", "row_count": 365},
]

def introspect_token(token):
    """Call Keycloak's introspection endpoint to validate an opaque token."""
    data = urllib.parse.urlencode({
        "token": token,
        "client_id": INTROSPECT_CLIENT_ID,
        "client_secret": INTROSPECT_CLIENT_SECRET,
    }).encode()
    req = urllib.request.Request(INTROSPECT_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        sys.stderr.write(f"Introspection failed: {e}\n")
        return {"active": False, "error": str(e)}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()

        # Extract token and introspect
        token = auth[7:] if auth.startswith("Bearer ") else None
        introspection = None
        if token:
            # Check if this looks like a JWT (3 dot-separated parts) or opaque
            is_jwt = len(token.split(".")) == 3
            token_type = "jwt" if is_jwt else "opaque"
            introspection = introspect_token(token)
            sys.stderr.write(
                f"\n{'='*50}\n"
                f"SNOWFLAKE MCP SERVER\n"
                f"  token_type: {token_type}\n"
                f"  active: {introspection.get('active')}\n"
                f"  sub: {introspection.get('sub', 'n/a')}\n"
                f"  client_id: {introspection.get('client_id', 'n/a')}\n"
                f"{'='*50}\n"
            )
            sys.stderr.flush()

        try:
            req = json.loads(body)
        except Exception:
            req = {}

        method = req.get("method", "")
        req_id = req.get("id")

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "snowflake-mcp", "version": "1.0"},
                },
            }
        elif method == "notifications/initialized":
            self.send_response(200)
            self.end_headers()
            return
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "query_sales",
                            "description": "Query sales data from Snowflake. Returns sales totals by region.",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                        {
                            "name": "list_tables",
                            "description": "List available tables in Snowflake.",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                    ]
                },
            }
        elif method == "tools/call":
            tool_name = req.get("params", {}).get("name", "")
            if not introspection or not introspection.get("active"):
                result = {"error": "Token introspection failed — access denied", "introspection": introspection}
            elif tool_name == "query_sales":
                result = {
                    "token_type": token_type,
                    "introspection": {
                        "active": introspection.get("active"),
                        "sub": introspection.get("sub"),
                        "scope": introspection.get("scope"),
                        "client_id": introspection.get("client_id"),
                    },
                    "query_result": MOCK_SALES,
                }
            elif tool_name == "list_tables":
                result = {
                    "token_type": token_type,
                    "introspection": {
                        "active": introspection.get("active"),
                        "sub": introspection.get("sub"),
                    },
                    "tables": MOCK_TABLES,
                }
            else:
                result = {"error": f"Unknown tool: {tool_name}"}
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
            }
        else:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown: {method}"}}

        out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, format, *args):
        pass  # Suppress default access logs


if __name__ == "__main__":
    print(f"Snowflake MCP server starting on :80")
    print(f"  Introspection endpoint: {INTROSPECT_URL}")
    HTTPServer(("", 80), Handler).serve_forever()
