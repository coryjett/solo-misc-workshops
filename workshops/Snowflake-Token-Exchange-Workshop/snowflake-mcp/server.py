"""Mock Snowflake MCP server.

This server lives behind two AGW Enterprise policies on the same HTTPRoute:

  1. ``entExtAuth`` -> AuthConfig -> Keycloak ``/introspect``
     reads the ``Authorization`` header, surfaces the user id upstream as
     ``x-user-id``.
  2. ``jwtAuthentication`` with ``location.header.name=aembitauth``
     reads the ``aembitauth`` header, validates the JWT against an inline
     JWKS, and strips the header from the upstream request after success.

The server's job around identity is to read ``x-user-id``, log every
``x-*`` header, AND log whether each auth-bearing header (``authorization``,
``aembitauth``) is present or stripped — so workshop attendees can see the
gateway behavior without this server ever seeing either token directly.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import json
import sys
import time
import uuid

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

SESSION_ID = str(uuid.uuid4())


AUTH_HEADER_NAMES = ("authorization", "aembitauth")


def log_identity(headers) -> dict:
    """Log the identity-related headers the gateway injected, and prove
    that auth-bearing headers were stripped before they reached us.

    The dual-policy demo wires up two independent auth mechanisms at AGW:

      Authorization: Bearer <Keycloak user token>   → ext-auth introspection.
                                                      The user identity is
                                                      surfaced upstream as
                                                      `x-user-id` (controlled
                                                      by `userIdAttributeName`
                                                      in the AuthConfig).
      aembitauth:    <workload JWT>                  → local JWKS validation
                                                      via `jwtAuthentication`
                                                      with `location.header
                                                      .name=aembitauth`.

    After successful JWT validation the gateway calls `location.remove(req)`
    so the upstream sees no `aembitauth` header. We log every `x-*` header
    plus an explicit "stripped?" line for each auth-bearing header so the
    behavior is visible in the workshop logs.
    """
    primary = headers.get("x-user-id", "")
    x_headers = {k.lower(): v for k, v in headers.items() if k.lower().startswith("x-")}
    auth_present = {
        name: headers.get(name) for name in AUTH_HEADER_NAMES if headers.get(name)
    }

    sys.stderr.write("\n" + "=" * 60 + "\n")
    sys.stderr.write("SNOWFLAKE MCP SERVER — headers from AGW\n")
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.write(f"  x-user-id:  {primary or '(missing — extauth did not propagate)'}\n")
    sys.stderr.write("  auth headers visible upstream:\n")
    for name in AUTH_HEADER_NAMES:
        if name in auth_present:
            sys.stderr.write(f"    {name}: {auth_present[name][:24]}... (NOT stripped)\n")
        else:
            sys.stderr.write(f"    {name}: (stripped by gateway ✓)\n")
    sys.stderr.write("  all x-* headers:\n")
    for k in sorted(x_headers):
        sys.stderr.write(f"    {k}: {x_headers[k]}\n")
    sys.stderr.write("=" * 60 + "\n\n")
    sys.stderr.flush()

    return {
        "x-user-id": primary,
        "x_headers": x_headers,
        "auth_headers_visible_upstream": list(auth_present.keys()),
    }


def build_response(method, req_id, req, identity):
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "snowflake-mcp", "version": "2.0"},
            },
        }
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
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
                ],
            },
        }
    if method == "tools/call":
        tool_name = req.get("params", {}).get("name", "")
        if tool_name == "query_sales":
            result = {
                "identity_from_gateway": identity,
                "message": (
                    "Identity was introspected at AGW via entExtAuth -> AuthConfig "
                    "-> Keycloak /introspect. The dual-policy companion validates a "
                    "second JWT from the aembitauth header via jwtAuthentication. "
                    "This server never sees either token — it just receives the "
                    "x-user-id header set by extauth."
                ),
                "query_result": MOCK_SALES,
            }
        elif tool_name == "list_tables":
            result = {
                "identity_from_gateway": identity,
                "tables": MOCK_TABLES,
            }
        else:
            result = {"error": f"Unknown tool: {tool_name}"}
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
        }
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown: {method}"}}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Mcp-Session-Id", SESSION_ID)
        self.end_headers()
        try:
            while True:
                time.sleep(30)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        accept = self.headers.get("Accept", "")
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()

        identity = log_identity(self.headers)

        try:
            req = json.loads(body)
        except Exception:
            req = {}

        method = req.get("method", "")
        req_id = req.get("id")

        if method == "notifications/initialized":
            self.send_response(204)
            self.send_header("Mcp-Session-Id", SESSION_ID)
            self.end_headers()
            return

        resp = build_response(method, req_id, req, identity)

        if "text/event-stream" in accept:
            sse_bytes = (f"event: message\ndata: {json.dumps(resp)}\n\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Mcp-Session-Id", SESSION_ID)
            self.end_headers()
            self.wfile.write(sse_bytes)
            self.wfile.flush()
        else:
            out = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.send_header("Mcp-Session-Id", SESSION_ID)
            self.end_headers()
            self.wfile.write(out)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[HTTP] {args[0]} {args[1]} {args[2]}\n")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    sys.stderr.write("Snowflake MCP server starting on :80 (introspection-by-gateway flow)\n")
    sys.stderr.flush()
    ThreadedHTTPServer(("", 80), Handler).serve_forever()
