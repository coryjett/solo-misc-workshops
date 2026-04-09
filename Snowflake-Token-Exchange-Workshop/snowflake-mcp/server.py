"""Mock Snowflake MCP server with opaque token introspection.

Receives opaque tokens from AGW (after external STS exchange) and
introspects them against the external STS to resolve identity.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import json, os, sys, urllib.request, urllib.parse, uuid, base64, time

INTROSPECT_URL = os.environ.get(
    "INTROSPECT_URL",
    "http://external-sts.default.svc.cluster.local:9000/introspect",
)

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


def is_jwt(token):
    return token.count('.') == 2


def decode_jwt_payload(token):
    try:
        payload = token.split('.')[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def introspect_token(token):
    """Call external STS introspection endpoint (RFC 7662)."""
    try:
        data = urllib.parse.urlencode({"token": token}).encode()
        req = urllib.request.Request(INTROSPECT_URL, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        sys.stderr.write(f"Introspection failed: {e}\n")
        return {"active": False, "error": str(e)}


def process_token(token):
    """Process incoming token — introspect if opaque, decode if JWT."""
    if is_jwt(token):
        claims = decode_jwt_payload(token)
        sys.stderr.write(f"RECEIVED JWT (unexpected — exchange may not have happened)\n")
        sys.stderr.flush()
        return {"type": "jwt", "claims": claims}

    intro = introspect_token(token)
    status = "ACTIVE" if intro.get("active") else "NOT ACTIVE"
    sys.stderr.write(f"RECEIVED OPAQUE ({len(token)} chars) -> introspect: {status}\n")
    sys.stderr.flush()
    return {"type": "opaque", "introspection": intro}


def build_response(method, req_id, req, token_info, raw_token):
    """Build the JSON-RPC response for a given MCP method."""
    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "snowflake-mcp", "version": "1.0"},
            },
        }
    elif method == "tools/list":
        return {
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
        intro = token_info.get("introspection", {}) if token_info.get("type") == "opaque" else {}

        if token_info.get("type") == "opaque" and not intro.get("active"):
            result = {"error": "Token validation failed — access denied", "details": intro}
        elif tool_name == "query_sales":
            result = {
                "token_info": {
                    "token_type": token_info["type"],
                    "token_length": len(raw_token),
                    "is_jwt": is_jwt(raw_token) if raw_token else False,
                },
                "identity": {
                    "active": intro.get("active"),
                    "sub": intro.get("sub"),
                    "username": intro.get("username"),
                    "iss": intro.get("iss"),
                    "original_issuer": intro.get("original_issuer"),
                } if token_info.get("type") == "opaque" else {},
                "message": "Opaque token received. Identity resolved via RFC 7662 introspection."
                    if token_info.get("type") == "opaque"
                    else "JWT received (unexpected — exchange may not have happened).",
                "query_result": MOCK_SALES,
            }
        elif tool_name == "list_tables":
            result = {
                "token_info": {
                    "token_type": token_info["type"],
                    "is_jwt": is_jwt(raw_token) if raw_token else False,
                },
                "identity": {
                    "active": intro.get("active"),
                    "sub": intro.get("sub"),
                    "username": intro.get("username"),
                } if token_info.get("type") == "opaque" else {},
                "tables": MOCK_TABLES,
            }
        else:
            result = {"error": f"Unknown tool: {tool_name}"}
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
        }
    else:
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
        auth = self.headers.get("Authorization", "")
        accept = self.headers.get("Accept", "")
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()

        raw_token = auth[7:] if auth.startswith("Bearer ") else ""
        token_info = {"type": "none"}
        if raw_token:
            token_info = process_token(raw_token)
            sys.stderr.write(
                f"\n{'='*50}\n"
                f"SNOWFLAKE MCP SERVER\n"
                f"  token_type: {token_info['type']}\n"
            )
            if token_info["type"] == "opaque":
                intro = token_info.get("introspection", {})
                sys.stderr.write(
                    f"  active: {intro.get('active')}\n"
                    f"  sub: {intro.get('sub', 'n/a')}\n"
                    f"  username: {intro.get('username', 'n/a')}\n"
                )
            sys.stderr.write(f"{'='*50}\n")
            sys.stderr.flush()

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

        resp = build_response(method, req_id, req, token_info, raw_token)

        if "text/event-stream" in accept:
            out = json.dumps(resp)
            sse_data = f"event: message\ndata: {out}\n\n"
            sse_bytes = sse_data.encode()
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

    def log_message(self, format, *args):
        sys.stderr.write(f"[HTTP] {args[0]} {args[1]} {args[2]}\n")


if __name__ == "__main__":
    sys.stderr.write(f"Snowflake MCP server starting on :80\n")
    sys.stderr.write(f"  Introspection endpoint: {INTROSPECT_URL}\n")
    sys.stderr.flush()
    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
    ThreadedHTTPServer(("", 80), Handler).serve_forever()
