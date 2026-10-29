#!/usr/bin/env python3
"""Tiny MCP client for the demo (terminal fallback for MCP Inspector).
  ./mcp.py <user|none> list
  ./mcp.py <user|none> call <tool> '<json args>'
Gets a Keycloak token for <user> (password = username), does the MCP handshake against the gateway, prints the result."""
import json, os, sys, urllib.request, urllib.parse, urllib.error

ISSUER = os.environ.get("OIDC_ISSUER", "http://keycloak.localhost:8080/realms/demo")
URL = os.environ.get("MCP_URL", "http://localhost:8081/mcp")

def token(user):
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "mcp-inspector", "username": user,
                                   "password": user, "scope": "openid"}).encode()
    return json.load(urllib.request.urlopen(ISSUER + "/protocol/openid-connect/token", data))["access_token"]

def rpc(method, params, tok, sid=None, notify=False):
    body = {"jsonrpc": "2.0", "method": method, "params": params}
    if not notify: body["id"] = 1
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if tok: h["Authorization"] = "Bearer " + tok
    if sid: h["Mcp-Session-Id"] = sid
    try:
        r = urllib.request.urlopen(urllib.request.Request(URL, json.dumps(body).encode(), h))
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code}: {e.read().decode()[:300]}")
    raw = r.read().decode()
    sid = r.headers.get("Mcp-Session-Id", sid)
    if notify or not raw.strip(): return None, sid
    for line in raw.splitlines():
        if line.startswith("data:"): raw = line[5:]
    return json.loads(raw), sid

user, op = sys.argv[1], sys.argv[2]
tok = None if user == "none" else token(user)
_, sid = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agw-demo", "version": "1"}}, tok)
rpc("notifications/initialized", {}, tok, sid, notify=True)
if op == "list":
    res, _ = rpc("tools/list", {}, tok, sid)
    if "error" in res: sys.exit(json.dumps(res["error"]))
    tools = [t["name"] for t in res["result"]["tools"]]
    print(f"{user}: {len(tools)} tools"); [print("  " + t) for t in sorted(tools)]
else:
    res, _ = rpc("tools/call", {"name": sys.argv[3], "arguments": json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}}, tok, sid)
    if "error" in res: print("DENIED/ERROR:", json.dumps(res["error"])); sys.exit(0)
    for c in res["result"].get("content", []): print(c.get("text", c))
    if res["result"].get("isError"): print("(isError)")
