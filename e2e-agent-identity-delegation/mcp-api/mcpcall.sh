#!/usr/bin/env bash
# Calls the mcp-api tool through the gateway with the given bearer token and prints the API status the tool saw.
# Usage: mcp-api/mcpcall.sh <token> [gateway-host:port] [route-path] [api-path]
set -euo pipefail
T="$1"; GW="${2:-e2e-gw.e2e-demo.svc.cluster.local:8080}"; ROUTE="${3:-/mcp-api}"; APIPATH="${4:-/get}"
K() { kubectl exec -n wp-a deploy/sleep -- sh -c "$1"; }
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ws","version":"1.0"}}}'
CALL="{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"httpbin_get\",\"arguments\":{\"path\":\"$APIPATH\"}}}"
H="-H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' -H 'Authorization: Bearer $T'"
SID=$(K "curl -s -D - -o /dev/null -X POST $H -d '$INIT' http://$GW$ROUTE" | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}' | tr -d '\r')
[ -n "$SID" ] || { echo "no MCP session (gateway returned $(K "curl -s -o /dev/null -w '%{http_code}' -X POST $H -d '$INIT' http://$GW$ROUTE"))"; exit 1; }
K "curl -s -o /dev/null -X POST $H -H 'mcp-session-id: $SID' -d '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}' http://$GW$ROUTE"
K "curl -s -X POST $H -H 'mcp-session-id: $SID' -d '$CALL' http://$GW$ROUTE" | sed -n 's/^data: //p' | python3 -c '
import sys,json
for line in sys.stdin:
    line=line.strip()
    if not line.startswith("{"): continue
    d=json.loads(line)
    if "result" in d:
        txt=d["result"].get("content",[{}])[0].get("text","")
        print(txt.splitlines()[0] if txt else d["result"])
    elif "error" in d:
        print("error:", d["error"])'
