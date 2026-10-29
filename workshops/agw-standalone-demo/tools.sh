#!/usr/bin/env bash
# Starts (or stops) the demo's backend systems as plain local processes, no containers:
#   records   MCP server (customer PII, one destructive tool)      127.0.0.1:$RECORDS_PORT/mcp
#   inventory MCP server                                            127.0.0.1:$INVENTORY_PORT/mcp
#   ops-api   plain REST API + OpenAPI (the gateway turns it into MCP tools)   127.0.0.1:$OPSAPI_PORT
#   guard     AI prompt-injection judge (webhook guardrail)        127.0.0.1:$GUARD_PORT
# Usage: ./tools.sh start | stop | status
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
RUN="$DIR/.run"; mkdir -p "$RUN"
VENV="$DIR/.venv"

start_one() {  # name port cmd...
  local name="$1" port="$2"; shift 2
  if [ -f "$RUN/$name.pid" ] && kill -0 "$(cat "$RUN/$name.pid")" 2>/dev/null; then echo "$name: already running (pid $(cat "$RUN/$name.pid"))"; return; fi
  lsof -ti tcp:"$port" | xargs kill 2>/dev/null || true
  (cd "$DIR/tools" && PORT="$port" exec nohup "$@" > "$RUN/$name.log" 2>&1 < /dev/null) &   # detached, no lingering wrapper
  for i in $(seq 1 40); do curl -s -o /dev/null -m 1 "http://127.0.0.1:$port/" && break; sleep 0.25; done
  lsof -ti tcp:"$port" -sTCP:LISTEN | head -1 > "$RUN/$name.pid"   # the listening process, not a shell wrapper
  [ -s "$RUN/$name.pid" ] || { echo "$name failed to start:" >&2; tail -5 "$RUN/$name.log" >&2; exit 1; }
  echo "$name: pid $(cat "$RUN/$name.pid") on 127.0.0.1:$port"
}

case "${1:-start}" in
  start)
    [ -x "$VENV/bin/python" ] || { python3 -m venv "$VENV" && "$VENV/bin/pip" install -q "mcp[cli]==1.*" fastapi "uvicorn[standard]"; }
    load_openai_key; load_local_llm_key
    start_one records   "$RECORDS_PORT"   "$VENV/bin/python" records.py
    start_one inventory "$INVENTORY_PORT" "$VENV/bin/python" inventory.py
    start_one opsapi    "$OPSAPI_PORT"    "$VENV/bin/uvicorn" ops_api:app --host 127.0.0.1 --port "$OPSAPI_PORT" --log-level warning
    OPENAI_AUTH="Bearer $OPENAI_API_KEY" LOCAL_LLM_BASE_URL="$LOCAL_LLM_BASE_URL" LOCAL_LLM_MODEL="$LOCAL_LLM_MODEL" LOCAL_LLM_KEY="${LOCAL_LLM_KEY:-}" JUDGE="${JUDGE:-openai}" \
      start_one guard "$GUARD_PORT" "$VENV/bin/python" injection_guard.py
    # OpenAPI spec for the gateway's OpenAPI-to-MCP target, taken from the running API (3.0.x for the gateway).
    curl -s "http://127.0.0.1:$OPSAPI_PORT/openapi.json" | python3 -c 'import json,sys; d=json.load(sys.stdin); d["openapi"]="3.0.3"; print(json.dumps(d, indent=1))' > "$DIR/gateway/opsapi-openapi.json"
    echo "opsapi-openapi.json: $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["paths"]))' "$DIR/gateway/opsapi-openapi.json") operations";;
  stop)
    for f in "$RUN"/*.pid; do [ -f "$f" ] || continue; kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
    for p in "$RECORDS_PORT" "$INVENTORY_PORT" "$OPSAPI_PORT" "$GUARD_PORT"; do lsof -ti tcp:"$p" | xargs kill 2>/dev/null || true; done
    echo "tools stopped";;
  status)
    for n in records inventory opsapi guard; do
      if [ -f "$RUN/$n.pid" ] && kill -0 "$(cat "$RUN/$n.pid")" 2>/dev/null; then echo "$n: up (pid $(cat "$RUN/$n.pid"))"; else echo "$n: down"; fi
    done;;
esac
