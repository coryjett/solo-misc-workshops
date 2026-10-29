#!/usr/bin/env bash
# Runs Solo Enterprise agentgateway (standalone binary) with gateway/config.yaml, exactly as it would run on a VM.
# Usage: ./gateway.sh start | stop | restart | render | validate | log
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
RUN="$DIR/.run"; mkdir -p "$RUN"
CFG="$DIR/gateway/config.yaml"

install_bin() {
  [ -x "$AGW_BIN" ] && "$AGW_BIN" -V 2>/dev/null | grep -q "$AGW_VERSION" && return 0
  echo "installing enterprise agentgateway $AGW_VERSION to ~/.agentgateway/bin"
  curl -fsSL https://run.solo.io/agentgateway/install | AGENTGATEWAY_VERSION="$AGW_VERSION" sh >/dev/null
}
render_cfg() { render "$DIR/gateway/config.tmpl.yaml" > "$CFG"; }
env_for_run() { load_license; load_openai_key; load_local_llm_key; export OPENAI_API_KEY LOCAL_LLM_KEY; }

case "${1:-start}" in
  render) render_cfg; echo "rendered $CFG";;
  validate) env_for_run; render_cfg; "$AGW_BIN" -f "$CFG" --validate-only 2>&1 | grep -v "^20.*info";;
  start)
    install_bin; env_for_run; render_cfg
    if [ -f "$RUN/gateway.pid" ] && kill -0 "$(cat "$RUN/gateway.pid")" 2>/dev/null; then echo "gateway: already running"; exit 0; fi
    lsof -ti tcp:"$GW_PORT" | xargs kill 2>/dev/null || true; lsof -ti tcp:"$ADMIN_PORT" | xargs kill 2>/dev/null || true
    # exec in a detached subshell with every fd redirected, so no shell wrapper lingers holding the caller's pipes
    (cd "$DIR/gateway" && exec nohup "$AGW_BIN" -f "$CFG" > "$RUN/gateway.log" 2>&1 < /dev/null) &
    for i in $(seq 1 60); do curl -s -o /dev/null -m 1 "http://localhost:${ADMIN_PORT}/config_dump" && break; sleep 0.5; done
    curl -s -o /dev/null -m 2 "http://localhost:${ADMIN_PORT}/config_dump" || { echo "gateway did not come up:" >&2; tail -20 "$RUN/gateway.log" >&2; exit 1; }
    lsof -ti tcp:"$ADMIN_PORT" -sTCP:LISTEN | head -1 > "$RUN/gateway.pid"
    echo "gateway: pid $(cat "$RUN/gateway.pid")  endpoints ${GW_URL}/mcp ${GW_URL}/v1/chat/completions  UI ${UI_URL}";;
  stop) [ -f "$RUN/gateway.pid" ] && kill "$(cat "$RUN/gateway.pid")" 2>/dev/null; rm -f "$RUN/gateway.pid"; lsof -ti tcp:"$GW_PORT" | xargs kill 2>/dev/null || true; echo "gateway stopped";;
  restart) "$0" stop; "$0" start;;
  log) tail -f "$RUN/gateway.log";;
esac
