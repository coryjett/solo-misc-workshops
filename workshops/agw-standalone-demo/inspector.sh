#!/usr/bin/env bash
# Opens MCP Inspector (stand-in for any MCP client: Cursor, Claude, Copilot) connected to the gateway's one MCP
# endpoint as a given user. Usage: ./inspector.sh support-agent | ops-manager | security-analyst   (re-run to switch)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
USER_NAME="${1:-support-agent}"
TOK="$(token "$USER_NAME")"
for p in 6274 6275 6277; do lsof -ti tcp:$p | xargs kill 2>/dev/null || true; done
echo "MCP Inspector as ${USER_NAME}: http://127.0.0.1:6274  (Ctrl-C to stop)"
DANGEROUSLY_OMIT_AUTH=true MCP_AUTO_OPEN_ENABLED=false exec npx -y @modelcontextprotocol/inspector --web \
  --transport http --server-url "$MCP_URL" --header "Authorization: Bearer ${TOK}"
