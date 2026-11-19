#!/usr/bin/env bash
# Opens MCP Inspector (stand-in for Cursor/Claude/any MCP client) connected to a gateway MCP endpoint as a user.
# Usage: ./inspector.sh <user> [url]      users: eng-dev sales-dev approver admin auditor
#   ./inspector.sh eng-dev                                  the platform's federated endpoint (/mcp)
#   ./inspector.sh eng-dev http://localhost:8081/registry/records   a registry-published server
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
USER_NAME="${1:-eng-dev}"; MCP_URL="${2:-$MCP_URL}"
TOK="$(token "$USER_NAME")"
for p in 6274 6275 6277; do lsof -ti tcp:$p | xargs kill 2>/dev/null || true; done
echo "MCP Inspector as ${USER_NAME}: http://127.0.0.1:6274  (Ctrl-C to stop)"
DANGEROUSLY_OMIT_AUTH=true MCP_AUTO_OPEN_ENABLED=false exec npx -y @modelcontextprotocol/inspector@2.13.0 --web \
  --transport http --server-url "$MCP_URL" --header "Authorization: Bearer ${TOK}"
