#!/usr/bin/env bash
# Stops everything. Add --purge to also delete the request database, rendered config and secrets (fresh start).
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
"$DIR/gateway.sh" stop
"$DIR/tools.sh" stop
"$DIR/keycloak.sh" stop
for p in 6274 6275 6277; do lsof -ti tcp:$p | xargs kill 2>/dev/null || true; done   # MCP Inspector
if [ "${1:-}" = "--purge" ]; then rm -rf "$DIR/.run" "$DIR/.secrets" "$DIR/gateway/config.yaml" "$DIR/gateway/opsapi-openapi.json"; echo "purged state"; fi
echo "down"
