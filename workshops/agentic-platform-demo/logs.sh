#!/usr/bin/env bash
# Live, readable audit trail from the gateway: who called which tool, and what happened. Ctrl-C to stop.
# Usage: ./logs.sh [since, default 10m]
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
kubectl --context "$KCTX" -n agentgateway-system logs deploy/mcp-gateway -f --since="${1:-10m}" | python3 -u "$DIR/tools/logfmt.py"
