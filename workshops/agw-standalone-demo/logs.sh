#!/usr/bin/env bash
# Live, readable audit trail from the gateway: who called which tool or model, tokens, cost, and what happened.
# Usage: ./logs.sh            (Ctrl-C to stop)      ./logs.sh all   (replay everything so far, then follow)
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
N=0; [ "${1:-}" = all ] && N=+1
tail -n "$N" -f "$DIR/.run/gateway.log" | python3 -u "$DIR/tools/logfmt.py"
