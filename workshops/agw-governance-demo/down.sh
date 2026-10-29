#!/usr/bin/env bash
# Deletes ONLY this demo's kind cluster ($CLUSTER) and the Open WebUI container.
set -euo pipefail
. "$(dirname "$0")/env.sh"
for p in 6274 6275 6277; do lsof -ti tcp:$p | xargs kill 2>/dev/null || true; done
"$(dirname "$0")/openwebui.sh" down >/dev/null 2>&1 || true
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" && kind delete cluster --name "$CLUSTER" || echo "no cluster $CLUSTER"
