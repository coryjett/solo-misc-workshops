#!/usr/bin/env bash
# Deletes ONLY the agentic-demo kind cluster. Leaves arctl, other clusters and the mirrors alone.
set -euo pipefail
ENV_QUIET=1 . "$(dirname "$0")/env.sh"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then kind delete cluster --name "$CLUSTER"; else echo "no cluster $CLUSTER"; fi
