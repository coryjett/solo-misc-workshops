#!/usr/bin/env bash
# Snowflake Token Exchange Workshop — cleanup
set -euo pipefail

CLUSTER_NAME="snowflake-workshop"

echo "Cleaning up..."
pkill -f "port-forward" 2>/dev/null || true

if command -v k3d >/dev/null 2>&1 && k3d cluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  k3d cluster delete "${CLUSTER_NAME}"
  echo "Cluster ${CLUSTER_NAME} deleted"
else
  echo "No cluster to delete"
fi
