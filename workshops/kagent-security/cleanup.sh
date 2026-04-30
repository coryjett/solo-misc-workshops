#!/usr/bin/env bash
#
# kagent Enterprise Security Workshop — Cleanup
#
set -euo pipefail

echo "Stopping Keycloak..."
docker stop keycloak 2>/dev/null && docker rm keycloak 2>/dev/null || true

echo "Deleting k3d cluster..."
k3d cluster delete kagent-security 2>/dev/null || true

echo "Cleaning up generated files..."
rm -rf "$(dirname "$0")/ssl" "$(dirname "$0")/realm-data"

echo "Killing port-forwards..."
pkill -f "port-forward.*kagent-security" 2>/dev/null || true
pkill -f "port-forward.*solo-enterprise-ui" 2>/dev/null || true

echo "Done."
