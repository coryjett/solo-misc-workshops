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
DIR="$(dirname "$0")"
rm -rf "${DIR}/ssl"
rm -f "${DIR}/access-policy.yaml"
# realm-data/ is committed to the repo — do not delete

echo "Killing port-forwards..."
pkill -f "port-forward.*kagent-security" 2>/dev/null || true
pkill -f "port-forward.*solo-enterprise-ui" 2>/dev/null || true

echo "Done."
