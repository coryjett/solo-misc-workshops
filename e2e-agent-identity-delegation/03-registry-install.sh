#!/usr/bin/env bash
# Agentregistry Enterprise. Requires LICENSE_KEY and Keycloak.
set -euo pipefail
: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
ARE_VERSION="${ARE_VERSION:-2026.9.0}"
DIR="$(cd "$(dirname "$0")" && pwd)"

helm upgrade --install agentregistry-enterprise \
  oci://us-docker.pkg.dev/solo-public/agentregistry-enterprise/helm/agentregistry-enterprise \
  --version "$ARE_VERSION" -n agentregistry-system --create-namespace \
  -f "$DIR/03-registry-values.yaml" \
  --set licensing.createSecret=true --set-string licensing.licenseKey="$LICENSE_KEY" \
  --wait --timeout 8m
kubectl get pods -n agentregistry-system
# The server restarted; drop any stale port-forward.
pkill -f "port-forward -n agentregistry-system svc/agentregistry-enterprise-server 12121" 2>/dev/null || true

echo REGISTRY-READY
