#!/usr/bin/env bash
# Installs Agentregistry Enterprise into the current context, then registers the kagent runtime.
# Requires: LICENSE_KEY, arctl on PATH (Step 9), Keycloak from 00-keycloak.yaml, kagent from 05-kagent-install.sh.
# Already running Agentregistry Enterprise? Skip this script and run 06-register-kagent-runtime.sh.
set -euo pipefail
: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
ARE_VERSION="${ARE_VERSION:-2026.9.0}"
DIR="$(cd "$(dirname "$0")" && pwd)"

helm upgrade --install agentregistry-enterprise \
  oci://us-docker.pkg.dev/solo-public/agentregistry-enterprise/helm/agentregistry-enterprise \
  --version "$ARE_VERSION" -n agentregistry-system --create-namespace \
  -f "$DIR/06-registry-values.yaml" \
  --set licensing.createSecret=true --set-string licensing.licenseKey="$LICENSE_KEY" \
  --wait --timeout 8m
kubectl get pods -n agentregistry-system
# The server restarted; drop a stale port-forward so 06-registry-env.sh opens a fresh one.
pkill -f "port-forward -n agentregistry-system svc/agentregistry-enterprise-server 12121" 2>/dev/null || true

"$DIR/06-register-kagent-runtime.sh"
echo REGISTRY-READY
