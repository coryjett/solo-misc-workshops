#!/usr/bin/env bash
# Installs the Solo UI (management chart) with the agentgateway product and sends e2e-gw traces to it.
# Requires: LICENSE_KEY, Keycloak from 00-keycloak.yaml, the gateway from 01-agent-authz.yaml.
# The same release is upgraded in 05-kagent-install.sh to add kagent and agentregistry, so the UI lives in namespace kagent.
set -euo pipefail
: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
KAGENT_ENT_VERSION="${KAGENT_ENT_VERSION:-0.5.8}"
KEYCLOAK_ISSUER="${KEYCLOAK_ISSUER:-http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry}"
DIR="$(cd "$(dirname "$0")" && pwd)"

helm upgrade -i kagent-mgmt oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/management \
  -n kagent --create-namespace --version "$KAGENT_ENT_VERSION" \
  --set cluster=mgmt-cluster \
  --set products.agentgateway.enabled=true \
  --set products.agentgateway.namespace=agentgateway-system \
  --set-string licensing.licenseKey="$LICENSE_KEY" \
  --set-string oidc.issuer="$KEYCLOAK_ISSUER" \
  --set-string ui.backend.oidc.clientId=kagent-backend \
  --set-string ui.backend.oidc.secret=kagent-backend-secret \
  --set-string ui.frontend.oidc.clientId=kagent-ui
kubectl -n kagent rollout status deploy/solo-enterprise-ui --timeout=300s
kubectl apply -f "$DIR/01-tracing.yaml"
echo "UI-READY"
