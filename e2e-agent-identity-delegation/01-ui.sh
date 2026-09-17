#!/usr/bin/env bash
# Solo UI (management chart, agentgateway product). Requires LICENSE_KEY and Keycloak.
# Existing Solo UI: skip this script and set MGMT_RELEASE and MGMT_NAMESPACE for 10-kagent-install.sh.
set -euo pipefail
: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
KAGENT_ENT_VERSION="${KAGENT_ENT_VERSION:-0.5.8}"
KEYCLOAK_ISSUER="${KEYCLOAK_ISSUER:-http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry}"
MGMT_RELEASE="${MGMT_RELEASE:-kagent-mgmt}"
MGMT_NAMESPACE="${MGMT_NAMESPACE:-kagent}"
AGW_NAMESPACE="${AGW_NAMESPACE:-agentgateway-system}"
DIR="$(cd "$(dirname "$0")" && pwd)"

helm upgrade -i "$MGMT_RELEASE" oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/management \
  -n "$MGMT_NAMESPACE" --create-namespace --version "$KAGENT_ENT_VERSION" \
  --set cluster=mgmt-cluster \
  --set products.agentgateway.enabled=true \
  --set products.agentgateway.namespace="$AGW_NAMESPACE" \
  --set-string licensing.licenseKey="$LICENSE_KEY" \
  --set-string oidc.issuer="$KEYCLOAK_ISSUER" \
  --set-string ui.backend.oidc.clientId=kagent-backend \
  --set-string ui.backend.oidc.secret=kagent-backend-secret \
  --set-string ui.frontend.oidc.clientId=kagent-ui
kubectl -n "$MGMT_NAMESPACE" rollout status deploy/solo-enterprise-ui --timeout=300s
echo "UI-READY"
