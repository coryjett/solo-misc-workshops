#!/usr/bin/env bash
# Solo Enterprise for kagent. Upgrades the management release from 01-ui.sh, then installs kagent CRDs and kagent-enterprise.
# Existing Solo UI: set MGMT_RELEASE and MGMT_NAMESPACE to that release. kagent itself installs into namespace kagent.
set -euo pipefail
: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
KAGENT_ENT_VERSION="${KAGENT_ENT_VERSION:-0.5.8}"
KEYCLOAK_ISSUER="${KEYCLOAK_ISSUER:-http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry}"
MGMT_RELEASE="${MGMT_RELEASE:-kagent-mgmt}"
MGMT_NAMESPACE="${MGMT_NAMESPACE:-kagent}"

helm upgrade -i "$MGMT_RELEASE" oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/management \
  -n "$MGMT_NAMESPACE" --create-namespace --version "$KAGENT_ENT_VERSION" \
  --set cluster=mgmt-cluster \
  --set products.kagent.enabled=true \
  --set products.kagent.namespace=kagent \
  --set products.agentregistry.enabled=true \
  --set products.agentgateway.enabled=true \
  --set products.agentgateway.namespace=agentgateway-system \
  --set-string licensing.licenseKey="$LICENSE_KEY" \
  --set-string oidc.issuer="$KEYCLOAK_ISSUER" \
  --set-string ui.backend.oidc.clientId=kagent-backend \
  --set-string ui.backend.oidc.secret=kagent-backend-secret \
  --set-string ui.frontend.oidc.clientId=kagent-ui

helm upgrade -i kagent-crds oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise-crds \
  -n kagent --version "$KAGENT_ENT_VERSION"

openssl genrsa -out /tmp/kagent-jwt.pem 2048 2>/dev/null
kubectl create secret generic jwt -n kagent --from-file=jwt=/tmp/kagent-jwt.pem --dry-run=client -o yaml | kubectl apply -f -
rm -f /tmp/kagent-jwt.pem

cat > /tmp/kagent-rbac.yaml <<'YAML'
rbac:
  roleMapping:
    roleMapper: 'has(claims.Groups) ? claims.Groups.transformList(i, v, v in rolesMap, rolesMap[v]) : []'
    roleMappings:
      admins: global.Admin
      agentregistry: global.Writer
YAML

helm upgrade -i kagent oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise \
  -n kagent --version "$KAGENT_ENT_VERSION" \
  --set-string licensing.licenseKey="$LICENSE_KEY" \
  --set kmcp.licensing.createSecret=false \
  --set-string oidc.issuer="$KEYCLOAK_ISSUER" \
  --set oidc.clientId=kagent-backend \
  --set-string oidc.secret=kagent-backend-secret \
  --set providers.openAI.apiKey=placeholder \
  -f /tmp/kagent-rbac.yaml

kubectl -n kagent rollout status deploy/kagent-controller --timeout=300s
kubectl get pods -n kagent
echo KAGENT-READY
