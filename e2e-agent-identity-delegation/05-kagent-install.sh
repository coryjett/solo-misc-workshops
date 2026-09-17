#!/usr/bin/env bash
# Installs Solo Enterprise for kagent (management chart, CRDs, kagent-enterprise) into the current context.
# Requires: LICENSE_KEY. Keycloak with the agentregistry realm from 00-keycloak.yaml.
set -euo pipefail
: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
KAGENT_ENT_VERSION="${KAGENT_ENT_VERSION:-0.5.8}"
KEYCLOAK_ISSUER="${KEYCLOAK_ISSUER:-http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry}"

helm upgrade -i kagent-mgmt oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/management \
  -n kagent --create-namespace --version "$KAGENT_ENT_VERSION" \
  --set cluster=mgmt-cluster \
  --set products.kagent.enabled=true \
  --set products.agentregistry.enabled=true \
  --set-string licensing.licenseKey="$LICENSE_KEY" \
  --set-string oidc.issuer="$KEYCLOAK_ISSUER" \
  --set-string ui.backend.oidc.clientId=kagent-backend \
  --set-string ui.backend.oidc.secret=kagent-backend-secret \
  --set-string ui.frontend.oidc.clientId=kagent-ui

helm upgrade -i kagent-crds oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise-crds \
  -n kagent --version "$KAGENT_ENT_VERSION"

# Signing key for on-behalf-of tokens issued by the controller.
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

# No LLM key is needed for this lab: the agent deployed from the registry is a bring-your-own image.
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
