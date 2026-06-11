#!/usr/bin/env bash
#
# Solo.io AI Platform — Workshop Setup
#
# Provisions a k3d cluster and installs the three Solo.io AI Platform products:
#   - Agent Registry
#   - Agent Gateway Enterprise
#   - kagent Enterprise
#
# The workshop guide (demo-guide.md) walks attendees through building, publishing,
# and deploying an MCP server, configuring AGW routing/security, and creating a
# kagent agent.
#
# Prerequisites:
#   - docker, kubectl, helm, curl, k3d, arctl (Enterprise v2026.6.0) installed
#   - export OPENAI_API_KEY=sk-...
#   - export SOLO_LICENSE_KEY=eyJ...
#
# Usage:
#   ./setup.sh
#
set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# --- Pre-flight checks ---
info "Checking prerequisites..."
command -v docker  >/dev/null 2>&1 || fail "docker not found"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found"
command -v helm    >/dev/null 2>&1 || fail "helm not found"
command -v curl    >/dev/null 2>&1 || fail "curl not found"
command -v k3d     >/dev/null 2>&1 || fail "k3d not found"
command -v arctl   >/dev/null 2>&1 || fail "arctl not found (install Enterprise v2026.6.0: https://storage.googleapis.com/agentregistry-enterprise/install.sh)"
arctl version 2>/dev/null | grep -q "v2026.6.0" || fail "arctl must be Enterprise v2026.6.0 (a pre-existing OSS arctl on PATH lacks the 'user login' / 'apply' commands)"

[[ -n "${OPENAI_API_KEY:-}" ]]            || fail "OPENAI_API_KEY not set"
[[ -n "${SOLO_LICENSE_KEY:-}" ]]  || fail "SOLO_LICENSE_KEY not set"
ok "Prerequisites met"

CLUSTER_NAME="${CLUSTER_NAME:-solo-ai-demo}"
KAGENT_ENT_VERSION="${KAGENT_ENT_VERSION:-0.3.12}"
AGW_VERSION="${AGW_VERSION:-v2.3.0-rc.1}"

# ============================================================================
# 1. Provision k3d cluster
# ============================================================================
info "Creating k3d cluster: ${CLUSTER_NAME}..."
if k3d cluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  warn "Cluster ${CLUSTER_NAME} already exists, using it"
else
  k3d cluster create "${CLUSTER_NAME}" \
    --servers 1 \
    --agents 2 \
    --port "8080:80@loadbalancer" \
    --port "8443:443@loadbalancer" \
    --k3s-arg "--disable=traefik@server:0" \
    --wait
fi

kubectl config use-context "k3d-${CLUSTER_NAME}"
kubectl get nodes
ok "Cluster ready"

# ============================================================================
# 2. Namespaces + Gateway API CRDs
# ============================================================================
info "Creating namespaces..."
for ns in agentregistry-system agentgateway-system kagent demo; do
  kubectl create namespace "$ns" 2>/dev/null || true
done

info "Installing Gateway API CRDs..."
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
ok "Namespaces and CRDs ready"

# ============================================================================
# 2b. Keycloak (shared IdP for agentregistry + kagent)
# ============================================================================
info "Deploying Keycloak..."
kubectl create namespace keycloak 2>/dev/null || true

export AR_BACKEND_SECRET="$(openssl rand -hex 32)"
export KAGENT_BACKEND_SECRET="$(openssl rand -hex 32)"
# Issuer host uses sslip.io wildcard DNS: keycloak.127.0.0.1.sslip.io resolves to
# 127.0.0.1 everywhere with zero host config. On the host (browser + arctl) it hits the
# Keycloak port-forward. In-cluster validators (agentregistry, kagent) can't reach
# 127.0.0.1, so a CoreDNS rewrite (added below) points this name at the Keycloak
# Service. Keycloak's KC_HOSTNAME is pinned to the same value, so the token `iss` claim
# is identical inside and outside the cluster — no /etc/hosts edit required.
export KEYCLOAK_HOST="keycloak.127.0.0.1.sslip.io:8080"
export KEYCLOAK_ISSUER="http://${KEYCLOAK_HOST}/realms/solo-ai-demo"

# Point the issuer hostname at the Keycloak Service for in-cluster token validation.
# k3s/k3d CoreDNS auto-imports /etc/coredns/custom/*.override inside the .:53 server
# block (mounted from the optional `coredns-custom` ConfigMap), so a `rewrite` dropped
# there applies cluster-wide — no fragile Corefile editing, and it covers both
# agentregistry + kagent without per-chart hostAliases. Idempotent (apply).
info "Adding CoreDNS rewrite for issuer hostname..."
kubectl -n kube-system create configmap coredns-custom \
  --from-literal=keycloak.override="rewrite name ${KEYCLOAK_HOST%%:*} keycloak.keycloak.svc.cluster.local" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kube-system rollout restart deployment/coredns
kubectl -n kube-system rollout status deployment/coredns --timeout=60s

# Substitute the backend client secrets into the realm import, then load as ConfigMap.
sed -e "s|\${AR_BACKEND_SECRET}|${AR_BACKEND_SECRET}|g" \
    -e "s|\${KAGENT_BACKEND_SECRET}|${KAGENT_BACKEND_SECRET}|g" \
  "$(dirname "$0")/keycloak/realm-solo-ai-demo.json" > /tmp/realm-solo-ai-demo.json
kubectl create configmap keycloak-realm -n keycloak \
  --from-file=realm-solo-ai-demo.json=/tmp/realm-solo-ai-demo.json \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f "$(dirname "$0")/keycloak/keycloak.yaml"
kubectl -n keycloak rollout status deployment/keycloak --timeout=180s
rm -f /tmp/realm-solo-ai-demo.json
ok "Keycloak deployed (realm solo-ai-demo)"

# ============================================================================
# 3. Agent Registry (Enterprise)
# ============================================================================
info "Deploying Agent Registry Enterprise..."
helm upgrade --install agentregistry \
  oci://us-docker.pkg.dev/solo-public/agentregistry-enterprise/helm/agentregistry-enterprise \
  --version 2026.6.0 \
  --namespace agentregistry-system \
  --create-namespace \
  --set oidc.issuer="${KEYCLOAK_ISSUER}" \
  --set oidc.clientId=ar-backend \
  --set oidc.clientSecret="${AR_BACKEND_SECRET}" \
  --set oidc.publicClientId=ar-ui \
  --set oidc.roleClaim=Groups \
  --set oidc.superuserRole=admins \
  --set database.postgres.vectorEnabled=true \
  --wait --timeout 300s
ok "Agent Registry Enterprise deployed"

# ============================================================================
# 4. Agent Gateway Enterprise
# ============================================================================
info "Deploying Agent Gateway Enterprise ${AGW_VERSION}..."
helm install enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --namespace agentgateway-system \
  --version "${AGW_VERSION}"

helm install enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --namespace agentgateway-system \
  --version "${AGW_VERSION}" \
  --set-string licensing.licenseKey="${SOLO_LICENSE_KEY}" \
  --set agentgateway.enabled=true

kubectl -n agentgateway-system wait --for=condition=ready pod \
  -l app.kubernetes.io/name=enterprise-agentgateway --timeout=120s
ok "Agent Gateway Enterprise deployed"

# ============================================================================
# 5. kagent Enterprise (management + CRDs + workload)
# ============================================================================
info "Deploying kagent Enterprise ${KAGENT_ENT_VERSION}..."

# Management plane
cat > /tmp/management.yaml <<EOF
cluster: solo-ai-demo
products:
  kagent:
    enabled: true
  agentgateway:
    enabled: true
    namespace: agentgateway-system
oidc:
  issuer: "${KEYCLOAK_ISSUER}"
ui:
  backend:
    oidc:
      clientId: kagent-backend
      secret: "${KAGENT_BACKEND_SECRET}"
  frontend:
    oidc:
      clientId: kagent-ui
EOF

helm upgrade -i kagent-mgmt \
  oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/management \
  -n kagent --create-namespace \
  --version "${KAGENT_ENT_VERSION}" \
  --values /tmp/management.yaml \
  --wait --timeout 300s

# CRDs
helm upgrade -i kagent-crds \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise-crds \
  -n kagent \
  --version "${KAGENT_ENT_VERSION}"

# Workload plane
cat > /tmp/kagent.yaml <<EOF
licensing:
  licenseKey: ${SOLO_LICENSE_KEY}
providers:
  default: openAI
  openAI:
    apiKey: ${OPENAI_API_KEY}
oidc:
  issuer: "${KEYCLOAK_ISSUER}"
  clientId: kagent-backend
  secret: "${KAGENT_BACKEND_SECRET}"
  skipOBO: true
rbac:
  roleMapping:
    roleMappings:
      admins: "global.Admin"
      developers: "global.Writer"
      viewers: "global.Reader"
otel:
  tracing:
    enabled: true
    exporter:
      otlp:
        endpoint: solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
        insecure: true
EOF

helm upgrade -i kagent \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise \
  -n kagent \
  --version "${KAGENT_ENT_VERSION}" \
  --values /tmp/kagent.yaml \
  --wait --timeout 300s

rm -f /tmp/management.yaml /tmp/kagent.yaml

kubectl rollout status deployment/kagent-controller -n kagent --timeout=120s
kubectl rollout status deployment/solo-enterprise-ui -n kagent --timeout=120s

ok "kagent Enterprise deployed"

# ============================================================================
# 6. Start port-forwards
# ============================================================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Solo.io AI Platform — Setup Complete  ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

info "Starting port-forwards..."
kubectl port-forward -n agentregistry-system svc/agentregistry-enterprise-server 12121:12121 &>/dev/null &
kubectl port-forward -n agentgateway-system svc/ai-gateway 3001:3000 &>/dev/null &
kubectl port-forward -n kagent svc/solo-enterprise-ui 8082:80 &>/dev/null &
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &>/dev/null &
sleep 2

# ----------------------------------------------------------------------------
# Seed RBAC (admin logs in, applies AccessPolicies)
# ----------------------------------------------------------------------------
info "Seeding RBAC policies..."
# Password-grant login as admin via the ar-cli-password public client.
# Flags verified against arctl v2026.6.0 'user login --help'.
arctl user login \
  --oidc-flow password-credentials \
  --oidc-client-id ar-cli-password \
  --oidc-issuer-url "${KEYCLOAK_ISSUER}" \
  --oidc-username admin \
  --oidc-password password
for p in rbac/accesspolicy-admins.yaml rbac/accesspolicy-developers.yaml rbac/accesspolicy-viewers.yaml; do
  arctl apply -f "$(dirname "$0")/$p"
done
ok "RBAC policies applied"

echo ""
echo "UIs (port-forwards running in background):"
echo "  Agent Registry:     http://localhost:12121"
echo "  Solo Enterprise UI: http://localhost:8082"
echo "  Keycloak:           http://localhost:8080 (admin/admin)"
echo ""
echo "The platform is ready. Continue to the Demo Guide (demo-guide.md)"
echo "to build, publish, and deploy your first MCP server and agent."
echo ""
