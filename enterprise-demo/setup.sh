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
#   - docker, kubectl, helm, curl installed
#   - export OPENAI_API_KEY=sk-...
#   - export AGENTGATEWAY_LICENSE_KEY=eyJ...
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

[[ -n "${OPENAI_API_KEY:-}" ]]            || fail "OPENAI_API_KEY not set"
[[ -n "${AGENTGATEWAY_LICENSE_KEY:-}" ]]  || fail "AGENTGATEWAY_LICENSE_KEY not set"
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
  # Install k3d if missing
  if ! command -v k3d >/dev/null 2>&1; then
    info "Installing k3d..."
    curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
  fi

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
for ns in agentregistry agentgateway-system kagent demo; do
  kubectl create namespace "$ns" 2>/dev/null || true
done

info "Installing Gateway API CRDs..."
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
ok "Namespaces and CRDs ready"

# ============================================================================
# 3. Agent Registry
# ============================================================================
info "Deploying Agent Registry..."
helm install agentregistry \
  oci://ghcr.io/agentregistry-dev/agentregistry/charts/agentregistry \
  --namespace agentregistry \
  --set config.enableAnonymousAuth="true" \
  --set config.disableBuiltinSeed="false" \
  --set config.jwtPrivateKey="$(openssl rand -hex 32)" \
  --set database.postgres.vectorEnabled=true \
  --set database.postgres.bundled.image.registry=docker.io \
  --set database.postgres.bundled.image.repository=pgvector \
  --set database.postgres.bundled.image.name=pgvector \
  --set database.postgres.bundled.image.tag=pg18 \
  --wait --timeout 300s
ok "Agent Registry deployed"

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
  --set-string licensing.licenseKey="${AGENTGATEWAY_LICENSE_KEY}" \
  --set agentgateway.enabled=true

kubectl -n agentgateway-system wait --for=condition=ready pod \
  -l app.kubernetes.io/name=enterprise-agentgateway --timeout=120s
ok "Agent Gateway Enterprise deployed"

# ============================================================================
# 5. kagent Enterprise (management + CRDs + workload)
# ============================================================================
info "Deploying kagent Enterprise ${KAGENT_ENT_VERSION}..."

# Management plane
cat > /tmp/management.yaml <<'EOF'
cluster: solo-ai-demo
products:
  kagent:
    enabled: true
  agentgateway:
    enabled: true
    namespace: agentgateway-system
oidc:
  issuer: ""
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
  licenseKey: ${AGENTGATEWAY_LICENSE_KEY}
providers:
  default: openAI
  openAI:
    apiKey: ${OPENAI_API_KEY}
oidc:
  skipOBO: true
  secret: "dummy-not-used"
autoAuth:
  enabled: false
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
# 6. Install arctl CLI
# ============================================================================
if ! command -v arctl >/dev/null 2>&1; then
  info "Installing arctl CLI..."
  curl -fsSL https://raw.githubusercontent.com/agentregistry-dev/agentregistry/main/scripts/get-arctl | bash
  ok "arctl installed"
else
  ok "arctl already installed"
fi

# ============================================================================
# 7. Start port-forwards
# ============================================================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Solo.io AI Platform — Setup Complete  ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

info "Starting port-forwards..."
kubectl port-forward -n agentregistry svc/agentregistry 12121:12121 &>/dev/null &
kubectl port-forward -n agentgateway-system svc/ai-gateway 3001:3000 &>/dev/null &
kubectl port-forward -n kagent svc/solo-enterprise-ui 8080:80 &>/dev/null &
sleep 2

echo ""
echo "UIs (port-forwards running in background):"
echo "  Agent Registry:     http://localhost:12121"
echo "  Solo Enterprise UI: http://localhost:8080"
echo ""
echo "The platform is ready. Continue to the Demo Guide (demo-guide.md)"
echo "to build, publish, and deploy your first MCP server and agent."
echo ""
