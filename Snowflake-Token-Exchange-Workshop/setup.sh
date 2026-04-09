#!/usr/bin/env bash
# Snowflake Token Exchange Workshop — setup script
# Deploys: k3d + AGW Enterprise + Keycloak + External STS + kagent OSS + mock Snowflake MCP server
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

kill_pf() { pkill -f "port-forward.*$1" 2>/dev/null || true; sleep 1; }

CLUSTER_NAME="snowflake-workshop"
AGW_VERSION="${AGW_VERSION:-v2.3.0-rc.1}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.0}"
KEYCLOAK_REALM="snowflake-workshop"
KEYCLOAK_ISSUER="http://localhost:9090/realms/${KEYCLOAK_REALM}"
KEYCLOAK_URL="http://localhost:9090"
KEYCLOAK_URL_INTERNAL="http://keycloak.keycloak.svc.cluster.local:8080"

# ── Prerequisites ────────────────────────────────────────────────────────────
info "Checking prerequisites..."
command -v docker  >/dev/null 2>&1 || fail "docker not found"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found"
command -v helm    >/dev/null 2>&1 || fail "helm not found"
command -v curl    >/dev/null 2>&1 || fail "curl not found"
command -v jq      >/dev/null 2>&1 || fail "jq not found"
[[ -n "${AGENTGATEWAY_LICENSE_KEY:-}" ]] || fail "AGENTGATEWAY_LICENSE_KEY not set"
[[ -n "${OPENAI_API_KEY:-}" ]] || fail "OPENAI_API_KEY not set"
ok "Prerequisites met"

# ── 1. k3d cluster ───────────────────────────────────────────────────────────
info "Creating k3d cluster: ${CLUSTER_NAME}..."
if k3d cluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  warn "Cluster ${CLUSTER_NAME} already exists, reusing"
else
  k3d cluster create "${CLUSTER_NAME}" \
    --servers 1 --agents 1 \
    --k3s-arg "--disable=traefik@server:0" \
    --wait
fi
kubectl config use-context "k3d-${CLUSTER_NAME}"
ok "Cluster ready"

# ── 2. Gateway API CRDs ─────────────────────────────────────────────────────
info "Installing Gateway API CRDs ${GATEWAY_API_VERSION}..."
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
ok "Gateway API CRDs installed"

# ── 3. AGW Enterprise ───────────────────────────────────────────────────────
info "Installing Enterprise Agentgateway CRDs ${AGW_VERSION}..."
helm upgrade -i --create-namespace \
  --namespace agentgateway-system \
  --version "${AGW_VERSION}" \
  enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds

info "Installing Enterprise Agentgateway ${AGW_VERSION} with STS (token exchange)..."
KEYCLOAK_JWKS_URL="http://keycloak.keycloak.svc.cluster.local:8080/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
helm upgrade -i -n agentgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version "${AGW_VERSION}" \
  --set-string licensing.licenseKey="${AGENTGATEWAY_LICENSE_KEY}" \
  --set agentgateway.enabled=true \
  --set tokenExchange.enabled=true \
  --set tokenExchange.issuer=enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777 \
  --set tokenExchange.tokenExpiration=24h \
  --set tokenExchange.subjectValidator.validatorType=remote \
  --set tokenExchange.subjectValidator.remoteConfig.url="${KEYCLOAK_JWKS_URL}" \
  --set tokenExchange.actorValidator.validatorType=k8s \
  --set tokenExchange.apiValidator.validatorType=remote \
  --set tokenExchange.apiValidator.remoteConfig.url="${KEYCLOAK_JWKS_URL}"

info "Waiting for AGW pods..."
kubectl -n agentgateway-system rollout status deployment/enterprise-agentgateway --timeout=180s
ok "Enterprise Agentgateway deployed with STS"

# ── 4. Keycloak ──────────────────────────────────────────────────────────────
info "Deploying Keycloak..."
kubectl apply -f "${SCRIPT_DIR}/k8s/keycloak.yaml"
info "Waiting for Keycloak (this takes ~2 min)..."
kubectl wait -n keycloak statefulset/keycloak --for=jsonpath='{.status.readyReplicas}'=1 --timeout=420s
ok "Keycloak deployed"

kill_pf "keycloak.*9090"
kubectl port-forward -n keycloak svc/keycloak 9090:8080 &>/dev/null &
sleep 3

# ── 5. Configure Keycloak realm ─────────────────────────────────────────────
info "Configuring Keycloak realm: ${KEYCLOAK_REALM}..."

# Get admin token
ADMIN_TOKEN=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" \
  | jq -r '.access_token')

# Create realm
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"realm":"snowflake-workshop","enabled":true}' || true

# Create kagent-ui client (confidential for oauth2-proxy — PKCE)
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "kagent-ui",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "secret": "kagent-ui-secret",
    "publicClient": false,
    "directAccessGrantsEnabled": true,
    "standardFlowEnabled": true,
    "redirectUris": ["http://localhost:8080/*"],
    "webOrigins": ["http://localhost:8080"]
  }' || true

# Create test user
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "testuser@example.com",
    "emailVerified": true,
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "credentials": [{"type":"password","value":"testuser","temporary":false}]
  }' || true

ok "Keycloak configured (realm=${KEYCLOAK_REALM}, client=kagent-ui, user=testuser/testuser)"

# ── 6. Deploy external STS ──────────────────────────────────────────────────
info "Deploying external STS (opaque token exchange)..."
kubectl create configmap external-sts-script \
  --from-file=sts.py="${SCRIPT_DIR}/external-sts/sts.py" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "${SCRIPT_DIR}/k8s/external-sts.yaml"
kubectl wait deployment/external-sts --for=condition=Available --timeout=120s
ok "External STS deployed"

# ── 7. Deploy mock Snowflake MCP server ──────────────────────────────────────
info "Deploying mock Snowflake MCP server..."
kubectl create configmap snowflake-mcp-script \
  --from-file=server.py="${SCRIPT_DIR}/snowflake-mcp/server.py" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "${SCRIPT_DIR}/k8s/snowflake-mcp.yaml"
kubectl wait deployment/snowflake-mcp --for=condition=Available --timeout=120s
ok "Snowflake MCP server deployed"

# ── 8. Install kagent OSS ───────────────────────────────────────────────────
info "Installing kagent CRDs..."
helm upgrade -i --create-namespace \
  --namespace kagent \
  kagent-crds \
  oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds

info "Installing kagent..."
AGW_PROXY_URL="http://workshop-gateway.default.svc.cluster.local:80"

kubectl create secret generic openai-api-key \
  --namespace kagent \
  --from-literal=api-key="${OPENAI_API_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

helm upgrade -i -n kagent kagent \
  oci://ghcr.io/kagent-dev/kagent/helm/kagent \
  --set proxy.url="${AGW_PROXY_URL}" \
  --set a2a.enabled=false

info "Waiting for kagent controller..."
kubectl -n kagent wait --for=condition=Available deployment -l app.kubernetes.io/name=kagent --timeout=180s
ok "kagent deployed"

# ── 9. Apply AGW resources ──────────────────────────────────────────────────
info "Applying AGW gateway + token exchange policy..."

# Apply kagent CRDs so the agent pod gets created
kubectl apply -f "${SCRIPT_DIR}/k8s/kagent.yaml"
sleep 10

# Wait for the agent deployment to appear
info "Waiting for kagent agent pod..."
kubectl -n kagent wait --for=condition=Available deployment/snowflake-analyst --timeout=120s 2>/dev/null || \
  kubectl -n kagent wait --for=condition=Available deployment -l kagent.dev/agent=snowflake-analyst --timeout=120s 2>/dev/null || \
  warn "Agent deployment not ready yet — will retry"

# Find the agent service
AGENT_SVC=$(kubectl get svc -n kagent -l kagent.dev/agent=snowflake-analyst -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "snowflake-analyst")
AGENT_PORT=$(kubectl get svc -n kagent "${AGENT_SVC}" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || echo "8080")

# Apply AGW resources with substituted values
export KEYCLOAK_URL_INTERNAL KEYCLOAK_ISSUER
export AGENT_SERVICE_NAME="${AGENT_SVC}"
export AGENT_SERVICE_NAMESPACE="kagent"
export AGENT_SERVICE_PORT="${AGENT_PORT}"
envsubst < "${SCRIPT_DIR}/k8s/agw.yaml" | kubectl apply -f -

kubectl wait gateway/workshop-gateway --for=condition=Programmed --timeout=120s
ok "AGW gateway + token exchange ready"

# ── 10. Deploy oauth2-proxy ─────────────────────────────────────────────────
info "Deploying oauth2-proxy..."

COOKIE_SECRET=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")

sed "s|REPLACE_WITH_RANDOM_32_BYTES|${COOKIE_SECRET}|g" \
  "${SCRIPT_DIR}/k8s/oauth2-proxy.yaml" | kubectl apply -f -

kubectl -n kagent wait --for=condition=Available deployment/oauth2-proxy --timeout=120s
ok "oauth2-proxy deployed"

# ── 11. Port-forward and print instructions ──────────────────────────────────
kill_pf "oauth2-proxy.*8080"
kill_pf "keycloak.*9090"
kubectl port-forward -n kagent svc/oauth2-proxy 8080:8080 &>/dev/null &
kubectl port-forward -n keycloak svc/keycloak 9090:8080 &>/dev/null &
sleep 2

echo ""
echo "=========================================="
echo "  Snowflake Token Exchange Workshop"
echo "=========================================="
echo ""
echo "  kagent UI:      http://localhost:8080"
echo "  Keycloak admin: http://localhost:9090 (admin/admin)"
echo "  Login as:       testuser / testuser"
echo ""
echo "  Architecture:"
echo "    User -> oauth2-proxy -> AGW (JWT auth) -> kagent agent"
echo "    kagent agent -> AGW -> External STS (JWT->opaque) -> Snowflake MCP"
echo "    Snowflake MCP -> External STS /introspect -> identity resolved"
echo ""
echo "  1. Open http://localhost:8080 in your browser"
echo "  2. Log in with testuser / testuser"
echo "  3. Select the 'Snowflake Analyst' agent"
echo "  4. Ask: 'Show me the sales data'"
echo ""
echo "  The response will show:"
echo "    - Mock Snowflake query results"
echo "    - Opaque token introspection metadata (identity resolved via RFC 7662)"
echo ""
echo "  Cleanup: ./cleanup.sh"
echo "=========================================="
