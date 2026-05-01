#!/usr/bin/env bash
#
# kagent Enterprise Security Workshop — Setup
#
# Provisions a k3d cluster and installs kagent Enterprise with:
#   - Keycloak IdP (3 users: admin, writer, reader — password: "password")
#   - OBO token generation (RSA key pair)
#   - Agent Gateway Enterprise
#   - Two demo agents in a "demo" namespace for testing policies
#
# Prerequisites:
#   - docker, kubectl, helm, jq installed
#   - export OPENAI_API_KEY=sk-...
#   - export AGENTGATEWAY_LICENSE_KEY=eyJ...
#
# Usage:
#   ./setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
command -v jq      >/dev/null 2>&1 || fail "jq not found"

[[ -n "${OPENAI_API_KEY:-}" ]]            || fail "OPENAI_API_KEY not set"
[[ -n "${AGENTGATEWAY_LICENSE_KEY:-}" ]]  || fail "AGENTGATEWAY_LICENSE_KEY not set"
ok "Prerequisites met"

CLUSTER_NAME="${CLUSTER_NAME:-kagent-security}"
KAGENT_ENT_VERSION="${KAGENT_ENT_VERSION:-0.3.19}"
AGW_VERSION="${AGW_VERSION:-v2.3.0-rc.1}"
ISTIO_VERSION="${ISTIO_VERSION:-1.27.1-solo}"
ISTIO_REPO="${ISTIO_REPO:-oci://us-docker.pkg.dev/soloio-img/istio-helm}"

# Detect LAN IP (used so both browser and cluster can reach Keycloak)
MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
[[ -n "${MAC_IP}" ]] || fail "Could not detect LAN IP. Set MAC_IP manually."
info "Using LAN IP: ${MAC_IP}"

KEYCLOAK_PORT=8088
KEYCLOAK_URL="http://${MAC_IP}:${KEYCLOAK_PORT}"
KEYCLOAK_REALM="kagent-dev"
KEYCLOAK_ISSUER="${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}"
KEYCLOAK_BACKEND_CLIENT_ID="kagent-backend"
KEYCLOAK_BACKEND_SECRET="hiIXdxOG5epokX92Es36RPEWuq4lORnw"
KEYCLOAK_FRONTEND_CLIENT_ID="kagent-ui"

# ============================================================================
# 1. Start Keycloak (Docker container on host)
# ============================================================================
info "Starting Keycloak..."
if docker ps --format '{{.Names}}' | grep -q '^keycloak$'; then
  warn "Keycloak container already running"
else
  docker stop keycloak 2>/dev/null || true
  docker rm keycloak 2>/dev/null || true

  # Download realm data if not present (pre-baked versions are committed to the repo)
  GITHUB_RAW_BASE="https://raw.githubusercontent.com/solo-io/gloo-mesh-use-cases/main/kagent/demo-keycloak/realm-data"
  mkdir -p "${SCRIPT_DIR}/realm-data"
  if [[ ! -f "${SCRIPT_DIR}/realm-data/kagent-dev-realm.json" ]]; then
    curl -sSL "${GITHUB_RAW_BASE}/kagent-dev-realm.json" -o "${SCRIPT_DIR}/realm-data/kagent-dev-realm.json"
    # Fix sslRequired and add group mapper to backend client
    python3 -c "
import json
with open('${SCRIPT_DIR}/realm-data/kagent-dev-realm.json') as f:
    d = json.load(f)
d['sslRequired'] = 'none'
mapper = {'name':'groups-to-claim','protocol':'openid-connect','protocolMapper':'oidc-group-membership-mapper','consentRequired':False,'config':{'full.path':'false','id.token.claim':'true','access.token.claim':'true','claim.name':'Groups','userinfo.token.claim':'true'}}
for c in d.get('clients',[]):
    if c.get('clientId')=='kagent-backend':
        if not any(m['name']=='groups-to-claim' for m in c.get('protocolMappers',[])):
            c.setdefault('protocolMappers',[]).append(mapper)
with open('${SCRIPT_DIR}/realm-data/kagent-dev-realm.json','w') as f:
    json.dump(d,f,indent=2)
"
  fi
  if [[ ! -f "${SCRIPT_DIR}/realm-data/kagent-dev-users-0.json" ]]; then
    curl -sSL "${GITHUB_RAW_BASE}/kagent-dev-users-0.json" -o "${SCRIPT_DIR}/realm-data/kagent-dev-users-0.json"
  fi

  docker run -d --name keycloak -p ${KEYCLOAK_PORT}:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    -v "${SCRIPT_DIR}/realm-data":/opt/keycloak/data/import:ro \
    quay.io/keycloak/keycloak:21.1.1 start-dev --import-realm --hostname-strict=false

  ok "Keycloak container started"
fi

# Wait for Keycloak
info "Waiting for Keycloak to start..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${KEYCLOAK_PORT}/realms/${KEYCLOAK_REALM}" > /dev/null 2>&1; then
    ok "Keycloak ready"
    break
  fi
  [[ $i -eq 30 ]] && fail "Keycloak failed to start"
  sleep 3
done

# Disable SSL on master realm (required for admin API over HTTP)
# Realm data is pre-baked (sslRequired=none, group mappers, user-group assignments)
# Only master realm needs runtime fix since it's not in the import
info "Configuring Keycloak master realm..."
docker exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master --user admin --password admin 2>/dev/null
docker exec keycloak /opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE 2>/dev/null
ok "Keycloak configured (pre-baked realm with 3 users, 3 groups, group mappers)"

# ============================================================================
# 2. Provision k3d cluster
# ============================================================================
info "Creating k3d cluster: ${CLUSTER_NAME}..."
if k3d cluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  warn "Cluster ${CLUSTER_NAME} already exists, using it"
else
  if ! command -v k3d >/dev/null 2>&1; then
    info "Installing k3d..."
    curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
  fi
  k3d cluster create "${CLUSTER_NAME}" \
    --servers 1 --agents 3 \
    --k3s-arg "--disable=traefik@server:0" \
    --wait
fi
kubectl config use-context "k3d-${CLUSTER_NAME}"
ok "Cluster ready"

# ============================================================================
# 3. Namespaces + Gateway API CRDs
# ============================================================================
info "Creating namespaces..."
for ns in kagent agentgateway-system demo istio-system; do
  kubectl create namespace "$ns" 2>/dev/null || true
done
# Demo namespace into Istio ambient mode (required for AccessPolicy enforcement)
kubectl label namespace demo istio.io/dataplane-mode=ambient --overwrite
# kagent namespace also ambient — kagent-controller proxies UI traffic to agents.
# If kagent ns is non-ambient, that traffic bypasses the waypoint and reaches
# the agent directly with no JWT enforcement (reader can chat with restricted agents).
kubectl label namespace kagent istio.io/dataplane-mode=ambient --overwrite
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml 2>&1 | tail -1
ok "Namespaces and CRDs ready"

# ============================================================================
# 3a. Istio Ambient Mesh (required for AccessPolicy enforcement at waypoint)
# ============================================================================
info "Installing Istio ambient mesh ${ISTIO_VERSION}..."
helm upgrade -i istio-base "${ISTIO_REPO}/base" \
  --version "${ISTIO_VERSION}" -n istio-system --wait 2>&1 | tail -1
helm upgrade -i istiod "${ISTIO_REPO}/istiod" \
  --version "${ISTIO_VERSION}" -n istio-system \
  --set profile=ambient --set meshConfig.accessLogFile=/dev/stdout \
  --wait 2>&1 | tail -1
helm upgrade -i istio-cni "${ISTIO_REPO}/cni" \
  --version "${ISTIO_VERSION}" -n istio-system \
  --set profile=ambient \
  --set cni.cniBinDir=/var/lib/rancher/k3s/data/cni \
  --set cni.cniConfDir=/var/lib/rancher/k3s/agent/etc/cni/net.d \
  --wait 2>&1 | tail -1

# Copy istio-cni binary to host CNI bin dir on every k3d node.
# install-cni container writes the conflist but ships the binary inside
# the image — k3s containerd only reads from /var/lib/rancher/k3s/data/cni.
# Tolerant of `set -e` — find/grep can exit 1 with no matches.
info "Installing istio-cni binary on k3d nodes..."
NODES=$(docker ps --filter "label=app=k3d" --format '{{.Names}}' 2>/dev/null | grep -E "${CLUSTER_NAME}-(server|agent)" || true)
for node in ${NODES}; do
  SRC=$(docker exec "$node" sh -c 'find /var/lib/rancher/k3s/agent/containerd -path "*/opt/cni/bin/istio-cni" 2>/dev/null | head -1' || true)
  if [[ -n "$SRC" ]]; then
    docker exec "$node" sh -c "cp '$SRC' /var/lib/rancher/k3s/data/cni/istio-cni && chmod +x /var/lib/rancher/k3s/data/cni/istio-cni" || warn "$node: copy failed"
    ok "$node: istio-cni binary installed"
  else
    warn "$node: istio-cni binary source not found"
  fi
done

helm upgrade -i ztunnel "${ISTIO_REPO}/ztunnel" \
  --version "${ISTIO_VERSION}" -n istio-system --wait 2>&1 | tail -1
kubectl -n istio-system wait --for=condition=ready pod -l app=istiod --timeout=180s
ok "Istio ambient mesh installed"

# ============================================================================
# 4. Backend client secret
# ============================================================================
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: kagent-backend-secret
  namespace: kagent
type: Opaque
stringData:
  clientSecret: ${KEYCLOAK_BACKEND_SECRET}
EOF

# ============================================================================
# 5. Agent Gateway Enterprise
# ============================================================================
info "Deploying Agent Gateway Enterprise ${AGW_VERSION}..."
helm upgrade -i enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --namespace agentgateway-system --version "${AGW_VERSION}" 2>&1 | tail -1

helm upgrade -i enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --namespace agentgateway-system --version "${AGW_VERSION}" \
  --set-string "licensing.licenseKey=${AGENTGATEWAY_LICENSE_KEY}" \
  --set agentgateway.enabled=true 2>&1 | tail -1

kubectl -n agentgateway-system wait --for=condition=ready pod \
  -l app.kubernetes.io/name=enterprise-agentgateway --timeout=180s
ok "Agent Gateway Enterprise deployed"

# ============================================================================
# 5a. AgentgatewayParameters + GatewayClass patch
#     (required so waypoint Gateways trust istiod's local cluster identity)
# ============================================================================
info "Configuring AgentgatewayParameters for waypoint..."
kubectl apply -f - <<'EOF'
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayParameters
metadata:
  name: agentgateway-waypoint-params
  namespace: agentgateway-system
spec:
  env:
    - name: CLUSTER_ID
      value: "Kubernetes"
    - name: NETWORK
      value: ""
EOF

# Wait for GatewayClass created by AGW controller
for i in $(seq 1 30); do
  kubectl get gatewayclass enterprise-agentgateway-waypoint >/dev/null 2>&1 && break
  [[ $i -eq 30 ]] && fail "GatewayClass enterprise-agentgateway-waypoint not found"
  sleep 2
done

kubectl patch gatewayclass enterprise-agentgateway-waypoint --type=merge -p \
  '{"spec":{"parametersRef":{"group":"agentgateway.dev","kind":"AgentgatewayParameters","name":"agentgateway-waypoint-params","namespace":"agentgateway-system"}}}'
ok "GatewayClass patched"

# ============================================================================
# 6. OBO RSA key pair
# ============================================================================
info "Generating OBO RSA key pair..."
openssl genpkey -algorithm RSA -out /tmp/obo-key.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
kubectl create secret generic jwt -n kagent \
  --from-file=jwt=/tmp/obo-key.pem --dry-run=client -o yaml | kubectl apply -f -
rm -f /tmp/obo-key.pem
ok "OBO key pair stored"

# ============================================================================
# 7. kagent Enterprise — Management Plane
# ============================================================================
info "Deploying kagent Enterprise management plane..."
cat > /tmp/management.yaml <<EOF
cluster: ${CLUSTER_NAME}
products:
  kagent: {enabled: true}
  agentgateway: {enabled: true, namespace: agentgateway-system}
licensing:
  licenseKey: ${AGENTGATEWAY_LICENSE_KEY}
oidc:
  issuer: ${KEYCLOAK_ISSUER}
istioAuthzTranslation:
  enabled: true
ui:
  backend:
    oidc: {clientId: ${KEYCLOAK_BACKEND_CLIENT_ID}, secretRef: kagent-backend-secret}
  frontend:
    oidc: {clientId: ${KEYCLOAK_FRONTEND_CLIENT_ID}}
EOF

helm upgrade -i kagent-mgmt \
  oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/management \
  -n kagent --create-namespace --version "${KAGENT_ENT_VERSION}" \
  --values /tmp/management.yaml --wait --timeout 300s 2>&1 | tail -1
ok "Management plane deployed"

# ============================================================================
# 8. kagent Enterprise — CRDs + Workload
# ============================================================================
info "Deploying kagent Enterprise CRDs and workload..."
helm upgrade -i kagent-crds \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise-crds \
  -n kagent --version "${KAGENT_ENT_VERSION}" 2>&1 | tail -1

cat > /tmp/kagent.yaml <<EOF
licensing: {licenseKey: ${AGENTGATEWAY_LICENSE_KEY}}
providers: {default: openAI, openAI: {apiKey: ${OPENAI_API_KEY}}}
oidc:
  issuer: ${KEYCLOAK_ISSUER}
  secret: kagent-backend-secret
  oboClaimsToPropagate:
    - Groups
kagent-tools:
  enabled: true
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
  -n kagent --version "${KAGENT_ENT_VERSION}" \
  --values /tmp/kagent.yaml --wait --timeout 300s 2>&1 | tail -1

rm -f /tmp/management.yaml /tmp/kagent.yaml
ok "kagent Enterprise deployed"

# Restart Solo Enterprise UI so the k8sobjects-collector picks up CRDs that
# were registered AFTER the management plane started. Without this, the
# AccessPolicy CRD watch is never set up and the UI's "Access Policies"
# tab stays empty (UI reads policies from ClickHouse, not the K8s API).
info "Restarting Solo Enterprise UI to pick up new CRDs..."
kubectl rollout restart deploy/solo-enterprise-ui -n kagent 2>&1 | tail -1
kubectl rollout status deploy/solo-enterprise-ui -n kagent --timeout=180s 2>&1 | tail -1
ok "UI restarted with full CRD watch list"

# ============================================================================
# 8a. AccessPolicy patcher
#     Workaround for kagent-enterprise 0.3.19 translation bugs (Issues 1+1b
#     in TROUBLESHOOTING.md): when an AccessPolicy is created (UI or kubectl),
#     kagent generates an EnterpriseAgentgatewayPolicy that targets the wrong
#     resource and uses string-eq CEL on an array claim. The patcher
#     Deployment watches AccessPolicy + EAP and rewrites the bad bits so the
#     UI-only flow actually enforces.
# ============================================================================
info "Deploying access-policy-patcher..."
kubectl apply -f "${SCRIPT_DIR}/manifests/access-policy-patcher.yaml" 2>&1 | tail -1
kubectl -n kagent rollout status deploy/access-policy-patcher --timeout=120s 2>&1 | tail -1
ok "AccessPolicy patcher running"

# ============================================================================
# 9. Create demo agents (in demo namespace)
# ============================================================================
info "Creating demo agents..."

# Copy OpenAI secret to demo namespace
kubectl get secret kagent-openai -n kagent -o yaml | \
  sed 's/namespace: kagent/namespace: demo/' | kubectl apply -f -

# Create ModelConfig in demo namespace
kubectl apply -f - <<'EOF'
apiVersion: kagent.dev/v1alpha2
kind: ModelConfig
metadata:
  name: default-model-config
  namespace: demo
spec:
  apiKeySecret: kagent-openai
  apiKeySecretKey: OPENAI_API_KEY
  model: gpt-4.1-mini
  provider: OpenAI
EOF

# Allow cross-namespace tool references from demo namespace
info "Configuring tool server cross-namespace access..."
kubectl patch remotemcpserver kagent-tool-server -n kagent --type=merge \
  -p '{"spec":{"allowedNamespaces":{"from":"All"}}}' 2>/dev/null || true

# Create agents — 3 agents with different access levels and live K8s tools
kubectl apply -f - <<'EOF'
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: cluster-assistant
  namespace: demo
spec:
  description: "General-purpose Kubernetes assistant for basic operations"
  declarative:
    modelConfig: default-model-config
    systemMessage: |
      You are a helpful Kubernetes cluster assistant. You help users understand
      their cluster by answering questions about namespaces, pods, and services.
---
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: k8s-explorer
  namespace: demo
spec:
  description: "Kubernetes explorer with live cluster access"
  declarative:
    modelConfig: default-model-config
    tools:
      - type: McpServer
        mcpServer:
          name: kagent-tool-server
          namespace: kagent
          kind: RemoteMCPServer
          apiGroup: kagent.dev
          toolNames:
            - k8s_get_resources
            - k8s_describe_resource
            - k8s_get_pod_logs
            - k8s_get_events
            - k8s_get_available_api_resources
    systemMessage: |
      You are a Kubernetes explorer with live access to the cluster.
      Use your tools to query real cluster state — list pods, services,
      namespaces, and describe resources.
---
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: security-auditor
  namespace: demo
  labels:
    kagent.solo.io/waypoint: "true"
spec:
  description: "Elevated security auditor with live cluster access"
  declarative:
    modelConfig: default-model-config
    tools:
      - type: McpServer
        mcpServer:
          name: kagent-tool-server
          namespace: kagent
          kind: RemoteMCPServer
          apiGroup: kagent.dev
          toolNames:
            - k8s_get_resources
            - k8s_describe_resource
            - k8s_get_pod_logs
            - k8s_get_events
            - k8s_get_cluster_configuration
    systemMessage: |
      You are a security auditor for Kubernetes clusters. You have live access
      to review cluster state, RBAC policies, and security configurations.
      Only authorized security team members should use this agent.
EOF

info "Waiting for agents..."
kubectl wait --for=jsonpath='{.status.conditions[?(@.type=="Accepted")].status}'=True \
  agent/cluster-assistant agent/k8s-explorer agent/security-auditor -n demo --timeout=120s 2>/dev/null || true
sleep 30
ok "Demo agents created (3 agents)"

# ============================================================================
# 9a. Pre-bake EnterpriseAgentgatewayPolicy YAML for the demo
#     (workshop applies this during Part 3 — JWKS must be fetched now since
#      it depends on kagent controller running)
# ============================================================================
info "Waiting for security-auditor waypoint Gateway..."
for i in $(seq 1 60); do
  kubectl get gateway agent-security-auditor-waypoint -n demo >/dev/null 2>&1 && break
  [[ $i -eq 60 ]] && fail "waypoint Gateway not created — check kagent.solo.io/waypoint label on security-auditor"
  sleep 3
done
ok "Waypoint Gateway provisioned"

info "Fetching kagent OBO JWKS..."
KAGENT_SVC="kagent"
kubectl get svc kagent -n kagent >/dev/null 2>&1 || KAGENT_SVC="kagent-controller"
KAGENT_PORT=$(kubectl get svc -n kagent "${KAGENT_SVC}" -o jsonpath='{.spec.ports[?(@.name=="http")].port}' 2>/dev/null)
[[ -z "${KAGENT_PORT}" ]] && KAGENT_PORT=8083

pkill -f "port-forward.*${KAGENT_SVC}.*18083" 2>/dev/null || true
kubectl port-forward -n kagent "svc/${KAGENT_SVC}" 18083:${KAGENT_PORT} >/dev/null 2>&1 &
PF_PID=$!
sleep 4
JWKS=$(curl -sf http://localhost:18083/jwks.json 2>/dev/null || true)
kill ${PF_PID} 2>/dev/null || true
[[ -z "${JWKS}" ]] && fail "Could not fetch JWKS from kagent controller (svc=${KAGENT_SVC} port=${KAGENT_PORT})"
JWKS_INLINE=$(echo "${JWKS}" | jq -c .)

cat > "${SCRIPT_DIR}/access-policy.yaml" <<EOF
# Restricts the security-auditor agent to users in the "admins" Keycloak group.
#
# Same shape as what the kagent UI produces when you create an AccessPolicy
# in the Access Policies tab. The access-policy-patcher Deployment fixes the
# auto-generated EnterpriseAgentgatewayPolicy so this actually enforces — see
# TROUBLESHOOTING.md Issues 1 + 1b for why that's needed in 0.3.19.
apiVersion: policy.kagent-enterprise.solo.io/v1alpha1
kind: AccessPolicy
metadata:
  name: admin-only-security-auditor
  namespace: demo
spec:
  action: ALLOW
  from:
    subjects:
      - kind: UserGroup
        userGroup:
          claimName: Groups
          claimValue: admins
          issuer: kagent.kagent
          jwksKey:
            inline: '${JWKS_INLINE}'
  targetRef:
    kind: Agent
    name: security-auditor
EOF
ok "Policy YAML generated: ${SCRIPT_DIR}/access-policy.yaml"

# ============================================================================
# 10. Start port-forwards
# ============================================================================
info "Starting port-forwards..."
pkill -f "port-forward.*solo-enterprise-ui" 2>/dev/null || true
sleep 1
kubectl port-forward -n kagent svc/solo-enterprise-ui 4000:80 &>/dev/null &
sleep 3

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  kagent Security Workshop — Setup Complete ${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "kagent UI:         http://localhost:4000 (open in incognito)"
echo "Keycloak Admin:    ${KEYCLOAK_URL}/admin (admin/admin)"
echo ""
echo "Demo users (Keycloak — password for all: 'password'):"
echo "  admin   — admins group  — global.Admin"
echo "  writer  — writers group — global.Writer"
echo "  reader  — readers group — global.Reader"
echo ""
echo "Demo agents (namespace: demo):"
echo "  cluster-assistant  — General purpose, no tools (no policy restriction)"
echo "  k8s-explorer       — Live kubectl tools (no policy restriction)"
echo "  security-auditor   — Live kubectl tools, waypoint-attached (policy target)"
echo ""
echo "Pre-baked policy:  ${SCRIPT_DIR}/access-policy.yaml"
echo "  Apply during demo: kubectl apply -f access-policy.yaml"
echo ""
echo -e "${YELLOW}NOTE:${NC} Keycloak is at ${MAC_IP}:${KEYCLOAK_PORT}."
echo "      If your IP changes, run reconfig.sh"
echo ""
echo "Continue to the Workshop Guide (workshop-guide.md)"
echo ""
