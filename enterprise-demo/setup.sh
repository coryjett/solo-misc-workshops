#!/usr/bin/env bash
#
# Solo.io AI Platform — End-to-End Demo Setup
#
# Provisions a k3d cluster and deploys Agent Registry, Agent Gateway Enterprise,
# kagent Enterprise, a demo MCP server, AGW routing + security, and a kagent agent.
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
AGW_VERSION="${AGW_VERSION:-v2.2.0}"

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
ok "kagent Enterprise deployed"

# ============================================================================
# 6. Build and deploy the demo MCP server
# ============================================================================
info "Building demo MCP server..."
WORKDIR=$(mktemp -d)

# Install arctl if missing
if ! command -v arctl >/dev/null 2>&1; then
  info "Installing arctl..."
  curl -fsSL https://raw.githubusercontent.com/agentregistry-dev/agentregistry/main/scripts/get-arctl | bash
fi

# Scaffold
arctl mcp init python weather-tools --non-interactive \
  --description "Weather forecast MCP server" \
  --author "demo-user" \
  --no-git \
  2>/dev/null || true
cd weather-tools 2>/dev/null || cd "${WORKDIR}"

# If arctl created it in CWD, handle that
if [ -d weather-tools ]; then
  cd weather-tools
fi

# Replace example tools with weather tools
rm -f src/tools/echo.py src/tools/sum.py 2>/dev/null || true

cat > src/tools/weather.py << 'PYEOF'
"""Weather tools for the demo MCP server."""
import random
from core.server import mcp

@mcp.tool()
def get_forecast(city: str) -> str:
    """Get the current weather forecast for a city.
    Args:
        city: The city name (e.g., "San Francisco", "New York")
    Returns:
        A weather forecast for the specified city
    """
    conditions = ["Sunny", "Partly Cloudy", "Cloudy", "Light Rain", "Clear Skies"]
    temp = random.randint(55, 85)
    humidity = random.randint(30, 80)
    condition = random.choice(conditions)
    return (
        f"Weather for {city}:\n"
        f"  Condition: {condition}\n"
        f"  Temperature: {temp} F\n"
        f"  Humidity: {humidity}%\n"
        f"  Wind: {random.randint(5, 20)} mph"
    )

@mcp.tool()
def get_alerts(state: str) -> str:
    """Get active weather alerts for a US state.
    Args:
        state: Two-letter US state code (e.g., "CA", "NY")
    Returns:
        Active weather alerts for the specified state
    """
    alerts = {
        "CA": "Heat Advisory: High temperatures expected in inland areas through Thursday.",
        "FL": "Tropical Storm Watch: Monitor conditions along the Gulf Coast.",
        "TX": "Severe Thunderstorm Warning: Large hail and damaging winds possible.",
        "NY": "Winter Weather Advisory: 3-5 inches of snow expected overnight.",
    }
    state = state.upper()
    if state in alerts:
        return f"Active alerts for {state}:\n  {alerts[state]}"
    return f"No active weather alerts for {state}."
PYEOF

# Build Docker image
docker build -t weather-tools:latest .

# Load into k3d
k3d image import weather-tools:latest -c "${CLUSTER_NAME}"

# Publish to Agent Registry
info "Publishing to Agent Registry..."
kubectl port-forward svc/agentregistry 12121:12121 -n agentregistry &
PF_PID=$!
sleep 3

arctl mcp publish . --type oci --package-id weather-tools:latest --overwrite 2>/dev/null || true

# Deploy via Agent Registry
arctl deployments create demo-user/weather-tools \
  --type mcp \
  --provider-id kubernetes-default \
  --namespace demo \
  --version 0.1.0 2>/dev/null || true

kill $PF_PID 2>/dev/null || true
cd - >/dev/null

# Wait for pod
kubectl -n demo wait --for=condition=ready pod -l app=demo-user-weather-tools --timeout=120s 2>/dev/null || \
  sleep 15  # Fallback wait
ok "MCP server deployed"

# ============================================================================
# 7. Configure AGW routing + security
# ============================================================================
info "Configuring Agent Gateway routing..."

# Gateway
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ai-gateway
  namespace: agentgateway-system
spec:
  gatewayClassName: enterprise-agentgateway
  listeners:
  - name: mcp
    port: 3000
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
EOF

sleep 10

# Get the MCP server service name (arctl-deployed)
MCP_SVC=$(kubectl get svc -n demo -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "weather-tools")

# Backend
kubectl apply -f - <<EOF
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: weather-tools
  namespace: agentgateway-system
spec:
  mcp:
    targets:
    - name: weather
      static:
        host: ${MCP_SVC}.demo.svc.cluster.local
        port: 3000
        protocol: StreamableHTTP
EOF

# HTTPRoute
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: weather-tools
  namespace: agentgateway-system
spec:
  parentRefs:
  - name: ai-gateway
    sectionName: mcp
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /weather
    backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: weather-tools
EOF

# API Keys
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: demo-api-keys
  namespace: agentgateway-system
stringData:
  agent-key: |
    {
      "key": "demo-key-12345",
      "metadata": { "role": "agent", "name": "weather-agent" }
    }
  admin-key: |
    {
      "key": "admin-key-99999",
      "metadata": { "role": "admin", "name": "admin-user" }
    }
EOF

# Security Policy
kubectl apply -f - <<'EOF'
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: weather-security
  namespace: agentgateway-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: weather-tools
  traffic:
    apiKeyAuthentication:
      mode: Strict
      secretRef:
        name: demo-api-keys
    authorization:
      action: Allow
      policy:
        matchExpressions:
        - 'apiKey.role == "agent" || apiKey.role == "admin"'
EOF

ok "Agent Gateway routing + security configured"

# ============================================================================
# 8. Create kagent agent
# ============================================================================
info "Creating kagent agent..."

# Secrets for agent
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: demo-keys
  namespace: kagent
stringData:
  openai-api-key: "${OPENAI_API_KEY}"
  agw-api-key: "Bearer demo-key-12345"
EOF

# ModelConfig
kubectl apply -f - <<'EOF'
apiVersion: kagent.dev/v1alpha2
kind: ModelConfig
metadata:
  name: gpt-4o-mini
  namespace: kagent
spec:
  provider: OpenAI
  model: gpt-4o-mini
  apiKeySecret: kagent-openai
  apiKeySecretKey: OPENAI_API_KEY
EOF

# RemoteMCPServer
kubectl apply -f - <<'EOF'
apiVersion: kagent.dev/v1alpha2
kind: RemoteMCPServer
metadata:
  name: weather-tools
  namespace: kagent
spec:
  url: http://ai-gateway.agentgateway-system.svc.cluster.local:3000/weather/mcp
  protocol: STREAMABLE_HTTP
  description: "Weather forecast and alerts MCP server"
  headersFrom:
  - name: Authorization
    valueFrom:
      name: demo-keys
      key: agw-api-key
      type: Secret
EOF

# Wait for tool discovery
info "Waiting for tool discovery..."
sleep 15

# Agent
kubectl apply -f - <<'EOF'
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: weather-assistant
  namespace: kagent
spec:
  type: Declarative
  description: "An AI assistant that can check weather forecasts and alerts"
  declarative:
    modelConfig: gpt-4o-mini
    systemMessage: |
      You are a helpful weather assistant. You can check weather forecasts
      for cities and weather alerts for US states. Use the available tools
      to answer weather-related questions.
    tools:
    - type: McpServer
      mcpServer:
        name: weather-tools
        kind: RemoteMCPServer
        apiGroup: kagent.dev
        toolNames:
        - get_forecast
        - get_alerts
EOF

# Wait for agent to be ready
info "Waiting for agent to be ready..."
for i in $(seq 1 30); do
  READY=$(kubectl get agent weather-assistant -n kagent -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
  if [ "$READY" = "True" ]; then
    break
  fi
  sleep 5
done

ok "kagent agent created"

# ============================================================================
# 9. Final status
# ============================================================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Solo.io AI Platform — Demo Ready!     ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Resources:"
kubectl get gateway,httproute,agentgatewaybackend,agentgatewaypolicy -n agentgateway-system 2>/dev/null
echo ""
kubectl get remotemcpserver,modelconfig,agent -n kagent 2>/dev/null
echo ""
echo "Port-forwards (run these in separate terminals):"
echo ""
echo "  # Agent Registry UI"
echo "  kubectl port-forward -n agentregistry svc/agentregistry 12121:12121"
echo ""
echo "  # Agent Gateway proxy"
echo "  kubectl port-forward -n agentgateway-system svc/ai-gateway 3001:3000"
echo ""
echo "  # Solo Enterprise UI (kagent + AGW dashboards)"
echo "  kubectl port-forward -n kagent svc/solo-enterprise-ui 8080:80"
echo ""
echo "UIs:"
echo "  Agent Registry:     http://localhost:12121"
echo "  Solo Enterprise UI: http://localhost:8080"
echo "  AGW proxy (curl):   http://localhost:3001"
echo ""
echo "Test AGW auth:"
echo '  curl -s http://localhost:3001/weather/mcp -X POST \'
echo '    -H "Content-Type: application/json" \'
echo '    -H "Accept: application/json, text/event-stream" \'
echo '    -H "Authorization: Bearer demo-key-12345" \'
echo "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}'"
echo ""
