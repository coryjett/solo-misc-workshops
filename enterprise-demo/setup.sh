#!/usr/bin/env bash
#
# Solo.io AI Platform — End-to-End Demo Setup
#
# Provisions a k3d cluster and deploys Agent Registry, Agent Gateway Enterprise,
# kagent Enterprise, a demo MCP server + skill + agent, AGW routing + security,
# and a kagent agent.
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

# Workload plane — includes OBO skip + auth disable + real OpenAI key
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
# 6. Build and deploy the demo MCP server
# ============================================================================
info "Building demo MCP server..."
WORKDIR=$(mktemp -d)

# Install arctl if missing
if ! command -v arctl >/dev/null 2>&1; then
  info "Installing arctl..."
  curl -fsSL https://raw.githubusercontent.com/agentregistry-dev/agentregistry/main/scripts/get-arctl | bash
fi

# Port-forward Agent Registry (needed for arctl scaffold + publish)
kubectl port-forward svc/agentregistry 12121:12121 -n agentregistry &
PF_PID=$!
sleep 3

# Scaffold in temp directory
cd "${WORKDIR}"
arctl mcp init python weather-tools --non-interactive \
  --description "Weather forecast MCP server" \
  --author "demo-user" \
  --no-git
cd weather-tools

# Replace the generated main.py with a simple FastMCP server
# (arctl scaffold's DynamicMCPServer is incompatible with FastMCP 3.0)
cat > src/main.py << 'PYEOF'
"""Simple weather MCP server."""
import random
from fastmcp import FastMCP

mcp = FastMCP(name="weather-tools")

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
        f"  Temperature: {temp}F\n"
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

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=3000, path="/mcp")
PYEOF

# Build Docker image
docker build -t weather-tools:latest .

# Load into k3d
k3d image import weather-tools:latest -c "${CLUSTER_NAME}"

# Publish to Agent Registry
info "Publishing to Agent Registry..."
arctl mcp publish . --type oci --package-id weather-tools:latest --overwrite 2>/dev/null || true

cd "${WORKDIR}"

# --- Create a Prompt ---
info "Creating weather-assistant prompt..."
cat > weather-assistant-prompt.md << 'PROMPTEOF'
You are a friendly and knowledgeable weather assistant. You help users with:

- Current weather forecasts for any city
- Active weather alerts for US states
- Travel recommendations based on weather conditions
- Clothing suggestions for the day

Always use your available tools to fetch real-time weather data before answering.
Be concise but thorough. If a user asks about multiple cities, check each one.
PROMPTEOF

arctl prompt publish weather-assistant-prompt.md \
  --name weather-assistant-prompt \
  --version "1.0.0" \
  --description "System prompt for the weather assistant agent" 2>/dev/null || true
ok "Prompt published to Agent Registry"

# --- Create a Skill ---
info "Creating weather-analysis skill..."
arctl skill init weather-analysis --no-git --force

cat > weather-analysis/SKILL.md << 'SKILLEOF'
---
name: weather-analysis
description: Analyze weather data and provide travel recommendations
version: "1.0"
---

# Weather Analysis Skill

You are a weather analysis expert. When given weather data, you:

1. **Summarize conditions** — Provide a clear, concise summary of current weather
2. **Travel advisory** — Rate conditions for outdoor activities (Good / Fair / Poor)
3. **What to wear** — Suggest appropriate clothing based on temperature and conditions
4. **Alerts check** — Flag any active weather alerts and explain their impact

Always be specific and actionable. Use the weather tools to fetch current data before analyzing.
SKILLEOF

arctl skill publish weather-analysis/ \
  --docker-image weather-analysis:latest \
  --version "1.0.0" 2>/dev/null || true
ok "Skill published to Agent Registry"

# --- Create an Agent with MCP server + Skill ---
info "Creating weather-assistant agent..."

rm -rf weatherassistant
arctl agent init adk python weatherassistant \
  --model-provider OpenAI \
  --model-name gpt-4o-mini \
  --description "AI weather assistant with forecasts, alerts, and travel recommendations" \
  --instruction-file "${WORKDIR}/weather-assistant-prompt.md"

cd weatherassistant

# Add the MCP server from the registry
arctl agent add-mcp weather-tools \
  --registry-server-name weather-tools \
  --registry-url http://localhost:12121 \
  --project-dir . 2>/dev/null || true

# Add the skill from the registry
arctl agent add-skill weather-analysis \
  --registry-skill-name weather-analysis \
  --project-dir . 2>/dev/null || true

# Build agent Docker image
arctl agent build . 2>/dev/null || true

# Publish agent to registry
arctl agent publish . 2>/dev/null || true
ok "Agent published to Agent Registry"

cd "${WORKDIR}"

kill $PF_PID 2>/dev/null || true

# --- Deploy MCP server to K8s ---
# Note: `arctl deployments create` can deploy from the registry to K8s, but
# for local k3d clusters we use kubectl directly for reliability (imagePullPolicy).
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: weather-tools
  namespace: demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: weather-tools
  template:
    metadata:
      labels:
        app: weather-tools
    spec:
      containers:
      - name: weather-tools
        image: weather-tools:latest
        imagePullPolicy: Never
        ports:
        - containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: weather-tools
  namespace: demo
spec:
  selector:
    app: weather-tools
  ports:
  - port: 3000
    targetPort: 3000
EOF

# Wait for pod
kubectl -n demo wait --for=condition=ready pod -l app=weather-tools --timeout=120s
ok "MCP server deployed"

# ============================================================================
# 7. Configure AGW routing + security
# ============================================================================
info "Configuring Agent Gateway routing..."

# AGW telemetry — send OTEL traces to Solo Enterprise collector
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: ai-gateway-params
  namespace: agentgateway-system
spec:
  rawConfig:
    config:
      tracing:
        otlpEndpoint: "http://solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317"
EOF

# Gateway
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ai-gateway
  namespace: agentgateway-system
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: ai-gateway-params
  listeners:
  - name: mcp
    port: 3000
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
EOF

sleep 10

# Backend
kubectl apply -f - <<'EOF'
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
        host: weather-tools.demo.svc.cluster.local
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

# Tracing Policy — export OTLP traces per-request to Solo Enterprise collector
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: agw-to-collector
  namespace: kagent
spec:
  from:
    - group: agentgateway.dev
      kind: AgentgatewayPolicy
      namespace: agentgateway-system
  to:
    - group: ""
      kind: Service
      name: solo-enterprise-telemetry-collector
---
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: tracing
  namespace: agentgateway-system
spec:
  targetRefs:
  - kind: Gateway
    name: ai-gateway
    group: gateway.networking.k8s.io
  frontend:
    tracing:
      backendRef:
        name: solo-enterprise-telemetry-collector
        namespace: kagent
        port: 4317
      protocol: GRPC
      randomSampling: "true"
EOF

# Restart proxy pod so it initializes the tracer with the new policy
kubectl delete pod -n agentgateway-system -l app.kubernetes.io/name=ai-gateway --wait=false 2>/dev/null
sleep 10

ok "Agent Gateway routing + security configured"

# ============================================================================
# 7b. Patch telemetry collector to scrape AGW proxy Prometheus metrics
# ============================================================================
info "Patching telemetry collector for AGW metrics..."

# Get the Helm-rendered collector config, add AGW Prometheus scraping
if kubectl get configmap -n kagent solo-enterprise-telemetry-collector-config &>/dev/null; then
  kubectl get configmap solo-enterprise-telemetry-collector-config -n kagent \
    -o jsonpath='{.data.relay}' > /tmp/relay-current.yaml

  if ! grep -q "prometheus/agw" /tmp/relay-current.yaml; then
    python3 - /tmp/relay-current.yaml <<'PYEOF'
import sys

with open(sys.argv[1]) as f:
    content = f.read()

# 1. Add resource/agw_metrics processor (before resource/cluster_context)
content = content.replace(
    "\n  resource/cluster_context:",
    """
  resource/agw_metrics:
    attributes:
      - key: "cluster_name"
        action: upsert
        value: "solo-ai-demo"
      - key: "service.name"
        action: upsert
        value: "ai-gateway"

  resource/cluster_context:""")

# 2. Add prometheus/agw receiver (before connectors: or service: section)
receiver_block = """  prometheus/agw:
    config:
      scrape_configs:
      - job_name: agentgateway-proxy
        scrape_interval: 15s
        kubernetes_sd_configs:
        - role: pod
          namespaces:
            names:
            - agentgateway-system
        relabel_configs:
        - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
          action: keep
          regex: ai-gateway
        - source_labels: [__meta_kubernetes_pod_ip]
          action: replace
          target_label: __address__
          regex: (.+)
          replacement: $1:15020
"""
# Insert before connectors: or service: (whichever comes first after receivers)
for anchor in ["\nconnectors:", "\nservice:"]:
    if anchor in content:
        content = content.replace(anchor, "\n" + receiver_block + anchor)
        break

# 3. Append metrics/agw pipeline at end of file
content = content.rstrip() + """
    metrics/agw:
      receivers:
        - prometheus/agw
      processors:
        - memory_limiter
        - resource/agw_metrics
        - batch
      exporters:
        - clickhouse/metrics
"""

with open(sys.argv[1], 'w') as f:
    f.write(content)
print("Patched collector config with AGW metrics scraping")
PYEOF

    kubectl create configmap solo-enterprise-telemetry-collector-config -n kagent \
      --from-file=relay=/tmp/relay-current.yaml \
      --dry-run=client -o yaml | kubectl apply -f -
    kubectl delete pod -n kagent -l app=solo-enterprise-telemetry-collector --wait=false
    ok "Telemetry collector patched for AGW metrics"
  else
    ok "Telemetry collector already has AGW metrics config"
  fi
  rm -f /tmp/relay-current.yaml
else
  warn "Telemetry collector configmap not found, skipping metrics patch"
fi

# ============================================================================
# 7c. Deploy load generator for continuous AGW dashboard data
# ============================================================================
info "Deploying AGW load generator..."

kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agw-load-generator
  namespace: demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agw-load-generator
  template:
    metadata:
      labels:
        app: agw-load-generator
    spec:
      containers:
      - name: load-gen
        image: curlimages/curl
        command: ["/bin/sh", "-c"]
        args:
        - |
          GW="http://ai-gateway.agentgateway-system.svc.cluster.local:3000"
          AUTH="Authorization: Bearer admin-key-99999"
          CT="Content-Type: application/json"
          ACC="Accept: application/json, text/event-stream"

          CITIES="San_Francisco New_York Chicago Seattle Miami Denver Austin Portland Boston Los_Angeles"
          STATES="CA NY IL WA FL CO TX OR MA GA"

          echo "Starting AGW load generator..."
          while true; do
            CITY=$(echo $CITIES | tr " " "\n" | shuf | head -1 | tr "_" " ")
            STATE=$(echo $STATES | tr " " "\n" | shuf | head -1)

            SESSION=$(curl -s -D /dev/stderr "$GW/weather/mcp" -H "$CT" -H "$ACC" -H "$AUTH" \
              -d "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"id\":1,\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"load-gen\",\"version\":\"1.0\"}}}" \
              2>&1 1>/dev/null | grep -i mcp-session-id | tr -d "\r" | cut -d" " -f2)

            if [ -n "$SESSION" ]; then
              curl -s -o /dev/null "$GW/weather/mcp" -H "$CT" -H "$ACC" -H "$AUTH" -H "mcp-session-id: $SESSION" \
                -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":2,\"params\":{}}"
              curl -s -o /dev/null "$GW/weather/mcp" -H "$CT" -H "$ACC" -H "$AUTH" -H "mcp-session-id: $SESSION" \
                -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":3,\"params\":{\"name\":\"get_forecast\",\"arguments\":{\"city\":\"$CITY\"}}}"
              curl -s -o /dev/null "$GW/weather/mcp" -H "$CT" -H "$ACC" -H "$AUTH" -H "mcp-session-id: $SESSION" \
                -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":4,\"params\":{\"name\":\"get_alerts\",\"arguments\":{\"state\":\"$STATE\"}}}"
              echo "$(date +%H:%M:%S) Session OK - forecast:$CITY alerts:$STATE"
            else
              echo "$(date +%H:%M:%S) Session failed, retrying..."
            fi

            sleep 10
          done
        resources:
          requests:
            cpu: 10m
            memory: 16Mi
          limits:
            cpu: 50m
            memory: 32Mi
EOF

ok "AGW load generator deployed (1 session every 10s)"

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

# RemoteMCPServer — uses headersFrom for AGW API key auth
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
echo "Agent Gateway Resources:"
kubectl get gateway,httproute,agentgatewaybackend,agentgatewaypolicy -n agentgateway-system 2>/dev/null
echo ""
echo "kagent Resources:"
kubectl get remotemcpserver,modelconfig,agent -n kagent 2>/dev/null
echo ""
echo "Starting port-forwards..."
kubectl port-forward -n agentregistry svc/agentregistry 12121:12121 &>/dev/null &
kubectl port-forward -n agentgateway-system svc/ai-gateway 3001:3000 &>/dev/null &
kubectl port-forward -n kagent svc/solo-enterprise-ui 8080:80 &>/dev/null &
sleep 2
echo ""
echo "UIs (port-forwards running in background):"
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
