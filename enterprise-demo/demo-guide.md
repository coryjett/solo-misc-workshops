# Solo.io AI Platform — Demo Guide

> **Time:** ~45 minutes
> **Products:** Agent Registry, Agent Gateway (Enterprise), kagent (Enterprise)
> **Cluster:** Local k3d/kind cluster or cloud Kubernetes (GKE/EKS/AKS)

---

## Setup (Before the Demo)

Deploy all three products before the demo starts. The demo itself walks through *using* them.

A fully automated setup script is available: **[`setup.sh`](setup.sh)**. Run it with:

```bash
export OPENAI_API_KEY=sk-...
export AGENTGATEWAY_LICENSE_KEY=eyJ...

./setup.sh
```

The script provisions the cluster, installs all products, builds and deploys the MCP server, configures AGW routing, and creates the kagent agent. Skip to **Part 1** when it completes.

<details>
<summary>Manual Setup Steps (click to expand)</summary>

### Prerequisites

- `docker`, `kubectl`, `helm` installed
- An OpenAI API key (`export OPENAI_API_KEY=...`)
- An Agent Gateway Enterprise license key (`export AGENTGATEWAY_LICENSE_KEY=...`)
- ~8 GB RAM available for the local cluster

### 0. Provision a Local Cluster

You can use either **k3d** (lightweight k3s in Docker) or **kind** (Kubernetes in Docker). k3d is recommended — it's faster to start and uses fewer resources.

**Option A: k3d (recommended)**

```bash
# Install k3d (if not already installed)
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# Create a cluster with enough resources for all three products
k3d cluster create solo-ai-demo \
  --servers 1 \
  --agents 2 \
  --port "8080:80@loadbalancer" \
  --port "8443:443@loadbalancer" \
  --k3s-arg "--disable=traefik@server:0" \
  --wait

# Verify
kubectl cluster-info
kubectl get nodes
```

> **Note:** `--disable=traefik` prevents k3s's built-in ingress from conflicting with Agent Gateway's Envoy-based proxy. The `--port` flags map host ports 8080/8443 to the cluster's load balancer so you can reach services without port-forwarding.

**Option B: kind**

```bash
# Install kind (if not already installed)
# macOS
brew install kind
# Linux
go install sigs.k8s.io/kind@latest

# Create a cluster config
cat > kind-config.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30080
    hostPort: 8080
    protocol: TCP
  - containerPort: 30443
    hostPort: 8443
    protocol: TCP
- role: worker
- role: worker
EOF

# Create the cluster
kind create cluster --name solo-ai-demo --config kind-config.yaml

# Verify
kubectl cluster-info
kubectl get nodes
```

### 1. Create Namespaces and Install Gateway API CRDs

```bash
kubectl create namespace agentregistry
kubectl create namespace agentgateway-system
kubectl create namespace kagent
kubectl create namespace demo

# Gateway API CRDs (required by Agent Gateway)
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
```

### 2. Deploy Agent Registry

Agent Registry bundles its own PostgreSQL instance. For semantic search, override the bundled image to include pgvector.

```bash
helm install agentregistry \
  oci://ghcr.io/agentregistry-dev/agentregistry/charts/agentregistry \
  --namespace agentregistry \
  --set config.enableAnonymousAuth="true" \
  --set config.disableBuiltinSeed="false" \
  --set config.jwtPrivateKey=$(openssl rand -hex 32) \
  --set database.postgres.vectorEnabled=true \
  --set database.postgres.bundled.image.registry=docker.io \
  --set database.postgres.bundled.image.repository=pgvector \
  --set database.postgres.bundled.image.name=pgvector \
  --set database.postgres.bundled.image.tag=pg18 \
  --wait --timeout 300s

# Verify
kubectl -n agentregistry wait --for=condition=ready pod -l app.kubernetes.io/name=agentregistry --timeout=120s
```

> **Note:** `disableBuiltinSeed=false` pre-loads 183 community MCP servers into the catalog so it looks populated for the demo. `enableAnonymousAuth=true` skips auth for the UI (demo only — not for production).

### 3. Deploy Agent Gateway (Enterprise)

```bash
# Install CRDs
helm install enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --namespace agentgateway-system \
  --version v2.2.0

# Install Agent Gateway
helm install enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --namespace agentgateway-system \
  --version v2.2.0 \
  --set-string licensing.licenseKey=$AGENTGATEWAY_LICENSE_KEY \
  --set agentgateway.enabled=true

# Verify
kubectl -n agentgateway-system wait --for=condition=ready pod -l app.kubernetes.io/name=enterprise-agentgateway --timeout=120s
```

### 4. Deploy kagent (Enterprise)

Solo Enterprise for kagent is installed in two parts: the **management plane** (UI, telemetry, federation) and the **workload plane** (agent controller, CRDs). All charts are publicly available OCI artifacts.

> **Full install docs:** https://docs.solo.io/kagent-enterprise/docs/latest/install/install-kagent/

```bash
export KAGENT_ENT_VERSION=0.3.12

# --- Management plane (Solo Enterprise UI) ---
cat << 'EOF' > /tmp/management.yaml
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
  --version ${KAGENT_ENT_VERSION} \
  --values /tmp/management.yaml

# --- Workload plane (agent controller + CRDs) ---
cat << EOF > /tmp/kagent.yaml
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

helm upgrade -i kagent-crds \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise-crds \
  -n kagent \
  --version ${KAGENT_ENT_VERSION}

helm upgrade -i kagent \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise \
  -n kagent \
  --version ${KAGENT_ENT_VERSION} \
  --values /tmp/kagent.yaml

# Verify
kubectl -n kagent wait --for=condition=ready pod -l app.kubernetes.io/name=solo-enterprise-ui --timeout=300s
```

> **Note:** Setting `oidc.issuer: ""` uses the built-in auto IdP for testing. For production, configure your OIDC provider (Keycloak, Okta, etc.).

### 5. Create the Demo MCP Server

We use Agent Registry's scaffold to create a real MCP server, then deploy it via the registry's Kubernetes integration.

```bash
# Install arctl CLI
curl -fsSL https://raw.githubusercontent.com/agentregistry-dev/agentregistry/main/scripts/get-arctl | bash

# Create an MCP server project
arctl mcp init python weather-tools --non-interactive \
  --description "Weather forecast MCP server" \
  --author "demo-user" \
  --no-git
```

Replace the scaffolded tools with weather tools:

```bash
# Remove example tools
rm weather-tools/src/tools/echo.py weather-tools/src/tools/sum.py

# Create weather tools
cat > weather-tools/src/tools/weather.py << 'PYEOF'
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
```

Build the Docker image and load it into the cluster:

```bash
# Build the image
docker build -t weather-tools:latest weather-tools/

# k3d: load into cluster
k3d image import weather-tools:latest -c solo-ai-demo

# kind: load into cluster
# kind load docker-image weather-tools:latest --name solo-ai-demo
```

### 6. Publish and Deploy via Agent Registry

```bash
# Port-forward Agent Registry API
kubectl port-forward svc/agentregistry 12121:12121 -n agentregistry &

# Publish the MCP server to the catalog
arctl mcp publish weather-tools/ \
  --type oci \
  --package-id weather-tools:latest \
  --overwrite

# Deploy to Kubernetes via Agent Registry
arctl deployments create demo-user/weather-tools \
  --type mcp \
  --provider-id kubernetes-default \
  --namespace demo \
  --version 0.1.0
```

> **Verify:** `kubectl get pods -n demo` — the weather-tools pod should be Running.

### 7. Configure Agent Gateway Routing and Security

```bash
# Create the Gateway (HTTP listener)
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

# Wait for the Gateway to be programmed
sleep 10
kubectl get gateway -n agentgateway-system

# Get the service name of the arctl-deployed MCP server
MCP_SVC=$(kubectl get svc -n demo -o jsonpath='{.items[0].metadata.name}')

# Create MCP Backend pointing to the deployed server
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

# Create the HTTPRoute
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

# Create API Key secret for auth
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
      "metadata": {
        "role": "agent",
        "name": "weather-agent"
      }
    }
  admin-key: |
    {
      "key": "admin-key-99999",
      "metadata": {
        "role": "admin",
        "name": "admin-user"
      }
    }
EOF

# Create Security Policy (API Key auth + RBAC)
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

# Verify
kubectl get gateway,httproute,agentgatewaybackend,agentgatewaypolicy -n agentgateway-system
```

### 8. Create the kagent Agent

```bash
# Create secrets for the agent
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

# ModelConfig — OpenAI model
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

# RemoteMCPServer — connects to weather-tools via Agent Gateway
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

# Wait for RemoteMCPServer to discover tools
sleep 10
kubectl get remotemcpserver -n kagent

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

# Verify agent is ready
sleep 20
kubectl get agent -n kagent
```

### 9. Port-Forwards (for the demo)

```bash
# Agent Registry UI (http://localhost:12121)
kubectl port-forward -n agentregistry svc/agentregistry 12121:12121 &

# Agent Gateway proxy (http://localhost:3001)
kubectl port-forward -n agentgateway-system svc/ai-gateway 3001:3000 &

# Solo Enterprise UI — kagent + Agent Gateway dashboards (http://localhost:8080)
kubectl port-forward -n kagent svc/solo-enterprise-ui 8080:80 &
```

</details>

---

## Part 1: Agent Registry (15 min)

> **Goal:** Show how Agent Registry solves the "where are my MCP servers?" problem.

### The Problem (2 min)

> **Talk track:** "In most organizations, MCP servers are scattered everywhere — some on npm, some as Docker images, some as internal HTTP endpoints. Every developer has to manually find, configure, and connect to them. There's no central catalog, no versioning, no governance."

### The Solution: A Central Catalog (3 min)

> **Talk track:** "Agent Registry gives you a single place to discover, publish, and manage all your AI artifacts — MCP servers, agents, skills, and prompts."

**Open the Agent Registry UI** at `http://localhost:12121`.

> **Show:** The catalog view — 183 community MCP servers pre-loaded. Browse, search, filter by type.

### Register and Publish the Weather MCP Server (5 min)

> **Talk track:** "We just built a weather MCP server using Agent Registry's scaffold. Let's publish it to the catalog so the rest of the team can discover and deploy it."

> **Show:** The CLI workflow — `arctl mcp init` scaffolds, `arctl mcp publish` registers, `arctl deployments create` deploys to K8s.

```bash
# This was already done in setup, but show the commands:
arctl mcp publish weather-tools/ --type oci --package-id weather-tools:latest

# Deploy from the catalog to Kubernetes
arctl deployments create demo-user/weather-tools \
  --type mcp \
  --provider-id kubernetes-default \
  --namespace demo

# Verify
arctl deployments list
kubectl get pods -n demo
```

> **Show:** The newly published server in the catalog — navigate to it in the UI. Click the **Deployed** tab to see it running.

### Semantic Search (2 min)

> **Talk track:** "Now that we have servers registered, developers can search by what they need, not by what they know exists."

> **Show in the UI:** Type "weather" in the search bar. Our `demo-user/weather-tools` server appears alongside community weather servers from the catalog — developers can discover tools without knowing the exact name.

### Key Takeaway (1 min)

> **Talk track:** "Agent Registry is your single pane of glass for all AI artifacts. Platform teams curate what's approved, developers discover what they need, and anyone can deploy from the catalog. But discovery is just step one — how do we actually *route* traffic to these servers securely? That's where Agent Gateway comes in."

---

## Part 2: Agent Gateway (15 min)

> **Goal:** Show how Agent Gateway secures and observes all agent-to-tool traffic.

### The Problem (2 min)

> **Talk track:** "You've got MCP servers in your registry. But who can access them? How do you know what's happening? What if a rogue agent floods your backend with requests? Right now, agents connect directly to MCP servers — no auth, no rate limits, no visibility."

### The Solution: An AI-Native Proxy (3 min)

> **Talk track:** "Agent Gateway is an AI-native reverse proxy built on Envoy. It sits between your agents and your MCP servers, and gives you routing, authentication, RBAC, rate limiting, guardrails, and full observability — all without changing your agents or MCP servers."

### Configure the Gateway and Route (5 min)

> **Talk track:** "Let's walk through the Gateway API resources that were set up to route traffic to our weather MCP server."

**Show the Gateway resources:**

```bash
kubectl get gateway,httproute,agentgatewaybackend -n agentgateway-system
```

**Step 1 — The Gateway (listener):**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ai-gateway
spec:
  gatewayClassName: enterprise-agentgateway
  listeners:
  - name: mcp
    port: 3000
    protocol: HTTP
```

**Step 2 — The MCP Backend (upstream target):**

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: weather-tools
spec:
  mcp:
    targets:
    - name: weather
      static:
        host: weather-tools.demo.svc.cluster.local
        port: 3000
        protocol: StreamableHTTP
```

**Step 3 — The HTTPRoute (path-based routing):**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: weather-tools
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
```

**Test the route (without auth):**

```bash
curl -s http://localhost:3001/weather/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

> **Expected:** `api key authentication failure: no API Key found` — auth is already enforced!

### Add Security: API Key Auth + RBAC (3 min)

> **Talk track:** "We've already added API key authentication with role-based access control. Let me show you how it works."

**Show the security policy:**

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: weather-security
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
```

> **Talk track:** "The API keys carry metadata — each key has a `role` field. The authorization policy uses CEL expressions to check that the caller has the `agent` or `admin` role. You can write any CEL expression — require specific roles for specific tools, check custom metadata fields, time-based access, and more."

**Demo the auth in action:**

```bash
# Without API key — blocked
curl -s http://localhost:3001/weather/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# With wrong key — blocked
curl -s http://localhost:3001/weather/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer wrong-key" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# With valid key — success!
curl -s http://localhost:3001/weather/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer demo-key-12345" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

> **Talk track:** "No key? Rejected. Wrong key? Rejected. Valid key with the right role? The MCP server initializes. This is the same auth that our kagent agent uses — it sends its API key through the Authorization header, and Agent Gateway validates it before forwarding to the MCP server."

### Show the Solo Enterprise UI — Agent Gateway Dashboards (2 min)

**Open the Solo Enterprise UI** at `http://localhost:8080` and navigate to **Agent Gateway**.

> **Talk track:** "Every request through Agent Gateway generates OpenTelemetry traces. The Solo Enterprise UI gives you pre-built dashboards for LLM traffic, MCP tool calls, cost tracking, and more."

> **Show:**
> - **MCP dashboard** — request rate by tool name, error rates, latency
> - **LLM dashboard** — token usage by model, cost tracking
> - **Traces** — drill into a specific request to see the full path: agent -> gateway -> MCP server

### Key Takeaway (1 min)

> **Talk track:** "Agent Gateway gives you a single control point for all agent traffic. Auth, RBAC, rate limiting, guardrails, and observability — without changing your agents or MCP servers. Now let's actually *use* this by creating an agent."

---

## Part 3: kagent (15 min)

> **Goal:** Create an AI agent that uses the MCP tools we registered and secured.

### The Problem (2 min)

> **Talk track:** "We have tools in our registry and a secure gateway in front of them. But how do we actually build an agent that uses them? Most teams write custom Python/JS code to wire up LLMs to tools. Every agent is a snowflake. kagent lets you define agents as Kubernetes resources — declarative, GitOps-friendly, and fully managed."

### The Solution: Agents as Kubernetes Resources (3 min)

> **Talk track:** "With kagent, an agent is just a YAML file. You define the model, the system prompt, and which MCP tools it can use. Apply it to the cluster, and it's running."

```yaml
# agent.yaml — that's the entire agent definition
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: weather-assistant
spec:
  type: Declarative
  declarative:
    modelConfig: gpt-4o-mini          # Which LLM
    systemMessage: "You are a..."      # Personality
    tools:                             # What it can do
    - type: McpServer
      mcpServer:
        name: weather-tools
        kind: RemoteMCPServer
        apiGroup: kagent.dev
        toolNames:
        - get_forecast
        - get_alerts
```

> **Talk track:** "Apply it, and it's live: `kubectl apply -f agent.yaml`. No Docker images, no custom code, no framework lock-in."

### Step 1: Configure the Model (2 min)

**Show the ModelConfig:**

```bash
kubectl get modelconfig -n kagent
```

```yaml
apiVersion: kagent.dev/v1alpha2
kind: ModelConfig
metadata:
  name: gpt-4o-mini
spec:
  provider: OpenAI
  model: gpt-4o-mini
  apiKeySecret: kagent-openai
  apiKeySecretKey: OPENAI_API_KEY
```

### Step 2: Connect the MCP Server (2 min)

**Show the RemoteMCPServer:**

```bash
kubectl get remotemcpserver -n kagent
```

```yaml
apiVersion: kagent.dev/v1alpha2
kind: RemoteMCPServer
metadata:
  name: weather-tools
spec:
  url: http://ai-gateway.agentgateway-system.svc.cluster.local:3000/weather/mcp
  protocol: STREAMABLE_HTTP
  headersFrom:
  - name: Authorization
    valueFrom:
      name: demo-keys
      key: agw-api-key
      type: Secret
```

> **Talk track:** "The RemoteMCPServer points to the Agent Gateway route we created in Part 2 — not directly to the MCP server. The `headersFrom` field injects the API key from a Kubernetes Secret. The agent never connects to backends directly. All traffic flows through the gateway."

**Show the discovered tools:**

```bash
kubectl get remotemcpserver weather-tools -n kagent -o yaml | tail -20
```

> **Talk track:** "The kagent controller automatically connected to the MCP server through Agent Gateway, authenticated with the API key, and discovered the available tools: `get_forecast` and `get_alerts`."

### Step 3: Show the Agent (3 min)

```bash
kubectl get agent -n kagent
```

> **Show:** The agent is `ACCEPTED: True` and `READY: True`.

### Step 4: Use the Agent via the Solo Enterprise UI (3 min)

**Open the Solo Enterprise UI** at `http://localhost:8080` and navigate to **kagent** > **Agents** > **weather-assistant**.

1. Open the **Chat** panel
2. Type: **"What's the weather in San Francisco?"**

> **Show:** The agent:
> 1. Receives the question
> 2. Calls the `get_forecast` tool via Agent Gateway
> 3. Agent Gateway validates the API key, checks RBAC, logs the trace
> 4. Weather MCP server returns data
> 5. Agent formats and returns the response

3. Type: **"Any weather alerts for California?"**

> **Show:** The agent calls `get_alerts` with state "CA".

> **Talk track:** "That chat message just exercised the entire stack. The agent called a tool registered in Agent Registry, routed through Agent Gateway with API key auth and RBAC, and the weather MCP server returned the data. Let's see that in the Solo Enterprise UI traces."

> **Show in the Solo Enterprise UI:** Navigate to **Agent Gateway** > **Traces** — find the trace for this request and show the spans.

---

## Putting It All Together (5 min)

### The Three UIs

| UI | URL | What It Shows |
|----|-----|---------------|
| **Agent Registry** | `http://localhost:12121` | MCP server catalog, semantic search, deployment status |
| **Solo Enterprise UI — Agent Gateway** | `http://localhost:8080` (AGW tab) | LLM/MCP dashboards, cost tracking, OTEL traces, route status |
| **Solo Enterprise UI — kagent** | `http://localhost:8080` (kagent tab) | Agent list, chat interface, tool execution, agent configuration |

### What Each Product Contributed

| Product | Role | What It Did |
|---------|------|-------------|
| **Agent Registry** | Catalog & Discovery | The weather MCP server was scaffolded, published, and deployed from the catalog. Developers searched "weather" and found it. |
| **Agent Gateway** | Routing & Security | Routed the MCP call, validated the API key, enforced RBAC, generated OTEL traces. Zero changes to the agent or MCP server. |
| **kagent** | Agent Lifecycle | The agent was defined as a K8s resource (YAML), connected to tools via the gateway, and accessible through the Solo Enterprise chat UI. No custom code. |

### The Value: Each Product Works Alone, Better Together

```
Standalone value:

  Agent Registry alone    --> Central catalog for your MCP servers
  Agent Gateway alone     --> Secure proxy for any agent-to-tool traffic
  kagent alone            --> K8s-native agent lifecycle management

Combined value:

  Registry + Gateway      --> Discover tools AND route to them securely
  Gateway + kagent        --> Agents use tools through a governed proxy
  All three               --> Full platform: discover --> secure --> run
```

### What to Demo Next

Depending on audience interest, you can extend the demo with:

| Extension | Time | What to Show |
|-----------|------|-------------|
| **Token exchange** | +10 min | OBO exchange so the MCP server sees the user's identity, not the agent's. See [OBO Enablement](../obo-token-exchange-enablement/). |
| **Rate limiting** | +5 min | Add a rate limit policy — show an agent getting throttled after too many calls. |
| **Guardrails** | +5 min | Add a regex or moderation guardrail — show blocked content. |
| **Multi-agent** | +10 min | Create a second agent with different tool permissions — show RBAC in action. |
| **Observability deep-dive** | +5 min | Walk through Solo Enterprise UI dashboards — LLM cost, tool call latency, agent activity. |

---

## Cleanup

```bash
# Remove demo resources
kubectl delete agent weather-assistant -n kagent
kubectl delete remotemcpserver weather-tools -n kagent
kubectl delete modelconfig gpt-4o-mini -n kagent
kubectl delete secret demo-keys -n kagent
kubectl delete agentgatewaypolicy weather-security -n agentgateway-system
kubectl delete httproute weather-tools -n agentgateway-system
kubectl delete agentgatewaybackend weather-tools -n agentgateway-system
kubectl delete gateway ai-gateway -n agentgateway-system

# Remove MCP server deployment (via Agent Registry)
arctl deployments list
arctl deployments delete <deployment-ID>

# Remove products (if desired)
helm uninstall kagent -n kagent
helm uninstall kagent-crds -n kagent
helm uninstall kagent-mgmt -n kagent
helm uninstall enterprise-agentgateway -n agentgateway-system
helm uninstall enterprise-agentgateway-crds -n agentgateway-system
helm uninstall agentregistry -n agentregistry

# Delete the local cluster (if using k3d/kind)
k3d cluster delete solo-ai-demo
# or: kind delete cluster --name solo-ai-demo
```

---

## Reference

- [Agent Registry](https://aregistry.ai/) — Catalog for MCP servers, agents, skills
- [Agent Registry Docs](https://aregistry.ai/docs/quickstart/) — Get started with arctl
- [Agent Gateway Docs](https://docs.solo.io/agentgateway/2.2.x/) — AI-native proxy
- [kagent Docs](https://kagent.dev/) — K8s-native agent framework
- [kagent Enterprise Install](https://docs.solo.io/kagent-enterprise/docs/latest/install/install-kagent/) — Full install guide
- [Authentication Patterns](../Agentgateway-AuthN-Patterns/) — 14 auth patterns for AGW
- [Authorization Patterns](../Agentgateway-AuthZ-Patterns/) — RBAC, rate limiting, guardrails
- [OBO Token Exchange Enablement](../obo-token-exchange-enablement/) — Deep-dive on token exchange
