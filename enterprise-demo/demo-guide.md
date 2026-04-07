# Solo.io AI Platform — Demo Guide

> **Time:** ~45 minutes
> **Products:** Agent Registry, Agent Gateway (Enterprise), kagent (Enterprise)
> **Cluster:** Local k3d/kind cluster or cloud Kubernetes (GKE/EKS/AKS)

---

## Setup (Before the Demo)

Deploy all three products before the demo starts. The demo itself walks through *using* them.

### Prerequisites

- `kubectl`, `helm`, `docker` installed
- An OpenAI API key (`export OPENAI_API_KEY=...`)
- An Agent Gateway Enterprise license key (saved as `license.yaml`)
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

```
Cluster ready:

  ┌─────────────────────────────────────────────┐
  │  solo-ai-demo (k3d or kind)                 │
  │                                             │
  │  Nodes: 1 server + 2 agents/workers         │
  │  Ports: 8080 (HTTP), 8443 (HTTPS)           │
  │  Traefik: disabled (AGW will handle routing)│
  └─────────────────────────────────────────────┘
```

### 1. Create Namespaces

```bash
kubectl create namespace agentregistry
kubectl create namespace agentgateway-system
kubectl create namespace kagent
```

### 2. Deploy Agent Registry

```bash
# Deploy PostgreSQL with pgvector (required for semantic search)
kubectl apply -n agentregistry -f https://raw.githubusercontent.com/agentregistry-dev/agentregistry/main/examples/postgres-pgvector.yaml
kubectl -n agentregistry wait --for=condition=ready pod -l app=postgres-pgvector --timeout=120s

# Install Agent Registry
helm install agentregistry oci://ghcr.io/agentregistry-dev/agentregistry/charts/agentregistry \
  --namespace agentregistry \
  --set database.host=postgres-pgvector.agentregistry.svc.cluster.local \
  --set database.password=agentregistry \
  --set database.sslMode=disable \
  --set config.jwtPrivateKey=$(openssl rand -hex 32)

# Verify
kubectl -n agentregistry wait --for=condition=ready pod -l app.kubernetes.io/name=agentregistry --timeout=120s
```

### 3. Deploy Agent Gateway (Enterprise)

```bash
# Install CRDs
helm install enterprise-agentgateway-crds solo/enterprise-agentgateway-crds \
  --namespace agentgateway-system

# Install Agent Gateway
helm install enterprise-agentgateway solo/enterprise-agentgateway \
  --namespace agentgateway-system \
  --set-file licenseKey=license.yaml \
  --values agw-values.yaml
```

<details>
<summary><strong>agw-values.yaml</strong></summary>

```yaml
# Agent Gateway Helm values for demo
tokenExchange:
  enabled: true
  issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
  tokenExpiration: 24h
  subjectValidator:
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/demo/protocol/openid-connect/certs"
  actorValidator:
    validatorType: k8s
  apiValidator:
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/demo/protocol/openid-connect/certs"
```

</details>

### 4. Deploy kagent (Enterprise)

```bash
# Install CRDs
helm install kagent-crds kagent-enterprise/kagent-enterprise-crds -n kagent

# Install workload plane (controller)
helm install kagent kagent-enterprise/kagent-enterprise -n kagent \
  -f kagent-values-workload.yaml

# Install management plane (UI)
helm install kagent-mgmt kagent-enterprise/management -n kagent \
  -f kagent-values-mgmt.yaml
```

### 5. Deploy the Demo MCP Server

We'll use a simple weather MCP server for the demo. This gives us a concrete, easy-to-understand tool.

```bash
kubectl apply -f demo-mcp-server.yaml
```

<details>
<summary><strong>demo-mcp-server.yaml</strong></summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: weather-mcp
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: weather-mcp
  template:
    metadata:
      labels:
        app: weather-mcp
    spec:
      containers:
      - name: weather-mcp
        image: ghcr.io/modelcontextprotocol/servers/everything:latest
        ports:
        - containerPort: 3001
---
apiVersion: v1
kind: Service
metadata:
  name: weather-mcp
  namespace: default
spec:
  selector:
    app: weather-mcp
  ports:
  - port: 80
    targetPort: 3001
```

</details>

### 6. Port-Forwards (for the demo)

```bash
# Agent Registry UI
kubectl port-forward -n agentregistry svc/agentregistry 12121:12121 &

# Agent Gateway proxy
kubectl port-forward -n agentgateway-system svc/agentgateway-proxy 8080:80 &

# kagent UI
kubectl port-forward -n kagent svc/solo-enterprise-ui 8081:80 &
```

---

## Part 1: Agent Registry (15 min)

> **Goal:** Show how Agent Registry solves the "where are my MCP servers?" problem.

### The Problem (2 min)

> **Talk track:** "In most organizations, MCP servers are scattered everywhere — some on npm, some as Docker images, some as internal HTTP endpoints. Every developer has to manually find, configure, and connect to them. There's no central catalog, no versioning, no governance."

```
Without Agent Registry:

  Developer A                    Developer B                    Developer C
  ┌──────────┐                  ┌──────────┐                  ┌──────────┐
  │ npm      │                  │ Docker   │                  │ GitHub   │
  │ registry │                  │ Hub      │                  │ repo     │
  │          │                  │          │                  │          │
  │ @mcp/    │                  │ mcp-     │                  │ internal/│
  │ postgres │                  │ server:  │                  │ crm-mcp  │
  │          │                  │ latest   │                  │          │
  └──────────┘                  └──────────┘                  └──────────┘
       ?                             ?                             ?
   "What version?"            "Is this approved?"           "How do I connect?"
```

### The Solution: A Central Catalog (3 min)

> **Talk track:** "Agent Registry gives you a single place to discover, publish, and manage all your AI artifacts — MCP servers, agents, skills, and prompts."

**Open the Agent Registry UI** at `http://localhost:12121`.

> **Show:** The catalog view — browse available artifacts, search, filter by type.

```
With Agent Registry:

  ┌──────────────────────────────────────────────────────┐
  │                   Agent Registry                      │
  │                                                      │
  │  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
  │  │ weather    │  │ postgres   │  │ crm-tools  │    │
  │  │ MCP Server │  │ MCP Server │  │ MCP Server │    │
  │  │            │  │            │  │            │    │
  │  │ v1.2.0     │  │ v3.1.0     │  │ v2.0.1     │    │
  │  │ ★ Approved │  │ ★ Approved │  │ ⚠ Review   │    │
  │  │ npm        │  │ Docker     │  │ HTTP       │    │
  │  └────────────┘  └────────────┘  └────────────┘    │
  │                                                      │
  │  🔍 Search: "query database"  →  postgres MCP       │
  │                                                      │
  └──────────────────────────────────────────────────────┘
```

### Register the Weather MCP Server (5 min)

> **Talk track:** "Let's register our weather MCP server so the rest of the team can discover it."

**Option A: Via the UI**
1. Click **"Add Artifact"** → **MCP Server**
2. Fill in:
   - **Name:** `weather-tools`
   - **Description:** "Weather data — current conditions, forecasts, and alerts"
   - **Type:** HTTP/SSE endpoint
   - **URL:** `http://weather-mcp.default.svc.cluster.local:80`
3. Click **Save**

**Option B: Via the CLI**
```bash
# Install the arctl CLI
curl -fsSL https://raw.githubusercontent.com/agentregistry-dev/agentregistry/main/scripts/get-arctl | bash

# Register the MCP server
arctl server add weather-tools \
  --description "Weather data — current conditions, forecasts, and alerts" \
  --url http://weather-mcp.default.svc.cluster.local:80 \
  --protocol streamable-http
```

> **Show:** The newly registered server in the catalog with its metadata.

### Semantic Search (2 min)

> **Talk track:** "Now that we have servers registered, developers can search by what they need, not by what they know exists."

```bash
# Search by capability, not by name
arctl search "get weather forecast"
```

> **Show:** The search returns the weather-tools server based on the description match — developers don't need to know the exact name.

### Key Takeaway (1 min)

> **Talk track:** "Agent Registry is your single pane of glass for all AI artifacts. Platform teams curate what's approved, developers discover what they need. But discovery is just step one — how do we actually *route* traffic to these servers securely? That's where Agent Gateway comes in."

```
What we built in Part 1:

  ┌───────────────────┐
  │  Agent Registry    │
  │                   │
  │  weather-tools ✓  │   ← Registered and discoverable
  │  (MCP Server)     │
  └───────────────────┘
```

---

## Part 2: Agent Gateway (15 min)

> **Goal:** Show how Agent Gateway secures and observes all agent-to-tool traffic.

### The Problem (2 min)

> **Talk track:** "You've got MCP servers in your registry. But who can access them? How do you know what's happening? What if a rogue agent floods your backend with requests? Right now, agents connect directly to MCP servers — no auth, no rate limits, no visibility."

```
Without Agent Gateway:

  Agent A ──────────────────────► MCP Server 1
  Agent B ──────────────────────► MCP Server 2     No auth, no limits,
  Agent C ──────────────────────► MCP Server 1     no traces, no control
  Agent D ──────────────────────► MCP Server 3
```

### The Solution: An AI-Native Proxy (3 min)

> **Talk track:** "Agent Gateway is an AI-native reverse proxy built on Envoy. It sits between your agents and your MCP servers, and gives you routing, authentication, RBAC, rate limiting, guardrails, and full observability — all without changing your agents or MCP servers."

```
With Agent Gateway:

                        ┌────────────────────────────────┐
                        │        Agent Gateway            │
                        │                                │
  Agent A ──────►       │  ┌──────────┐  ┌───────────┐  │  ──────► MCP Server 1
  Agent B ──────►       │  │ Routing  │  │ RBAC      │  │  ──────► MCP Server 2
  Agent C ──────►       │  │ Auth     │  │ Rate Limit│  │  ──────► MCP Server 3
  Agent D ──────►       │  │ Traces   │  │ Guardrails│  │
                        │  └──────────┘  └───────────┘  │
                        │                                │
                        │  Single entry point            │
                        │  Full visibility               │
                        │  Policy enforcement            │
                        └────────────────────────────────┘
```

### Configure the Gateway and Route (5 min)

> **Talk track:** "Let's set up Agent Gateway to route traffic to our weather MCP server. This is all declarative Kubernetes config — Gateway API resources."

**Step 1 — Create the Gateway:**

```bash
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: demo-gateway
  namespace: agentgateway-system
spec:
  gatewayClassName: enterprise-agentgateway
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
EOF
```

**Step 2 — Register the MCP backend:**

```bash
kubectl apply -f - <<'EOF'
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: weather-backend
  namespace: default
spec:
  mcp:
    targets:
    - name: weather-tools
      static:
        host: weather-mcp.default.svc.cluster.local
        path: /mcp
        port: 80
        protocol: StreamableHTTP
EOF
```

**Step 3 — Create the HTTPRoute:**

```bash
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: weather-route
  namespace: default
spec:
  parentRefs:
  - name: demo-gateway
    namespace: agentgateway-system
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /weather
    backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: weather-backend
EOF
```

> **Show:** `kubectl get gateway,httproute,agentgatewaybackend` — all resources are healthy.

### Add Security: JWT Auth + RBAC (3 min)

> **Talk track:** "The route works, but anyone can call it. Let's add JWT authentication and tool-level RBAC."

```bash
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: weather-security
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: weather-backend
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        jwks:
          backendRef:
            name: enterprise-agentgateway
            namespace: agentgateway-system
            port: 7777
          jwksPath: .well-known/jwks.json
      rbac:
      - tool: "get_weather"
        celExpression: 'claims.sub != ""'
      - tool: "set_alert"
        celExpression: 'claims.groups.exists(g, g == "admin")'
EOF
```

> **Talk track:** "Now `get_weather` requires any authenticated user, but `set_alert` requires the `admin` group. This is tool-level RBAC — not just 'can you access the server' but 'can you call this specific tool.'"

```
Security Policy:

  ┌────────────────────────────────────────────────────┐
  │  EnterpriseAgentgatewayPolicy                      │
  │                                                    │
  │  Authentication: JWT (Strict mode)                 │
  │  ├─ Issuer: AGW STS                               │
  │  └─ JWKS: /.well-known/jwks.json                  │
  │                                                    │
  │  RBAC (per-tool):                                  │
  │  ├─ get_weather → any authenticated user ✓         │
  │  └─ set_alert   → admin group only 🔒             │
  └────────────────────────────────────────────────────┘
```

### Observability (2 min)

> **Talk track:** "Every request through Agent Gateway generates OpenTelemetry traces. You can see exactly which agent called which tool, how long it took, and whether it succeeded."

```bash
# Show Agent Gateway logs — MCP requests are visible
kubectl logs -n agentgateway-system deploy/agentgateway-proxy --tail=20
```

> **Show:** Grafana dashboard (if deployed) or Agent Gateway traces showing:
> - Request path (agent → gateway → MCP server)
> - Latency per tool call
> - Auth decisions (allowed/denied)

```
Observability:

  Agent ──► AGW ──► MCP Server
    │        │         │
    │        │         └─ Response time: 45ms
    │        └─ Auth: ✓ JWT valid, sub=alice
    └─ Trace ID: abc123

  All visible in Grafana / Solo Enterprise UI dashboards
```

### Key Takeaway (1 min)

> **Talk track:** "Agent Gateway gives you a single control point for all agent traffic. Auth, RBAC, rate limiting, guardrails, and observability — without changing your agents or MCP servers. Now let's actually *use* this by creating an agent."

```
What we built in Parts 1 + 2:

  ┌───────────────────┐     ┌───────────────────────┐
  │  Agent Registry    │     │   Agent Gateway        │
  │                   │     │                       │
  │  weather-tools ✓  │────►│  /weather route ✓     │──► weather-mcp
  │  (discoverable)   │     │  JWT auth ✓           │    (backend)
  │                   │     │  Tool-level RBAC ✓    │
  └───────────────────┘     │  OTEL traces ✓        │
                            └───────────────────────┘
```

---

## Part 3: kagent (15 min)

> **Goal:** Create an AI agent that uses the MCP tools we registered and secured.

### The Problem (2 min)

> **Talk track:** "We have tools in our registry and a secure gateway in front of them. But how do we actually build an agent that uses them? Most teams write custom Python/JS code to wire up LLMs to tools. Every agent is a snowflake. kagent lets you define agents as Kubernetes resources — declarative, GitOps-friendly, and fully managed."

```
Without kagent:

  main.py (Agent A)          server.js (Agent B)         notebook.ipynb (Agent C)
  ┌──────────────────┐      ┌──────────────────┐        ┌──────────────────┐
  │ import openai    │      │ const OpenAI =   │        │ from langchain   │
  │ import mcp_sdk   │      │   require(...)   │        │ import Agent     │
  │                  │      │                  │        │                  │
  │ # 200 lines of   │      │ // 300 lines of  │        │ # Different      │
  │ # boilerplate    │      │ // boilerplate   │        │ # framework      │
  │ # per agent      │      │ // per agent     │        │ # per team       │
  └──────────────────┘      └──────────────────┘        └──────────────────┘
```

### The Solution: Agents as Kubernetes Resources (3 min)

> **Talk track:** "With kagent, an agent is just a YAML file. You define the model, the system prompt, and which MCP tools it can use. Apply it to the cluster, and it's running."

```
With kagent:

  agent.yaml
  ┌──────────────────────────────────────┐
  │ apiVersion: kagent.dev/v1alpha2      │
  │ kind: Agent                          │
  │ metadata:                            │
  │   name: weather-assistant            │
  │ spec:                                │
  │   modelConfig: gpt-model             │   ← Which LLM
  │   systemMessage: "You are a..."      │   ← Personality
  │   tools:                             │   ← What it can do
  │   - mcpServer: weather-tools         │
  └──────────────────────────────────────┘

  kubectl apply -f agent.yaml   ← Done. Agent is live.
```

### Step 1: Configure the Model (2 min)

```bash
# Create the OpenAI API key secret
kubectl create secret generic openai-key -n kagent \
  --from-literal=OPENAI_API_KEY=$OPENAI_API_KEY

# Create the ModelConfig
kubectl apply -f - <<'EOF'
apiVersion: kagent.dev/v1alpha2
kind: ModelConfig
metadata:
  name: gpt-model
  namespace: kagent
spec:
  apiKeySecret: openai-key
  apiKeySecretKey: OPENAI_API_KEY
  model: gpt-4o-mini
  openAI:
    baseUrl: http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:3001/v1
  provider: OpenAI
EOF
```

> **Talk track:** "Notice the `baseUrl` points to Agent Gateway, not directly to OpenAI. All LLM traffic also flows through the gateway — same auth, rate limiting, and observability."

```
LLM traffic routing:

  kagent agent ──► Agent Gateway ──► OpenAI API
                   (:3001/v1)
                   │
                   ├─ Rate limiting (tokens/min)
                   ├─ Cost tracking (input/output tokens)
                   └─ OTEL traces (model, latency, tokens)
```

### Step 2: Connect the MCP Server (2 min)

```bash
kubectl apply -f - <<'EOF'
apiVersion: kagent.dev/v1alpha2
kind: RemoteMCPServer
metadata:
  name: weather-tools
  namespace: kagent
spec:
  description: "Weather data — current conditions, forecasts, and alerts"
  url: "http://enterprise-agentgateway.agentgateway-system.svc.cluster.local/weather"
  protocol: STREAMABLE_HTTP
EOF
```

> **Talk track:** "The RemoteMCPServer points to the Agent Gateway route we created in Part 2 — not directly to the MCP server. The agent never connects to backends directly. All traffic flows through the gateway."

```
MCP traffic routing:

  kagent agent ──► Agent Gateway ──► weather-mcp backend
                   (/weather)
                   │
                   ├─ JWT auth ✓
                   ├─ Tool-level RBAC ✓
                   └─ OTEL traces ✓
```

### Step 3: Create the Agent (3 min)

```bash
kubectl apply -f - <<'EOF'
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: weather-assistant
  namespace: kagent
spec:
  description: "Friendly weather assistant that provides forecasts and conditions"
  type: Declarative
  declarative:
    modelConfig: gpt-model
    systemMessage: |
      You are a helpful weather assistant. You can look up current weather
      conditions, forecasts, and severe weather alerts for any location.

      When a user asks about weather, use the available tools to fetch
      real data. Always include the location, temperature, and conditions
      in your response.
    tools:
    - type: McpServer
      mcpServer:
        kind: RemoteMCPServer
        name: weather-tools
EOF
```

> **Show:** `kubectl get agents -n kagent` — the agent is created and ready.

```
What we just created:

  ┌──────────────────────────────────────────────────┐
  │  Agent: weather-assistant                        │
  │                                                  │
  │  Model: gpt-4o-mini (via AGW → OpenAI)          │
  │  Tools: weather-tools (via AGW → weather-mcp)   │
  │  System: "You are a helpful weather assistant"   │
  └──────────────────────────────────────────────────┘
```

### Step 4: Use the Agent (3 min)

**Open the kagent UI** at `http://localhost:8081`.

1. Navigate to **Agents** → **weather-assistant**
2. Open the **Chat** panel
3. Type: **"What's the weather in San Francisco?"**

> **Show:** The agent:
> 1. Receives the question
> 2. Calls the `get_weather` tool via Agent Gateway
> 3. Agent Gateway validates the JWT, checks RBAC, logs the trace
> 4. Weather MCP server returns data
> 5. Agent formats and returns the response

> **Talk track:** "That one chat message just exercised the entire stack. The agent called a tool registered in Agent Registry, routed through Agent Gateway with JWT auth and RBAC, and the weather MCP server returned the data."

---

## Putting It All Together (5 min)

### The Full Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                     │
│  "What's the weather in San Francisco?"                                             │
│                                                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────────────┐    ┌───────────────┐  │
│  │          │    │              │    │                     │    │               │  │
│  │  User    │───►│  kagent      │───►│  Agent Gateway      │───►│  Weather      │  │
│  │          │    │  Agent       │    │                     │    │  MCP Server   │  │
│  │          │    │              │    │  1. Validate JWT ✓  │    │               │  │
│  │          │    │  1. Receive  │    │  2. Check RBAC ✓    │    │  1. Look up   │  │
│  │          │◄───│     question │◄───│  3. Route to MCP    │◄───│     weather   │  │
│  │          │    │  2. Call LLM │    │  4. Log trace       │    │  2. Return    │  │
│  │          │    │  3. Use tool │    │  5. Return response │    │     data      │  │
│  │          │    │  4. Format   │    │                     │    │               │  │
│  │          │    │     response │    │                     │    │               │  │
│  └──────────┘    └──────────────┘    └─────────────────────┘    └───────────────┘  │
│                         │                      │                                    │
│                         │                      │                                    │
│                         ▼                      ▼                                    │
│                  ┌──────────────┐    ┌─────────────────────┐                        │
│                  │ Agent        │    │  Observability      │                        │
│                  │ Registry     │    │                     │                        │
│                  │              │    │  Traces: agent →    │                        │
│                  │ weather-     │    │    gateway → MCP    │                        │
│                  │ tools ✓      │    │  Latency: 45ms      │                        │
│                  │ (discovered) │    │  Auth: sub=alice ✓  │                        │
│                  └──────────────┘    └─────────────────────┘                        │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### What Each Product Contributed

| Product | Role | What It Did |
|---------|------|-------------|
| **Agent Registry** | Catalog & Discovery | The weather MCP server was registered, versioned, and discoverable. Developers searched "weather" and found it. |
| **Agent Gateway** | Routing & Security | Routed the MCP call, validated the JWT, enforced tool-level RBAC, generated OTEL traces. Zero changes to the agent or MCP server. |
| **kagent** | Agent Lifecycle | The agent was defined as a K8s resource (YAML), connected to tools via the gateway, and accessible through a chat UI. No custom code. |

### The Value: Each Product Works Alone, Better Together

```
Standalone value:

  Agent Registry alone    → Central catalog for your MCP servers
  Agent Gateway alone     → Secure proxy for any agent-to-tool traffic
  kagent alone            → K8s-native agent lifecycle management

Combined value:

  Registry + Gateway      → Discover tools AND route to them securely
  Gateway + kagent        → Agents use tools through a governed proxy
  All three               → Full platform: discover → secure → run
```

### What to Demo Next

Depending on audience interest, you can extend the demo with:

| Extension | Time | What to Show |
|-----------|------|-------------|
| **Token exchange** | +10 min | OBO exchange so the MCP server sees the user's identity, not the agent's. See [OBO Enablement](../obo-token-exchange-enablement/). |
| **Rate limiting** | +5 min | Add a rate limit policy — show an agent getting throttled after too many calls. |
| **Guardrails** | +5 min | Add a regex or moderation guardrail — show blocked content. |
| **Multi-agent** | +10 min | Create a second agent with different tool permissions — show RBAC in action. |
| **Observability deep-dive** | +5 min | Walk through Grafana dashboards — LLM cost, tool call latency, agent activity. |

---

## Cleanup

```bash
# Remove demo resources
kubectl delete agent weather-assistant -n kagent
kubectl delete remotemcpserver weather-tools -n kagent
kubectl delete modelconfig gpt-model -n kagent
kubectl delete secret openai-key -n kagent
kubectl delete enterpriseagentgatewaypolicy weather-security
kubectl delete httproute weather-route
kubectl delete agentgatewaybackend weather-backend
kubectl delete gateway demo-gateway -n agentgateway-system
kubectl delete -f demo-mcp-server.yaml

# Remove products (if desired)
helm uninstall kagent-mgmt -n kagent
helm uninstall kagent -n kagent
helm uninstall kagent-crds -n kagent
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
- [Agent Gateway Docs](https://docs.solo.io/agentgateway/2.2.x/) — AI-native proxy
- [kagent Docs](https://docs.solo.io/agentgateway/2.2.x/) — K8s-native agent framework
- [Authentication Patterns](../Agentgateway-AuthN-Patterns/) — 14 auth patterns for AGW
- [Authorization Patterns](../Agentgateway-AuthZ-Patterns/) — RBAC, rate limiting, guardrails
- [OBO Token Exchange Enablement](../obo-token-exchange-enablement/) — Deep-dive on token exchange
