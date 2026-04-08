# Solo.io AI Platform — Demo Guide

> **Time:** ~45 minutes
> **Products:** Agent Registry, Agent Gateway (Enterprise), kagent (Enterprise)
> **Cluster:** Local k3d/kind cluster or cloud Kubernetes (GKE/EKS/AKS)

---

## Setup (Before the Demo)

Run the setup script to provision the cluster and install all three products:

```bash
export OPENAI_API_KEY=sk-...
export AGENTGATEWAY_LICENSE_KEY=eyJ...

./setup.sh
```

The script installs Agent Registry, Agent Gateway, and kagent. The demo itself walks through *building, publishing, and deploying* on top of them.

When setup completes, verify the UIs are accessible:
- **Agent Registry:** http://localhost:12121
- **Solo Enterprise UI:** http://localhost:8080

---

## Part 1: Agent Registry (15 min)

> **Goal:** Show how Agent Registry solves the "where are my MCP servers?" problem.

### The Problem (2 min)

> **Talk track:** "In most organizations, MCP servers are scattered everywhere — some on npm, some as Docker images, some as internal HTTP endpoints. Every developer has to manually find, configure, and connect to them. There's no central catalog, no versioning, no governance."

### The Solution: A Central Catalog (3 min)

> **Talk track:** "Agent Registry gives you a single place to discover, publish, and manage all your AI artifacts — MCP servers, agents, skills, and prompts."

**Open the Agent Registry UI** at `http://localhost:12121`.

> **Show:** The catalog view — 183 community MCP servers pre-loaded. Browse, search, filter by type.

### Build and Publish the Weather MCP Server (5 min)

> **Talk track:** "Let's build a real MCP server from scratch using Agent Registry's CLI, then publish it to the catalog."

**Step 1 — Scaffold the MCP server:**

```bash
arctl mcp init python weather-tools --non-interactive \
  --description "Weather forecast MCP server" \
  --author "demo-user" \
  --no-git
```

**Step 2 — Replace the generated code with a simple FastMCP server:**

```bash
cat > weather-tools/src/main.py << 'PYEOF'
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
```

**Step 3 — Build the Docker image and load into the cluster:**

```bash
docker build -t weather-tools:latest weather-tools/
k3d image import weather-tools:latest -c solo-ai-demo
```

**Step 4 — Publish to Agent Registry:**

```bash
arctl mcp publish weather-tools/ \
  --type oci \
  --package-id weather-tools:latest \
  --overwrite
```

> **Show:** Navigate to the Agent Registry UI — the weather-tools server now appears in the catalog.

**Step 5 — Deploy the MCP server to Kubernetes:**

```bash
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
```

### Create a Prompt, Skill, and Agent (5 min)

> **Talk track:** "Agent Registry isn't just for MCP servers. It's a catalog for all your AI artifacts — prompts, skills, and complete agents. Let's create all three and wire them together."

**Create a prompt** — a reusable system prompt published to the registry:

```bash
cat > weather-assistant-prompt.md << 'EOF'
You are a friendly weather assistant. Use your tools to fetch
real-time weather data before answering. Be concise but thorough.
EOF

arctl prompt publish weather-assistant-prompt.md \
  --name weather-assistant-prompt \
  --version 1.0.0 \
  --description "System prompt for the weather assistant agent"
```

> **Show:** The prompt in the Agent Registry UI — `arctl prompt list` to verify.

**Create a skill** — a reusable set of instructions for weather analysis:

```bash
arctl skill init weather-analysis --no-git

arctl skill publish weather-analysis/ \
  --docker-image weather-analysis:latest \
  --version 1.0.0
```

> **Show:** The skill in the Agent Registry UI under the Skills tab.

**Create an agent** — wire together the model, MCP server, prompt, and skill:

```bash
arctl agent init adk python weatherassistant \
  --model-provider OpenAI \
  --model-name gpt-4o-mini \
  --description "AI weather assistant with forecasts and alerts" \
  --instruction-file weather-assistant-prompt.md

cd weatherassistant

# Add the MCP server from the registry
arctl agent add-mcp weather-tools \
  --registry-server-name weather-tools \
  --registry-url http://localhost:12121

# Add the skill from the registry
arctl agent add-skill weather-analysis \
  --registry-skill-name weather-analysis

# Build and publish the complete agent
arctl agent build .
arctl agent publish .

cd ..
```

> **Show:** The agent in the Agent Registry UI — click into it to see its MCP servers, skills, and configuration. Developers can now discover and deploy this entire agent from the catalog.
>
> **Note:** The `add-mcp` and `add-skill` commands wire the agent to registry entries — this is catalog metadata for discovery, not a runtime connection. The actual runtime wiring (agent → Agent Gateway → MCP server) happens in Part 3 with kagent.

### Semantic Search (2 min)

> **Talk track:** "Now that we have MCP servers, prompts, skills, and agents registered, developers can search by what they need, not by what they know exists."

> **Show in the UI:** Type "weather" in the search bar. Our MCP server, prompt, skill, and agent all appear — developers can discover complete AI capabilities without knowing the exact names.

### Key Takeaway (1 min)

> **Talk track:** "Agent Registry is your single pane of glass for all AI artifacts — MCP servers, skills, prompts, and agents. Platform teams curate what's approved, developers discover what they need, and anyone can deploy from the catalog. But discovery is just step one — how do we actually *route* traffic to these servers securely? That's where Agent Gateway comes in."

---

## Part 2: Agent Gateway (15 min)

> **Goal:** Show how Agent Gateway secures and observes all agent-to-tool traffic.

### The Problem (2 min)

> **Talk track:** "You've got MCP servers in your registry. But who can access them? How do you know what's happening? What if a rogue agent floods your backend with requests? Right now, agents connect directly to MCP servers — no auth, no rate limits, no visibility."

### The Solution: An AI-Native Proxy (3 min)

> **Talk track:** "Agent Gateway is an AI-native reverse proxy built on Envoy. It sits between your agents and your MCP servers, and gives you routing, authentication, RBAC, rate limiting, guardrails, and full observability — all without changing your agents or MCP servers."

### Configure the Gateway and Route (5 min)

> **Talk track:** "Let's configure Agent Gateway to route traffic to our weather MCP server."

**Step 1 — Create the Gateway with telemetry:**

```bash
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
```

**Step 2 — Create the MCP Backend (upstream target):**

```bash
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
```

**Step 3 — Create the HTTPRoute (path-based routing):**

```bash
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
```

**Verify the resources:**

```bash
kubectl get gateway,httproute,agentgatewaybackend -n agentgateway-system
```

### Add Security: API Key Auth + RBAC (3 min)

> **Talk track:** "Now let's add security — API key authentication with role-based access control."

**Create the API keys:**

```bash
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
```

**Create the security policy:**

```bash
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
```

> **Talk track:** "The API keys carry metadata — each key has a `role` field. The authorization policy uses CEL expressions to check that the caller has the `agent` or `admin` role."

**Create the tracing policy:**

```bash
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
```

**Restart the proxy to pick up the tracing config:**

```bash
kubectl delete pod -n agentgateway-system -l app.kubernetes.io/name=ai-gateway --wait=false
sleep 10
```

**Update the port-forward** (the proxy pod restarted):

```bash
# Kill the old port-forward and restart it
kill $(lsof -ti:3001) 2>/dev/null || true
kubectl port-forward -n agentgateway-system svc/ai-gateway 3001:3000 &>/dev/null &
sleep 2
```

**Demo the auth in action:**

```bash
# Without API key — blocked
curl -s http://localhost:3001/weather/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# With valid key — success!
curl -s http://localhost:3001/weather/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer demo-key-12345" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

> **Talk track:** "No key? Rejected. Valid key with the right role? The MCP server initializes. This is the same auth that our kagent agent will use."

### Show the Solo Enterprise UI — Agent Gateway Dashboards (2 min)

**Open the Solo Enterprise UI** at `http://localhost:8080` and navigate to **Agent Gateway**.

> **Talk track:** "Every request through Agent Gateway generates OpenTelemetry traces. The Solo Enterprise UI gives you pre-built dashboards for LLM traffic, MCP tool calls, cost tracking, and more."

> **Show:**
> - **MCP dashboard** — request rate by tool name, error rates, latency
> - **Traces** — drill into a specific request to see the full path: agent -> gateway -> MCP server

### Key Takeaway (1 min)

> **Talk track:** "Agent Gateway gives you a single control point for all agent traffic. Auth, RBAC, rate limiting, guardrails, and observability — without changing your agents or MCP servers. Now let's actually *run* an agent — we published one to the registry in Part 1, but now we'll deploy it as a live Kubernetes resource with kagent."

---

## Part 3: kagent (15 min)

> **Goal:** Create an AI agent that uses the MCP tools we registered and secured.

### The Problem (2 min)

> **Talk track:** "We have tools in our registry and a secure gateway in front of them. But how do we actually build an agent that uses them? Most teams write custom Python/JS code to wire up LLMs to tools. Every agent is a snowflake. kagent lets you define agents as Kubernetes resources — declarative, GitOps-friendly, and fully managed."

### The Solution: Agents as Kubernetes Resources (3 min)

> **Talk track:** "With kagent, an agent is just a YAML file. You define the model, the system prompt, and which MCP tools it can use. Apply it to the cluster, and it's running."

### Step 1: Configure the Model (2 min)

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
  apiKeySecret: demo-keys
  apiKeySecretKey: openai-api-key
EOF
```

> **Talk track:** "The ModelConfig tells kagent which LLM to use. The API key is stored in a Kubernetes Secret — no credentials in your agent definition."

### Step 2: Connect the MCP Server via Agent Gateway (2 min)

```bash
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
```

> **Talk track:** "The RemoteMCPServer points to the Agent Gateway route we created in Part 2 — not directly to the MCP server. The `headersFrom` field injects the API key from a Kubernetes Secret. The agent never connects to backends directly. All traffic flows through the gateway."

**Wait for tool discovery:**

```bash
sleep 15
kubectl get remotemcpserver weather-tools -n kagent
```

> **Talk track:** "The kagent controller automatically connected to the MCP server through Agent Gateway, authenticated with the API key, and discovered the available tools: `get_forecast` and `get_alerts`."

### Step 3: Create the Agent (3 min)

```bash
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
sleep 20
kubectl get agent -n kagent
```

> **Show:** The agent is `ACCEPTED: True` and `READY: True`.

> **Talk track:** "That's the entire agent definition. Apply it, and it's live. No Docker images, no custom code, no framework lock-in."

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
| **Agent Registry** | Catalog & Discovery | MCP servers, prompts, skills, and agents were published to the catalog. Developers searched "weather" and found them. |
| **Agent Gateway** | Routing & Security | Routed the MCP call, validated the API key, enforced RBAC, generated OTEL traces. Zero changes to the agent or MCP server. |
| **kagent** | Agent Lifecycle | The agent was defined as K8s resources (YAML), connected to tools via the gateway, and accessible through the Solo Enterprise chat UI. No custom code. |

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
# Remove local files created during the workshop
rm -rf weather-tools/ weather-analysis/ weatherassistant/ weather-assistant-prompt.md

# Remove demo resources
kubectl delete agent weather-assistant -n kagent
kubectl delete remotemcpserver weather-tools -n kagent
kubectl delete modelconfig gpt-4o-mini -n kagent
kubectl delete secret demo-keys -n kagent
kubectl delete agentgatewaypolicy weather-security tracing -n agentgateway-system
kubectl delete httproute weather-tools -n agentgateway-system
kubectl delete agentgatewaybackend weather-tools -n agentgateway-system
kubectl delete gateway ai-gateway -n agentgateway-system
kubectl delete referencegrant agw-to-collector -n kagent

# Remove MCP server deployment
kubectl delete deployment weather-tools -n demo
kubectl delete service weather-tools -n demo

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
