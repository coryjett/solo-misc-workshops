# Solo.io AI Platform — Demo Guide

> **Time:** ~50 minutes
> **Products:** Agent Registry (Enterprise), Agent Gateway (Enterprise), kagent (Enterprise)
> **Cluster:** Local k3d/kind cluster or cloud Kubernetes (GKE/EKS/AKS)

| Part | Topic | Time |
|------|-------|------|
| Part 1 | Agent Registry (Enterprise) — SSO, RBAC, catalog | ~20 min |
| Part 2 | Agent Gateway (Enterprise) | ~17 min |
| Part 3 | kagent (Enterprise) | ~13 min |
| Wrap-up | Putting it all together | ~3 min |
| **Total** | | **~50 min** |

## Contents

- [Setup (Before the Demo)](#setup-before-the-demo)
- **[Part 1: Agent Registry](#part-1-agent-registry-enterprise-2022-min)** — catalog MCP servers behind SSO + group RBAC
  - [The Problem](#the-problem-2-min) — MCP servers scattered, no catalog, no governance
  - [SSO Login](#sso-login-2-min) — registry UI redirects to Keycloak; log in as `admin`
  - [The Catalog](#the-catalog-2-min) — tour the (empty) catalog, type filters, search
  - [Authenticate the CLI](#authenticate-the-cli-with-arctl-user-login-2-min) — `arctl user login` device flow; `whoami` shows the `developers` group
  - [Build and Publish the Weather MCP Server](#build-and-publish-the-weather-mcp-server-4-min) — scaffold FastMCP, add `get_forecast`/`get_alerts`, build, publish
  - [RBAC: Deny → Grant](#rbac-deny--grant-3-min) — `viewer` publish = forbidden, `dev` = success; then deploy MCP from the UI
  - [Create a Prompt, Skill, and Agent](#create-a-prompt-skill-and-agent-4-min) — publish a prompt, skill, and ADK agent (agent left unbound on purpose)
  - [Semantic Search + Key Takeaway](#semantic-search--key-takeaway-1-min) — search "weather" surfaces all four artifacts
- **[Part 2: Agent Gateway](#part-2-agent-gateway-enterprise-17-min)** — secure + observe all agent-to-tool traffic
  - [The Problem](#the-problem-2-min-1) — agents hit MCP directly: no auth, no limits, no visibility
  - [The Solution: An AI-Native Proxy](#the-solution-an-ai-native-proxy-3-min) — Envoy-based proxy: routing, auth, RBAC, rate limit, guardrails, traces
  - [Configure the Gateway and Route](#configure-the-gateway-and-route-5-min) — Gateway + MCP backend + HTTPRoute `/weather`
  - [Route the LLM through the Gateway](#route-the-llm-through-the-gateway-3-min) — `ai` backend + `/openai` route; gateway holds the key
  - [Add Security: API Key Auth + RBAC](#add-security-api-key-auth--rbac-3-min) — API keys with role metadata, CEL authz policy, tracing
  - [Show the Solo Enterprise UI — Dashboards](#show-the-solo-enterprise-ui--agent-gateway-dashboards-2-min) — MCP rate/error/latency + trace drill-down
  - [Key Takeaway](#key-takeaway-1-min) — single control point, zero agent changes
- **[Part 3: kagent](#part-3-kagent-enterprise-13-min)** — run the Part 1 agent as a managed workload, wired through the gateway
  - [The Problem](#the-problem-2-min-2) — a published agent is just an artifact; how do you run it?
  - [The Solution: Deploy the Registry Agent onto kagent](#the-solution-deploy-the-registry-agent-onto-kagent-3-min) — registry creates a kagent BYO agent, no YAML
  - [Step 1: Bind the Agent to its Tools via the Gateway](#step-1-bind-the-agent-to-its-tools-via-the-gateway-4-min) — register the gateway route as a remote MCP server, bind, deploy
  - [Step 2: Confirm the Agent is Running](#step-2-confirm-the-agent-is-running-2-min) — `arctl get deployments` + `kubectl get agents`
  - [Step 3: Chat with the Agent](#step-3-chat-with-the-agent-in-the-solo-enterprise-ui-3-min) — ask Tokyo weather + CA alerts; LLM + tool calls both traced
- **[Putting It All Together](#putting-it-all-together-3-min)** — three UIs, per-product contribution, alone-vs-together value
  - [What to Demo Next](#what-to-demo-next) — token exchange, rate limiting, guardrails, multi-agent, observability
- [Cleanup](#cleanup)
- [Reference](#reference)

---

## Setup (Before the Demo)

Run the setup script to provision the cluster and install all three products:

```bash
export OPENAI_API_KEY=sk-...
export SOLO_LICENSE_KEY=eyJ...

./setup.sh
```

The script installs Agent Registry, Agent Gateway, and kagent. The demo itself walks through *building, publishing, and deploying* on top of them.

When setup completes, verify the UIs are accessible:
- **Agent Registry:** http://localhost:12121
- **Keycloak:** http://localhost:8080 (admin/admin)
- **Solo Enterprise UI:** http://localhost:8082

> **Demo users** (all password `password`): `admin` (group `admins`), `dev` (group `developers`), `viewer` (group `viewers`). All three products authenticate against the shared Keycloak realm `solo-ai-demo`, so group membership drives access across Agent Registry and kagent.

---

## Part 1: Agent Registry (Enterprise) (~20–22 min)

> **Goal:** Show how the enterprise registry solves the "where are my MCP servers?" problem — behind SSO and group-based RBAC.

### The Problem (2 min)

> **Talk track:** "In most organizations, MCP servers are scattered everywhere — npm, Docker images, internal HTTP endpoints. No central catalog, no versioning, no governance — and no access control."

### SSO Login (2 min)

**Open the Agent Registry UI** at `http://localhost:12121`. You're immediately redirected to Keycloak. Log in as **`admin`** / `password`.

> **Talk track:** "The enterprise registry is locked down — every user authenticates through your IdP. We're using Keycloak here; in your environment it's Okta, Entra, ForgeRock — anything that speaks OIDC."

### The Catalog (2 min)

> **Talk track:** "Agent Registry is a single place to discover, publish, and manage all your AI artifacts — MCP servers, agents, skills, and prompts."

> **Show:** The catalog view. On a fresh install the registry starts empty — that's intentional. Over the next few minutes you'll publish an MCP server, an agent, a skill, and a prompt, and watch the catalog fill up live. Point out the type filters (MCP / Agent / Skill / Prompt) and search you'll be using shortly.

### Authenticate the CLI with `arctl user login` (2 min)

> **Talk track:** "The UI is SSO'd — and so is the CLI. `arctl` logs in through the same OIDC issuer using the device flow."

> **PATH:** `setup.sh` installs the Enterprise `arctl` to `~/.arctl/bin`. Make sure it's first on your PATH (the installer prints this too) so you don't hit an older `arctl` from another tool:
> ```bash
> export PATH="$HOME/.arctl/bin:$PATH"
> arctl version   # expect v2026.6.0
> ```

```bash
arctl user login \
  --oidc-client-id ar-cli-interactive \
  --oidc-issuer-url http://keycloak.127.0.0.1.sslip.io:8080/realms/solo-ai-demo
# device-authorization is the default flow; the browser opens — log in as dev / password

# `arctl user whoami` resolves roles through the registry, which reads the bearer
# token from $ARCTL_API_TOKEN. The `user` command group skips keychain token
# resolution (a CLI limitation), so pass the token inline for this one call:
ARCTL_API_TOKEN=$(curl -s -X POST \
  http://keycloak.127.0.0.1.sslip.io:8080/realms/solo-ai-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ar-cli-password \
  -d username=dev -d password=password \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])') \
  arctl user whoami
```

> **Talk track:** "`whoami` shows the identity we just authenticated and the `developers` group it belongs to — that group is what the registry uses to decide what `dev` can do."

### Build and Publish the Weather MCP Server (4 min)

> **Talk track:** "Let's build a real MCP server with the CLI and publish it to the catalog."

**Step 1 — Scaffold the MCP server:**

```bash
arctl init mcp weather-tools \
  --framework fastmcp \
  --language python \
  --description "Weather forecast MCP server"
```

> This scaffolds a FastMCP project with a *dynamic tool loader*: `src/main.py` auto-discovers any function decorated with `@mcp.tool()` under `src/tools/`. You add a tool by dropping a file in that directory — no manual registration.

**Step 2 — Add a weather tool:**

```bash
cat > weather-tools/src/tools/weather.py << 'PYEOF'
"""Weather forecast tool for the weather-tools MCP server."""

from core.server import mcp

_FORECASTS = {
    "san francisco": "Foggy, 58°F, light wind from the west.",
    "new york": "Partly cloudy, 71°F, humid.",
    "london": "Rain, 54°F, overcast all day.",
    "tokyo": "Clear, 77°F, calm.",
}

_ALERTS = {
    "CA": "Heat Advisory: high temperatures inland through Thursday.",
    "FL": "Tropical Storm Watch: monitor the Gulf Coast.",
    "TX": "Severe Thunderstorm Warning: large hail and damaging winds possible.",
    "NY": "Winter Weather Advisory: 3–5 inches of snow overnight.",
}

_STATE_CODES = {
    "california": "CA",
    "florida": "FL",
    "texas": "TX",
    "new york": "NY",
}


@mcp.tool(description="Get the current weather forecast for a city.")
def get_forecast(city: str) -> str:
    """Return a short weather forecast for the given city."""
    return _FORECASTS.get(city.strip().lower(), f"No forecast on file for {city}.")


@mcp.tool(description="Get active weather alerts for a US state (name or two-letter code).")
def get_alerts(state: str) -> str:
    """Return active weather alerts for a US state name or two-letter code."""
    key = state.strip()
    code = key.upper() if len(key) == 2 else _STATE_CODES.get(key.lower(), key.upper())
    return _ALERTS.get(code, f"No active weather alerts for {state}.")
PYEOF
```

**Step 3 — Build the image and load it into the cluster:**

```bash
arctl build weather-tools/
k3d image import localhost:5001/weather-tools:latest -c solo-ai-demo
```

> `arctl build` reads the project's resource spec (`weather-tools/mcp.yaml`) and tags the image from `spec.source.package.origin.identifier` → `localhost:5001/weather-tools:latest`. `k3d image import` loads that tag onto the cluster nodes — the registry deploys with `imagePullPolicy: IfNotPresent`, so no external image registry is required.

**Step 4 — Publish to Agent Registry:**

```bash
arctl apply -f weather-tools/mcp.yaml
```

> **Show:** Navigate to the Agent Registry UI — the `weather-tools` server now appears in the catalog.

### RBAC: Deny → Grant (3 min)

> **Talk track:** "That publish worked because we're `dev` — in the `developers` group. Let's see what happens as a read-only user."

**Switch to `viewer` (password flow) and retry the publish:**

```bash
arctl user logout
arctl user login \
  --oidc-flow password-credentials \
  --oidc-client-id ar-cli-password \
  --oidc-issuer-url http://keycloak.127.0.0.1.sslip.io:8080/realms/solo-ai-demo \
  --oidc-username viewer --oidc-password password

# viewer → viewers group, read-only (token passed inline, see note above)
ARCTL_API_TOKEN=$(curl -s -X POST \
  http://keycloak.127.0.0.1.sslip.io:8080/realms/solo-ai-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ar-cli-password \
  -d username=viewer -d password=password \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])') \
  arctl user whoami

# Same publish — now denied
arctl apply -f weather-tools/mcp.yaml
# => forbidden
```

> **Talk track:** "Same command, different user — `forbidden`. The `viewer` lands in the `viewers` group, which the registry's AccessPolicy maps to read-only. Discovery yes, publish no."

**Switch back to a writer and confirm it succeeds again:**

```bash
arctl user logout
arctl user login \
  --oidc-client-id ar-cli-interactive \
  --oidc-issuer-url http://keycloak.127.0.0.1.sslip.io:8080/realms/solo-ai-demo
# log in as dev (developers) — or admin (admins) for full control

arctl apply -f weather-tools/mcp.yaml
# => success
```

> **Talk track:** "Back as `dev`, the publish goes through. Group membership in your IdP maps straight to an AccessPolicy in the registry — no per-user config, no separate access system to maintain."

**Step 5 — Deploy the MCP server from the Agent Registry UI:**

> **Talk track:** "Publishing put the server in the catalog. The enterprise registry can also *deploy* it — straight from the UI, no hand-written kagent manifests. The registry reconciles a live workload through one of its registered runtimes. `setup.sh` already connected this cluster as a **Kubernetes (kagent)** runtime, so it's ready to deploy onto."

1. In the Agent Registry UI, open the **weather-tools** MCP server's detail page.
2. Click **Deploy**.
3. In the dialog: choose **Platform = Kubernetes**, **Connection = `kagent-demo`**, and set **Deployment Name** to `weather-tools` (the field auto-fills a longer name — overwrite it so the Service name is predictable). Click **Deploy MCP Server**.

The registry creates a `Deployment` resource (`targetRef` → the published `weather-tools` server, `runtimeRef` → the `kagent-demo` runtime) and the kagent runtime reconciles it into a running `MCPServer` workload. Watch the deployment status reach **Running** in the UI, and tail the workload logs from the same page.

> **Why a runtime had to be connected first:** the catalog Deploy dialog only
> offers a runtime of type `Kagent` (labeled "Kubernetes (kagent)" in the UI).
> The chart pre-seeds a `kubernetes-default` runtime of type `Kubernetes` that
> the UI does *not* recognize — so `setup.sh` seeds a proper `kagent-demo`
> runtime (`runtimes/kagent-runtime.yaml`). Without it the dialog shows
> "No cloud runtimes configured".

> **Verify (CLI):**
> ```bash
> arctl get deployments
> # kagent deploys into the runtime's configured namespace (kagent) and names
> # the Service after the deployment. With Deployment Name = weather-tools the
> # Service is simply `weather-tools`. Part 2's Agent Gateway backend points at it:
> kubectl get svc -n kagent weather-tools
> # => weather-tools   ClusterIP   ...   3000/TCP
> kubectl get mcpservers.kagent.dev -n kagent weather-tools   # READY: True
> ```

> **Prefer the CLI?** The same deploy without the UI:
> ```bash
> cat <<'EOF' | arctl apply -f -
> apiVersion: ar.dev/v1alpha1
> kind: Deployment
> metadata:
>   name: weather-tools
> spec:
>   targetRef:
>     kind: MCPServer
>     name: weather-tools
>   runtimeRef:
>     kind: Runtime
>     name: kagent-demo
> EOF
> ```

> **Talk track:** "Same catalog, one click — and the server is running in the cluster, governed by the same SSO and RBAC. Developers deploy what they discover without ever touching raw kagent CRDs."

### Create a Prompt, Skill, and Agent (4 min)

> **Talk track:** "Agent Registry isn't just MCP servers — it catalogs prompts, skills, and complete agents. Let's create all three and publish them to the catalog."

**Create a prompt** — a reusable system prompt published to the registry:

```bash
arctl init prompt weather-assistant-prompt \
  --description "System prompt for the weather assistant agent" \
  --content "You are a friendly weather assistant. Use your tools to fetch real-time weather data before answering. Be concise but thorough."

arctl apply -f weather-assistant-prompt.yaml
```

> **Show:** The prompt in the Agent Registry UI — `arctl get prompts` to verify.

**Create a skill** — a reusable capability published to the registry:

```bash
arctl init skill weather-analysis \
  --description "Weather analysis skill"

arctl apply -f weather-analysis/skill.yaml
```

> **Show:** The skill in the Agent Registry UI under the Skills tab.

**Create an agent** — scaffold, build, and publish a complete agent:

```bash
arctl init agent weatherassistant \
  --framework adk \
  --language python \
  --model-provider openai \
  --model-name gpt-4o-mini \
  --description "AI weather assistant with forecasts and alerts"

arctl build weatherassistant/
k3d image import localhost:5001/weatherassistant:latest -c solo-ai-demo

arctl apply -f weatherassistant/agent.yaml
```

> **Show:** The agent in the Agent Registry UI — click into it to see its model and configuration.
>
> **Note:** We publish the agent *without* a tool binding. Binding to the in-cluster `weather-tools` Service now would bypass Agent Gateway; in Part 3 we bind it to the gateway route instead, so every tool call is authed and traced.

### Semantic Search + Key Takeaway (1 min)

> **Show in the UI:** Type "weather" in the search bar — our MCP server, prompt, skill, and agent all appear. Developers search by what they need, not by exact names.

> **Talk track:** "So: a single pane of glass for all AI artifacts, behind SSO, with group-based RBAC deciding who can publish. Discovery is step one — how do we *route* to these servers securely? That's Agent Gateway."

---

## Part 2: Agent Gateway (Enterprise) (~17 min)

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
      # Host = the Service the registry created in Part 1 Step 5
      # (named after the deployment, in the kagent runtime's namespace).
      # Confirm with `kubectl get svc -n kagent weather-tools`.
      static:
        host: weather-tools.kagent.svc.cluster.local
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

### Route the LLM through the Gateway (3 min)

> **Talk track:** "Agent Gateway doesn't just front MCP tools — it fronts the LLM too. Let's add an `ai` backend for OpenAI so every model call our agent makes flows through the gateway: the gateway holds the API key, and gets auth, RBAC, and tracing on LLM traffic. The agent never sees the real key."

**Step 1 — Store the OpenAI key in a Secret the gateway owns:**

```bash
# The gateway injects this value as the `Authorization` header on every LLM
# call — so it must be the full `Bearer <key>` string. The agent we deploy in
# Part 3 carries only a placeholder; the gateway overrides it with this key.
kubectl create secret generic openai-secret -n agentgateway-system \
  --from-literal=Authorization="Bearer $OPENAI_API_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
```

**Step 2 — Create the AI (LLM) Backend:**

```bash
kubectl apply -f - <<'EOF'
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: openai
  namespace: agentgateway-system
spec:
  ai:
    groups:
    - providers:
      - name: openai
        openai:
          model: gpt-4o-mini
        policies:
          auth:
            secretRef:
              name: openai-secret
EOF
```

**Step 3 — Create the HTTPRoute (OpenAI-compatible path):**

```bash
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: openai
  namespace: agentgateway-system
spec:
  parentRefs:
  - name: ai-gateway
    sectionName: mcp
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /openai
    backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: openai
EOF
```

**Verify the LLM route — a chat completion through the gateway:**

```bash
# No Authorization header — the gateway injects it from openai-secret.
kubectl run agw-llm-test --rm -i --restart=Never \
  --image=curlimages/curl:8.10.1 -n agentgateway-system --quiet -- \
  -sS -X POST "http://ai-gateway.agentgateway-system.svc.cluster.local:3000/openai/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"reply with just the word PONG"}]}'
# => {... "content":"PONG" ...}
```

> **Talk track:** "That call carried no API key — the gateway supplied it. In Part 3 we point the agent's `OPENAI_BASE_URL` at this route, so the agent's model calls are governed and traced here too, and the key lives only in the gateway."

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

**Open the Solo Enterprise UI** at `http://localhost:8082` and navigate to **Agent Gateway**.

> **Talk track:** "Every request through Agent Gateway generates OpenTelemetry traces. The Solo Enterprise UI gives you pre-built dashboards for LLM traffic, MCP tool calls, cost tracking, and more."

> **Show:**
> - **MCP dashboard** — request rate by tool name, error rates, latency
> - **Traces** — drill into a specific request to see the full path: agent -> gateway -> MCP server

### Key Takeaway (1 min)

> **Talk track:** "Agent Gateway gives you a single control point for all agent traffic. Auth, RBAC, rate limiting, guardrails, and observability — without changing your agents or MCP servers. Now let's actually *run* an agent — we published one to the registry in Part 1, but now we'll deploy it as a live Kubernetes resource with kagent."

---

## Part 3: kagent (Enterprise) (~13 min)

> **Goal:** Run the agent we built in Part 1 as a managed Kubernetes workload, wired to its tools through Agent Gateway, and chat with it.

### The Problem (2 min)

> **Talk track:** "We have a tool in the registry, a secure gateway in front of it, and an agent published to the catalog. But a published agent is just an artifact — how do we actually *run* it? Most teams hand-write Kubernetes manifests and custom glue code for every agent. kagent runs agents as first-class Kubernetes resources, managed for you."

### The Solution: Deploy the Registry Agent onto kagent (3 min)

> **Talk track:** "We deploy the agent onto the same `kagent-demo` runtime we used for the MCP server in Part 1. The registry creates a kagent **BYO agent** — a managed workload running our agent image, fronted by kagent's A2A endpoint. There's no separate agent YAML to author; the registry and kagent build it for us."

### Step 1: Bind the Agent to its Tools via the Gateway (4 min)

> **Talk track:** "We left the agent unbound in Part 1. Now we register the gateway's weather route as a *remote* MCP server and bind the agent to that — so tool calls flow through Agent Gateway (auth, RBAC, tracing) instead of straight to the Service. The binding lives in the catalog: discoverable, versioned, portable."

**Register the Agent Gateway weather route as a remote MCP server:**

```bash
cat > weather-tools-remote.yaml <<'EOF'
apiVersion: ar.dev/v1alpha1
kind: MCPServer
metadata:
  name: weather-tools-remote
spec:
  description: Weather MCP, fronted by Agent Gateway
  remote:
    type: streamable-http
    url: http://ai-gateway.agentgateway-system.svc.cluster.local:3000/weather/mcp
    headers:
    - name: Authorization
      value: Bearer demo-key-12345
EOF

arctl apply -f weather-tools-remote.yaml
```

> **Talk track:** "`remote.url` is the gateway route from Part 2, not the tool's Service; `remote.headers` carries the gateway API key. The agent authenticates to the gateway, which validates the key, checks RBAC, then reaches the MCP server — the agent never talks to the tool directly."

**Bind the agent to it** — add an `mcpServers` block to the scaffolded agent spec, then re-publish:

```bash
# Add the tool binding to the agent published in Part 1.
cat >> weatherassistant/agent.yaml <<'EOF'
  mcpServers:
  - kind: MCPServer
    name: weather-tools-remote
    tag: latest
EOF

arctl apply -f weatherassistant/agent.yaml
```

> **Show:** Reopen the agent in the Agent Registry UI — it now lists `weather-tools-remote` under its tools/MCP servers.

**Deploy the agent onto the kagent runtime:**

```bash
cat > agent-deployment.yaml <<'EOF'
apiVersion: ar.dev/v1alpha1
kind: Deployment
metadata:
  name: weatherassistant
spec:
  targetRef:
    kind: Agent
    name: weatherassistant
    tag: latest
  runtimeRef:
    kind: Runtime
    name: kagent-demo
  env:
    # Placeholder only — the real key lives in the gateway's openai-secret
    # (Part 2). The agent's model client requires OPENAI_API_KEY to be
    # non-empty; Agent Gateway overrides whatever the agent sends with the
    # real key.
    OPENAI_API_KEY: "sk-agw-managed"
    # Point the agent's model calls at the Agent Gateway LLM route from Part 2.
    # The client appends /chat/completions to this base.
    OPENAI_BASE_URL: "http://ai-gateway.agentgateway-system.svc.cluster.local:3000/openai/v1"
    OPENAI_API_BASE: "http://ai-gateway.agentgateway-system.svc.cluster.local:3000/openai/v1"
EOF

arctl apply -f agent-deployment.yaml
```

> **Talk track:** "Tool routing now comes from the *catalog* — the remote `MCPServer` we just bound, pointed at the gateway. The Deployment env only carries the *model* wiring: `OPENAI_BASE_URL` sends the agent's LLM calls through the gateway's LLM route, and the placeholder `OPENAI_API_KEY` satisfies the client's non-empty check — the gateway holds the real key. Both LLM and tool traffic flow through Agent Gateway; the agent itself holds no real credentials."
>
> **Security note:** The registry's Deployment `env` is a plaintext map (it can't reference a Kubernetes Secret), so we *don't* put the OpenAI key here — the agent carries only the placeholder `sk-agw-managed`. The real key lives solely in the gateway's `openai-secret` (created in Part 2), and the gateway injects it. The tool API key lives in the catalog `MCPServer` instead of the deployment — for a real (non-demo) key, set `spec.remote.headers[].value` via shell expansion (`${...}`) at apply time, never a literal in committed YAML.
>
> **Verify on first run:** This catalog-binding path replaces the older deploy-time `MCP_SERVERS_CONFIG` env. On a fresh cluster, after the chat in Step 3, confirm in **Agent Gateway > Traces** that you see a `…/weather/mcp` span originating from the agent pod — that proves the running agent picked up the catalog-declared tool (and didn't silently fall back to no tools). If the agent reports no tools available, the runtime didn't project the catalog binding into the container; in that case re-add the `MCP_SERVERS_CONFIG` env entry (remote MCP, gateway URL, same `Authorization` header) as the fallback.

### Step 2: Confirm the Agent is Running (2 min)

```bash
arctl get deployments
kubectl get agents.kagent.dev -A
```

> **Show:** The registry Deployment moves from `STATUS: deploying` to `STATUS: deployed`, and a kagent **BYO** agent named `weatherassistant` (in the `kagent` namespace, alongside the MCP server) shows `ACCEPTED: True` and `READY: True`. The registry created that kagent resource automatically.

> **Talk track:** "One `arctl apply`, and the registry stood up a managed kagent agent running our image — wired to its tools through the gateway. No agent code, no hand-written kagent manifest."

### Step 3: Chat with the Agent in the Solo Enterprise UI (3 min)

**Open the Solo Enterprise UI** at `http://localhost:8082` and navigate to **kagent** > **Agents** > **weatherassistant**.

1. Open the **Chat** panel
2. Type: **"What's the weather in Tokyo?"**

> **Show:** The agent:
> 1. Receives the question
> 2. Calls its LLM — *through Agent Gateway* (the gateway supplies the OpenAI key, records the trace)
> 3. Calls the `get_forecast` tool — *also through Agent Gateway*
> 4. Agent Gateway validates the API key, checks RBAC, records the trace
> 5. The weather MCP server returns the forecast
> 6. The agent formats and returns the answer

3. Type: **"Any weather alerts for California?"**

> **Show:** The agent calls `get_alerts` with state "CA".

> **Talk track:** "That chat exercised the entire stack: an agent built and deployed by Agent Registry, running on kagent — with *both* its LLM calls and its tool calls routed through Agent Gateway's auth, RBAC, and tracing. The agent itself holds no credentials."

> **Show in the Solo Enterprise UI:** Navigate to **Agent Gateway** > **Traces** — find this request and show the spans: `agent → gateway → OpenAI` (the LLM call) and `agent → gateway → MCP server` (the tool call).

---

## Putting It All Together (~3 min)

### The Three UIs

| UI | URL | What It Shows |
|----|-----|---------------|
| **Agent Registry** | `http://localhost:12121` | MCP server catalog, semantic search, deployment status |
| **Solo Enterprise UI — Agent Gateway** | `http://localhost:8082` (AGW tab) | LLM/MCP dashboards, cost tracking, OTEL traces, route status |
| **Solo Enterprise UI — kagent** | `http://localhost:8082` (kagent tab) | Agent list, chat interface, tool execution, agent configuration |

### What Each Product Contributed

| Product | Role | What It Did |
|---------|------|-------------|
| **Agent Registry** | Catalog & Discovery | MCP servers, prompts, skills, and agents were published to the catalog. Developers searched "weather" and found them. |
| **Agent Gateway** | Routing & Security | Routed both the agent's LLM calls and its MCP tool calls, held the OpenAI key, validated the API key, enforced RBAC, generated OTEL traces. Zero changes to the agent or MCP server. |
| **kagent** | Agent Lifecycle | The registry-built agent ran as a managed kagent **BYO** workload, wired to its tools through the gateway, and accessible through the Solo Enterprise chat UI. No hand-written agent manifest. |

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
rm -rf weather-tools/ weather-analysis/ weatherassistant/ \
  weather-assistant-prompt.yaml agent-deployment.yaml weather-tools-remote.yaml

# Remove the registry deployments (this also removes the kagent BYO agent,
# the MCP workload, and their Services that the registry created).
# Deployments are namespaced — list them first, then delete by the shown <ns>/<name>:
arctl get deployments
arctl delete deployment default/weatherassistant
arctl delete deployment demo/weather-tools

# Remove the registry artifacts
arctl delete agent weatherassistant
arctl delete mcp weather-tools
arctl delete mcp weather-tools-remote
arctl delete skill weather-analysis
arctl delete prompt weather-assistant-prompt

# Remove the Agent Gateway resources
kubectl delete secret demo-api-keys openai-secret -n agentgateway-system
kubectl delete agentgatewaypolicy weather-security tracing -n agentgateway-system
kubectl delete httproute weather-tools openai -n agentgateway-system
kubectl delete agentgatewaybackend weather-tools openai -n agentgateway-system
kubectl delete gateway ai-gateway -n agentgateway-system
kubectl delete referencegrant agw-to-collector -n kagent

# Remove products (if desired)
helm uninstall kagent -n kagent
helm uninstall kagent-crds -n kagent
helm uninstall kagent-mgmt -n kagent
helm uninstall enterprise-agentgateway -n agentgateway-system
helm uninstall enterprise-agentgateway-crds -n agentgateway-system
helm uninstall agentregistry -n agentregistry-system

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
