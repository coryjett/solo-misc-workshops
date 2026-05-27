# Snowflake Token Exchange Workshop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a workshop demonstrating credential isolation — user authenticates via OIDC, AGW exchanges the JWT for an opaque token before it reaches the agent, and the mock Snowflake MCP server validates the opaque token via Keycloak introspection.

**Architecture:** kagent UI → AGW (JWT→opaque token exchange via Keycloak) → kagent Agent Pod → Mock Snowflake MCP server (introspects opaque token against Keycloak). oauth2-proxy sits in front of kagent UI for OIDC login.

**Tech Stack:** k3d, Keycloak 26.x, AGW Enterprise, kagent OSS, oauth2-proxy, Python MCP server

---

## File Structure

```
Snowflake-Token-Exchange-Workshop/
├── README.md                     # Workshop overview, architecture, step-by-step guide
├── setup.sh                      # Single script to deploy everything
├── cleanup.sh                    # Tear down k3d cluster
├── snowflake-mcp/
│   └── server.py                 # Mock Snowflake MCP server with Keycloak introspection
└── k8s/
    ├── keycloak.yaml             # Keycloak StatefulSet + PostgreSQL + Services
    ├── snowflake-mcp.yaml        # ConfigMap + Deployment + Service for mock MCP server
    ├── agw.yaml                  # Gateway + HTTPRoute + EnterpriseAgentgatewayPolicy
    ├── oauth2-proxy.yaml         # oauth2-proxy Deployment + Service + ConfigMap
    └── kagent.yaml               # Agent + ModelConfig + RemoteMCPServer CRDs
```

Each file has one responsibility. `setup.sh` orchestrates them in order with waits between steps.

---

### Task 1: Mock Snowflake MCP Server

The MCP server that receives opaque tokens and introspects them against Keycloak. This is the core demo artifact — it proves the backend never sees a JWT.

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/snowflake-mcp/server.py`

- [ ] **Step 1: Write `server.py`**

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, os, sys, urllib.request, urllib.parse

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak.keycloak.svc.cluster.local:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "snowflake-workshop")
INTROSPECT_CLIENT_ID = os.environ.get("INTROSPECT_CLIENT_ID", "agw-exchange")
INTROSPECT_CLIENT_SECRET = os.environ.get("INTROSPECT_CLIENT_SECRET", "agw-exchange-secret")

INTROSPECT_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"

MOCK_SALES = [
    {"region": "WEST", "total_sales": 142500, "quarter": "Q1"},
    {"region": "EAST", "total_sales": 198300, "quarter": "Q1"},
    {"region": "CENTRAL", "total_sales": 167800, "quarter": "Q1"},
]

MOCK_TABLES = [
    {"schema": "SALES", "name": "ORDERS", "row_count": 15420},
    {"schema": "SALES", "name": "CUSTOMERS", "row_count": 3200},
    {"schema": "ANALYTICS", "name": "DAILY_REVENUE", "row_count": 365},
]

def introspect_token(token):
    """Call Keycloak's introspection endpoint to validate an opaque token."""
    data = urllib.parse.urlencode({
        "token": token,
        "client_id": INTROSPECT_CLIENT_ID,
        "client_secret": INTROSPECT_CLIENT_SECRET,
    }).encode()
    req = urllib.request.Request(INTROSPECT_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        sys.stderr.write(f"Introspection failed: {e}\n")
        return {"active": False, "error": str(e)}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()

        # Extract token and introspect
        token = auth[7:] if auth.startswith("Bearer ") else None
        introspection = None
        if token:
            # Check if this looks like a JWT (3 dot-separated parts) or opaque
            is_jwt = len(token.split(".")) == 3
            token_type = "jwt" if is_jwt else "opaque"
            introspection = introspect_token(token)
            sys.stderr.write(
                f"\n{'='*50}\n"
                f"SNOWFLAKE MCP SERVER\n"
                f"  token_type: {token_type}\n"
                f"  active: {introspection.get('active')}\n"
                f"  sub: {introspection.get('sub', 'n/a')}\n"
                f"  client_id: {introspection.get('client_id', 'n/a')}\n"
                f"{'='*50}\n"
            )
            sys.stderr.flush()

        try:
            req = json.loads(body)
        except Exception:
            req = {}

        method = req.get("method", "")
        req_id = req.get("id")

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "snowflake-mcp", "version": "1.0"},
                },
            }
        elif method == "notifications/initialized":
            self.send_response(200)
            self.end_headers()
            return
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "query_sales",
                            "description": "Query sales data from Snowflake. Returns sales totals by region.",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                        {
                            "name": "list_tables",
                            "description": "List available tables in Snowflake.",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                    ]
                },
            }
        elif method == "tools/call":
            tool_name = req.get("params", {}).get("name", "")
            if not introspection or not introspection.get("active"):
                result = {"error": "Token introspection failed — access denied", "introspection": introspection}
            elif tool_name == "query_sales":
                result = {
                    "token_type": token_type,
                    "introspection": {
                        "active": introspection.get("active"),
                        "sub": introspection.get("sub"),
                        "scope": introspection.get("scope"),
                        "client_id": introspection.get("client_id"),
                    },
                    "query_result": MOCK_SALES,
                }
            elif tool_name == "list_tables":
                result = {
                    "token_type": token_type,
                    "introspection": {
                        "active": introspection.get("active"),
                        "sub": introspection.get("sub"),
                    },
                    "tables": MOCK_TABLES,
                }
            else:
                result = {"error": f"Unknown tool: {tool_name}"}
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
            }
        else:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown: {method}"}}

        out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, format, *args):
        pass  # Suppress default access logs


if __name__ == "__main__":
    print(f"Snowflake MCP server starting on :80")
    print(f"  Introspection endpoint: {INTROSPECT_URL}")
    HTTPServer(("", 80), Handler).serve_forever()
```

- [ ] **Step 2: Test locally**

Run: `python3 snowflake-mcp/server.py &`
Then: `curl -s -X POST http://localhost:80 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq .`
Expected: JSON listing `query_sales` and `list_tables` tools.
Kill: `kill %1`

- [ ] **Step 3: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/snowflake-mcp/server.py
git commit -m "feat: add mock Snowflake MCP server with Keycloak introspection"
```

---

### Task 2: Kubernetes Manifests — Keycloak

Keycloak with PostgreSQL, same pattern as existing auth flows but with a different realm.

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/k8s/keycloak.yaml`

- [ ] **Step 1: Write `keycloak.yaml`**

This is the same Keycloak + PostgreSQL deployment used across the auth patterns. It's a static manifest that `setup.sh` will `kubectl apply`.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: keycloak
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: keycloak
spec:
  ports:
  - port: 8080
    targetPort: http
    name: http
  selector:
    app: keycloak
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak-discovery
  namespace: keycloak
spec:
  selector:
    app: keycloak
  clusterIP: None
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: keycloak
  namespace: keycloak
spec:
  serviceName: keycloak-discovery
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:26.5.2
        args: ["start"]
        env:
        - name: KC_BOOTSTRAP_ADMIN_USERNAME
          value: "admin"
        - name: KC_BOOTSTRAP_ADMIN_PASSWORD
          value: "admin"
        - name: KC_PROXY_HEADERS
          value: "xforwarded"
        - name: KC_HTTP_ENABLED
          value: "true"
        - name: KC_HOSTNAME_STRICT
          value: "false"
        - name: KC_HEALTH_ENABLED
          value: "true"
        - name: KC_DB_URL_DATABASE
          value: "keycloak"
        - name: KC_DB_URL_HOST
          value: "postgres"
        - name: KC_DB
          value: "postgres"
        - name: KC_DB_PASSWORD
          value: "keycloak"
        - name: KC_DB_USERNAME
          value: "keycloak"
        ports:
        - name: http
          containerPort: 8080
        startupProbe:
          httpGet:
            path: /health/started
            port: 9000
          periodSeconds: 5
          failureThreshold: 60
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 9000
          periodSeconds: 10
          failureThreshold: 3
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: keycloak
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_USER
          value: "keycloak"
        - name: POSTGRES_PASSWORD
          value: "keycloak"
        - name: POSTGRES_DB
          value: "keycloak"
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-data
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: keycloak
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
```

- [ ] **Step 2: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/k8s/keycloak.yaml
git commit -m "feat: add Keycloak + PostgreSQL k8s manifests"
```

---

### Task 3: Kubernetes Manifests — Snowflake MCP Server

Deploy the mock Snowflake MCP server as a ConfigMap + Deployment + Service.

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/k8s/snowflake-mcp.yaml`

- [ ] **Step 1: Write `snowflake-mcp.yaml`**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: snowflake-mcp-script
  namespace: default
data:
  server.py: |
    # Content is mounted from the snowflake-mcp/server.py file via setup.sh
    # This ConfigMap is created dynamically by setup.sh using:
    #   kubectl create configmap snowflake-mcp-script --from-file=server.py=snowflake-mcp/server.py
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: snowflake-mcp
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: snowflake-mcp
  template:
    metadata:
      labels:
        app: snowflake-mcp
    spec:
      containers:
      - name: mcp
        image: python:3.12-slim
        command: ["python", "/app/server.py"]
        ports:
        - containerPort: 80
        env:
        - name: KEYCLOAK_URL
          value: "http://keycloak.keycloak.svc.cluster.local:8080"
        - name: KEYCLOAK_REALM
          value: "snowflake-workshop"
        - name: INTROSPECT_CLIENT_ID
          value: "agw-exchange"
        - name: INTROSPECT_CLIENT_SECRET
          value: "agw-exchange-secret"
        volumeMounts:
        - name: script
          mountPath: /app
      volumes:
      - name: script
        configMap:
          name: snowflake-mcp-script
---
apiVersion: v1
kind: Service
metadata:
  name: snowflake-mcp
  namespace: default
spec:
  selector:
    app: snowflake-mcp
  ports:
  - port: 80
    targetPort: 80
```

- [ ] **Step 2: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/k8s/snowflake-mcp.yaml
git commit -m "feat: add Snowflake MCP server k8s manifests"
```

---

### Task 4: Kubernetes Manifests — AGW

Gateway, HTTPRoute, and EnterpriseAgentgatewayPolicy for JWT validation + token exchange. Note: the AGW in this workshop routes between kagent UI and the Agent Pod, not between agent and MCP. The exact Agent Pod service name depends on kagent's naming — `setup.sh` will template it.

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/k8s/agw.yaml`

- [ ] **Step 1: Write `agw.yaml`**

This file uses `envsubst`-style variables that `setup.sh` will substitute at apply time.

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-default-to-keycloak
  namespace: keycloak
spec:
  from:
  - group: enterpriseagentgateway.solo.io
    kind: EnterpriseAgentgatewayPolicy
    namespace: default
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    namespace: default
  to:
  - group: ""
    kind: Service
    name: keycloak
---
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: workshop-params
  namespace: default
spec:
  env:
  - name: STS_URI
    value: "${KEYCLOAK_URL_INTERNAL}/realms/snowflake-workshop/protocol/openid-connect/token"
  - name: STS_TOKEN_EXCHANGE_CLIENT_ID
    value: "agw-exchange"
  - name: STS_TOKEN_EXCHANGE_CLIENT_SECRET
    value: "agw-exchange-secret"
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: workshop-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: workshop-params
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: workshop-route
  namespace: default
spec:
  parentRefs:
  - name: workshop-gateway
  rules:
  - backendRefs:
    - name: ${AGENT_SERVICE_NAME}
      namespace: ${AGENT_SERVICE_NAMESPACE}
      port: ${AGENT_SERVICE_PORT}
    matches:
    - path:
        type: PathPrefix
        value: /
---
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: workshop-policy
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: workshop-route
  traffic:
    jwtAuthentication:
      issuer: "${KEYCLOAK_ISSUER}"
      jwks:
        backendRef:
          name: keycloak
          kind: Service
          namespace: keycloak
          port: 8080
        jwksPath: "realms/snowflake-workshop/protocol/openid-connect/certs"
      audiences:
      - account
      - kagent-ui
      mode: Strict
      provider: Keycloak
    tokenExchange:
      mode: ExchangeOnly
```

- [ ] **Step 2: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/k8s/agw.yaml
git commit -m "feat: add AGW gateway + token exchange policy manifests"
```

---

### Task 5: Kubernetes Manifests — oauth2-proxy

Deploys oauth2-proxy in front of kagent UI for OIDC login.

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/k8s/oauth2-proxy.yaml`

- [ ] **Step 1: Write `oauth2-proxy.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-proxy
  namespace: kagent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: oauth2-proxy
  template:
    metadata:
      labels:
        app: oauth2-proxy
    spec:
      containers:
      - name: oauth2-proxy
        image: quay.io/oauth2-proxy/oauth2-proxy:v7.7.1
        args:
        - --provider=keycloak-oidc
        - --client-id=kagent-ui
        - --client-secret=kagent-ui-secret
        - --redirect-url=http://localhost:8080/oauth2/callback
        - --oidc-issuer-url=http://keycloak.keycloak.svc.cluster.local:8080/realms/snowflake-workshop
        - --upstream=http://kagent-ui.kagent.svc.cluster.local:8080
        - --http-address=0.0.0.0:4180
        - --cookie-secret=REPLACE_WITH_RANDOM_32_BYTES
        - --cookie-secure=false
        - --email-domain=*
        - --pass-access-token=true
        - --pass-authorization-header=true
        - --skip-provider-button=true
        - --code-challenge-method=S256
        ports:
        - containerPort: 4180
        readinessProbe:
          httpGet:
            path: /ping
            port: 4180
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: oauth2-proxy
  namespace: kagent
spec:
  selector:
    app: oauth2-proxy
  ports:
  - port: 8080
    targetPort: 4180
```

- [ ] **Step 2: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/k8s/oauth2-proxy.yaml
git commit -m "feat: add oauth2-proxy manifests for kagent UI OIDC login"
```

---

### Task 6: Kubernetes Manifests — kagent CRDs

Agent, ModelConfig, and RemoteMCPServer definitions.

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/k8s/kagent.yaml`

- [ ] **Step 1: Write `kagent.yaml`**

```yaml
apiVersion: kagent.dev/v1alpha2
kind: ModelConfig
metadata:
  name: openai-config
  namespace: kagent
spec:
  provider: openai
  model: gpt-4o
  apiKeySecretName: openai-api-key
  apiKeySecretKey: api-key
---
apiVersion: kagent.dev/v1alpha2
kind: RemoteMCPServer
metadata:
  name: snowflake-mcp
  namespace: kagent
spec:
  protocol: STREAMABLE_HTTP
  url: http://snowflake-mcp.default.svc.cluster.local:80
  timeout: 30s
---
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: snowflake-analyst
  namespace: kagent
spec:
  description: "Snowflake data analyst — queries sales data and lists available tables"
  type: Declarative
  declarative:
    modelConfig: openai-config
    systemMessage: |
      You are a Snowflake data analyst. You have access to a Snowflake database
      through MCP tools. Use the available tools to help users query data and
      explore the database schema.

      When you receive results, present them clearly. The results include
      introspection metadata showing how the token was validated — include this
      in your response so the user can see the security flow in action.

      Available tools:
      - query_sales: Query sales data by region
      - list_tables: List available database tables
    tools:
    - type: McpServer
      mcpServer:
        name: snowflake-mcp
        kind: RemoteMCPServer
        apiGroup: kagent.dev
        toolNames:
        - query_sales
        - list_tables
```

- [ ] **Step 2: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/k8s/kagent.yaml
git commit -m "feat: add kagent Agent, ModelConfig, RemoteMCPServer CRDs"
```

---

### Task 7: Setup Script

Orchestrates the full deployment.

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/setup.sh`

- [ ] **Step 1: Write `setup.sh`**

```bash
#!/usr/bin/env bash
# Snowflake Token Exchange Workshop — setup script
# Deploys: k3d + AGW Enterprise + Keycloak + kagent OSS + mock Snowflake MCP server
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
KEYCLOAK_ISSUER="http://keycloak.keycloak.svc.cluster.local:8080/realms/${KEYCLOAK_REALM}"
KEYCLOAK_URL="http://localhost:8080"
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

info "Installing Enterprise Agentgateway ${AGW_VERSION}..."
helm upgrade -i -n agentgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version "${AGW_VERSION}" \
  --set-string licensing.licenseKey="${AGENTGATEWAY_LICENSE_KEY}" \
  --set agentgateway.enabled=true

info "Waiting for AGW pods..."
kubectl -n agentgateway-system wait --for=condition=ready pod \
  -l app.kubernetes.io/name=enterprise-agentgateway --timeout=180s
ok "Enterprise Agentgateway deployed"

# ── 4. Keycloak ──────────────────────────────────────────────────────────────
info "Deploying Keycloak..."
kubectl apply -f "${SCRIPT_DIR}/k8s/keycloak.yaml"
info "Waiting for Keycloak (this takes ~2 min)..."
kubectl wait -n keycloak statefulset/keycloak --for=jsonpath='{.status.readyReplicas}'=1 --timeout=420s
ok "Keycloak deployed"

kill_pf "keycloak.*8080"
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &>/dev/null &
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

# Create agw-exchange client (confidential, token exchange + opaque tokens)
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "agw-exchange",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "secret": "agw-exchange-secret",
    "publicClient": false,
    "serviceAccountsEnabled": true,
    "directAccessGrantsEnabled": false,
    "standardFlowEnabled": false,
    "attributes": {
      "access.token.lifespan": "300",
      "use.refresh.tokens": "false"
    }
  }' || true

# Enable token exchange permission on agw-exchange
# Get the agw-exchange client internal ID
AGW_CLIENT_ID=$(curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=agw-exchange" \
  | jq -r '.[0].id')

# Enable token-exchange scope on realm management
info "Enabling token exchange permissions..."
# The token exchange grant type needs to be enabled via fine-grained permissions
# For Keycloak 26.x, enable permissions on the agw-exchange client
curl -sf -X PUT "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${AGW_CLIENT_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"clientId\": \"agw-exchange\",
    \"enabled\": true,
    \"clientAuthenticatorType\": \"client-secret\",
    \"secret\": \"agw-exchange-secret\",
    \"serviceAccountsEnabled\": true,
    \"attributes\": {
      \"oidc.ciba.grant.enabled\": \"false\",
      \"oauth2.device.authorization.grant.enabled\": \"false\",
      \"token.endpoint.auth.signing.alg\": \"RS256\"
    }
  }" || true

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

ok "Keycloak configured (realm=${KEYCLOAK_REALM}, clients=kagent-ui+agw-exchange, user=testuser/testuser)"

# ── 6. Deploy mock Snowflake MCP server ──────────────────────────────────────
info "Deploying mock Snowflake MCP server..."
kubectl create configmap snowflake-mcp-script \
  --from-file=server.py="${SCRIPT_DIR}/snowflake-mcp/server.py" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "${SCRIPT_DIR}/k8s/snowflake-mcp.yaml"
kubectl wait deployment/snowflake-mcp --for=condition=Available --timeout=120s
ok "Snowflake MCP server deployed"

# ── 7. Install kagent OSS ───────────────────────────────────────────────────
info "Installing kagent CRDs..."
helm upgrade -i --create-namespace \
  --namespace kagent \
  kagent-crds \
  oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds

info "Installing kagent..."
# Get the AGW gateway service name (will be created after we apply the gateway)
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

# ── 8. Apply AGW resources ──────────────────────────────────────────────────
info "Applying AGW gateway + token exchange policy..."

# We need to discover the agent pod service that kagent creates
# First apply the kagent CRDs so the agent pod gets created
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

# ── 9. Deploy oauth2-proxy ──────────────────────────────────────────────────
info "Deploying oauth2-proxy..."

# Generate a random cookie secret
COOKIE_SECRET=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")

# Patch the oauth2-proxy manifest with the cookie secret
sed "s|REPLACE_WITH_RANDOM_32_BYTES|${COOKIE_SECRET}|g" \
  "${SCRIPT_DIR}/k8s/oauth2-proxy.yaml" | kubectl apply -f -

kubectl -n kagent wait --for=condition=Available deployment/oauth2-proxy --timeout=120s
ok "oauth2-proxy deployed"

# ── 10. Port-forward and print instructions ─────────────────────────────────
kill_pf "oauth2-proxy.*8080"
kubectl port-forward -n kagent svc/oauth2-proxy 8080:8080 &>/dev/null &
sleep 2

echo ""
echo "=========================================="
echo "  Snowflake Token Exchange Workshop"
echo "=========================================="
echo ""
echo "  kagent UI:  http://localhost:8080"
echo "  Keycloak:   http://localhost:8080 (admin/admin)"
echo "  Login as:   testuser / testuser"
echo ""
echo "  1. Open http://localhost:8080 in your browser"
echo "  2. Log in with testuser / testuser"
echo "  3. Select the 'Snowflake Analyst' agent"
echo "  4. Ask: 'Show me the sales data'"
echo ""
echo "  The response will show:"
echo "    - Mock Snowflake query results"
echo "    - Token introspection metadata (proving opaque token was used)"
echo ""
echo "  Cleanup: ./cleanup.sh"
echo "=========================================="
```

- [ ] **Step 2: Make executable**

```bash
chmod +x Snowflake-Token-Exchange-Workshop/setup.sh
```

- [ ] **Step 3: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/setup.sh
git commit -m "feat: add setup.sh — full workshop deployment script"
```

---

### Task 8: Cleanup Script

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/cleanup.sh`

- [ ] **Step 1: Write `cleanup.sh`**

```bash
#!/usr/bin/env bash
# Snowflake Token Exchange Workshop — cleanup
set -euo pipefail

CLUSTER_NAME="snowflake-workshop"

echo "Cleaning up..."
pkill -f "port-forward" 2>/dev/null || true

if command -v k3d >/dev/null 2>&1 && k3d cluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  k3d cluster delete "${CLUSTER_NAME}"
  echo "Cluster ${CLUSTER_NAME} deleted"
else
  echo "No cluster to delete"
fi
```

- [ ] **Step 2: Make executable**

```bash
chmod +x Snowflake-Token-Exchange-Workshop/cleanup.sh
```

- [ ] **Step 3: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/cleanup.sh
git commit -m "feat: add cleanup.sh"
```

---

### Task 9: README

Workshop overview with architecture diagram, prerequisites, and step-by-step guide.

**Files:**
- Create: `Snowflake-Token-Exchange-Workshop/README.md`

- [ ] **Step 1: Write `README.md`**

```markdown
# Snowflake Token Exchange Workshop

Demonstrates credential isolation for agentic AI: a user authenticates via OIDC, Agent Gateway exchanges the JWT for an opaque token, and the mock Snowflake MCP server validates the opaque token via Keycloak introspection. The sensitive backend never sees the original JWT.

## Architecture

```
User (browser)
  │
  ▼
oauth2-proxy ──► kagent UI ──(JWT)──► AGW Enterprise ──(opaque token)──► kagent Agent Pod
                                          │                                    │
                                          │ token exchange                     │ direct
                                          ▼                                    ▼
                                      Keycloak                       Mock Snowflake MCP Server
                                          ▲                                    │
                                          │ introspection                      │
                                          └────────────────────────────────────┘
```

### How it works

1. **User opens kagent UI** → oauth2-proxy redirects to Keycloak OIDC login
2. **User authenticates** → Keycloak returns JWT → oauth2-proxy proxies to kagent UI
3. **User chats** with the Snowflake Analyst agent
4. **kagent sends request** with JWT → **AGW** (via `proxy.url`)
5. **AGW exchanges JWT** for an opaque token at Keycloak (RFC 8693 token exchange)
6. **AGW forwards** the opaque token → **kagent Agent Pod**
7. **Agent calls** `query_sales` or `list_tables` → **Mock Snowflake MCP server**
8. **Snowflake MCP introspects** the opaque token against Keycloak
9. **Results returned** with introspection metadata proving credential isolation

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- `export OPENAI_API_KEY="<your-openai-key>"`

## Quick Start

```bash
./setup.sh
```

Then open `http://localhost:8080`, log in as `testuser` / `testuser`, select the **Snowflake Analyst** agent, and ask "Show me the sales data".

## What to look for

The agent's response includes **introspection metadata** alongside the query results:

```json
{
  "token_type": "opaque",
  "introspection": {
    "active": true,
    "sub": "testuser",
    "scope": "openid email",
    "client_id": "agw-exchange"
  },
  "query_result": [
    {"region": "WEST", "total_sales": 142500},
    {"region": "EAST", "total_sales": 198300}
  ]
}
```

This proves:
- The Snowflake MCP server received an **opaque token** (not a JWT)
- It validated the token by calling Keycloak's **introspection endpoint**
- It knows the user's identity (`sub: testuser`) without ever seeing the original JWT

## Cleanup

```bash
./cleanup.sh
```
```

- [ ] **Step 2: Commit**

```bash
git add Snowflake-Token-Exchange-Workshop/README.md
git commit -m "feat: add workshop README with architecture and instructions"
```

---

### Task 10: End-to-End Test

Deploy the workshop and verify the full flow works.

**Files:** None (manual testing)

- [ ] **Step 1: Run setup**

```bash
cd Snowflake-Token-Exchange-Workshop
./setup.sh
```

Expected: All components deploy successfully, port-forwards established, instructions printed.

- [ ] **Step 2: Verify Keycloak realm**

```bash
# Get admin token
ADMIN_TOKEN=$(curl -sf -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" | jq -r '.access_token')

# Verify realm exists
curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "http://localhost:8080/admin/realms/snowflake-workshop" | jq '{realm, enabled}'
```

Expected: `{"realm": "snowflake-workshop", "enabled": true}`

- [ ] **Step 3: Verify token exchange works**

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -sf -X POST "http://localhost:8080/realms/snowflake-workshop/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=kagent-ui&client_secret=kagent-ui-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# Exchange for opaque token
OPAQUE=$(curl -sf -X POST "http://localhost:8080/realms/snowflake-workshop/protocol/openid-connect/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=agw-exchange" \
  -d "client_secret=agw-exchange-secret" \
  -d "subject_token=${USER_JWT}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  | jq -r '.access_token')

echo "Opaque token (should NOT have 3 dot-separated parts): ${OPAQUE:0:40}..."
```

- [ ] **Step 4: Verify introspection works**

```bash
# Introspect the opaque token
curl -sf -X POST "http://localhost:8080/realms/snowflake-workshop/protocol/openid-connect/token/introspect" \
  -d "token=${OPAQUE}" \
  -d "client_id=agw-exchange" \
  -d "client_secret=agw-exchange-secret" | jq .
```

Expected: `{"active": true, "sub": "...", "scope": "...", ...}`

- [ ] **Step 5: Verify kagent UI is accessible**

Open `http://localhost:8080` in browser. Expected: Keycloak OIDC login page.

- [ ] **Step 6: Test the full chat flow**

Log in as `testuser`/`testuser`, select Snowflake Analyst agent, type "Show me the sales data". Expected: Agent returns sales data with introspection metadata showing opaque token validation.

- [ ] **Step 7: Check MCP server logs**

```bash
kubectl logs -l app=snowflake-mcp --tail=20
```

Expected: Log entries showing `token_type: opaque`, `active: True`, `sub: testuser`

- [ ] **Step 8: Fix any issues, commit fixes**

```bash
git add -A
git commit -m "fix: end-to-end testing fixes for workshop"
```

- [ ] **Step 9: Cleanup**

```bash
./cleanup.sh
```
