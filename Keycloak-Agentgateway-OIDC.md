# Keycloak, Agentgateway, and MCP Server with OIDC

Deploy **Keycloak**, **Enterprise Agentgateway**, and the **kagent-tools** MCP server; connect to MCP with a Keycloak-issued token (MCP Inspector or curl). Optional **OBO delegation** (Step 9): exchange a user token and an actor token for an OBO token with `sub` and `act`.

---

## Prerequisites

- **Kubernetes cluster** (e.g. kind, minikube, or cloud), **kubectl**, **helm** (v3+), **jq**, **curl**
- **Solo Enterprise license:** `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- Run all steps in the same shell so variables persist.

---

## Step 1: Deploy Keycloak and PostgreSQL

Create the `keycloak` namespace and deploy Keycloak with a Postgres backend.

```bash
kubectl create namespace keycloak 2>/dev/null || true

kubectl apply -n keycloak -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: keycloak
  labels:
    app: keycloak
spec:
  ports:
  - port: 8080
    targetPort: http
    name: http
  selector:
    app: keycloak
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak-discovery
  namespace: keycloak
  labels:
    app: keycloak
spec:
  selector:
    app: keycloak
  clusterIP: None
  type: ClusterIP
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: keycloak
  namespace: keycloak
  labels:
    app: keycloak
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
  labels:
    app: postgres
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
        - name: postgres
          containerPort: 5432
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
  labels:
    app: postgres
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
EOF

kubectl wait -n keycloak statefulset/keycloak --for=condition=Ready --timeout=420s
```

---

## Step 2: Install Enterprise Agentgateway

Install the Gateway API (standard) CRDs, then the Solo Enterprise Agentgateway CRDs and control plane. Create a Gateway in `kgateway-system` so the controller is active.

### Gateway API CRDs (standard)

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml
```

### Enterprise Agentgateway CRDs and control plane

```bash
echo "${AGENTGATEWAY_LICENSE_KEY:?Set AGENTGATEWAY_LICENSE_KEY before running}"

helm upgrade -i --create-namespace --namespace kgateway-system \
  --version 2.1.1 enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds

helm upgrade -i -n kgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version 2.1.1 --set-string licensing.licenseKey=$AGENTGATEWAY_LICENSE_KEY
```

### Default Gateway (data plane) in kgateway-system

```bash
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: agentgateway-debug
  namespace: kgateway-system
spec:
  logging:
    level: debug
    format: text
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway
  namespace: kgateway-system
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: agentgateway-debug
  listeners:
  - name: http
    port: 80
    protocol: HTTP
EOF
```

### Verify

```bash
kubectl get pods,gateway,svc -n kgateway-system
```

---

## Step 3: Keycloak realm, client, user, and dynamic client registration

Port-forward Keycloak, then create the OIDC realm, client `agw-client`, user `testuser`, audience mapper for the MCP URL, and enable **dynamic client registration**.

```bash
pkill -f "port-forward.*keycloak.*8080" 2>/dev/null || true
sleep 1
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &
sleep 3

export KEYCLOAK_URL="http://localhost:8080"
export KEYCLOAK_ISSUER="${KEYCLOAK_URL}/realms/oidc-realm"

ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token')

# Create realm
curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"realm":"oidc-realm","enabled":true}'

# Create test user
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/oidc-realm/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "testuser@example.com",
    "emailVerified": true,
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "requiredActions": [],
    "credentials": [{"type": "password", "value": "testuser", "temporary": false}]
  }'

# Confidential client (Step 8 token; Step 9 OBO)
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/oidc-realm/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "agw-client",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "secret": "agw-client-secret",
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": false
  }'

# Audience mapper: aud=http://localhost:8888/mcp for Step 8
CLIENT_UUID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/oidc-realm/clients?clientId=agw-client" -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id')
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/oidc-realm/clients/${CLIENT_UUID}/protocol-mappers/models" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -d '{"name":"aud-mcp-resource","protocol":"openid-connect","protocolMapper":"oidc-hardcoded-claim-mapper","config":{"claim.name":"aud","claim.value":"http://localhost:8888/mcp","jsonType.label":"String","access.token.claim":"true","id.token.claim":"false"}}'

# Enable dynamic client registration
trusted_hosts=$(curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/oidc-realm/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" \
  | jq -r '.[] | select(.providerId=="trusted-hosts") | .id // empty')
[ -n "$trusted_hosts" ] && curl -s -X DELETE -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/oidc-realm/components/${trusted_hosts}"

allowed_templates=$(curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/oidc-realm/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" \
  | jq -r '.[] | select(.providerId=="allowed-client-templates" and .subType=="anonymous") | .id // empty')
[ -n "$allowed_templates" ] && curl -s -X DELETE -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/oidc-realm/components/${allowed_templates}"

# For OBO (Step 9)
export KEYCLOAK_JWKS_URL="http://keycloak.keycloak.svc.cluster.local:8080/realms/oidc-realm/protocol/openid-connect/certs"
```

Keep the Keycloak port-forward running for Step 8 and, if you use OBO, Step 9.

---

## Step 4: Deploy MCP server (kagent-tools)

Deploy **[KAgent Tools](https://github.com/kagent-dev/tools)** via Helm (Streamable HTTP on port 8084, path `/mcp`). Patch the Service with `appProtocol: kgateway.dev/mcp` so the gateway can proxy MCP.

```bash
helm upgrade -i -n default kagent-tools oci://ghcr.io/kagent-dev/tools/helm/kagent-tools --version 0.0.13
kubectl wait -n default deployment/kagent-tools --for=condition=Available --timeout=120s

# Mark Service port for MCP proxying
kubectl patch svc kagent-tools -n default --type=merge -p '{"spec":{"ports":[{"name":"tools","port":8084,"targetPort":8084,"appProtocol":"kgateway.dev/mcp"}]}}'
```

---

## Step 5: Gateway, AgentgatewayBackend (MCP), and HTTPRoute

Create a **Gateway** in `default`, an **AgentgatewayBackend** (MCP) with **protocol: StreamableHTTP** (required for kagent-tools; SSE would hang), and an **HTTPRoute** that:

- Serves `/mcp` (MCP endpoint).
- Serves `/.well-known/oauth-protected-resource/mcp`, `/.well-known/oauth-authorization-server/mcp`, and the JWKS path for OAuth discovery.

```bash
# Gateway and params (must exist before HTTPRoute)
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: agentgateway-mcp-params
  namespace: default
spec:
  logging:
    level: info
    format: text
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: enterprise-agentgateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: agentgateway-mcp-params
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
EOF

# AgentgatewayBackend and HTTPRoute
kubectl apply -f - <<'EOF'
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: mcp-backend
  namespace: default
spec:
  mcp:
    targets:
    - name: mcp-target
      static:
        host: kagent-tools.default.svc.cluster.local
        port: 8084
        protocol: StreamableHTTP
        path: /mcp
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: mcp-route
  namespace: default
spec:
  parentRefs:
  - name: enterprise-agentgateway
    namespace: default
  rules:
  # MCP endpoint
  - matches:
    - path:
        type: PathPrefix
        value: /mcp
    backendRefs:
    - name: mcp-backend
      group: agentgateway.dev
      kind: AgentgatewayBackend
  # OAuth discovery and JWKS (gateway serves or proxies these)
  - matches:
    - path:
        type: PathPrefix
        value: /.well-known/oauth-protected-resource/mcp
    - path:
        type: PathPrefix
        value: /.well-known/oauth-authorization-server/mcp
    - path:
        type: PathPrefix
        value: /realms/oidc-realm/protocol/openid-connect/certs
    filters:
    - type: CORS
      cors:
        allowCredentials: true
        allowHeaders:
        - Origin
        - Authorization
        - Content-Type
        - mcp-protocol-version
        allowMethods:
        - "*"
        allowOrigins:
        - "*"
        maxAge: 86400
    backendRefs:
    - name: mcp-backend
      group: agentgateway.dev
      kind: AgentgatewayBackend
EOF
```

**Verify:** `kubectl get agentgatewaybackend,httproute,gateway -n default`

---

## Step 6: MCP auth policy (Keycloak)

Attach an **EnterpriseAgentgatewayPolicy** to the MCP backend with Keycloak (issuer, JWKS, JWT validation). Set resource and audiences to `http://localhost:8888/mcp` and **mode: Strict** so unauthenticated access is rejected.

```bash
export MCP_RESOURCE_URL="http://localhost:8888/mcp"
export KEYCLOAK_ISSUER_IN_CLUSTER="http://keycloak.keycloak.svc.cluster.local:8080/realms/oidc-realm"

kubectl apply -f - <<EOF
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-keycloak-authn
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:
        issuer: "${KEYCLOAK_ISSUER_IN_CLUSTER}"
        jwks:
          backendRef:
            kind: Service
            name: keycloak
            namespace: keycloak
            port: 8080
          jwksPath: realms/oidc-realm/protocol/openid-connect/certs
        provider: Keycloak
        resourceMetadata:
          resource: "${MCP_RESOURCE_URL}"
        audiences:
        - "${MCP_RESOURCE_URL}"
        mode: Strict
EOF
```

---

## Step 7: Port-forward and verify

Port-forward the gateway to `http://localhost:8888`. Expect 401/406 on `/mcp` without a token and 200 on the well-known URL.

```bash
pkill -f "port-forward.*enterprise-agentgateway" 2>/dev/null || true
sleep 1
kubectl port-forward -n default svc/enterprise-agentgateway 8888:80 &
sleep 2
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8888/mcp
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8888/.well-known/oauth-protected-resource/mcp
```

---

## Step 8: Connect to MCP and list tools

Get a token (Step 3 sets `aud` for the MCP URL), then connect with **MCP Inspector** or curl and list tools. Ensure the gateway port-forward on 8888 is active (Step 7).

1. **Get a token:**

```bash
RAW=$(kubectl run -n default mcp-token --rm -i --restart=Never --image=curlimages/curl -- \
  curl -s -X POST "http://keycloak.keycloak.svc.cluster.local:8080/realms/oidc-realm/protocol/openid-connect/token" \
  -d "username=testuser" -d "password=testuser" -d "grant_type=password" \
  -d "client_id=agw-client" -d "client_secret=agw-client-secret" 2>/dev/null)
TOKEN=$(echo "$RAW" | sed 's/pod "mcp-token" deleted.*//' | jq -r '.access_token')
```

(Optional: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" -H "Accept: text/event-stream" http://localhost:8888/mcp` → **422** = token accepted.)

2. **MCP Inspector:** run `npx @modelcontextprotocol/inspector`. In the UI: **Transport** → Streamable HTTP, **URL** → `http://localhost:8888/mcp`, **Headers** → add `Authorization: Bearer <token>` (paste `$TOKEN`). Connect, then open **Tools** → **List Tools** to see kagent-tools (e.g. `argo_*`, `k8s_*`, `helm_*`, `shell`).

### curl alternative (no MCP Inspector)

With `TOKEN` from above, run:

```bash
MCP_URL="http://localhost:8888/mcp"
ACCEPT_HDR="Accept: application/json, text/event-stream"
INIT_RESP=$(curl -s -i --max-time 15 -X POST "$MCP_URL" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "$ACCEPT_HDR" -H "Connection: close" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}},"id":1}')
SESSION_ID=$(echo "$INIT_RESP" | grep -i "^mcp-session-id:" | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | head -1)
if [ -z "$SESSION_ID" ]; then echo "Initialize failed (no Mcp-Session-Id)."; echo "$INIT_RESP"; exit 1; fi
curl -s --max-time 10 -X POST "$MCP_URL" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "$ACCEPT_HDR" -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' > /dev/null
TOOLS_RESP=$(curl -s --max-time 10 -X POST "$MCP_URL" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "$ACCEPT_HDR" -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}')
echo "$TOOLS_RESP" | sed 's/^data: //' | jq -r '.result.tools[]?.name // .error.message // "No tools key in response"'
```

---

## Step 9: OBO delegation (optional)

Requires Step 3 (for `KEYCLOAK_JWKS_URL`), Keycloak port-forward, and Kubernetes 1.24+ (`kubectl create token`). Exchange a user JWT and a Kubernetes SA token at the STS for an OBO token with `sub` and `act`. The user token must include `may_act` (added in 9.4).

### 9.1 Enable token exchange (STS)

```bash
echo "${KEYCLOAK_JWKS_URL:?Run Step 3 first}"
echo "${AGENTGATEWAY_LICENSE_KEY:?Set AGENTGATEWAY_LICENSE_KEY}"

helm upgrade -n kgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version 2.1.1 --set-string licensing.licenseKey=$AGENTGATEWAY_LICENSE_KEY \
  --set tokenExchange.enabled=true \
  --set tokenExchange.issuer="enterprise-agentgateway.kgateway-system.svc.cluster.local:7777" \
  --set tokenExchange.tokenExpiration=24h \
  --set tokenExchange.subjectValidator.validatorType=remote \
  --set tokenExchange.subjectValidator.remoteConfig.url="$KEYCLOAK_JWKS_URL" \
  --set tokenExchange.actorValidator.validatorType=k8s \
  --reuse-values
kubectl rollout status deployment -n kgateway-system -l app.kubernetes.io/instance=enterprise-agentgateway --timeout=120s
```

### 9.2 Port-forward the STS

```bash
pkill -f "port-forward.*7777" 2>/dev/null || true
sleep 1
kubectl port-forward -n kgateway-system svc/enterprise-agentgateway 7777:7777 &
sleep 2
export STS_URL="http://localhost:7777"
```

### 9.3 Create actor token and derive may_act

Create a service account, get its token, and decode the JWT payload for `sub` and `iss` (used in `may_act`).

```bash
kubectl create serviceaccount sts-exchange-client -n kgateway-system 2>/dev/null || true
export ACTOR_TOKEN=$(kubectl create token sts-exchange-client -n kgateway-system --duration=3600s)
_pl=$(echo "$ACTOR_TOKEN" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_pl} % 4)) -ne 0 ]; do _pl="${_pl}="; done; _pl=$(echo "$_pl" | base64 -d 2>/dev/null)
export MAY_ACT_SUB=$(echo "$_pl" | jq -r '.sub')
export MAY_ACT_ISS=$(echo "$_pl" | jq -r '.iss')
```

### 9.4 Add may_act to the user token

Add a hardcoded-claim mapper to `agw-client` so the user access token includes `may_act` for the actor.

```bash
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token')
CLIENT_UUID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/oidc-realm/clients?clientId=agw-client" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id')
MAY_ACT_JSON=$(jq -nc --arg sub "$MAY_ACT_SUB" --arg iss "$MAY_ACT_ISS" '{sub: $sub, iss: $iss}')
MAPPER_JSON=$(jq -n \
  --arg claim_name "may_act" \
  --arg claim_value "$MAY_ACT_JSON" \
  '{
    name: "may-act",
    protocol: "openid-connect",
    protocolMapper: "oidc-hardcoded-claim-mapper",
    config: {
      "claim.name": $claim_name,
      "claim.value": $claim_value,
      "jsonType.label": "JSON",
      "access.token.claim": "true",
      "id.token.claim": "false"
    }
  }')
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/oidc-realm/clients/${CLIENT_UUID}/protocol-mappers/models" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" -d "$MAPPER_JSON"
```

### 9.5 Get user JWT and call STS

Fetch a fresh user token (with `may_act`) and exchange it with the actor token at the STS.

```bash
export USER_JWT=$(curl -s -X POST "${KEYCLOAK_URL}/realms/oidc-realm/protocol/openid-connect/token" \
  -d "username=testuser" -d "password=testuser" -d "grant_type=password" \
  -d "client_id=agw-client" -d "client_secret=agw-client-secret" | jq -r '.access_token')

export STS_RESPONSE=$(curl -s -X POST "${STS_URL}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer ${USER_JWT}" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${USER_JWT}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "actor_token=${ACTOR_TOKEN}" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:jwt")
echo "$STS_RESPONSE" | jq '.' 2>/dev/null || echo "$STS_RESPONSE"
```

### 9.6 Decode the OBO token (optional)

```bash
export OBO_JWT=$(echo "$STS_RESPONSE" | jq -r '.access_token // empty')
seg=$(echo "$OBO_JWT" | cut -d'.' -f2 | tr '_-' '/+'); while [ $((${#seg} % 4)) -ne 0 ]; do seg="${seg}="; done; echo "$seg" | base64 -d 2>/dev/null | jq '.'
```

The decoded payload shows `sub` (user) and `act` (actor). Use the OBO token for downstream auth and audit.

---

## Cleanup

Remove all resources created by this guide:

```bash
pkill -f "port-forward.*keycloak" 2>/dev/null || true
pkill -f "port-forward.*enterprise-agentgateway" 2>/dev/null || true
pkill -f "port-forward.*7777" 2>/dev/null || true

kubectl delete enterpriseagentgatewaypolicy mcp-keycloak-authn -n default
kubectl delete httproute mcp-route -n default
kubectl delete agentgatewaybackend mcp-backend -n default
helm uninstall kagent-tools -n default
kubectl delete gateway enterprise-agentgateway -n default
kubectl delete enterpriseagentgatewayparameters agentgateway-mcp-params -n default
kubectl delete serviceaccount sts-exchange-client -n kgateway-system 2>/dev/null || true
kubectl delete namespace keycloak
kubectl delete gateway agentgateway -n kgateway-system
kubectl delete enterpriseagentgatewayparameters agentgateway-debug -n kgateway-system 2>/dev/null || true
helm uninstall enterprise-agentgateway -n kgateway-system
helm uninstall enterprise-agentgateway-crds -n kgateway-system
kubectl delete namespace kgateway-system
```

---

**References:** [Enterprise Agentgateway](https://docs.solo.io/agentgateway/latest/), [Keycloak](https://www.keycloak.org/), [Gateway API](https://gateway-api.sigs.k8s.io/), [MCP](https://modelcontextprotocol.io/), [KAgent Tools](https://github.com/kagent-dev/tools). OBO: [OBO-Complete-Guide-Delegation.md](./OBO-Complete-Guide-Delegation.md), [OBO-Complete-Guide-Impersonation.md](./OBO-Complete-Guide-Impersonation.md).