# Flow 13: Gateway-Mediated OIDC + Token Exchange with MCP

Agent Gateway handles OIDC authentication, then exchanges the IdP token with the built-in RFC 8693 Security Token Service (STS) before forwarding to the MCP server. The MCP server never sees the original IdP token -- it trusts only the STS issuer. This decouples the IdP from downstream services and embeds both user and agent identities in the forwarded token.

### Flow in brief

1. **User** authenticates with the OIDC provider (Keycloak) and receives a **user JWT**.
2. The user (or agent) sends the JWT to **Agent Gateway**, which validates it against the IdP's JWKS.
3. The agent calls the **built-in STS** with the user JWT as `subject_token` + a K8s service account `actor_token`.
4. The STS validates both tokens, checks `may_act` authorization, and issues a **new JWT** signed by the STS -- with `sub` (user) and `act` (actor).
5. The **exchanged token** is sent to the MCP server via Agent Gateway. The MCP server only trusts the STS issuer.

```
                              +-----------+
                              |   OIDC    |
                              | Provider  |
                              | (Keycloak)|
                              +-----+-----+
                                    |
                              1. User JWT
                                    |
+--------+     2. Bearer JWT  +-----v-----------+     4. STS JWT    +------------+
|  User/ |-------------------->  Agent Gateway   |------------------>  MCP Server |
|  Agent |                    |   (Proxy)        |                   | (Fetcher)  |
+--------+                    |                  |                   +------------+
                              |  Validates JWT   |
                              |  (step 2)        |
                              +--------+---------+
                                       |
                              3. Token Exchange
                                       |
                              +--------v---------+
                              |   Built-in STS   |
                              |   (port 7777)    |
                              |                  |
                              |  subject_token + |
                              |  actor_token     |
                              |  --> STS JWT     |
                              |  (sub + act)     |
                              +------------------+
```

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) | [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) | [MCP Authentication](https://docs.solo.io/agentgateway/2.2.x/security/mcp-auth/) | [Helm values reference](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

---

## Prerequisites

- **Kubernetes cluster** (e.g. AKS, GKE, kind), **kubectl**, **helm** (v3+), **jq**, **curl**
- **Solo Enterprise license:** `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- **Node.js 18+** (for MCP Inspector)
- Run all steps in the same shell so variables persist.

---

## Step 1: Deploy Keycloak and PostgreSQL

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

## Step 2: Configure Keycloak realm, client, and user

Port-forward Keycloak and create the OIDC realm, client, user, and relax DCR policies for dynamic client registration.

```bash
pkill -f "port-forward.*keycloak.*8080" 2>/dev/null || true
sleep 1
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &
sleep 3
export KEYCLOAK_URL="http://localhost:8080"
export KEYCLOAK_JWKS_URL="http://keycloak.keycloak.svc.cluster.local:8080/realms/flow13-realm/protocol/openid-connect/certs"
```

> If port 8080 is already in use, use a different local port (e.g. `9080:8080`) and update `KEYCLOAK_URL` accordingly. The in-cluster URL (`KEYCLOAK_JWKS_URL`) stays the same.

```bash
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token')

# Create realm
curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"realm":"flow13-realm","enabled":true}'

# Create client
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/flow13-realm/clients" \
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

# Create user
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/flow13-realm/users" \
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

# Relax DCR policies (remove trusted-hosts and allowed-client-templates)
for POLICY_NAME in "trusted-hosts" "allowed-client-templates"; do
  POLICY_ID=$(curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${KEYCLOAK_URL}/admin/realms/flow13-realm/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" \
    | jq -r ".[] | select(.name==\"${POLICY_NAME}\") | .id")
  [ -n "$POLICY_ID" ] && curl -s -X DELETE \
    "${KEYCLOAK_URL}/admin/realms/flow13-realm/components/${POLICY_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}"
done
```

Use `Host: keycloak.keycloak.svc.cluster.local:8080` when requesting tokens (Step 7) so the JWT `iss` matches the in-cluster issuer in the MCP auth policy.

---

## Step 3: Install Enterprise Agentgateway with STS

Install Gateway API CRDs, then Enterprise Agentgateway with the **token exchange (STS)** enabled. The STS subject validator points to Keycloak's JWKS so it can validate incoming user JWTs.

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml

echo "${AGENTGATEWAY_LICENSE_KEY:?Set AGENTGATEWAY_LICENSE_KEY before running}"

helm upgrade -i --create-namespace --namespace agentgateway-system \
  enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --version v2.2.0

helm upgrade -i -n agentgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version v2.2.0 \
  --set-string licensing.licenseKey=$AGENTGATEWAY_LICENSE_KEY \
  --set agentgateway.enabled=true \
  --set tokenExchange.enabled=true \
  --set tokenExchange.issuer="enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777" \
  --set tokenExchange.tokenExpiration=24h \
  --set tokenExchange.subjectValidator.validatorType=remote \
  --set tokenExchange.subjectValidator.remoteConfig.url="$KEYCLOAK_JWKS_URL" \
  --set tokenExchange.actorValidator.validatorType=k8s

kubectl rollout status deployment -n agentgateway-system -l app.kubernetes.io/instance=enterprise-agentgateway --timeout=120s
```

**Verify:** The control plane service exposes port 7777 for the STS:

```bash
kubectl get svc enterprise-agentgateway -n agentgateway-system
# PORT(S) should include 7777/TCP
```

| Helm Setting | Purpose |
|---|---|
| `tokenExchange.enabled` | Enable the built-in STS |
| `tokenExchange.issuer` | STS token issuer (address of control plane on port 7777) |
| `tokenExchange.tokenExpiration` | Lifetime of exchanged tokens |
| `tokenExchange.subjectValidator.remoteConfig.url` | Keycloak JWKS endpoint -- STS validates the user JWT against this |
| `tokenExchange.actorValidator.validatorType: k8s` | STS validates actor tokens as Kubernetes service account JWTs |

---

## Step 4: Deploy MCP server

Deploy the [mcp-website-fetcher](https://github.com/peterj/mcp-website-fetcher) as an SSE-based MCP server. This server exposes a `fetch` tool that retrieves web page content.

```bash
kubectl apply -n default -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-website-fetcher
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mcp-website-fetcher
  template:
    metadata:
      labels:
        app: mcp-website-fetcher
    spec:
      containers:
      - name: fetcher
        image: ghcr.io/peterj/mcp-website-fetcher:main
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-website-fetcher
  namespace: default
  labels:
    app: mcp-website-fetcher
spec:
  selector:
    app: mcp-website-fetcher
  ports:
  - port: 80
    targetPort: 80
    name: http
    appProtocol: agentgateway.dev/mcp
  type: ClusterIP
EOF

kubectl wait deployment/mcp-website-fetcher -n default --for=condition=Available --timeout=120s
```

---

## Step 5: Create Gateway, Backend, HTTPRoute, and MCP auth policy

Create the Gateway, an `AgentgatewayBackend` pointing to the MCP server, an HTTPRoute with OAuth discovery paths + Keycloak proxy paths, and an MCP authentication policy.

```bash
kubectl apply -f - <<'EOF'
# ReferenceGrant: allow HTTPRoute in default to reference Keycloak in keycloak namespace
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-default-to-keycloak
  namespace: keycloak
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    namespace: default
  to:
  - group: ""
    kind: Service
    name: keycloak
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: flow13-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
---
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: mcp-backend
  namespace: default
spec:
  mcp:
    targets:
    - name: mcp-fetcher
      static:
        host: mcp-website-fetcher.default.svc.cluster.local
        port: 80
        protocol: SSE
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: mcp-route
  namespace: default
spec:
  parentRefs:
  - name: flow13-gateway
    namespace: default
  rules:
  # MCP + OAuth discovery paths -> MCP backend (handled by AGW MCP auth)
  - backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: mcp-backend
    matches:
    - path:
        type: PathPrefix
        value: /mcp
    - path:
        type: PathPrefix
        value: /.well-known/oauth-protected-resource/mcp
    - path:
        type: PathPrefix
        value: /.well-known/oauth-authorization-server/mcp
    filters:
    - type: ResponseHeaderModifier
      responseHeaderModifier:
        add:
        - name: Access-Control-Allow-Origin
          value: "*"
        - name: Access-Control-Allow-Methods
          value: "GET, POST, OPTIONS"
        - name: Access-Control-Allow-Headers
          value: "Authorization, Content-Type, Accept, Mcp-Protocol-Version"
  # Proxy Keycloak endpoints through the gateway (browser-accessible)
  - backendRefs:
    - name: keycloak
      namespace: keycloak
      port: 8080
    matches:
    - path:
        type: PathPrefix
        value: /realms/flow13-realm
    filters:
    - type: ResponseHeaderModifier
      responseHeaderModifier:
        add:
        - name: Access-Control-Allow-Origin
          value: "*"
        - name: Access-Control-Allow-Methods
          value: "GET, POST, OPTIONS"
        - name: Access-Control-Allow-Headers
          value: "Authorization, Content-Type, Accept"
---
# MCP authentication policy -- validates JWTs against Keycloak JWKS
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-auth-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:
        issuer: "http://keycloak.keycloak.svc.cluster.local:8080/realms/flow13-realm"
        jwks:
          backendRef:
            name: keycloak
            kind: Service
            namespace: keycloak
            port: 8080
          jwksPath: realms/flow13-realm/protocol/openid-connect/certs
        audiences:
        - account
        - agw-client
        - http://localhost:8888/mcp
        mode: Strict
        provider: Keycloak
        resourceMetadata:
          resourceMetadata:
            resource: http://localhost:8888/mcp
            scopesSupported:
            - email
            - openid
            bearerMethodsSupported:
            - header
EOF

kubectl wait gateway/flow13-gateway -n default --for=condition=Programmed --timeout=120s
```

**Verify policies are attached:**

```bash
kubectl get enterpriseagentgatewaypolicy -n default
# NAME              ACCEPTED   ATTACHED
# mcp-auth-policy   True       True
```

---

## Step 6: Port-forward and verify OAuth discovery

```bash
pkill -f "port-forward.*flow13" 2>/dev/null || true
pkill -f "port-forward.*7777" 2>/dev/null || true
sleep 1
kubectl port-forward -n default svc/flow13-gateway 8888:80 &
kubectl port-forward -n agentgateway-system svc/enterprise-agentgateway 7777:7777 &
sleep 2
```

```bash
# OAuth Protected Resource metadata
curl -s http://localhost:8888/.well-known/oauth-protected-resource/mcp | jq .

# Keycloak OIDC discovery (proxied through gateway)
curl -s http://localhost:8888/realms/flow13-realm/.well-known/openid-configuration | jq '{issuer, authorization_endpoint, token_endpoint}'
```

**Expected:** Protected resource shows `resource: http://localhost:8888/mcp`. Keycloak OIDC endpoints show `localhost:8888` URLs (proxied through gateway).

---

## Step 7: Test with MCP Inspector

### 7.1 Get a Keycloak token

```bash
export USER_JWT=$(curl -s -X POST "${KEYCLOAK_URL}/realms/flow13-realm/protocol/openid-connect/token" \
  -H "Host: keycloak.keycloak.svc.cluster.local:8080" \
  -d "username=testuser" -d "password=testuser" -d "grant_type=password" \
  -d "client_id=agw-client" -d "client_secret=agw-client-secret" | jq -r '.access_token')

# Verify issuer matches
_p=$(echo "$USER_JWT" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_p} % 4)) -ne 0 ]; do _p="${_p}="; done
echo "$_p" | base64 -d 2>/dev/null | jq '{iss, sub, preferred_username}'
```

**Expected:** `iss: http://keycloak.keycloak.svc.cluster.local:8080/realms/flow13-realm`

### 7.2 Connect with MCP Inspector

Launch MCP Inspector:

```bash
npx @modelcontextprotocol/inspector@latest
```

In the MCP Inspector UI:

1. Set **Transport Type** to `Streamable HTTP`
2. Set **URL** to `http://localhost:8888/mcp`
3. Under **Headers**, add: `Authorization` = `Bearer <paste $USER_JWT>`
4. Click **Connect**
5. Go to **Tools** tab -> **List Tools** -> you should see the `fetch` tool
6. Call the `fetch` tool with `url: "https://example.com"` to verify it works

### 7.3 Verify auth is enforced (curl)

```bash
# No token -> 401
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8888/mcp \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
# Expect: HTTP 401

# With token -> 200
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
# Expect: HTTP 200
```

---

## Step 8: Add may_act claim and exchange at STS

Create a Kubernetes service account as the actor. Add a `may_act` claim to the Keycloak client that authorizes this actor, then exchange at the STS.

```bash
# Create actor service account
kubectl create serviceaccount flow13-actor -n default 2>/dev/null || true
export ACTOR_TOKEN=$(kubectl create token flow13-actor -n default --duration=3600s)

# Get actor identity for may_act
_ap=$(echo "$ACTOR_TOKEN" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_ap} % 4)) -ne 0 ]; do _ap="${_ap}="; done
_ap=$(echo "$_ap" | base64 -d 2>/dev/null)
export MAY_ACT_SUB=$(echo "$_ap" | jq -r '.sub')
export MAY_ACT_ISS=$(echo "$_ap" | jq -r '.iss')

# Add may_act hardcoded claim mapper to agw-client
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token')
CLIENT_UUID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/flow13-realm/clients?clientId=agw-client" \
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

# Remove existing mapper if re-running
EXISTING=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/flow13-realm/clients/${CLIENT_UUID}/protocol-mappers/models" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[] | select(.name=="may-act") | .id // empty')
[ -n "$EXISTING" ] && curl -s -X DELETE "${KEYCLOAK_URL}/admin/realms/flow13-realm/clients/${CLIENT_UUID}/protocol-mappers/models/${EXISTING}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

curl -s -o /dev/null -w "Add may_act mapper: HTTP %{http_code}\n" \
  -X POST "${KEYCLOAK_URL}/admin/realms/flow13-realm/clients/${CLIENT_UUID}/protocol-mappers/models" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" -d "$MAPPER_JSON"
```

### 8.1 Get fresh JWT (with may_act) and exchange

```bash
# Get user JWT with may_act claim
export USER_JWT=$(curl -s -X POST "${KEYCLOAK_URL}/realms/flow13-realm/protocol/openid-connect/token" \
  -H "Host: keycloak.keycloak.svc.cluster.local:8080" \
  -d "username=testuser" -d "password=testuser" -d "grant_type=password" \
  -d "client_id=agw-client" -d "client_secret=agw-client-secret" | jq -r '.access_token')

# Verify may_act is present
_p=$(echo "$USER_JWT" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_p} % 4)) -ne 0 ]; do _p="${_p}="; done
echo "$_p" | base64 -d 2>/dev/null | jq '{iss, sub, may_act}'

# Exchange at STS
export STS_RESPONSE=$(curl -s -X POST "http://localhost:7777/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=${USER_JWT}" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  --data-urlencode "actor_token=${ACTOR_TOKEN}" \
  --data-urlencode "actor_token_type=urn:ietf:params:oauth:token-type:jwt")

echo "$STS_RESPONSE" | jq '.'
```

**Expected:** STS returns `access_token` with `issued_token_type: urn:ietf:params:oauth:token-type:jwt`.

### 8.2 Decode the exchanged token

```bash
export STS_JWT=$(echo "$STS_RESPONSE" | jq -r '.access_token')
_p=$(echo "$STS_JWT" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_p} % 4)) -ne 0 ]; do _p="${_p}="; done
echo "$_p" | base64 -d 2>/dev/null | jq '{iss, sub, act, exp}'
```

**Expected output:**

```json
{
  "iss": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777",
  "sub": "7e886f4c-...",
  "act": {
    "sub": "system:serviceaccount:default:flow13-actor",
    "iss": "https://..."
  },
  "exp": 1775238668
}
```

Key differences from the original Keycloak JWT:
- **`iss`** changed from `keycloak.../flow13-realm` to `enterprise-agentgateway...:7777` (STS signed)
- **`sub`** preserved (same user identity)
- **`act`** added (actor/agent identity for delegation)

---

## Step 9: Validate STS token reaches the MCP server

This is the critical step. We switch the MCP auth policy to trust **only** the STS issuer, then prove that:
- Raw Keycloak JWTs are **rejected** (wrong issuer)
- STS-exchanged JWTs are **accepted** and forwarded to the MCP server

### 9.1 Switch to STS-only trust

```bash
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-auth-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:
        issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        jwks:
          backendRef:
            name: enterprise-agentgateway
            kind: Service
            namespace: agentgateway-system
            port: 7777
          jwksPath: .well-known/jwks.json
        mode: Strict
        provider: Keycloak
        resourceMetadata:
          resourceMetadata:
            resource: http://localhost:8888/mcp
            scopesSupported:
            - email
            - openid
            bearerMethodsSupported:
            - header
EOF

# Wait for JWKS ConfigMap to be created
sleep 10
kubectl get enterpriseagentgatewaypolicy -n default
# Verify: ACCEPTED=True, ATTACHED=True
```

### 9.2 Test: Keycloak JWT rejected, STS JWT accepted

```bash
# Keycloak JWT -> 401 (wrong issuer)
echo "Keycloak JWT:"
curl -s -o /dev/null -w "  HTTP %{http_code} (expected 401)\n" \
  -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'

# STS JWT -> 200 (correct issuer)
echo "STS JWT:"
curl -s -o /dev/null -w "  HTTP %{http_code} (expected 200)\n" \
  -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${STS_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

**Expected:**

| Token | Issuer | HTTP | Result |
|---|---|---|---|
| Keycloak JWT | `keycloak.../flow13-realm` | 401 | Rejected -- wrong issuer |
| STS JWT | `enterprise-agentgateway...:7777` | **200** | Accepted -- forwarded to MCP |

### 9.3 Full MCP session with STS token

Run a complete MCP session (initialize -> tools/list -> tool call) using only the STS-exchanged token:

```bash
MCP_URL="http://localhost:8888/mcp"
HDR_AUTH="Authorization: Bearer $STS_JWT"
HDR_JSON="Content-Type: application/json"
HDR_ACCEPT="Accept: application/json, text/event-stream"

# Initialize
INIT_RESP=$(curl -s -i --max-time 15 -X POST "$MCP_URL" \
  -H "$HDR_AUTH" -H "$HDR_JSON" -H "$HDR_ACCEPT" -H "Connection: close" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agent","version":"1.0"}},"id":1}')
SESSION_ID=$(echo "$INIT_RESP" | grep -i "^mcp-session-id:" | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | head -1)
echo "Session: ${SESSION_ID}"
echo "$INIT_RESP" | tail -1

# Send initialized notification
curl -s -o /dev/null -w "Initialized: HTTP %{http_code}\n" -X POST "$MCP_URL" \
  -H "$HDR_AUTH" -H "$HDR_JSON" -H "$HDR_ACCEPT" -H "Mcp-Session-Id: ${SESSION_ID}" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# List tools
echo "Tools:"
curl -s --max-time 15 -X POST "$MCP_URL" \
  -H "$HDR_AUTH" -H "$HDR_JSON" -H "$HDR_ACCEPT" -H "Mcp-Session-Id: ${SESSION_ID}" -H "Connection: close" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}' | grep -o '"name":"[^"]*"'
```

### 9.4 MCP Inspector with STS token

Reconnect MCP Inspector with the STS-exchanged token:

1. In MCP Inspector, update the **Authorization** header to `Bearer <paste $STS_JWT>`
2. Click **Connect**
3. **Tools** -> **List Tools** -> `fetch` tool appears
4. This proves the STS-exchanged token (with `sub` + `act`) is what the MCP server receives

---

## What this proves

```
+--------+                 +---------------+                 +---------+         +------------+
| User   |  1. Login       | Keycloak      |                 |  AGW    |         | MCP Server |
|        |---------------->| (IdP)         |                 |  STS    |         |            |
|        |<----------------|               |                 | (:7777) |         |            |
|        |  Keycloak JWT   +---------------+                 |         |         |            |
|        |                                                   |         |         |            |
| Agent  |  2. Exchange    +---------------+  subject_token  |         |         |            |
|        |---------------->| Agent Gateway |---------------->|         |         |            |
|        |                 |   (Proxy)     |  actor_token    |         |         |            |
|        |                 |               |<----------------|         |         |            |
|        |                 |               |  STS JWT        +---------+         |            |
|        |                 |               |  (sub + act)                        |            |
|        |                 |               |--------- STS JWT ------------------>|            |
|        |                 |               |                                     |  Validates |
|        |                 |               |<--------- MCP response ------------|  STS JWKS  |
|        |<----------------|               |                                     +------------+
|        |                 +---------------+
+--------+
```

| Step | Token | Issuer | Contains | MCP Server |
|---|---|---|---|---|
| 1 | Keycloak JWT | `keycloak.../flow13-realm` | `sub` (user) | Rejected (wrong issuer) |
| 2 | STS JWT | `enterprise-agentgateway...:7777` | `sub` (user) + `act` (agent) | **Accepted** |

**Key takeaways:**

1. The **original IdP token never reaches the MCP server** -- it's rejected by the STS-only policy
2. The **STS-exchanged token carries both identities** -- `sub` (which user) and `act` (which agent) -- enabling fine-grained authorization
3. The MCP server **trusts only the STS issuer** -- it doesn't need to know about Keycloak
4. The STS is **built into Agent Gateway** -- no external token exchange service required
5. The token exchange is **RFC 8693 compliant** -- standard `urn:ietf:params:oauth:grant-type:token-exchange` grant type

---

## Cleanup

```bash
pkill -f "port-forward.*keycloak" 2>/dev/null || true
pkill -f "port-forward.*flow13" 2>/dev/null || true
pkill -f "port-forward.*7777" 2>/dev/null || true

kubectl delete enterpriseagentgatewaypolicy mcp-auth-policy -n default
kubectl delete httproute mcp-route -n default
kubectl delete agentgatewaybackend mcp-backend -n default
kubectl delete gateway flow13-gateway -n default
kubectl delete deployment mcp-website-fetcher -n default
kubectl delete service mcp-website-fetcher -n default
kubectl delete serviceaccount flow13-actor -n default 2>/dev/null || true
kubectl delete referencegrant allow-default-to-keycloak -n keycloak 2>/dev/null || true
kubectl delete namespace keycloak
```

---

## References

- [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) -- STS configuration and Helm values
- [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) -- JWT authentication policies
- [MCP Authentication](https://docs.solo.io/agentgateway/2.2.x/security/mcp-auth/) -- MCP OAuth discovery and token validation
- [Keycloak as an IdP](https://docs.solo.io/agentgateway/2.2.x/security/extauth/oauth/keycloak/) -- Keycloak setup guide
- [About OBO and Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/) -- Conceptual overview
- [Enterprise API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/) -- EnterpriseAgentgatewayPolicy, JWTAuthentication
- [Helm Values Reference](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/) -- tokenExchange values
- [Token Flow Diagrams](token-flow-diagrams/agent-gateway-token-flows.md) -- All 15 auth flow diagrams including Flow 13
