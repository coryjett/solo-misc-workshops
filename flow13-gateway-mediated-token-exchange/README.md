# Flow 13: Gateway-Mediated OIDC + Token Exchange with MCP

Agent Gateway handles OIDC authentication, then **automatically** exchanges the IdP token with the built-in RFC 8693 Security Token Service (STS) before forwarding to the MCP server. The MCP server never sees the original IdP token -- it trusts only the STS issuer. The client never calls the STS directly -- the gateway mediates the exchange transparently.

### Flow in brief

1. **Client** authenticates with the OIDC provider (Keycloak) and receives a **user JWT**.
2. The client sends the JWT to **Agent Gateway**.
3. Agent Gateway **automatically exchanges** the JWT at the built-in STS (RFC 8693 token exchange).
4. The STS validates the user JWT and issues a **new JWT** signed by the STS.
5. Agent Gateway forwards the **STS-signed token** to the MCP server. The original IdP token is never forwarded.

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
| Client |-------------------->  Agent Gateway   |------------------>  MCP Server |
|        |                    |   (Proxy)        |                   | (Fetcher)  |
+--------+                    |                  |                   +------------+
                              |  Validates JWT   |
                              |  Exchanges at    |
                              |  built-in STS    |
                              |  (automatic)     |
                              +--------+---------+
                                       |
                              3. Token Exchange
                                  (gateway-mediated,
                                   not client-initiated)
                                       |
                              +--------v---------+
                              |   Built-in STS   |
                              |   (port 7777)    |
                              |                  |
                              |  subject_token   |
                              |  --> STS JWT     |
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

Install Gateway API CRDs, then Enterprise Agentgateway with the **token exchange (STS)** enabled. The STS subject validator points to Keycloak's JWKS so it can validate incoming user JWTs before exchanging them.

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

## Step 5: Create Gateway, Backend, HTTPRoute, and policies

Create the Gateway, an `AgentgatewayBackend` pointing to the MCP server, an HTTPRoute with OAuth discovery paths + Keycloak proxy paths, and an MCP authentication policy with **gateway-mediated token exchange**.

The key configuration is `backend.tokenExchange.mode: ExchangeOnly` -- this tells Agent Gateway to **automatically** exchange the client's Keycloak JWT at the built-in STS before forwarding to the MCP server. The client never calls the STS directly.

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
# MCP authentication policy + gateway-mediated token exchange
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
    tokenExchange:
      mode: ExchangeOnly
EOF

kubectl wait gateway/flow13-gateway -n default --for=condition=Programmed --timeout=120s
```

**Verify policies are attached:**

```bash
kubectl get enterpriseagentgatewaypolicy -n default
# NAME              ACCEPTED   ATTACHED
# mcp-auth-policy   True       True
```

The `tokenExchange.mode: ExchangeOnly` field is the critical piece -- it tells Agent Gateway to:
1. Take the incoming bearer token (Keycloak JWT)
2. Send it to the built-in STS as `subject_token`
3. Replace the `Authorization` header with the STS-issued JWT
4. Forward the exchanged token to the MCP backend

---

## Step 6: Port-forward and verify OAuth discovery

```bash
pkill -f "port-forward.*flow13" 2>/dev/null || true
sleep 1
kubectl port-forward -n default svc/flow13-gateway 8888:80 &
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

## Step 7: Test -- client sends Keycloak JWT, gateway exchanges transparently

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

### 7.2 Verify auth is enforced and MCP works

```bash
# No token -> 401
curl -s -o /dev/null -w "No token:      HTTP %{http_code} (expect 401)\n" \
  -X POST http://localhost:8888/mcp \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'

# With Keycloak JWT -> 200 (AGW validates, exchanges at STS, forwards STS JWT to MCP server)
curl -s -o /dev/null -w "Keycloak JWT:  HTTP %{http_code} (expect 200)\n" \
  -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

The client sends a **Keycloak JWT** -- but the MCP server never sees it. Agent Gateway automatically exchanges it at the STS and forwards the **STS-signed JWT** instead. This is completely transparent to the client.

### 7.3 Connect with MCP Inspector

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

MCP Inspector sends the Keycloak JWT, but Agent Gateway transparently exchanges it before the request reaches the MCP server.

---

## Step 8: Prove the STS token reaches the MCP server

This is the critical validation step. We switch the MCP auth policy to trust **only the STS issuer** and prove that:

1. The same Keycloak JWT **still works** (because AGW exchanges it to an STS JWT before the MCP auth policy validates it)
2. Without token exchange, the same Keycloak JWT would be **rejected**

### 8.1 Switch to STS-only trust (keep token exchange)

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
    tokenExchange:
      mode: ExchangeOnly
EOF

sleep 10
kubectl get enterpriseagentgatewaypolicy -n default
# Verify: ACCEPTED=True, ATTACHED=True
```

### 8.2 Test: Keycloak JWT still works (exchange is active)

```bash
# Same Keycloak JWT -> should still be 200
# AGW exchanges it to STS JWT before the MCP auth policy validates
curl -s -o /dev/null -w "Keycloak JWT (exchange active):  HTTP %{http_code} (expect 200)\n" \
  -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

**Expected:** HTTP 200 -- the Keycloak JWT is exchanged for an STS JWT, which passes the STS-only auth policy.

### 8.3 Remove token exchange (STS-only trust, no exchange)

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

sleep 10
```

### 8.4 Test: Same Keycloak JWT now fails (no exchange)

```bash
# Same Keycloak JWT -> 401 (no exchange, wrong issuer for STS-only policy)
curl -s -o /dev/null -w "Keycloak JWT (no exchange):      HTTP %{http_code} (expect 401)\n" \
  -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

**Expected:** HTTP 401 -- the same Keycloak JWT is now rejected because:
- Token exchange is disabled (no `tokenExchange` in the policy)
- The raw Keycloak JWT is forwarded to MCP auth
- MCP auth expects the STS issuer but sees the Keycloak issuer -> **rejected**

### Summary of proof

| Policy Config | Token Exchange | Client Sends | MCP Server Sees | Result |
|---|---|---|---|---|
| Keycloak trust + exchange | Active | Keycloak JWT | STS JWT | 200 |
| **STS trust + exchange** | **Active** | **Keycloak JWT** | **STS JWT** | **200** |
| STS trust, no exchange | Disabled | Keycloak JWT | Keycloak JWT | **401** |

The middle row is the proof: with `tokenExchange.mode: ExchangeOnly`, the client sends a Keycloak JWT but the MCP server receives an STS JWT. When exchange is removed (bottom row), the same Keycloak JWT fails -- proving the exchange was transparently converting the token.

---

## What this proves

```
+--------+                 +-------------------+                 +------------+
| Client |  Keycloak JWT   |   Agent Gateway   |   STS JWT       | MCP Server |
|        |---------------->|                   |---------------->|            |
|        |                 |  1. Validate JWT   |                 |  Trusts    |
|        |                 |  2. Exchange at    |                 |  only STS  |
|        |                 |     built-in STS   |                 |  issuer    |
|        |                 |  3. Forward STS    |                 |            |
|        |<----------------|     JWT only       |<----------------|            |
+--------+                 +-------------------+                 +------------+
                                    |
                           tokenExchange:
                             mode: ExchangeOnly
                           (automatic, no client
                            involvement)
```

**Key takeaways:**

1. **The client never calls the STS** -- Agent Gateway mediates the exchange transparently via `backend.tokenExchange.mode: ExchangeOnly`
2. **The original IdP token never reaches the MCP server** -- it's replaced by the STS-signed JWT
3. **The MCP server trusts only the STS issuer** -- it doesn't need to know about Keycloak
4. **The STS is built into Agent Gateway** -- no external token exchange service required
5. **The token exchange is RFC 8693 compliant** -- standard `urn:ietf:params:oauth:grant-type:token-exchange` grant type
6. **Configuration is declarative** -- a single `tokenExchange` field on the `EnterpriseAgentgatewayPolicy` enables the entire flow

---

## Cleanup

```bash
pkill -f "port-forward.*keycloak" 2>/dev/null || true
pkill -f "port-forward.*flow13" 2>/dev/null || true

kubectl delete enterpriseagentgatewaypolicy mcp-auth-policy -n default
kubectl delete httproute mcp-route -n default
kubectl delete agentgatewaybackend mcp-backend -n default
kubectl delete gateway flow13-gateway -n default
kubectl delete deployment mcp-website-fetcher -n default
kubectl delete service mcp-website-fetcher -n default
kubectl delete referencegrant allow-default-to-keycloak -n keycloak 2>/dev/null || true
kubectl delete namespace keycloak
helm uninstall enterprise-agentgateway -n agentgateway-system
helm uninstall enterprise-agentgateway-crds -n agentgateway-system
kubectl delete namespace agentgateway-system
```

---

## References

- [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) -- STS configuration and Helm values
- [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) -- JWT authentication policies
- [MCP Authentication](https://docs.solo.io/agentgateway/2.2.x/security/mcp-auth/) -- MCP OAuth discovery and token validation
- [Keycloak as an IdP](https://docs.solo.io/agentgateway/2.2.x/security/extauth/oauth/keycloak/) -- Keycloak setup guide
- [About OBO and Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/) -- Conceptual overview
- [Enterprise API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/) -- EnterpriseAgentgatewayPolicy, TokenExchangeMode
- [Helm Values Reference](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/) -- tokenExchange values
- [Token Flow Diagrams](../token-flow-diagrams/agent-gateway-token-flows.md) -- All 15 auth flow diagrams including Flow 13
