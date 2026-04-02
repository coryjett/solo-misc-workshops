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
|        |                    |   (Proxy)        |                   |            |
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
  --set tokenExchange.actorValidator.validatorType=k8s \
  --set tokenExchange.apiValidator.validatorType=remote \
  --set tokenExchange.apiValidator.remoteConfig.url="$KEYCLOAK_JWKS_URL"

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
| `tokenExchange.apiValidator.remoteConfig.url` | JWKS endpoint for authenticating API calls to the STS |

---

## Step 4: Deploy MCP server

Deploy a token-logging MCP server that decodes and logs the JWT it receives. This lets us prove which token (Keycloak vs STS) actually reaches the MCP server by checking `kubectl logs`.

```bash
kubectl apply -n default -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-server-script
  namespace: default
data:
  server.py: |
    """Minimal MCP server that logs the Authorization header (decoded JWT issuer)."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json, sys, base64

    def decode_jwt_payload(token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            return json.loads(base64.urlsafe_b64decode(payload))
        except Exception as e:
            return {"error": str(e)}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            auth = self.headers.get('Authorization', '')
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')

            if auth.startswith('Bearer '):
                claims = decode_jwt_payload(auth[7:])
                if claims:
                    sys.stderr.write(f"\n{'='*60}\n")
                    sys.stderr.write(f"INCOMING TOKEN ON MCP SERVER:\n")
                    sys.stderr.write(f"  iss: {claims.get('iss', 'N/A')}\n")
                    sys.stderr.write(f"  sub: {claims.get('sub', 'N/A')}\n")
                    sys.stderr.write(f"  act: {json.dumps(claims.get('act', 'N/A'))}\n")
                    sys.stderr.write(f"{'='*60}\n\n")
                    sys.stderr.flush()
            else:
                sys.stderr.write(f"No Bearer token in Authorization header\n")
                sys.stderr.flush()

            try:
                req = json.loads(body)
            except:
                req = {}

            method = req.get('method', '')
            req_id = req.get('id')

            if method == 'initialize':
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "token-logger-mcp", "version": "1.0"}
                }}
            elif method == 'notifications/initialized':
                self.send_response(200)
                self.end_headers()
                return
            elif method == 'tools/list':
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": [{
                    "name": "echo_token",
                    "description": "Returns the JWT issuer that reached this MCP server",
                    "inputSchema": {"type": "object", "properties": {}}
                }]}}
            elif method == 'tools/call':
                claims = decode_jwt_payload(auth[7:]) if auth.startswith('Bearer ') else {}
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps({
                    "token_issuer": claims.get('iss', 'unknown'),
                    "token_sub": claims.get('sub', 'unknown'),
                    "token_act": claims.get('act'),
                    "message": "This is the token that reached the MCP server"
                }, indent=2)}]}}
            else:
                resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}

            body_bytes = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)

    if __name__ == '__main__':
        server = HTTPServer(('', 80), Handler)
        sys.stderr.write("Token-logging MCP server started on port 80\n")
        sys.stderr.flush()
        server.serve_forever()
---
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
        image: python:3.12-slim
        command: ["python", "/app/server.py"]
        ports:
        - containerPort: 80
        volumeMounts:
        - name: script
          mountPath: /app
      volumes:
      - name: script
        configMap:
          name: mcp-server-script
          items:
          - key: server.py
            path: server.py
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

Create the Gateway with `EnterpriseAgentgatewayParameters` (configures the data plane's STS connection), an `AgentgatewayBackend` pointing to the MCP server, an HTTPRoute with OAuth discovery paths + Keycloak proxy paths, and an MCP authentication policy with **gateway-mediated token exchange**.

The key configurations are:
- **`EnterpriseAgentgatewayParameters`** with `STS_URI` and `STS_AUTH_TOKEN` -- tells the data plane where the STS is and how to authenticate to it
- **`backend.tokenExchange.mode: ExchangeOnly`** -- tells Agent Gateway to automatically exchange the client's Keycloak JWT at the STS before forwarding to the MCP server

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
# Data plane parameters: STS endpoint and auth token for token exchange
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: flow13-params
  namespace: default
spec:
  env:
  - name: STS_URI
    value: http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/token
  - name: STS_AUTH_TOKEN
    value: /var/run/secrets/xds-tokens/xds-token
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: flow13-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: flow13-params
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

### 7.3 Prove the exchange -- call the echo_token tool

```bash
# Get a fresh token (Keycloak tokens expire in 5 min)
export USER_JWT=$(curl -s -X POST "${KEYCLOAK_URL}/realms/flow13-realm/protocol/openid-connect/token" \
  -H "Host: keycloak.keycloak.svc.cluster.local:8080" \
  -d "username=testuser" -d "password=testuser" -d "grant_type=password" \
  -d "client_id=agw-client" -d "client_secret=agw-client-secret" | jq -r '.access_token')

MCP_URL="http://localhost:8888/mcp"
HDR="Authorization: Bearer ${USER_JWT}"

# Initialize and get session
INIT=$(curl -s -i --max-time 15 -X POST "$MCP_URL" \
  -H "$HDR" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}')
SID=$(echo "$INIT" | grep -i "^mcp-session-id:" | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')

# List tools
echo "=== Tools ==="
curl -s --max-time 15 -X POST "$MCP_URL" \
  -H "$HDR" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: ${SID}" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}' | sed 's/^data: //' | jq '.result.tools[].name' 2>/dev/null

# Call echo_token -- returns the token that actually reached the MCP server
echo ""
echo "=== Token that reached the MCP server ==="
curl -s --max-time 15 -X POST "$MCP_URL" \
  -H "$HDR" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: ${SID}" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo_token","arguments":{}},"id":3}' \
  | sed 's/^data: //' | jq -r '.result.content[0].text' 2>/dev/null | jq .
```

**Expected output:**

```json
{
  "token_issuer": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777",
  "token_sub": "faa04387-...",
  "token_act": null,
  "message": "This is the token that reached the MCP server"
}
```

The `echo_token` tool confirms: the MCP server received a token from the **STS issuer**, not Keycloak. The gateway exchanged it automatically.

> **Bonus:** You can also verify server-side via `kubectl logs -n default -l app=mcp-website-fetcher --tail=20 | grep -A 5 "INCOMING TOKEN"` — the MCP server logs every incoming token's `iss`, `sub`, and `act` claims.

### 7.4 Connect with MCP Inspector (optional)

```bash
npx @modelcontextprotocol/inspector@latest
```

In the MCP Inspector UI:

1. Set **Transport Type** to `Streamable HTTP`
2. Set **URL** to `http://localhost:8888/mcp`
3. Under **Headers**, add: `Authorization` = `Bearer <paste $USER_JWT>`
4. Click **Connect**
5. Go to **Tools** tab -> **List Tools** -> you should see the `echo_token` tool
6. Call `echo_token` -- the response shows the STS issuer, proving the exchange happened

---

## What this proves

```
+--------+                 +-------------------+                 +------------+
| Client |  Keycloak JWT   |   Agent Gateway   |   STS JWT       | MCP Server |
|        |---------------->|                   |---------------->|            |
|        |                 |  1. Validate JWT   |                 | Logs token |
|        |                 |  2. Exchange at    |                 | issuer:    |
|        |                 |     built-in STS   |                 |  STS :7777 |
|        |                 |  3. Forward STS    |                 | (not KC!)  |
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
2. **The original IdP token never reaches the MCP server** -- it's replaced by the STS-signed JWT (proven by `kubectl logs` and the `echo_token` tool)
3. **The MCP server trusts only the STS issuer** -- it doesn't need to know about Keycloak
4. **The STS is built into Agent Gateway** -- no external token exchange service required
5. **The token exchange is RFC 8693 compliant** -- standard `urn:ietf:params:oauth:grant-type:token-exchange` grant type
6. **Configuration is declarative** -- `EnterpriseAgentgatewayParameters` (STS_URI) + `tokenExchange` field on the `EnterpriseAgentgatewayPolicy` enables the entire flow

---

## Cleanup

```bash
pkill -f "port-forward.*keycloak" 2>/dev/null || true
pkill -f "port-forward.*flow13" 2>/dev/null || true

kubectl delete enterpriseagentgatewaypolicy mcp-auth-policy -n default
kubectl delete enterpriseagentgatewayparameters flow13-params -n default
kubectl delete httproute mcp-route -n default
kubectl delete agentgatewaybackend mcp-backend -n default
kubectl delete gateway flow13-gateway -n default
kubectl delete configmap mcp-server-script -n default
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
- [Authentication Flows](../token-flow-diagrams/agent-gateway-token-flows.md) -- All 15 auth flow diagrams including Flow 13
