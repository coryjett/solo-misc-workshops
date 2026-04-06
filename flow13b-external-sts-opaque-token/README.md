# Flow 13b: External STS with Opaque Token Exchange

Variant of [Flow 13](../flow13-gateway-mediated-token-exchange/) that uses an **external STS** returning **opaque tokens** instead of the built-in STS returning JWTs. The MCP server receives an opaque token (not a JWT) and calls the external STS introspection endpoint to validate it.

### Flow in brief

1. **Client** authenticates with Keycloak and receives a **user JWT**.
2. The client sends the JWT to **Agent Gateway**.
3. Agent Gateway **exchanges** the JWT at the **external STS** (RFC 8693 token exchange).
4. The external STS validates the JWT, stores the claims, and returns an **opaque token** (random hex string).
5. Agent Gateway forwards the **opaque token** to the MCP server. The original IdP token is never forwarded.
6. The MCP server calls the external STS **introspection endpoint** to resolve the opaque token back to claims.

```
                              +-----------+
                              |   OIDC    |
                              | Provider  |
                              | (Keycloak)|
                              +-----+-----+
                                    |
                              1. User JWT
                                    |
+--------+     2. Bearer JWT  +-----v-----------+   4. Opaque token  +------------+
| Client |-------------------->  Agent Gateway   |-------------------->  MCP Server |
|        |                    |   (Proxy)        |                    |            |
+--------+                    |                  |                    | 5. Calls   |
                              |  Validates JWT   |                    |  /introspect|
                              |  Exchanges at    |                    |  on ext STS |
                              |  external STS    |                    +------+-----+
                              |  (automatic)     |                           |
                              +------------------+                           |
                                       |                                     |
                              3. Token Exchange                              |
                                  (gateway-mediated)                         |
                                       |                                     |
                              +--------v---------+                           |
                              |  External STS    |<--------------------------+
                              |  (port 9000)     |   POST /introspect
                              |                  |   token=<opaque>
                              |  subject_token   |   -> { active: true,
                              |  --> opaque hex   |      sub: "alice" }
                              +------------------+
```

### Key differences from Flow 13

| | Flow 13 (built-in STS) | Flow 13b (external STS) |
|---|---|---|
| **STS** | Built-in on control plane (:7777) | External Python server (:9000) |
| **Token type** | JWT (self-contained, signed) | Opaque (random hex, no claims) |
| **Downstream validation** | JWKS signature check (local) | Introspection call to STS (network) |
| **AGW auth policy** | `mcp.authentication` validates OBO JWT | No `mcp.authentication` (AGW can't validate opaque tokens) |
| **MCP server** | Decodes JWT locally | Calls `/introspect` on external STS |

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) | [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) | [Helm values reference](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

---

## Prerequisites

- **Kubernetes cluster** (e.g. AKS, GKE, kind), **kubectl**, **helm** (v3+), **jq**, **curl**
- **Solo Enterprise license:** `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- Run all steps in the same shell so variables persist.

---

## Step 1: Deploy Keycloak and PostgreSQL

Same as [Flow 13 Step 1](../flow13-gateway-mediated-token-exchange/README.md#step-1-deploy-keycloak-and-postgresql).

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

```bash
pkill -f "port-forward.*keycloak.*8080" 2>/dev/null || true
sleep 1
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &
sleep 3
export KEYCLOAK_URL="http://localhost:8080"
export KEYCLOAK_JWKS_URL="http://keycloak.keycloak.svc.cluster.local:8080/realms/flow13b-realm/protocol/openid-connect/certs"
```

```bash
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token')

# Create realm
curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"realm":"flow13b-realm","enabled":true}'

# Create client
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/flow13b-realm/clients" \
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
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/flow13b-realm/users" \
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
```

---

## Step 3: Deploy the External STS

A minimal Python server that implements RFC 8693 token exchange and RFC 7662 introspection. It accepts a user JWT, stores the claims in memory, and returns a random opaque token.

```bash
kubectl apply -n default -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: external-sts-script
  namespace: default
data:
  sts.py: |
    """External STS: RFC 8693 token exchange (opaque tokens) + RFC 7662 introspection."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json, sys, base64, secrets, urllib.parse

    # In-memory token store: opaque_token -> { claims, issued_at }
    token_store = {}

    def decode_jwt_payload(token):
        """Decode JWT payload without signature verification (lab only)."""
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
        def log_message(self, format, *args):
            pass  # Suppress default access logs

        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)

            if self.path == '/token':
                self.handle_exchange(params)
            elif self.path == '/introspect':
                self.handle_introspect(params)
            else:
                self.send_json(404, {"error": "not_found"})

        def handle_exchange(self, params):
            """RFC 8693 token exchange: accept JWT, return opaque token."""
            grant_type = params.get('grant_type', [''])[0]

            if grant_type != 'urn:ietf:params:oauth:grant-type:token-exchange':
                self.send_json(400, {"error": "unsupported_grant_type"})
                return

            subject_token = params.get('subject_token', [''])[0]
            if not subject_token:
                self.send_json(400, {"error": "invalid_request", "error_description": "missing subject_token"})
                return

            claims = decode_jwt_payload(subject_token)
            if not claims:
                self.send_json(400, {"error": "invalid_request", "error_description": "subject_token is not a valid JWT"})
                return

            # Generate opaque token (64 hex chars = 32 bytes of randomness)
            opaque = secrets.token_hex(32)
            token_store[opaque] = claims

            sys.stderr.write(f"\n{'='*60}\n")
            sys.stderr.write(f"TOKEN EXCHANGE REQUEST\n")
            sys.stderr.write(f"  Input:  JWT from {claims.get('iss', 'unknown')}\n")
            sys.stderr.write(f"          sub = {claims.get('sub', 'unknown')}\n")
            sys.stderr.write(f"          preferred_username = {claims.get('preferred_username', 'unknown')}\n")
            sys.stderr.write(f"  Output: Opaque token {opaque[:20]}...\n")
            sys.stderr.write(f"  Store:  {len(token_store)} active tokens\n")
            sys.stderr.write(f"{'='*60}\n\n")
            sys.stderr.flush()

            self.send_json(200, {
                "access_token": opaque,
                "token_type": "Bearer",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 3600
            })

        def handle_introspect(self, params):
            """RFC 7662 introspection: resolve opaque token to claims."""
            token = params.get('token', [''])[0]
            claims = token_store.get(token)

            if claims:
                sys.stderr.write(f"INTROSPECT: token {token[:20]}... -> active (sub={claims.get('sub')})\n")
                sys.stderr.flush()
                self.send_json(200, {
                    "active": True,
                    "sub": claims.get('sub'),
                    "username": claims.get('preferred_username'),
                    "iss": "external-sts",
                    "token_type": "Bearer",
                    "original_issuer": claims.get('iss')
                })
            else:
                sys.stderr.write(f"INTROSPECT: token {token[:20] if token else '(empty)'}... -> NOT ACTIVE\n")
                sys.stderr.flush()
                self.send_json(200, {"active": False})

        def send_json(self, status, data):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    if __name__ == '__main__':
        server = HTTPServer(('', 9000), Handler)
        sys.stderr.write("External STS started on port 9000\n")
        sys.stderr.write("  POST /token      - RFC 8693 token exchange (JWT -> opaque)\n")
        sys.stderr.write("  POST /introspect - RFC 7662 introspection (opaque -> claims)\n")
        sys.stderr.flush()
        server.serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-sts
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: external-sts
  template:
    metadata:
      labels:
        app: external-sts
    spec:
      containers:
      - name: sts
        image: python:3.12-slim
        command: ["python", "/app/sts.py"]
        ports:
        - containerPort: 9000
        volumeMounts:
        - name: script
          mountPath: /app
      volumes:
      - name: script
        configMap:
          name: external-sts-script
          items:
          - key: sts.py
            path: sts.py
---
apiVersion: v1
kind: Service
metadata:
  name: external-sts
  namespace: default
  labels:
    app: external-sts
spec:
  selector:
    app: external-sts
  ports:
  - port: 9000
    targetPort: 9000
    name: http
  type: ClusterIP
EOF

kubectl wait deployment/external-sts -n default --for=condition=Available --timeout=120s
```

**Verify the STS is running:**

```bash
kubectl logs -n default -l app=external-sts --tail=5
# External STS started on port 9000
#   POST /token      - RFC 8693 token exchange (JWT -> opaque)
#   POST /introspect - RFC 7662 introspection (opaque -> claims)
```

---

## Step 4: Deploy MCP server (opaque token aware)

This MCP server detects whether the incoming token is a JWT or opaque, and calls the external STS introspection endpoint to resolve opaque tokens.

```bash
kubectl apply -n default -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-server-script
  namespace: default
data:
  server.py: |
    """MCP server that handles opaque tokens via introspection."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json, sys, base64, urllib.request, urllib.parse

    INTROSPECT_URL = "http://external-sts.default.svc.cluster.local:9000/introspect"

    def is_jwt(token):
        """Check if token looks like a JWT (3 dot-separated base64 parts)."""
        return token.count('.') == 2

    def decode_jwt_payload(token):
        try:
            parts = token.split('.')
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            return json.loads(base64.urlsafe_b64decode(payload))
        except:
            return None

    def introspect_token(token):
        """Call external STS introspection endpoint (RFC 7662)."""
        try:
            data = urllib.parse.urlencode({"token": token}).encode()
            req = urllib.request.Request(INTROSPECT_URL, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"active": False, "error": str(e)}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            auth = self.headers.get('Authorization', '')
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')

            # Analyze the token
            token_info = {"type": "none", "claims": None}
            raw_token = ""

            if auth.startswith('Bearer '):
                raw_token = auth[7:]

                if is_jwt(raw_token):
                    token_info["type"] = "jwt"
                    token_info["claims"] = decode_jwt_payload(raw_token)
                    sys.stderr.write(f"\n{'='*60}\n")
                    sys.stderr.write(f"RECEIVED JWT TOKEN (unexpected in this lab!)\n")
                    sys.stderr.write(f"  iss: {token_info['claims'].get('iss', 'N/A')}\n")
                    sys.stderr.write(f"  sub: {token_info['claims'].get('sub', 'N/A')}\n")
                    sys.stderr.write(f"{'='*60}\n\n")
                else:
                    token_info["type"] = "opaque"
                    sys.stderr.write(f"\n{'='*60}\n")
                    sys.stderr.write(f"RECEIVED OPAQUE TOKEN\n")
                    sys.stderr.write(f"  Token: {raw_token[:20]}...{raw_token[-8:]}\n")
                    sys.stderr.write(f"  Length: {len(raw_token)} chars\n")
                    sys.stderr.write(f"  NOT a JWT (no dots, no embedded claims)\n")
                    sys.stderr.write(f"\n  Calling introspection endpoint...\n")

                    intro = introspect_token(raw_token)
                    token_info["introspection"] = intro

                    if intro.get("active"):
                        sys.stderr.write(f"  Introspection result: ACTIVE\n")
                        sys.stderr.write(f"    sub: {intro.get('sub', 'N/A')}\n")
                        sys.stderr.write(f"    username: {intro.get('username', 'N/A')}\n")
                        sys.stderr.write(f"    iss: {intro.get('iss', 'N/A')}\n")
                        sys.stderr.write(f"    original_issuer: {intro.get('original_issuer', 'N/A')}\n")
                    else:
                        sys.stderr.write(f"  Introspection result: NOT ACTIVE\n")
                    sys.stderr.write(f"{'='*60}\n\n")

                sys.stderr.flush()
            else:
                sys.stderr.write(f"No Bearer token in Authorization header\n")
                sys.stderr.flush()

            # Handle MCP protocol
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
                    "serverInfo": {"name": "opaque-token-mcp", "version": "1.0"}
                }}
            elif method == 'notifications/initialized':
                self.send_response(200)
                self.end_headers()
                return
            elif method == 'tools/list':
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": [{
                    "name": "whoami",
                    "description": "Shows the token type and resolved identity that reached this MCP server",
                    "inputSchema": {"type": "object", "properties": {}}
                }]}}
            elif method == 'tools/call':
                result = {
                    "token_type": token_info["type"],
                    "token_preview": f"{raw_token[:20]}...{raw_token[-8:]}" if raw_token else "none",
                    "token_length": len(raw_token),
                    "is_jwt": is_jwt(raw_token) if raw_token else False,
                }

                if token_info["type"] == "opaque":
                    intro = token_info.get("introspection", {})
                    result["introspection"] = {
                        "active": intro.get("active", False),
                        "sub": intro.get("sub"),
                        "username": intro.get("username"),
                        "iss": intro.get("iss"),
                        "original_issuer": intro.get("original_issuer"),
                    }
                    result["message"] = "Opaque token received. Identity resolved via RFC 7662 introspection."
                elif token_info["type"] == "jwt":
                    claims = token_info.get("claims", {})
                    result["jwt_claims"] = {
                        "iss": claims.get("iss"),
                        "sub": claims.get("sub"),
                    }
                    result["message"] = "JWT received (unexpected in this lab -- exchange may not have happened)."

                resp = {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}}
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
        sys.stderr.write("Opaque-token MCP server started on port 80\n")
        sys.stderr.write(f"  Introspection endpoint: {INTROSPECT_URL}\n")
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

## Step 5: Install Enterprise Agentgateway with STS enabled

We keep the built-in STS enabled (required for the proxy to have exchange capabilities), but `STS_URI` in the next step will point to our external STS instead.

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

---

## Step 6: Create Gateway, Backend, HTTPRoute, and policies

Key difference from Flow 13: **`STS_URI` points to the external STS** (not the built-in one), and **no `mcp.authentication`** on the policy (AGW cannot validate opaque tokens -- the MCP server handles validation via introspection).

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
# Data plane parameters: STS_URI points to EXTERNAL STS (not built-in)
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: flow13b-params
  namespace: default
spec:
  env:
  - name: STS_URI
    value: http://external-sts.default.svc.cluster.local:9000/token
  - name: STS_AUTH_TOKEN
    value: /var/run/secrets/xds-tokens/xds-token
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: flow13b-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: flow13b-params
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
  - name: flow13b-gateway
    namespace: default
  rules:
  # MCP path -> MCP backend
  - backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: mcp-backend
    matches:
    - path:
        type: PathPrefix
        value: /mcp
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
  # Proxy Keycloak endpoints through the gateway
  - backendRefs:
    - name: keycloak
      namespace: keycloak
      port: 8080
    matches:
    - path:
        type: PathPrefix
        value: /realms/flow13b-realm
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
# Policy: token exchange only -- NO mcp.authentication (can't validate opaque tokens)
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-exchange-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    tokenExchange:
      mode: ExchangeOnly
EOF

kubectl wait gateway/flow13b-gateway -n default --for=condition=Programmed --timeout=120s
```

**Verify policy is attached:**

```bash
kubectl get enterpriseagentgatewaypolicy -n default
# NAME                   ACCEPTED   ATTACHED
# mcp-exchange-policy    True       True
```

---

## Step 7: Port-forward and get a Keycloak token

```bash
pkill -f "port-forward.*flow13b" 2>/dev/null || true
sleep 1
kubectl port-forward -n default svc/flow13b-gateway 8888:80 &
sleep 2
```

```bash
export USER_JWT=$(curl -s -X POST "${KEYCLOAK_URL}/realms/flow13b-realm/protocol/openid-connect/token" \
  -H "Host: keycloak.keycloak.svc.cluster.local:8080" \
  -d "username=testuser" -d "password=testuser" -d "grant_type=password" \
  -d "client_id=agw-client" -d "client_secret=agw-client-secret" | jq -r '.access_token')

# Verify it's a JWT from Keycloak
_p=$(echo "$USER_JWT" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_p} % 4)) -ne 0 ]; do _p="${_p}="; done
echo "$_p" | base64 -d 2>/dev/null | jq '{iss, sub, preferred_username}'
```

**Expected:** `iss: http://keycloak.keycloak.svc.cluster.local:8080/realms/flow13b-realm`

---

## Step 8: Test -- prove the MCP server receives an opaque token

### 8.1 Send request and call the whoami tool

```bash
MCP_URL="http://localhost:8888/mcp"
HDR="Authorization: Bearer ${USER_JWT}"

# Initialize and get session
INIT=$(curl -s -i --max-time 15 -X POST "$MCP_URL" \
  -H "$HDR" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}')
SID=$(echo "$INIT" | grep -i "^mcp-session-id:" | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')

# Call whoami -- shows what token the MCP server actually received
echo "=== Token that reached the MCP server ==="
curl -s --max-time 15 -X POST "$MCP_URL" \
  -H "$HDR" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: ${SID}" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"whoami","arguments":{}},"id":3}' \
  | sed 's/^data: //' | jq -r '.result.content[0].text' 2>/dev/null | jq .
```

**Expected output:**

```json
{
  "token_type": "opaque",
  "token_preview": "a3f7b2c9e1d04f68...4f2a8b1c",
  "token_length": 64,
  "is_jwt": false,
  "introspection": {
    "active": true,
    "sub": "faa04387-...",
    "username": "testuser",
    "iss": "external-sts",
    "original_issuer": "http://keycloak.keycloak.svc.cluster.local:8080/realms/flow13b-realm"
  },
  "message": "Opaque token received. Identity resolved via RFC 7662 introspection."
}
```

The MCP server confirms:
- **`is_jwt: false`** -- not a JWT, no dots, no embedded claims
- **`token_type: opaque`** -- a random hex string
- **`introspection.active: true`** -- the external STS confirmed the token is valid
- **`introspection.username: testuser`** -- identity resolved via introspection, not from the token itself
- **`introspection.original_issuer`** -- traces back to Keycloak (the original IdP)

### 8.2 Verify via server logs

```bash
echo "=== External STS logs (exchange) ==="
kubectl logs -n default -l app=external-sts --tail=10

echo ""
echo "=== MCP server logs (opaque token received + introspection) ==="
kubectl logs -n default -l app=mcp-website-fetcher --tail=15
```

**Expected STS logs:**

```
============================================================
TOKEN EXCHANGE REQUEST
  Input:  JWT from http://keycloak.keycloak.svc.cluster.local:8080/realms/flow13b-realm
          sub = faa04387-...
          preferred_username = testuser
  Output: Opaque token a3f7b2c9e1d04f68...
  Store:  1 active tokens
============================================================
```

**Expected MCP server logs:**

```
============================================================
RECEIVED OPAQUE TOKEN
  Token: a3f7b2c9e1d04f68...4f2a8b1c
  Length: 64 chars
  NOT a JWT (no dots, no embedded claims)

  Calling introspection endpoint...
  Introspection result: ACTIVE
    sub: faa04387-...
    username: testuser
    iss: external-sts
    original_issuer: http://keycloak.keycloak.svc.cluster.local:8080/realms/flow13b-realm
============================================================
```

---

## What this proves

```
+--------+                 +-------------------+                 +-------------+
| Client |  Keycloak JWT   |   Agent Gateway   |  Opaque token   |  MCP Server |
|        |---------------->|                   |---------------->|             |
|        |                 |  1. Receives JWT   |                 | NOT a JWT!  |
|        |                 |  2. Calls external |                 | Calls STS   |
|        |                 |     STS /token     |                 | /introspect |
|        |                 |  3. Gets opaque    |                 | to resolve  |
|        |<----------------|     token back     |<----------------| identity    |
+--------+                 +-------------------+                 +------+------+
                                    |                                   |
                           STS_URI = external STS                       |
                           (not built-in :7777)                         |
                                    |                                   |
                           +--------v---------+                         |
                           |  External STS    |<------------------------+
                           |  (port 9000)     |  POST /introspect
                           |                  |  token=a3f7b2c9...
                           |  Stores claims   |  -> { active: true,
                           |  in memory       |       sub: "faa04387..." }
                           +------------------+
```

**Key takeaways:**

1. **The token is NOT a JWT** -- it's a 64-character hex string with no embedded claims, no signature, no dots
2. **AGW cannot validate opaque tokens** -- there is no `mcp.authentication` on the policy (no JWKS to check against)
3. **The MCP server resolves identity via introspection** -- it calls the external STS's `/introspect` endpoint (RFC 7662) on every request
4. **The external STS is the source of truth** -- it stores the JWT claims in memory and returns them on introspection
5. **Trade-off: network call per request** -- unlike JWT validation (local crypto check), opaque tokens require a round-trip to the STS on every request
6. **Easy revocation** -- to revoke access, delete the token from the STS store. The next introspection call returns `active: false`. No waiting for JWT expiry.

---

## Cleanup

```bash
pkill -f "port-forward.*keycloak" 2>/dev/null || true
pkill -f "port-forward.*flow13b" 2>/dev/null || true

kubectl delete enterpriseagentgatewaypolicy mcp-exchange-policy -n default
kubectl delete enterpriseagentgatewayparameters flow13b-params -n default
kubectl delete httproute mcp-route -n default
kubectl delete agentgatewaybackend mcp-backend -n default
kubectl delete gateway flow13b-gateway -n default
kubectl delete configmap external-sts-script mcp-server-script -n default
kubectl delete deployment external-sts mcp-website-fetcher -n default
kubectl delete service external-sts mcp-website-fetcher -n default
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
- [RFC 8693 -- OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) -- Token exchange standard
- [RFC 7662 -- OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662) -- Introspection standard
- [Flow 13 (built-in STS variant)](../flow13-gateway-mediated-token-exchange/) -- Same flow with JWT tokens
- [OBO Deep Dive -- FAQ: Why JWTs and Not Opaque Tokens?](../Agentgateway-AuthN-Patterns/Agentgateway-OBO-Token-Exchange.md#faq-why-jwts-and-not-opaque-tokens)
