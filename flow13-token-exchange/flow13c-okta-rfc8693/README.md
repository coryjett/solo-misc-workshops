# Flow 13c: Gateway-Mediated Token Exchange against Okta (RFC 8693)

Variant of [Flow 13b](../flow13b-external-sts-opaque-token/) that performs the actual token exchange against a **real Okta custom authorization server** using **RFC 8693**. The gateway sends the inbound Okta user JWT to a small translator STS, which forwards it to Okta's `/v1/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, requests a specific audience (e.g. `api://snowflake-mcp`), and returns Okta's response. AGW forwards the exchanged token to the MCP backend.

```
┌──────────┐  ① user JWT     ┌─────┐  ② RFC 8693          ┌───────────────┐  ③ Okta /v1/token   ┌──────┐
│  client  │ ───────────────▶│ AGW │ ────────────────────▶│ translator    │ ───────────────────▶│ Okta │
│  (curl)  │                 └──┬──┘                       │ STS (Python)  │   + Basic auth      └───┬──┘
└──────────┘                    │                          └───────┬───────┘   + audience            │
                                │                                  │                                 │
                                │                                  │◀────────────────────────────────┘
                                │                                  │   ④ Okta access token (audience=snowflake)
                                │◀─────────────────────────────────┘
                                │   ⑤ forward exchanged token
                                ▼
                        ┌──────────────┐
                        │ MCP backend  │  ⑥ echoes Authorization → proves the swap
                        └──────────────┘
```

Why a translator? AGW's `STS_URI` speaks RFC 8693 directly, but it doesn't know how to authenticate to Okta (Basic auth with `client_id:client_secret`) or add `audience` / `scope` parameters. The translator is ~60 lines of Python that adds those bits.

---

## Part 1 — Configure Okta

Your tenant: `integrator-9380202.okta.com` (note: admin URL has `-admin`, runtime URL drops it).

### 1.1 Create a Custom Authorization Server

Okta admin console → **Security → API → Authorization Servers → Add Authorization Server**

| Field | Value |
|---|---|
| Name | `snowflake-mcp` |
| Audience | `api://snowflake-mcp` |
| Description | RFC 8693 token exchange demo for AGW |

After saving, copy the **Issuer URI** — looks like `https://integrator-9380202.okta.com/oauth2/aus<XYZ>`. Note the `aus<XYZ>` segment, you'll need it.

### 1.2 Add a scope

On that authorization server → **Scopes → Add Scope**

| Field | Value |
|---|---|
| Name | `snowflake.access` |
| Description | Access to Snowflake MCP |
| Default scope | ✅ (so client_credentials gets it automatically) |
| Include in public metadata | ✅ |

### 1.3 Enable the Token Exchange grant in the access policy

Same authorization server → **Access Policies → Add Policy** (or edit Default)

- Name: `allow-token-exchange`
- Assign to: All clients (or specific clients)

Then **Add Rule**:

| Field | Value |
|---|---|
| Rule name | `token-exchange-allowed` |
| Grant type is | **Token Exchange** ✅ (and Client Credentials, for testing) |
| User is | Any user (or pick the test user from 1.5) |
| Scopes | `snowflake.access` |

> If "Token Exchange" doesn't appear as a grant option, your Okta tenant edition may not have it. Confirm via the [Okta admin license page](https://help.okta.com/en-us/content/topics/security/api.htm) — Custom Auth Servers require the API Access Management feature. The **integrator** tenant has it.

### 1.4 Register the exchange client (the credentials AGW's translator will present)

**Applications → Applications → Create App Integration → OIDC – OpenID Connect → API Services**

| Field | Value |
|---|---|
| App name | `agw-token-exchange-client` |
| Client authentication | Client secret |
| Allowed grant types | ✅ Client Credentials, ✅ Token Exchange |

Save and copy:
- `Client ID` → `OKTA_CLIENT_ID`
- `Client Secret` → `OKTA_CLIENT_SECRET`

Back on the **Authorization Server → Access Policies → your rule** make sure this client is assigned.

### 1.5 (For testing) Register a public client to obtain a user subject token

To produce the **incoming Bearer JWT** that AGW will exchange, register one more app:

**Applications → Create App Integration → OIDC → Native Application**

| Field | Value |
|---|---|
| App name | `agw-test-subject-client` |
| Allowed grant types | ✅ Authorization Code, ✅ Resource Owner Password (Direct Auth) |
| Sign-in redirect URI | `http://localhost:8080/callback` (unused, just required) |
| Controlled access | Allow everyone (or assign to the test user) |

Copy `Client ID` → `OKTA_TEST_CLIENT_ID`. (Native apps are public — no secret.)

Create a test user under **Directory → People → Add Person** with a known password (e.g. `Pass123!`). Assign the user to `agw-test-subject-client`.

### 1.6 Export the values you collected

```bash
export OKTA_DOMAIN="integrator-9380202.okta.com"
export OKTA_AS_ID="aus<XYZ>"                                  # from 1.1
export OKTA_AS_ISSUER="https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}"
export OKTA_CLIENT_ID="<from 1.4>"
export OKTA_CLIENT_SECRET="<from 1.4>"
export OKTA_TEST_CLIENT_ID="<from 1.5>"
export OKTA_TEST_USERNAME="<test user email>"
export OKTA_TEST_PASSWORD="Pass123!"
export OKTA_AUDIENCE="api://snowflake-mcp"
export OKTA_SCOPE="snowflake.access"

export AGENTGATEWAY_LICENSE_KEY="<your license>"
```

---

## Part 2 — Deploy the translator STS, MCP backend, and AGW

### 2.1 Translator STS (RFC 8693 → Okta)

Receives AGW's RFC 8693 POST, forwards it to Okta's token endpoint with Basic auth and adds `audience` + `scope`.

<details>
<summary><strong>Translator STS YAML</strong></summary>

```bash
kubectl create namespace flow13c 2>/dev/null || true

kubectl create secret generic okta-client \
  -n flow13c \
  --from-literal=client_id="${OKTA_CLIENT_ID}" \
  --from-literal=client_secret="${OKTA_CLIENT_SECRET}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -n flow13c -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: okta-translator-script
data:
  sts.py: |
    """Translator STS: receives RFC 8693 from AGW, forwards to Okta with audience + Basic auth."""
    import base64, json, os, sys, urllib.parse, urllib.request, ssl
    from http.server import BaseHTTPRequestHandler, HTTPServer

    OKTA_TOKEN_URL = os.environ['OKTA_TOKEN_URL']        # https://.../oauth2/aus.../v1/token
    OKTA_INTROSPECT_URL = os.environ['OKTA_INTROSPECT_URL']  # for /introspect passthrough (optional)
    AUDIENCE = os.environ['OKTA_AUDIENCE']
    SCOPE = os.environ.get('OKTA_SCOPE', '')
    CLIENT_ID = os.environ['OKTA_CLIENT_ID']
    CLIENT_SECRET = os.environ['OKTA_CLIENT_SECRET']
    BASIC = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

    def forward_to_okta(url, body):
        req = urllib.request.Request(url, data=body.encode(), method='POST')
        req.add_header('Authorization', f'Basic {BASIC}')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Accept', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context()) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        except Exception as e:
            return 500, json.dumps({"error": "translator_error", "error_description": str(e)})

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, fmt, *args): pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            params = urllib.parse.parse_qs(body)

            if self.path == '/token':
                if params.get('grant_type', [''])[0] != 'urn:ietf:params:oauth:grant-type:token-exchange':
                    return self._send(400, json.dumps({"error": "unsupported_grant_type"}))

                # Inject audience + scope, force subject_token_type if missing
                params.setdefault('subject_token_type', ['urn:ietf:params:oauth:token-type:access_token'])
                params.setdefault('requested_token_type', ['urn:ietf:params:oauth:token-type:access_token'])
                params['audience'] = [AUDIENCE]
                if SCOPE:
                    params['scope'] = [SCOPE]

                rebuilt = urllib.parse.urlencode(params, doseq=True)
                sys.stderr.write(f"[STS] -> Okta /token  audience={AUDIENCE}  scope={SCOPE}\n"); sys.stderr.flush()
                status, resp_body = forward_to_okta(OKTA_TOKEN_URL, rebuilt)
                sys.stderr.write(f"[STS] <- Okta status={status} body[:120]={resp_body[:120]}\n"); sys.stderr.flush()
                self._send(status, resp_body)

            elif self.path == '/introspect':
                sys.stderr.write(f"[STS] -> Okta /introspect\n"); sys.stderr.flush()
                status, resp_body = forward_to_okta(OKTA_INTROSPECT_URL, body)
                self._send(status, resp_body)
            else:
                self._send(404, json.dumps({"error": "not_found"}))

        def _send(self, status, body):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    if __name__ == '__main__':
        sys.stderr.write(f"Translator STS on :9000 -> {OKTA_TOKEN_URL}\n"); sys.stderr.flush()
        HTTPServer(('', 9000), Handler).serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: okta-translator
spec:
  replicas: 1
  selector: { matchLabels: { app: okta-translator } }
  template:
    metadata: { labels: { app: okta-translator } }
    spec:
      containers:
      - name: sts
        image: python:3.12-slim
        command: ["python", "/app/sts.py"]
        ports: [{ containerPort: 9000 }]
        env:
        - name: OKTA_TOKEN_URL
          value: "${OKTA_AS_ISSUER}/v1/token"
        - name: OKTA_INTROSPECT_URL
          value: "${OKTA_AS_ISSUER}/v1/introspect"
        - name: OKTA_AUDIENCE
          value: "${OKTA_AUDIENCE}"
        - name: OKTA_SCOPE
          value: "${OKTA_SCOPE}"
        - name: OKTA_CLIENT_ID
          valueFrom: { secretKeyRef: { name: okta-client, key: client_id } }
        - name: OKTA_CLIENT_SECRET
          valueFrom: { secretKeyRef: { name: okta-client, key: client_secret } }
        volumeMounts: [{ name: script, mountPath: /app }]
      volumes:
      - name: script
        configMap:
          name: okta-translator-script
          items: [{ key: sts.py, path: sts.py }]
---
apiVersion: v1
kind: Service
metadata:
  name: okta-translator
spec:
  selector: { app: okta-translator }
  ports: [{ port: 9000, targetPort: 9000 }]
EOF

kubectl -n flow13c rollout status deployment/okta-translator --timeout=120s
```

</details>

### 2.2 MCP backend that echoes Authorization

Tiny MCP server. `tools/call → whoami` returns the token type + decoded JWT claims so you can prove the exchange happened.

<details>
<summary><strong>MCP backend YAML</strong></summary>

```bash
kubectl apply -n flow13c -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-echo-script
data:
  server.py: |
    """MCP server that returns the inbound Authorization for inspection."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import base64, json, sys

    def decode_jwt(token):
        try:
            p = token.split('.')[1]; p += '=' * (4 - len(p) % 4)
            return json.loads(base64.urlsafe_b64decode(p))
        except Exception as e:
            return {"_decode_error": str(e)}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            try: req = json.loads(body)
            except: req = {}
            method, rid = req.get('method', ''), req.get('id')
            auth = self.headers.get('Authorization', '')
            token = auth[7:] if auth.startswith('Bearer ') else ''

            if method == 'initialize':
                resp = {"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05",
                  "capabilities":{"tools":{"listChanged":False}},
                  "serverInfo":{"name":"okta-echo","version":"1.0"}}}
            elif method == 'notifications/initialized':
                self.send_response(200); self.end_headers(); return
            elif method == 'tools/list':
                resp = {"jsonrpc":"2.0","id":rid,"result":{"tools":[
                  {"name":"whoami","description":"echoes the inbound Authorization token",
                   "inputSchema":{"type":"object","properties":{}}}]}}
            elif method == 'tools/call':
                claims = decode_jwt(token) if token else None
                result = {
                    "token_preview": (token[:24]+"..."+token[-12:]) if token else "(none)",
                    "is_jwt": token.count('.') == 2,
                    "claims": claims,
                    "audience": claims.get('aud') if claims else None,
                    "issuer": claims.get('iss') if claims else None,
                    "scope": claims.get('scp') or claims.get('scope') if claims else None,
                    "subject": claims.get('sub') if claims else None,
                }
                resp = {"jsonrpc":"2.0","id":rid,"result":{"content":[
                  {"type":"text","text": json.dumps(result, indent=2)}]}}
            else:
                resp = {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":f"Unknown: {method}"}}
            out = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length', str(len(out)))
            self.end_headers(); self.wfile.write(out)

    if __name__ == '__main__':
        sys.stderr.write("MCP echo on :80\n"); sys.stderr.flush()
        HTTPServer(('', 80), H).serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-echo
spec:
  replicas: 1
  selector: { matchLabels: { app: mcp-echo } }
  template:
    metadata: { labels: { app: mcp-echo } }
    spec:
      containers:
      - name: echo
        image: python:3.12-slim
        command: ["python","/app/server.py"]
        ports: [{ containerPort: 80 }]
        volumeMounts: [{ name: script, mountPath: /app }]
      volumes:
      - name: script
        configMap: { name: mcp-echo-script, items: [{ key: server.py, path: server.py }] }
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-echo
spec:
  selector: { app: mcp-echo }
  ports:
  - { port: 80, targetPort: 80, appProtocol: agentgateway.dev/mcp }
EOF

kubectl -n flow13c rollout status deployment/mcp-echo --timeout=120s
```

</details>

### 2.3 Install AGW with token exchange enabled and `STS_URI` pointed at the translator

Subject validator JWKS = Okta's authorization-server JWKS endpoint, so AGW will validate the inbound user JWT against Okta before it agrees to exchange.

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml

helm upgrade -i --create-namespace -n agentgateway-system enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --version v2.2.0

helm upgrade -i -n agentgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version v2.2.0 \
  --set-string licensing.licenseKey="$AGENTGATEWAY_LICENSE_KEY" \
  --set agentgateway.enabled=true \
  --set tokenExchange.enabled=true \
  --set tokenExchange.issuer="enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777" \
  --set tokenExchange.tokenExpiration=24h \
  --set tokenExchange.subjectValidator.validatorType=remote \
  --set tokenExchange.subjectValidator.remoteConfig.url="${OKTA_AS_ISSUER}/v1/keys" \
  --set tokenExchange.actorValidator.validatorType=k8s \
  --set tokenExchange.apiValidator.validatorType=remote \
  --set tokenExchange.apiValidator.remoteConfig.url="${OKTA_AS_ISSUER}/v1/keys"

kubectl -n agentgateway-system rollout status deployment -l app.kubernetes.io/instance=enterprise-agentgateway --timeout=120s
```

### 2.4 Gateway, Backend, Route, Policy

`STS_URI` overrides AGW's default (the controller's built-in STS) and routes the exchange to our translator. `mcp.authentication` validates the inbound Okta JWT — required so AGW extracts the subject token for exchange. After exchange, the Okta-issued access token (Snowflake audience) is forwarded to the MCP backend.

<details>
<summary><strong>Gateway + Policy YAML</strong></summary>

```bash
kubectl apply -f - <<EOF
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: flow13c-params
  namespace: flow13c
spec:
  env:
  - name: STS_URI
    value: http://okta-translator.flow13c.svc.cluster.local:9000/token
  - name: STS_AUTH_TOKEN
    value: /var/run/secrets/xds-tokens/xds-token
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: flow13c-gateway
  namespace: flow13c
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: flow13c-params
  listeners:
  - { name: http, port: 80, protocol: HTTP, allowedRoutes: { namespaces: { from: All } } }
---
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: mcp-backend
  namespace: flow13c
spec:
  mcp:
    targets:
    - name: mcp-echo
      static:
        host: mcp-echo.flow13c.svc.cluster.local
        port: 80
        protocol: StreamableHTTP
        path: /mcp
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: mcp-route
  namespace: flow13c
spec:
  parentRefs: [{ name: flow13c-gateway }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: /mcp } }]
    backendRefs:
    - { name: mcp-backend, kind: AgentgatewayBackend, group: agentgateway.dev }
---
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: validate-inbound-okta-jwt
  namespace: flow13c
spec:
  targetRefs:
  - { group: agentgateway.dev, kind: AgentgatewayBackend, name: mcp-backend }
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "${OKTA_AS_ISSUER}"
        audiences: ["${OKTA_AUDIENCE}", "${OKTA_TEST_CLIENT_ID}"]
        jwks:
          backendRef: { name: okta-translator, port: 9000 }   # placeholder, see note
          jwksPath: "/keys"
---
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: exchange-only
  namespace: flow13c
spec:
  targetRefs:
  - { group: agentgateway.dev, kind: AgentgatewayBackend, name: mcp-backend }
  backend:
    tokenExchange:
      mode: ExchangeOnly
EOF
```

</details>

> **Note on the JWKS backendRef**: `mcp.authentication.jwks.backendRef` requires an in-cluster Service. To validate against Okta's JWKS, deploy a tiny passthrough (or use a `ServiceEntry` if you're on ambient). For a quick local test, a one-liner nginx proxy works:
>
> ```bash
> kubectl apply -n flow13c -f - <<EOF
> apiVersion: apps/v1
> kind: Deployment
> metadata: { name: okta-jwks-proxy }
> spec:
>   replicas: 1
>   selector: { matchLabels: { app: okta-jwks-proxy } }
>   template:
>     metadata: { labels: { app: okta-jwks-proxy } }
>     spec:
>       containers:
>       - name: nginx
>         image: nginx:alpine
>         ports: [{ containerPort: 8080 }]
>         volumeMounts: [{ name: conf, mountPath: /etc/nginx/conf.d }]
>       volumes:
>       - name: conf
>         configMap: { name: okta-jwks-proxy-conf }
> ---
> apiVersion: v1
> kind: ConfigMap
> metadata: { name: okta-jwks-proxy-conf }
> data:
>   default.conf: |
>     server {
>       listen 8080;
>       resolver 8.8.8.8 ipv6=off;
>       location /keys {
>         proxy_pass ${OKTA_AS_ISSUER}/v1/keys;
>         proxy_set_header Host ${OKTA_DOMAIN};
>       }
>     }
> ---
> apiVersion: v1
> kind: Service
> metadata: { name: okta-jwks-proxy }
> spec:
>   selector: { app: okta-jwks-proxy }
>   ports: [{ port: 8080, targetPort: 8080 }]
> EOF
> ```
>
> Then change `jwks.backendRef` to `{ name: okta-jwks-proxy, port: 8080 }` and `jwksPath: "/keys"`.

---

## Part 3 — Test

### 3.1 Get a subject token from Okta (Resource Owner Password)

```bash
SUBJECT_TOKEN=$(curl -sS -X POST "${OKTA_AS_ISSUER}/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=${OKTA_TEST_USERNAME}" \
  -d "password=${OKTA_TEST_PASSWORD}" \
  -d "scope=openid offline_access ${OKTA_SCOPE}" \
  -d "client_id=${OKTA_TEST_CLIENT_ID}" \
  | jq -r '.access_token')

echo "subject token (first 60 chars): ${SUBJECT_TOKEN:0:60}..."
echo
echo "decoded payload:"
echo "${SUBJECT_TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

### 3.2 Port-forward AGW and call the MCP backend

```bash
pkill -f "port-forward.*flow13c-gateway.*8080" 2>/dev/null || true
sleep 1
kubectl -n flow13c port-forward svc/flow13c-gateway 8080:80 &
sleep 2

curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer ${SUBJECT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}' | jq .

curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer ${SUBJECT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"whoami","arguments":{}}}' \
  | jq -r '.result.content[0].text' | jq .
```

### 3.3 What you should see

The `whoami` response shows what hit the **backend** — it's the **exchanged token**, not the original. Key fields:

```json
{
  "is_jwt": true,
  "audience": "api://snowflake-mcp",           ← from the exchange
  "issuer": "https://integrator-9380202.okta.com/oauth2/aus<XYZ>",
  "scope": "snowflake.access",                 ← requested by translator
  "subject": "<okta user id>"
}
```

And the translator pod log shows the round trip:

```bash
kubectl -n flow13c logs deploy/okta-translator
# [STS] -> Okta /token  audience=api://snowflake-mcp  scope=snowflake.access
# [STS] <- Okta status=200 body[:120]={"token_type":"Bearer","expires_in":3600,"access_token":"eyJ..."}
```

If the exchange fails, Okta's error comes back verbatim. Common ones:
- `invalid_grant` — Token Exchange grant not enabled on the access policy rule (Part 1.3)
- `invalid_client` — `OKTA_CLIENT_ID` / `OKTA_CLIENT_SECRET` mismatch, or client not assigned to the policy rule
- `invalid_scope` — Scope not defined or not allowed for this client
- `access_denied` — Subject user not assigned to the policy rule

---

## Part 4 — What this proves for the prospect

| Question | Answer |
|---|---|
| Can AGW do RFC 8693 against Okta? | ✅ — via the `STS_URI` override + a small translator (60 LOC) |
| Can it request a specific audience (Snowflake)? | ✅ — translator adds `audience=api://snowflake-mcp` |
| Is the original user token forwarded? | ❌ — only the exchanged token reaches the MCP backend |
| Is this Entra-only? | ❌ — works against any RFC 8693-capable AS (Okta, Keycloak, Auth0, ForgeRock, etc.) |
| Does it need ext-proc / sidecars on the MCP pod? | ❌ — pure AGW config + STS shim |
| What about Okta cross-app access / Identity Assertion grant? | Same pattern — the translator just sets a different `subject_token_type` + `requested_token_type` |

The translator is the only piece outside AGW. Replace it with Okta-native semantics, or fold it into Okta as a custom token-exchange policy, and it disappears entirely once AGW ships native Okta support (the Go `TokenExchanger` interface is already designed for it — `internal/tokenexchange/exchange/exchanger.go`).

---

## Cleanup

```bash
helm -n agentgateway-system uninstall enterprise-agentgateway enterprise-agentgateway-crds 2>/dev/null || true
kubectl delete namespace flow13c agentgateway-system 2>/dev/null || true
pkill -f "port-forward.*flow13c-gateway.*8080" 2>/dev/null || true
```
