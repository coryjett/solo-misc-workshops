#!/usr/bin/env bash
# Flow 11: MCP OAuth with Dynamic Client Registration — working example
# MCP clients register dynamically, then complete OAuth to get access.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYCLOAK_REALM="flow11-realm"
source "${SCRIPT_DIR}/../../common/setup-base.sh"
source "${SCRIPT_DIR}/../../common/deploy-keycloak.sh"

FLOW="flow-11"

# ── Deploy MCP server ────────────────────────────────────────────────────────
info "Deploying MCP server..."
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-server-script
  namespace: default
data:
  server.py: |
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            auth = self.headers.get('Authorization', '')
            body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            try: req = json.loads(body)
            except: req = {}
            method, req_id = req.get('method',''), req.get('id')
            if method == 'initialize':
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":False}},"serverInfo":{"name":"dcr-mcp","version":"1.0"}}}
            elif method == 'notifications/initialized':
                self.send_response(200); self.end_headers(); return
            elif method == 'tools/list':
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"tools":[{"name":"hello","description":"Says hello","inputSchema":{"type":"object","properties":{}}}]}}
            elif method == 'tools/call':
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"content":[{"type":"text","text":"Hello from MCP server! You authenticated via OAuth + DCR."}]}}
            else:
                resp = {"jsonrpc":"2.0","id":req_id,"error":{"code":-32601,"message":f"Unknown: {method}"}}
            out = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(out)))
            self.end_headers()
            self.wfile.write(out)
    HTTPServer(('',80),H).serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mcp-server
  template:
    metadata:
      labels:
        app: mcp-server
    spec:
      containers:
      - name: mcp
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
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-server
  namespace: default
spec:
  selector:
    app: mcp-server
  ports:
  - port: 80
    targetPort: 80
    appProtocol: agentgateway.dev/mcp
EOF
wait_for default deployment/mcp-server

# ── ReferenceGrant + Gateway + MCP Auth policy with Keycloak ─────────────────
kubectl apply -f - <<EOF
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
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ${FLOW}-gateway
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
    - name: dcr-mcp
      static:
        host: mcp-server.default.svc.cluster.local
        port: 80
        protocol: StreamableHTTP
        path: /mcp
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ${FLOW}-route
  namespace: default
spec:
  parentRefs:
  - name: ${FLOW}-gateway
  rules:
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
  - backendRefs:
    - name: keycloak
      namespace: keycloak
      port: 8080
    matches:
    - path:
        type: PathPrefix
        value: /realms/${KEYCLOAK_REALM}
---
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: ${FLOW}-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:
        issuer: "${KEYCLOAK_ISSUER}"
        jwks:
          backendRef:
            name: keycloak
            kind: Service
            namespace: keycloak
            port: 8080
          jwksPath: "realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
        audiences:
        - account
        - ${KEYCLOAK_CLIENT}
        - http://localhost:8888/mcp
        mode: Strict
        provider: Keycloak
        resourceMetadata:
          resource: http://localhost:8888/mcp
          scopesSupported:
          - email
          - openid
          bearerMethodsSupported:
          - header
EOF

kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready"

# ── Test ─────────────────────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8888:80 &>/dev/null &
sleep 2

echo ""
echo "=== Testing Flow 11: MCP OAuth + Dynamic Client Registration ==="
echo ""

# Test 1: Unauthenticated -> 401 with resource metadata endpoint
info "Step 1: Connect without auth (expect 401 + resource metadata URL)..."
HTTP_CODE=$(curl -s -o /tmp/mcp-unauth -w "%{http_code}" -X POST "http://localhost:8888/mcp" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}')
ok "Unauthenticated: HTTP ${HTTP_CODE}"

# Test 2: OAuth protected resource metadata
info "Step 2: Fetch resource metadata..."
curl -s "http://localhost:8888/.well-known/oauth-protected-resource/mcp" | jq . 2>/dev/null || echo "(no metadata endpoint)"

# Test 3: With pre-obtained JWT (simulating post-DCR OAuth flow)
info "Step 3: Authenticate with JWT (simulating completed OAuth flow)..."
USER_JWT=$(get_user_token "${KEYCLOAK_URL}" "${KEYCLOAK_REALM}" "${KEYCLOAK_CLIENT}" "${KEYCLOAK_SECRET}" \
  "testuser" "testuser" "keycloak.keycloak.svc.cluster.local:8080")

INIT=$(curl -s -D /tmp/mcp-headers --max-time 10 -X POST "http://localhost:8888/mcp" \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}' 2>/dev/null || true)
SID=$(grep -i "mcp-session-id" /tmp/mcp-headers 2>/dev/null | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n')

# Parse SSE data if present
SSE_DATA=$(echo "$INIT" | grep '^data: ' | sed 's/^data: //' | head -1)

if [[ -n "$SID" ]]; then
  ok "MCP session created: ${SID}"
  [[ -n "$SSE_DATA" ]] && echo "$SSE_DATA" | jq . 2>/dev/null

  RESULT=$(curl -s --max-time 10 -X POST "http://localhost:8888/mcp" \
    -H "Authorization: Bearer ${USER_JWT}" \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Session-Id: ${SID}" \
    -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"hello","arguments":{}},"id":3}' 2>/dev/null || true)
  RESULT_DATA=$(echo "$RESULT" | grep '^data: ' | sed 's/^data: //' | head -1)
  [[ -z "$RESULT_DATA" ]] && RESULT_DATA="$RESULT"
  echo "MCP response: $(echo "$RESULT_DATA" | jq -r '.result.content[0].text' 2>/dev/null)"
elif [[ -n "$SSE_DATA" ]]; then
  ok "MCP server responded (no session ID in headers)"
  echo "$SSE_DATA" | jq . 2>/dev/null || echo "$SSE_DATA"
else
  warn "Could not establish MCP session"
  [[ -n "$INIT" ]] && echo "$INIT"
fi

echo ""
info "For full DCR flow, connect with an MCP client (Claude Code, MCP Inspector):"
echo "  npx @modelcontextprotocol/inspector@latest"
echo "  URL: http://localhost:8888/mcp"
echo ""
ok "Flow 11: MCP OAuth + DCR — test complete"
echo "  Cleanup: source ../../common/cleanup.sh"
