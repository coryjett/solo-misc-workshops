#!/usr/bin/env bash
# Flow 13: Gateway-Mediated OIDC + Token Exchange — working example
# AGW handles OIDC, exchanges JWT at built-in STS, forwards STS token to MCP server.
# This is the same pattern as the flow13-token-exchange workshop.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYCLOAK_REALM="flow13-realm"

source "${SCRIPT_DIR}/../../common/setup-base.sh"
source "${SCRIPT_DIR}/../../common/deploy-keycloak.sh"
enable_sts "${KEYCLOAK_REALM}"

FLOW="flow-13"

# ── Deploy token-logging MCP server ──────────────────────────────────────────
info "Deploying MCP server (logs token issuer)..."
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-server-script
  namespace: default
data:
  server.py: |
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json, sys, base64
    def decode_jwt(token):
        try:
            p = token.split('.')[1]
            p += '=' * (4 - len(p) % 4)
            return json.loads(base64.urlsafe_b64decode(p))
        except: return None
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            auth = self.headers.get('Authorization', '')
            body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            claims = decode_jwt(auth[7:]) if auth.startswith('Bearer ') else None
            if claims:
                sys.stderr.write(f"\n{'='*50}\nMCP SERVER TOKEN:\n  iss: {claims.get('iss')}\n  sub: {claims.get('sub')}\n  act: {claims.get('act')}\n{'='*50}\n")
                sys.stderr.flush()
            try: req = json.loads(body)
            except: req = {}
            method, req_id = req.get('method',''), req.get('id')
            if method == 'initialize':
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":False}},"serverInfo":{"name":"token-logger","version":"1.0"}}}
            elif method == 'notifications/initialized':
                self.send_response(200); self.end_headers(); return
            elif method == 'tools/list':
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"tools":[{"name":"echo_token","description":"Returns token info","inputSchema":{"type":"object","properties":{}}}]}}
            elif method == 'tools/call':
                result = {"token_issuer": claims.get("iss","unknown") if claims else "none", "token_sub": claims.get("sub","unknown") if claims else "none", "token_act": claims.get("act") if claims else None, "message": "This is the token that reached the MCP server"}
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"content":[{"type":"text","text":json.dumps(result,indent=2)}]}}
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

# ── Gateway + Policy ─────────────────────────────────────────────────────────
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
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: ${FLOW}-params
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
  name: ${FLOW}-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: ${FLOW}-params
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
    - name: mcp-test
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
        mode: Strict
        provider: Keycloak
    tokenExchange:
      mode: ExchangeOnly
EOF

kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready"

# ── Test ─────────────────────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8888:80 &>/dev/null &
sleep 2

echo ""
echo "=== Testing Flow 13: Gateway-Mediated Token Exchange ==="
echo ""

USER_JWT=$(get_user_token "${KEYCLOAK_URL}" "${KEYCLOAK_REALM}" "${KEYCLOAK_CLIENT}" "${KEYCLOAK_SECRET}" \
  "testuser" "testuser" "keycloak.keycloak.svc.cluster.local:8080")

echo "Client JWT issuer (should be Keycloak):"
decode_jwt "$USER_JWT" | jq -r '.iss'

# Initialize MCP session
MCP_URL="http://localhost:8888/mcp"
INIT=$(curl -s -D /tmp/mcp-headers --max-time 15 -X POST "$MCP_URL" \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}')
SID=$(grep -i "mcp-session-id" /tmp/mcp-headers 2>/dev/null | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n')

if [[ -n "$SID" ]]; then
  # Call echo_token
  RESULT=$(curl -s --max-time 15 -X POST "$MCP_URL" \
    -H "Authorization: Bearer ${USER_JWT}" \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Session-Id: ${SID}" \
    -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo_token","arguments":{}},"id":3}' \
    | sed 's/^data: //' | jq -r '.result.content[0].text' 2>/dev/null)

  ISSUER=$(echo "$RESULT" | jq -r '.token_issuer' 2>/dev/null)
  if [[ "$ISSUER" == *"7777"* ]] || [[ "$ISSUER" == *"agentgateway"* ]]; then
    ok "Token exchanged! MCP server received STS token (issuer: ${ISSUER})"
  else
    info "MCP server received token with issuer: ${ISSUER}"
  fi
  echo "$RESULT" | jq . 2>/dev/null
else
  warn "Could not establish MCP session"
  echo "Init response: ${INIT}"
fi

echo ""
echo "Verify via server logs:"
echo "  kubectl logs -l app=mcp-server --tail=10"
echo ""
ok "Flow 13: Gateway-Mediated Token Exchange — test complete"
echo "  Cleanup: source ../../common/cleanup.sh"
