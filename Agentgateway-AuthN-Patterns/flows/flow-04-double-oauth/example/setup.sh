#!/usr/bin/env bash
# Flow 4: Double OAuth (OIDC + Elicitation) — working example
# Phase 1: OIDC auth gets user JWT. Phase 2: Elicitation triggers upstream OAuth.
#
# NOTE: Phase 2 (elicitation completion) requires the Solo Enterprise UI.
# This example demonstrates Phase 1 (OIDC) and the elicitation TRIGGER.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYCLOAK_REALM="flow04-realm"

source "${SCRIPT_DIR}/../../common/setup-base.sh"
source "${SCRIPT_DIR}/../../common/deploy-keycloak.sh"
enable_sts "${KEYCLOAK_REALM}"

FLOW="flow-04"

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
            body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            try: req = json.loads(body)
            except: req = {}
            method, req_id = req.get('method',''), req.get('id')
            if method == 'initialize':
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":False}},"serverInfo":{"name":"double-oauth-test","version":"1.0"}}}
            elif method == 'notifications/initialized':
                self.send_response(200); self.end_headers(); return
            elif method == 'tools/list':
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"tools":[{"name":"test","description":"Test","inputSchema":{"type":"object","properties":{}}}]}}
            else:
                resp = {"jsonrpc":"2.0","id":req_id,"result":{"content":[{"type":"text","text":"ok"}]}}
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

# ── Gateway + Policy (default mode = exchange + elicit) ──────────────────────
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
    tokenExchange: {}
EOF

kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready"

# ── Test ─────────────────────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8888:80 &>/dev/null &
sleep 2

echo ""
echo "=== Testing Flow 4: Double OAuth ==="
echo ""

# Phase 1: Get OIDC JWT (simulated via password grant)
USER_JWT=$(get_user_token "${KEYCLOAK_URL}" "${KEYCLOAK_REALM}" "${KEYCLOAK_CLIENT}" "${KEYCLOAK_SECRET}" \
  "testuser" "testuser" "keycloak.keycloak.svc.cluster.local:8080")
ok "Phase 1: OIDC JWT obtained from Keycloak"
decode_jwt "$USER_JWT" | jq '{iss, sub}'

# Phase 2: Send request — default mode tries exchange first, then elicit
echo ""
info "Phase 2: Sending request (default mode = exchange + elicit)..."
RESPONSE=$(curl -s --max-time 15 -X POST "http://localhost:8888/mcp" \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}')

echo "Response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"

echo ""
warn "NOTE: In the Double OAuth flow, if exchange succeeds (no upstream creds needed),"
warn "the request goes through. If an upstream API needs separate OAuth creds, the"
warn "gateway returns an elicitation URL. Completing elicitation requires Solo Enterprise UI."
echo ""
ok "Flow 4: Double OAuth — test complete"
echo "  Cleanup: source ../../common/cleanup.sh"
