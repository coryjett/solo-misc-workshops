#!/usr/bin/env bash
# Flow 8: API Key Auth — working example
# Clients authenticate with a static API key. Gateway validates against K8s secrets.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../common/setup-base.sh"

FLOW="flow-08"

# ── Deploy a simple echo backend ─────────────────────────────────────────────
info "Deploying echo backend..."
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: echo-server-script
  namespace: default
data:
  server.py: |
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json, sys
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            auth = self.headers.get('Authorization', 'none')
            resp = json.dumps({"message": "Hello from echo backend", "auth_header": auth}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        def do_GET(self): self.do_POST()
    HTTPServer(('', 80), H).serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-backend
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo-backend
  template:
    metadata:
      labels:
        app: echo-backend
    spec:
      containers:
      - name: echo
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
          name: echo-server-script
---
apiVersion: v1
kind: Service
metadata:
  name: echo-backend
  namespace: default
spec:
  selector:
    app: echo-backend
  ports:
  - port: 80
    targetPort: 80
EOF
wait_for default deployment/echo-backend

# ── Create API key secret ────────────────────────────────────────────────────
info "Creating API key secret..."
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: user-api-key
  namespace: default
  labels:
    agw-auth: api-key
type: Opaque
stringData:
  api-key: "my-secret-api-key-12345"
EOF

# ── Gateway + HTTPRoute + API key policy ─────────────────────────────────────
info "Creating Gateway, HTTPRoute, and API Key policy..."
kubectl apply -f - <<EOF
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
    - name: echo-backend
      port: 80
    matches:
    - path:
        type: PathPrefix
        value: /
---
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: ${FLOW}-api-key-policy
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: ${FLOW}-gateway
  traffic:
    apiKeyAuthentication:
      secretSelector:
        matchLabels:
          agw-auth: api-key
EOF

info "Waiting for Gateway to be programmed..."
kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready"

# ── Port-forward and test ────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8888:80 &>/dev/null &
sleep 2

echo ""
echo "=== Testing Flow 8: API Key Auth ==="
echo ""

# Test 1: No API key -> 401
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/)
if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
  ok "No API key: HTTP ${HTTP_CODE} (expected — access denied)"
else
  warn "No API key: HTTP ${HTTP_CODE} (expected 401/403)"
fi

# Test 2: Wrong API key -> 401
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer wrong-key" http://localhost:8888/)
if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
  ok "Wrong API key: HTTP ${HTTP_CODE} (expected — access denied)"
else
  warn "Wrong API key: HTTP ${HTTP_CODE} (expected 401/403)"
fi

# Test 3: Valid API key -> 200
RESPONSE=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer my-secret-api-key-12345" http://localhost:8888/)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)
if [[ "$HTTP_CODE" == "200" ]]; then
  ok "Valid API key: HTTP ${HTTP_CODE}"
  echo "  Response: ${BODY}"
else
  warn "Valid API key: HTTP ${HTTP_CODE} (expected 200)"
  echo "  Response: ${BODY}"
fi

echo ""
ok "Flow 8: API Key Auth — test complete"
echo "  Cleanup: source ../common/cleanup.sh"
