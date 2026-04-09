#!/usr/bin/env bash
# Flow 10: BYO External Auth (gRPC Ext Auth Service) — working example
# Delegates auth to a custom gRPC ext_authz service.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../common/setup-base.sh"

FLOW="flow-10"

# ── Deploy echo backend ─────────────────────────────────────────────────────
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
    import json
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            resp = json.dumps({"message": "Hello from protected backend"}).encode()
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

# ── Deploy external auth service (HTTP ext_authz) ────────────────────────────
# Simple HTTP service: checks for x-auth-token header == "allow-me"
info "Deploying external auth service..."
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: ext-auth-script
  namespace: default
data:
  auth.py: |
    """Simple HTTP ext_authz service. Checks x-auth-token header."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json, sys
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            token = self.headers.get('x-auth-token', '')
            sys.stderr.write(f"EXT AUTH CHECK: x-auth-token={token}\n")
            sys.stderr.flush()
            if token == "allow-me":
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{}')
            else:
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "access denied"}).encode())
        def do_GET(self): self.do_POST()
    HTTPServer(('', 9001), H).serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ext-auth-service
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ext-auth-service
  template:
    metadata:
      labels:
        app: ext-auth-service
    spec:
      containers:
      - name: auth
        image: python:3.12-slim
        command: ["python", "/app/auth.py"]
        ports:
        - containerPort: 9001
        volumeMounts:
        - name: script
          mountPath: /app
      volumes:
      - name: script
        configMap:
          name: ext-auth-script
---
apiVersion: v1
kind: Service
metadata:
  name: ext-auth-service
  namespace: default
spec:
  selector:
    app: ext-auth-service
  ports:
  - port: 9001
    targetPort: 9001
EOF
wait_for default deployment/ext-auth-service

# ── Gateway + HTTPRoute + Ext Auth policy ────────────────────────────────────
info "Creating Gateway and BYO Ext Auth policy..."
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
  name: ${FLOW}-ext-auth-policy
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: ${FLOW}-gateway
  traffic:
    extAuth:
      backendRef:
        name: ext-auth-service
        namespace: default
        port: 9001
      http:
        allowedRequestHeaders:
        - x-auth-token
EOF

kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready"

# ── Port-forward and test ────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8888:80 &>/dev/null &
sleep 2

echo ""
echo "=== Testing Flow 10: BYO External Auth ==="
echo ""

# Test 1: No auth token -> 403
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/)
if [[ "$HTTP_CODE" == "403" ]]; then
  ok "No auth token: HTTP ${HTTP_CODE} (expected 403)"
else
  warn "No auth token: HTTP ${HTTP_CODE} (expected 403)"
fi

# Test 2: Wrong token -> 403
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-auth-token: wrong" http://localhost:8888/)
if [[ "$HTTP_CODE" == "403" ]]; then
  ok "Wrong token: HTTP ${HTTP_CODE} (expected 403)"
else
  warn "Wrong token: HTTP ${HTTP_CODE} (expected 403)"
fi

# Test 3: Valid token -> 200
RESPONSE=$(curl -s -w "\n%{http_code}" -H "x-auth-token: allow-me" http://localhost:8888/)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)
if [[ "$HTTP_CODE" == "200" ]]; then
  ok "Valid token: HTTP ${HTTP_CODE}"
  echo "  Response: ${BODY}"
else
  warn "Valid token: HTTP ${HTTP_CODE} (expected 200)"
  echo "  Response: ${BODY}"
fi

echo ""
ok "Flow 10: BYO External Auth — test complete"
echo "  Cleanup: source ../common/cleanup.sh"
