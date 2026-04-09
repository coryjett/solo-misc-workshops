#!/usr/bin/env bash
# Flow 9: Basic Auth (RFC 7617) — working example
# Clients authenticate with username:password. Gateway validates against APR1 hashes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../common/setup-base.sh"

FLOW="flow-09"

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
            resp = json.dumps({"message": "Hello from echo backend"}).encode()
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

# ── Generate APR1 password hash ──────────────────────────────────────────────
# htpasswd format: user:$apr1$salt$hash
info "Generating password hash..."
HTPASSWD_LINE=$(docker run --rm httpd:2.4-alpine htpasswd -nb testuser testpass)
ok "Generated: ${HTPASSWD_LINE}"

# ── Create htpasswd secret ──────────────────────────────────────────────────
kubectl create secret generic basic-auth-htpasswd \
  --namespace default \
  --from-literal=".htaccess=${HTPASSWD_LINE}" \
  --dry-run=client -o yaml | kubectl apply -f -

# ── Gateway + HTTPRoute + Basic Auth policy ──────────────────────────────────
info "Creating Gateway and Basic Auth policy..."
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
  name: ${FLOW}-basic-auth-policy
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: ${FLOW}-gateway
  traffic:
    basicAuthentication:
      secretRef:
        name: basic-auth-htpasswd
EOF

kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready"

# ── Port-forward and test ────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8888:80 &>/dev/null &
sleep 2

echo ""
echo "=== Testing Flow 9: Basic Auth ==="
echo ""

# Test 1: No credentials -> 401
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/)
if [[ "$HTTP_CODE" == "401" ]]; then
  ok "No credentials: HTTP ${HTTP_CODE} (expected 401)"
else
  warn "No credentials: HTTP ${HTTP_CODE} (expected 401)"
fi

# Test 2: Wrong password -> 401
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "testuser:wrongpass" http://localhost:8888/)
if [[ "$HTTP_CODE" == "401" ]]; then
  ok "Wrong password: HTTP ${HTTP_CODE} (expected 401)"
else
  warn "Wrong password: HTTP ${HTTP_CODE} (expected 401)"
fi

# Test 3: Valid credentials -> 200
RESPONSE=$(curl -s -w "\n%{http_code}" -u "testuser:testpass" http://localhost:8888/)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)
if [[ "$HTTP_CODE" == "200" ]]; then
  ok "Valid credentials: HTTP ${HTTP_CODE}"
  echo "  Response: ${BODY}"
else
  warn "Valid credentials: HTTP ${HTTP_CODE} (expected 200)"
  echo "  Response: ${BODY}"
fi

echo ""
ok "Flow 9: Basic Auth — test complete"
echo "  Cleanup: source ../common/cleanup.sh"
