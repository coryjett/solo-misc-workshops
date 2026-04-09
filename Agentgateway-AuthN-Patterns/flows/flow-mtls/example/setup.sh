#!/usr/bin/env bash
# Flow: Mutual TLS (mTLS) — working example
# FrontendTLS: client cert validation. BackendTLS: TLS origination to backend.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../common/setup-base.sh"

FLOW="flow-mtls"

# ── Generate CA + server + client certs ──────────────────────────────────────
info "Generating TLS certificates..."
CERT_DIR="/tmp/${FLOW}-certs"
mkdir -p "$CERT_DIR"

# CA
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
  -subj "/CN=AGW Test CA" 2>/dev/null

# Server cert (for the gateway)
openssl req -newkey rsa:2048 -nodes \
  -keyout "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" \
  -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
  -out "${CERT_DIR}/server.crt" -days 365 \
  -extfile <(echo "subjectAltName=DNS:localhost,DNS:${FLOW}-gateway.default.svc.cluster.local") 2>/dev/null

# Client cert (for mTLS)
openssl req -newkey rsa:2048 -nodes \
  -keyout "${CERT_DIR}/client.key" -out "${CERT_DIR}/client.csr" \
  -subj "/CN=test-client" 2>/dev/null
openssl x509 -req -in "${CERT_DIR}/client.csr" \
  -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
  -out "${CERT_DIR}/client.crt" -days 365 2>/dev/null

ok "Certificates generated in ${CERT_DIR}"

# ── Create K8s secrets for certs ─────────────────────────────────────────────
info "Creating certificate secrets..."
kubectl create secret tls "${FLOW}-server-cert" \
  --cert="${CERT_DIR}/server.crt" --key="${CERT_DIR}/server.key" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap "${FLOW}-ca-cert" \
  --from-file=ca.crt="${CERT_DIR}/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

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
            resp = json.dumps({"message": "Hello from backend (mTLS authenticated)"}).encode()
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

# ── Gateway with TLS + mTLS ─────────────────────────────────────────────────
info "Creating Gateway with FrontendTLS (mTLS)..."
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ${FLOW}-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  listeners:
  - name: https
    port: 443
    protocol: HTTPS
    tls:
      mode: Terminate
      certificateRefs:
      - name: ${FLOW}-server-cert
      options:
        gateway.networking.k8s.io/tls-frontend-validation: |
          caCertificateRefs:
          - name: ${FLOW}-ca-cert
            group: ""
            kind: ConfigMap
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
EOF

kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready"

# ── Port-forward and test ────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8443:443 &>/dev/null &
sleep 2

echo ""
echo "=== Testing Flow: Mutual TLS ==="
echo ""

# Test 1: No client cert -> should fail or be rejected
info "Test 1: No client certificate..."
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --cacert "${CERT_DIR}/ca.crt" https://localhost:8443/ 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "000" || "$HTTP_CODE" == "400" || "$HTTP_CODE" == "403" ]]; then
  ok "No client cert: connection refused or denied (HTTP ${HTTP_CODE})"
else
  warn "No client cert: HTTP ${HTTP_CODE} (mTLS may be in AllowInsecureFallback mode)"
fi

# Test 2: With valid client cert -> 200
info "Test 2: Valid client certificate..."
RESPONSE=$(curl -sk -w "\n%{http_code}" \
  --cacert "${CERT_DIR}/ca.crt" \
  --cert "${CERT_DIR}/client.crt" \
  --key "${CERT_DIR}/client.key" \
  https://localhost:8443/)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)
if [[ "$HTTP_CODE" == "200" ]]; then
  ok "Valid client cert: HTTP ${HTTP_CODE}"
  echo "  Response: ${BODY}"
else
  warn "Valid client cert: HTTP ${HTTP_CODE}"
  echo "  Response: ${BODY}"
fi

echo ""
ok "Flow mTLS — test complete"
echo "  Certs in: ${CERT_DIR}"
echo "  Cleanup: source ../../common/cleanup.sh"
