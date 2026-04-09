#!/usr/bin/env bash
# Flow 1: Standard OIDC Authentication — working example
# Client obtains JWT from Keycloak, presents as bearer token. Gateway validates via JWKS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYCLOAK_REALM="flow01-realm"
source "${SCRIPT_DIR}/../../common/setup-base.sh"
source "${SCRIPT_DIR}/../../common/deploy-keycloak.sh"

FLOW="flow-01"

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
            auth = self.headers.get('Authorization', 'none')
            resp = json.dumps({"message": "Authenticated!", "auth_header_present": auth != "none"}).encode()
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

# ── ReferenceGrant for cross-namespace JWKS ──────────────────────────────────
kubectl apply -f - <<'EOF'
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
  to:
  - group: ""
    kind: Service
    name: keycloak
EOF

# ── Gateway + HTTPRoute + JWT Auth policy ────────────────────────────────────
info "Creating Gateway and JWT Auth policy..."
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
  name: ${FLOW}-jwt-policy
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: ${FLOW}-gateway
  traffic:
    jwtAuthentication:
      providers:
      - issuer: "${KEYCLOAK_ISSUER}"
        audiences:
        - account
        - ${KEYCLOAK_CLIENT}
        jwks:
          remote:
            backendRef:
              name: keycloak
              kind: Service
              namespace: keycloak
              port: 8080
            jwksPath: "realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
EOF

kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready"

# ── Port-forward and test ────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8888:80 &>/dev/null &
sleep 2

echo ""
echo "=== Testing Flow 1: Standard OIDC Authentication ==="
echo ""

# Get a Keycloak JWT (password grant, using Host header for in-cluster issuer)
info "Getting JWT from Keycloak..."
USER_JWT=$(get_user_token "${KEYCLOAK_URL}" "${KEYCLOAK_REALM}" "${KEYCLOAK_CLIENT}" "${KEYCLOAK_SECRET}" \
  "testuser" "testuser" "keycloak.keycloak.svc.cluster.local:8080")

echo "JWT claims:"
decode_jwt "$USER_JWT" | jq '{iss, sub, preferred_username, aud}'

# Test 1: No JWT -> 401/403
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/)
if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
  ok "No JWT: HTTP ${HTTP_CODE} (expected — access denied)"
else
  warn "No JWT: HTTP ${HTTP_CODE} (expected 401/403)"
fi

# Test 2: Invalid JWT -> 401/403
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid.jwt.token" http://localhost:8888/)
if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
  ok "Invalid JWT: HTTP ${HTTP_CODE} (expected — access denied)"
else
  warn "Invalid JWT: HTTP ${HTTP_CODE} (expected 401/403)"
fi

# Test 3: Valid Keycloak JWT -> 200
RESPONSE=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)
if [[ "$HTTP_CODE" == "200" ]]; then
  ok "Valid JWT: HTTP ${HTTP_CODE}"
  echo "  Response: ${BODY}"
else
  warn "Valid JWT: HTTP ${HTTP_CODE} (expected 200)"
  echo "  Response: ${BODY}"
fi

echo ""
ok "Flow 1: Standard OIDC Authentication — test complete"
echo "  Cleanup: source ../common/cleanup.sh"
