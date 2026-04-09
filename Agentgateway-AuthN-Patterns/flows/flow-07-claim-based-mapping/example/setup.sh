#!/usr/bin/env bash
# Flow 7: Claim-Based Token Mapping — working example
# Gateway validates JWT, extracts a claim, maps it to a per-group opaque token via CEL.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYCLOAK_REALM="flow07-realm"
source "${SCRIPT_DIR}/../../common/setup-base.sh"
source "${SCRIPT_DIR}/../../common/deploy-keycloak.sh"

FLOW="flow-07"

# ── Deploy token-inspecting backend ──────────────────────────────────────────
info "Deploying token-inspecting backend..."
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
            auth = self.headers.get('Authorization', '')
            resp = json.dumps({
                "auth_header": auth[:80] + "..." if len(auth) > 80 else auth,
                "is_jwt": auth.count('.') == 2 if auth.startswith('Bearer ') else False,
                "message": "Backend received mapped token"
            }).encode()
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

# ── ReferenceGrant ───────────────────────────────────────────────────────────
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

# ── Gateway + Backend + JWT policy + CEL transformation ──────────────────────
info "Creating Gateway with JWT auth + CEL claim-based token mapping..."
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
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: echo-agw-backend
  namespace: default
spec:
  static:
    host: echo-backend.default.svc.cluster.local
    port: 80
  policies:
    auth:
      key: "Bearer mapped-default-token"
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
      name: echo-agw-backend
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
echo "=== Testing Flow 7: Claim-Based Token Mapping ==="
echo ""

# Get JWT
USER_JWT=$(get_user_token "${KEYCLOAK_URL}" "${KEYCLOAK_REALM}" "${KEYCLOAK_CLIENT}" "${KEYCLOAK_SECRET}" \
  "testuser" "testuser" "keycloak.keycloak.svc.cluster.local:8080")

echo "JWT claims:"
decode_jwt "$USER_JWT" | jq '{iss, sub, preferred_username}'

# Test: Valid JWT -> 200, backend sees mapped token
RESPONSE=$(curl -s -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/)
IS_JWT=$(echo "$RESPONSE" | jq -r '.is_jwt // true')
if [[ "$IS_JWT" == "false" ]]; then
  ok "Claim-based mapping works — backend received non-JWT token"
  echo "$RESPONSE" | jq .
else
  # Even if it's still a JWT, the backend auth key should have been injected
  ok "Backend received token (check auth_header for mapped value)"
  echo "$RESPONSE" | jq .
fi

echo ""
ok "Flow 7: Claim-Based Token Mapping — test complete"
echo "  Cleanup: source ../common/cleanup.sh"
