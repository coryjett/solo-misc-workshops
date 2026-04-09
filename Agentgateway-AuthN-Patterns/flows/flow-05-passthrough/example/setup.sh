#!/usr/bin/env bash
# Flow 5: Passthrough Token — working example
# Gateway validates inbound JWT, then forwards the same token to the backend.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYCLOAK_REALM="flow05-realm"
source "${SCRIPT_DIR}/../../common/setup-base.sh"
source "${SCRIPT_DIR}/../../common/deploy-keycloak.sh"

FLOW="flow-05"

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
    import json, base64
    def decode_jwt(token):
        try:
            p = token.split('.')[1]
            p += '=' * (4 - len(p) % 4)
            return json.loads(base64.urlsafe_b64decode(p))
        except: return None
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            auth = self.headers.get('Authorization', '')
            result = {"auth_received": bool(auth)}
            if auth.startswith('Bearer '):
                claims = decode_jwt(auth[7:])
                if claims:
                    result["token_issuer"] = claims.get("iss", "unknown")
                    result["token_sub"] = claims.get("sub", "unknown")
                    result["message"] = "Backend received the original token (passthrough)"
            resp = json.dumps(result).encode()
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

# ── Gateway + HTTPRoute + JWT policy + passthrough backend auth ──────────────
info "Creating Gateway with JWT auth + passthrough backend auth..."
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
      passthrough: {}
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
echo "=== Testing Flow 5: Passthrough Token ==="
echo ""

# Get JWT
USER_JWT=$(get_user_token "${KEYCLOAK_URL}" "${KEYCLOAK_REALM}" "${KEYCLOAK_CLIENT}" "${KEYCLOAK_SECRET}" \
  "testuser" "testuser" "keycloak.keycloak.svc.cluster.local:8080")

# Test 1: No JWT -> 401
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/)
if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
  ok "No JWT: HTTP ${HTTP_CODE} (expected — access denied)"
else
  warn "No JWT: HTTP ${HTTP_CODE} (expected 401/403)"
fi

# Test 2: Valid JWT -> 200 with original token passed through to backend
RESPONSE=$(curl -s -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/)
if echo "$RESPONSE" | jq -e '.token_issuer' >/dev/null 2>&1; then
  ISSUER=$(echo "$RESPONSE" | jq -r '.token_issuer')
  ok "Passthrough works — backend received token with issuer: ${ISSUER}"
  echo "  Full response: ${RESPONSE}" | jq .
else
  warn "Unexpected response: ${RESPONSE}"
fi

echo ""
ok "Flow 5: Passthrough Token — test complete"
echo "  Cleanup: source ../common/cleanup.sh"
