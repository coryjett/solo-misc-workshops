#!/usr/bin/env bash
# Flow 12: Multi-Header Auth — working example
#
# Two independent jwtAuthentication policies on the same HTTPRoute, each
# reading from a different header and validating against its own JWKS:
#
#   Authorization: Bearer <token-A>   ── issuer-A's JWKS  (default header)
#   x-second-token: <token-B>          ── issuer-B's JWKS  (location.header.name)
#
# Demonstrates the `traffic.*.location` field that shipped in AGW Enterprise
# v2026.5.0-beta.1 (PR #1555). Earlier versions read JWT credentials only
# from `Authorization` and would reject `location` at apply time.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Pin to the first version that ships `traffic.*.location`. Override via
# AGW_VERSION=… if you want to try a newer beta. Anything in the v2.x.x
# line will fail because the field didn't exist yet.
export AGW_VERSION="${AGW_VERSION:-v2026.5.0-beta.3}"

source "${SCRIPT_DIR}/../../common/setup-env.sh"   # shared cluster + AGW + Keycloak + STS

FLOW="flow-12"

# ── Generate two independent keypairs + JWKS + JWTs ──────────────────────────
WORKLOAD_DIR="${SCRIPT_DIR}/.workload"
mkdir -p "${WORKLOAD_DIR}"

if [[ ! -f "${WORKLOAD_DIR}/issuer-a.priv.pem" || ! -f "${WORKLOAD_DIR}/issuer-b.priv.pem" ]]; then
  info "Generating two ES256 keypairs (issuer-a, issuer-b)..."
  for ISSUER in issuer-a issuer-b; do
    openssl ecparam -name prime256v1 -genkey -noout -out "${WORKLOAD_DIR}/${ISSUER}.priv.pem"
    openssl ec -in "${WORKLOAD_DIR}/${ISSUER}.priv.pem" -pubout -out "${WORKLOAD_DIR}/${ISSUER}.pub.pem" 2>/dev/null
  done
  ok "Keypairs at ${WORKLOAD_DIR}/{issuer-a,issuer-b}.{priv,pub}.pem"
else
  ok "Reusing existing keypairs"
fi

info "Building JWKS + signing demo JWTs for both issuers..."
python3 - "${WORKLOAD_DIR}" <<'PY'
import base64, hashlib, json, sys, time
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

workload_dir = sys.argv[1]


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make(issuer_name, audience, sub, header_label):
    with open(f"{workload_dir}/{issuer_name}.priv.pem", "rb") as f:
        priv = load_pem_private_key(f.read(), password=None)
    with open(f"{workload_dir}/{issuer_name}.pub.pem", "rb") as f:
        pub = load_pem_public_key(f.read())

    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    kid = hashlib.sha256(x + y).hexdigest()[:16]

    jwks = {"keys": [{
        "kty": "EC", "crv": "P-256",
        "x": b64url(x), "y": b64url(y),
        "kid": kid, "alg": "ES256", "use": "sig",
    }]}
    with open(f"{workload_dir}/{issuer_name}.jwks.json", "w") as f:
        json.dump(jwks, f)

    now = int(time.time())
    header = {"alg": "ES256", "typ": "JWT", "kid": kid}
    payload = {
        "iss": f"https://{issuer_name}.local",
        "sub": sub,
        "aud": audience,
        "iat": now, "nbf": now, "exp": now + 24 * 3600,
        "header_label": header_label,
    }
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    der = priv.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    token = f"{signing_input}.{b64url(sig)}"
    with open(f"{workload_dir}/{issuer_name}.jwt", "w") as f:
        f.write(token)


make("issuer-a", "audience-a", "user-42", "Authorization")
make("issuer-b", "audience-b", "workload-007", "x-second-token")
print("issuer-a + issuer-b: keypairs, JWKS, and 24h JWTs written")
PY
ok "Demo JWTs written to ${WORKLOAD_DIR}/{issuer-a,issuer-b}.jwt"

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
    import json
    class H(BaseHTTPRequestHandler):
        def _do(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            seen = {k.lower(): v for k, v in self.headers.items()}
            resp = json.dumps({
                "message": "Hello from echo backend",
                "authorization_header_visible": "authorization" in seen,
                "x_second_token_visible": "x-second-token" in seen,
            }).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        def do_POST(self): self._do()
        def do_GET(self): self._do()
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

# ── Gateway + HTTPRoute + two JWT policies ───────────────────────────────────
info "Creating Gateway + HTTPRoute..."
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
EOF

info "Applying TWO independent jwtAuthentication policies on the same route..."
JWKS_A=$(jq -c . "${WORKLOAD_DIR}/issuer-a.jwks.json")
JWKS_B=$(jq -c . "${WORKLOAD_DIR}/issuer-b.jwks.json")

# Policy A — default location (Authorization header, Bearer prefix)
cat <<EOF | kubectl apply -f -
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: ${FLOW}-jwt-a
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: ${FLOW}-route
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
      - issuer: https://issuer-a.local
        audiences: [audience-a]
        jwks:
          inline: '${JWKS_A}'
EOF

# Policy B — explicit location.header.name=x-second-token
cat <<EOF | kubectl apply -f -
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: ${FLOW}-jwt-b
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: ${FLOW}-route
  traffic:
    jwtAuthentication:
      mode: Strict
      location:
        header:
          name: x-second-token
      providers:
      - issuer: https://issuer-b.local
        audiences: [audience-b]
        jwks:
          inline: '${JWKS_B}'
EOF

info "Waiting for Gateway to be programmed..."
kubectl wait gateway/${FLOW}-gateway --for=condition=Programmed --timeout=120s
ok "Gateway ready, both policies attached"

# Confirm both policies report ATTACHED=True so a missing field doesn't
# silently leave one mechanism unenforced.
sleep 3
kubectl get enterpriseagentgatewaypolicy -n default -l '' -o custom-columns="NAME:.metadata.name,ACCEPTED:.status.ancestors[0].conditions[?(@.type=='Accepted')].status,ATTACHED:.status.ancestors[0].conditions[?(@.type=='Attached')].status" 2>/dev/null \
  | grep "${FLOW}-jwt" || true

# ── Port-forward and test ────────────────────────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl port-forward svc/${FLOW}-gateway 8888:80 &>/dev/null &
wait_for_pf http://localhost:8888/

TOKEN_A=$(cat "${WORKLOAD_DIR}/issuer-a.jwt")
TOKEN_B=$(cat "${WORKLOAD_DIR}/issuer-b.jwt")

echo ""
echo "=== Testing Flow 12: Multi-Header Auth ==="
echo ""

run() {
  local label="$1"; shift
  local expected="$1"; shift
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$@" http://localhost:8888/)
  if [[ "$code" == "$expected" ]]; then
    ok "${label}: HTTP ${code} (expected ${expected})"
  else
    warn "${label}: HTTP ${code} (expected ${expected})"
  fi
}

run "Both valid tokens"                 200 -H "Authorization: Bearer ${TOKEN_A}" -H "x-second-token: ${TOKEN_B}"
run "Missing token-B (only Auth)"       401 -H "Authorization: Bearer ${TOKEN_A}"
run "Missing token-A (only x-second)"   401 -H "x-second-token: ${TOKEN_B}"
run "No tokens"                         401
run "Token-A in wrong header (in B's)"  401 -H "x-second-token: ${TOKEN_A}"
run "Token-B in wrong header (in A's)"  401 -H "Authorization: Bearer ${TOKEN_B}" -H "x-second-token: ${TOKEN_A}"

echo ""
echo "  Inspect the response body on a successful request to see whether"
echo "  each header reached the backend (jwtAuthentication strips the"
echo "  validated header before forwarding):"
echo ""
echo "    curl -s -H \"Authorization: Bearer \$(cat ${WORKLOAD_DIR}/issuer-a.jwt)\" \\"
echo "         -H \"x-second-token: \$(cat ${WORKLOAD_DIR}/issuer-b.jwt)\" \\"
echo "         http://localhost:8888/ | jq"
echo ""
ok "Flow 12: Multi-Header Auth — test complete"
echo "  Cleanup: source ../../common/cleanup.sh && rm -rf ${WORKLOAD_DIR}"
