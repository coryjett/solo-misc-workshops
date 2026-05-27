#!/usr/bin/env bash
# Snowflake Workshop — dual-token gateway auth (introspection + workload JWT)
# Deploys: k3d + AGW Enterprise + Keycloak + kagent OSS + mock Snowflake MCP
#
# Two independent auth mechanisms run on the same MCP HTTPRoute:
#
#   Authorization: Bearer <Keycloak token>   ── entExtAuth -> AuthConfig
#                                              -> Keycloak /introspect
#                                              -> sets x-user-id upstream
#   aembitauth:    <workload JWT>             ── jwtAuthentication.location
#                                                 .header.name=aembitauth
#                                              -> JWKS signature check
#                                              -> strips the header upstream
#
# AGW's CP wires up the extauth filter from the AuthConfig (no sidecar in
# this repo). The dual-policy path requires AGW v2026.5.0-beta.1+ for the
# `jwtAuthentication.location` field — see PR #1555.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

kill_pf() { pkill -f "port-forward.*$1" 2>/dev/null || true; sleep 1; }

CLUSTER_NAME="snowflake-workshop"
# v2026.5.0-beta.1 was the first tag to ship `jwtAuthentication.location`
# (PR #1555). The dual-token demo below requires the field to be present
# in both the CRDs chart and the controller image.
AGW_VERSION="${AGW_VERSION:-v2026.5.0-beta.3}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.0}"
KEYCLOAK_REALM="snowflake-workshop"
KEYCLOAK_ISSUER="http://localhost:9090/realms/${KEYCLOAK_REALM}"
KEYCLOAK_URL="http://localhost:9090"
KEYCLOAK_URL_INTERNAL="http://keycloak.keycloak.svc.cluster.local:8080"

# ── Prerequisites ────────────────────────────────────────────────────────────
info "Checking prerequisites..."
command -v docker  >/dev/null 2>&1 || fail "docker not found"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found"
command -v helm    >/dev/null 2>&1 || fail "helm not found"
command -v curl    >/dev/null 2>&1 || fail "curl not found"
command -v jq      >/dev/null 2>&1 || fail "jq not found"
command -v openssl >/dev/null 2>&1 || fail "openssl not found"
command -v python3 >/dev/null 2>&1 || fail "python3 not found"
[[ -n "${AGENTGATEWAY_LICENSE_KEY:-}" ]] || fail "AGENTGATEWAY_LICENSE_KEY not set"
[[ -n "${OPENAI_API_KEY:-}" ]] || fail "OPENAI_API_KEY not set"
ok "Prerequisites met"

# ── 1. k3d cluster ───────────────────────────────────────────────────────────
info "Creating k3d cluster: ${CLUSTER_NAME}..."
if k3d cluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  warn "Cluster ${CLUSTER_NAME} already exists, reusing"
else
  k3d cluster create "${CLUSTER_NAME}" \
    --servers 1 --agents 1 \
    --k3s-arg "--disable=traefik@server:0" \
    --wait
fi
kubectl config use-context "k3d-${CLUSTER_NAME}"
ok "Cluster ready"

# ── 2. Gateway API CRDs ─────────────────────────────────────────────────────
info "Installing Gateway API CRDs ${GATEWAY_API_VERSION}..."
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
ok "Gateway API CRDs installed"

# ── 3. AGW Enterprise ───────────────────────────────────────────────────────
info "Installing Enterprise Agentgateway CRDs ${AGW_VERSION}..."
helm upgrade -i --create-namespace \
  --namespace agentgateway-system \
  --version "${AGW_VERSION}" \
  enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds

info "Installing Enterprise Agentgateway ${AGW_VERSION}..."
helm upgrade -i -n agentgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version "${AGW_VERSION}" \
  --set-string licensing.licenseKey="${AGENTGATEWAY_LICENSE_KEY}" \
  --set agentgateway.enabled=true

info "Waiting for AGW pods..."
kubectl -n agentgateway-system rollout status deployment/enterprise-agentgateway --timeout=180s
ok "Enterprise Agentgateway deployed"

# ── 4. Keycloak ──────────────────────────────────────────────────────────────
info "Deploying Keycloak..."
kubectl apply -f "${SCRIPT_DIR}/k8s/keycloak.yaml"
info "Waiting for Keycloak (this takes ~2 min)..."
kubectl wait -n keycloak statefulset/keycloak --for=jsonpath='{.status.readyReplicas}'=1 --timeout=420s
ok "Keycloak deployed"

kill_pf "keycloak.*9090"
kubectl port-forward -n keycloak svc/keycloak 9090:8080 &>/dev/null &
sleep 3

# ── 5. Configure Keycloak realm ─────────────────────────────────────────────
info "Configuring Keycloak realm: ${KEYCLOAK_REALM}..."

# Get admin token
ADMIN_TOKEN=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" \
  | jq -r '.access_token')

# Create realm
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"realm":"snowflake-workshop","enabled":true}' || true

# Create kagent-ui client (confidential for oauth2-proxy — PKCE)
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "kagent-ui",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "secret": "kagent-ui-secret",
    "publicClient": false,
    "directAccessGrantsEnabled": true,
    "standardFlowEnabled": true,
    "redirectUris": ["http://localhost:8080/*"],
    "webOrigins": ["http://localhost:8080"]
  }' || true

# Create test user
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "testuser@example.com",
    "emailVerified": true,
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "credentials": [{"type":"password","value":"testuser","temporary":false}]
  }' || true

ok "Keycloak configured (realm=${KEYCLOAK_REALM}, client=kagent-ui, user=testuser/testuser)"

# ── 6. Apply AuthConfig for AGW Enterprise extauth introspection ───────────
info "Applying introspection AuthConfig + client secret..."
kubectl apply -f "${SCRIPT_DIR}/k8s/introspection-authconfig.yaml"
ok "AuthConfig applied (AGW CP will wire up extauth)"

# ── 7. Deploy mock Snowflake MCP server ──────────────────────────────────────
info "Deploying mock Snowflake MCP server..."
kubectl create configmap snowflake-mcp-script \
  --from-file=server.py="${SCRIPT_DIR}/snowflake-mcp/server.py" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "${SCRIPT_DIR}/k8s/snowflake-mcp.yaml"
kubectl wait deployment/snowflake-mcp --for=condition=Available --timeout=120s
ok "Snowflake MCP server deployed"

# ── 8. Install kagent OSS ───────────────────────────────────────────────────
info "Installing kagent CRDs..."
helm upgrade -i --create-namespace \
  --namespace kagent \
  kagent-crds \
  oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds

info "Installing kagent..."
AGW_PROXY_URL="http://workshop-gateway.default.svc.cluster.local:80"

kubectl create secret generic openai-api-key \
  --namespace kagent \
  --from-literal=api-key="${OPENAI_API_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

helm upgrade -i -n kagent kagent \
  oci://ghcr.io/kagent-dev/kagent/helm/kagent \
  --set proxy.url="${AGW_PROXY_URL}" \
  --set a2a.enabled=false

info "Waiting for kagent controller..."
kubectl -n kagent wait --for=condition=Available deployment -l app.kubernetes.io/name=kagent --timeout=180s
ok "kagent deployed"

# ── 8b. Generate workload-identity keypair, JWKS, and demo JWT ──────────────
# Powers the dual-policy demo: the new mcp-workload-jwt-policy validates a
# JWT from the `aembitauth` header against this JWKS.
WORKLOAD_DIR="${SCRIPT_DIR}/.workload"
mkdir -p "${WORKLOAD_DIR}"

if [[ ! -f "${WORKLOAD_DIR}/priv.pem" ]]; then
  info "Generating workload-identity ES256 keypair..."
  openssl ecparam -name prime256v1 -genkey -noout -out "${WORKLOAD_DIR}/priv.pem"
  openssl ec -in "${WORKLOAD_DIR}/priv.pem" -pubout -out "${WORKLOAD_DIR}/pub.pem" 2>/dev/null
  ok "Keypair written to ${WORKLOAD_DIR}/{priv,pub}.pem"
else
  ok "Reusing existing keypair at ${WORKLOAD_DIR}/"
fi

info "Building JWKS + signing demo workload JWT..."
python3 - "${WORKLOAD_DIR}" <<'PY'
import base64, hashlib, json, sys, time
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

workload_dir = sys.argv[1]

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

with open(f"{workload_dir}/priv.pem", "rb") as f:
    priv = load_pem_private_key(f.read(), password=None)
with open(f"{workload_dir}/pub.pem", "rb") as f:
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
with open(f"{workload_dir}/jwks.json", "w") as f:
    json.dump(jwks, f)

header = {"alg": "ES256", "typ": "JWT", "kid": kid}
now = int(time.time())
payload = {
    "iss": "https://workshop-issuer.local/aembit",
    "sub": "snowflake-workload-001",
    "aud": "snowflake-mcp",
    "iat": now, "nbf": now, "exp": now + 24 * 3600,
    "credentialProviderId": "cp-workshop-001",
    "client_id": "snowflake-workload",
}
signing_input = (
    b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
    + b64url(json.dumps(payload, separators=(",", ":")).encode())
)
der = priv.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
r, s = decode_dss_signature(der)
sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
token = f"{signing_input}.{b64url(sig)}"
with open(f"{workload_dir}/workload.jwt", "w") as f:
    f.write(token)

print(f"kid={kid}")
PY
ok "Demo JWT written to ${WORKLOAD_DIR}/workload.jwt (24h validity)"

# ── 9. Apply AGW resources ──────────────────────────────────────────────────
info "Applying AGW gateway + extAuth introspection policy..."

# Apply kagent CRDs so the agent pod gets created
kubectl apply -f "${SCRIPT_DIR}/k8s/kagent.yaml"
sleep 10

# Wait for the agent deployment to appear
info "Waiting for kagent agent pod..."
kubectl -n kagent wait --for=condition=Available deployment/snowflake-analyst --timeout=120s 2>/dev/null || \
  kubectl -n kagent wait --for=condition=Available deployment -l kagent.dev/agent=snowflake-analyst --timeout=120s 2>/dev/null || \
  warn "Agent deployment not ready yet — will retry"

# Find the agent service
AGENT_SVC=$(kubectl get svc -n kagent -l kagent.dev/agent=snowflake-analyst -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "snowflake-analyst")
AGENT_PORT=$(kubectl get svc -n kagent "${AGENT_SVC}" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || echo "8080")

# Apply AGW resources with substituted values
export KEYCLOAK_URL_INTERNAL KEYCLOAK_ISSUER
export AGENT_SERVICE_NAME="${AGENT_SVC}"
export AGENT_SERVICE_NAMESPACE="kagent"
export AGENT_SERVICE_PORT="${AGENT_PORT}"
envsubst < "${SCRIPT_DIR}/k8s/agw.yaml" | kubectl apply -f -

# Inline the JWKS into the workload-JWT policy and apply it. The JWKS
# is a single JSON line so it embeds cleanly inside YAML single-quotes.
JWKS_INLINE=$(jq -c . "${WORKLOAD_DIR}/jwks.json") \
  envsubst '${JWKS_INLINE}' < "${SCRIPT_DIR}/k8s/aembit-jwt-policy.template.yaml" | kubectl apply -f -

kubectl wait gateway/workshop-gateway --for=condition=Programmed --timeout=120s
ok "AGW gateway + extAuth introspection + workload-JWT policies ready"

# ── 10. Deploy oauth2-proxy ─────────────────────────────────────────────────
info "Deploying oauth2-proxy..."

COOKIE_SECRET=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")

sed "s|REPLACE_WITH_RANDOM_32_BYTES|${COOKIE_SECRET}|g" \
  "${SCRIPT_DIR}/k8s/oauth2-proxy.yaml" | kubectl apply -f -

kubectl -n kagent wait --for=condition=Available deployment/oauth2-proxy --timeout=120s
ok "oauth2-proxy deployed"

# ── 11. Patch kagent-ui to forward Authorization header ───────────────────────
info "Patching kagent-ui to forward Authorization header to controller..."

# kagent 0.8.6 doesn't forward the Authorization header from oauth2-proxy to the
# kagent-controller when proxying A2A requests. This was fixed on main (583d7a4)
# but hasn't been released yet. Patch the compiled Next.js route to forward it.
UI_POD=$(kubectl get pod -n kagent -l app.kubernetes.io/name=kagent-ui -o jsonpath='{.items[0].metadata.name}')
ROUTE_CHUNK_PATH="/app/ui/.next/server/chunks/[root-of-the-server]__0u-gm~m._.js"
kubectl exec -n kagent "${UI_POD}" -- sh -c "cat '${ROUTE_CHUNK_PATH}'" > /tmp/ui-route-chunk.js 2>/dev/null

if grep -q '"User-Agent":"kagent-ui"' /tmp/ui-route-chunk.js && ! grep -q 'e.headers.get("authorization")' /tmp/ui-route-chunk.js; then
  sed 's/"User-Agent":"kagent-ui"}/"User-Agent":"kagent-ui",...(e.headers.get("authorization")?{Authorization:e.headers.get("authorization")}:{})}/g' \
    /tmp/ui-route-chunk.js > /tmp/ui-route-chunk-patched.js

  kubectl create configmap kagent-ui-a2a-patch \
    -n kagent \
    --from-file=route-chunk.js=/tmp/ui-route-chunk-patched.js \
    --dry-run=client -o yaml | kubectl apply -f -

  kubectl -n kagent patch deployment kagent-ui --type=json -p '[
    {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"a2a-patch","configMap":{"name":"kagent-ui-a2a-patch"}}},
    {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"a2a-patch","mountPath":"'"${ROUTE_CHUNK_PATH}"'","subPath":"route-chunk.js"}}
  ]'
  kubectl -n kagent rollout status deployment/kagent-ui --timeout=60s
  ok "kagent-ui patched to forward Authorization header"
else
  ok "kagent-ui already forwards Authorization header (newer version)"
fi

rm -f /tmp/ui-route-chunk.js /tmp/ui-route-chunk-patched.js

# ── 12. Port-forward and print instructions ──────────────────────────────────
kill_pf "oauth2-proxy.*8080"
kill_pf "keycloak.*9090"
kubectl port-forward -n kagent svc/oauth2-proxy 8080:8080 &>/dev/null &
kubectl port-forward -n keycloak svc/keycloak 9090:8080 &>/dev/null &
sleep 2

echo ""
echo "=========================================="
echo "  Snowflake Token Exchange Workshop"
echo "=========================================="
echo ""
echo "  kagent UI:      http://localhost:8080"
echo "  Keycloak admin: http://localhost:9090 (admin/admin)"
echo "  Login as:       testuser / testuser"
echo ""
echo "  Architecture:"
echo "    User -> oauth2-proxy -> AGW (JWT auth) -> kagent agent"
echo "    kagent agent -> AGW -(entExtAuth -> AuthConfig)-> Keycloak /introspect"
echo "                              -> Snowflake MCP (prints x-user-id header)"
echo ""
echo "  1. Open http://localhost:8080 in your browser"
echo "  2. Log in with testuser / testuser"
echo "  3. Select the 'Snowflake Analyst' agent"
echo "  4. Ask: 'Show me the sales data'"
echo ""
echo "  The response will show:"
echo "    - Mock Snowflake query results"
echo "    - identity_from_gateway: { x-user-id, plus any other propagated headers }"
echo ""
echo "  Watch the MCP server's headers while you chat:"
echo "    kubectl logs -f deployment/snowflake-mcp"
echo ""
echo "  ── Dual-token (Aembit-style) curl demo ──"
echo "  Two independent auth mechanisms on the same MCP route:"
echo "    Authorization: Bearer <Keycloak token>   ─ ext-auth /introspect"
echo "    aembitauth:    <workload JWT>             ─ local JWKS validation"
echo ""
echo "  Hit the gateway directly with both headers (the workload JWT is at"
echo "  ${SCRIPT_DIR}/.workload/workload.jwt):"
echo ""
echo "    USER_TOKEN=\$(curl -sf -X POST '${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token' \\"
echo "      -d 'username=testuser' -d 'password=testuser' \\"
echo "      -d 'grant_type=password' -d 'client_id=kagent-ui' \\"
echo "      -d 'client_secret=kagent-ui-secret' | jq -r .access_token)"
echo "    WORKLOAD_TOKEN=\$(cat ${SCRIPT_DIR}/.workload/workload.jwt)"
echo ""
echo "    kubectl port-forward -n default svc/workshop-gateway 18080:80 &"
echo "    curl -sS http://127.0.0.1:18080/ \\"
echo "      -H \"Authorization: Bearer \$USER_TOKEN\" \\"
echo "      -H \"aembitauth: \$WORKLOAD_TOKEN\" \\"
echo "      -H 'x-kagent-host: snowflake-mcp.default.svc.cluster.local'"
echo ""
echo "  In the MCP server logs you should see x-user-id (set from"
echo "  introspection) but NOT aembitauth — it was stripped by the JWT"
echo "  policy after validation."
echo ""
echo "  Cleanup: ./cleanup.sh"
echo "=========================================="
