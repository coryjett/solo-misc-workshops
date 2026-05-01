#!/usr/bin/env bash
#
# kagent Enterprise Security Workshop — Reconfigure for IP Change
#
# Run this if you switch networks and your LAN IP changes.
# Updates Keycloak hostname and kagent OIDC issuer.
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
[[ -n "${MAC_IP}" ]] || fail "Could not detect LAN IP"

KEYCLOAK_PORT=8088
NEW_ISSUER="http://${MAC_IP}:${KEYCLOAK_PORT}/realms/kagent-dev"
CTX="k3d-kagent-security"

info "New LAN IP: ${MAC_IP}"
info "New OIDC issuer: ${NEW_ISSUER}"

# Check if cluster exists
kubectl --context ${CTX} get nodes > /dev/null 2>&1 || fail "Cluster not found. Run setup.sh first."

# Restart Keycloak with new hostname
info "Restarting Keycloak with new hostname..."
docker stop keycloak 2>/dev/null || true
docker rm keycloak 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
docker run -d --name keycloak -p ${KEYCLOAK_PORT}:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v "${SCRIPT_DIR}/realm-data":/opt/keycloak/data/import:ro \
  quay.io/keycloak/keycloak:21.1.1 start-dev --import-realm --hostname-strict=false

info "Waiting for Keycloak..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${KEYCLOAK_PORT}/realms/kagent-dev" > /dev/null 2>&1; then
    ok "Keycloak ready"
    break
  fi
  [[ $i -eq 30 ]] && fail "Keycloak failed to start"
  sleep 3
done

docker exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master --user admin --password admin 2>/dev/null
docker exec keycloak /opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE 2>/dev/null

# Get current helm values and determine license key
LIC=$(helm --kube-context ${CTX} get values kagent-mgmt -n kagent -o json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('licensing',{}).get('licenseKey',''))" 2>/dev/null)
[[ -n "${LIC}" ]] || fail "Could not read license key from helm values"

OAI=$(helm --kube-context ${CTX} get values kagent -n kagent -o json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('providers',{}).get('openAI',{}).get('apiKey',''))" 2>/dev/null)
[[ -n "${OAI}" ]] || fail "Could not read OpenAI key from helm values"

info "Upgrading kagent management plane with new issuer..."
cat > /tmp/mgmt-reconfig.yaml <<EOF
cluster: kagent-security
products:
  kagent: {enabled: true}
  agentgateway: {enabled: true, namespace: agentgateway-system}
licensing: {licenseKey: ${LIC}}
oidc:
  issuer: ${NEW_ISSUER}
ui:
  backend:
    oidc: {clientId: kagent-backend, secretRef: kagent-backend-secret}
  frontend:
    oidc: {clientId: kagent-ui}
EOF

cat >> /tmp/mgmt-reconfig.yaml <<EOF
istioAuthzTranslation:
  enabled: true
EOF

helm --kube-context ${CTX} upgrade kagent-mgmt \
  oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/management \
  -n kagent --version 0.3.19 --values /tmp/mgmt-reconfig.yaml --wait --timeout 300s 2>&1 | tail -1

info "Upgrading kagent workload with new issuer..."
cat > /tmp/kagent-reconfig.yaml <<EOF
licensing: {licenseKey: ${LIC}}
providers: {default: openAI, openAI: {apiKey: ${OAI}}}
oidc:
  issuer: ${NEW_ISSUER}
  secret: kagent-backend-secret
  oboClaimsToPropagate:
    - Groups
kagent-tools:
  enabled: true
otel:
  tracing:
    enabled: true
    exporter:
      otlp:
        endpoint: solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
        insecure: true
EOF

helm --kube-context ${CTX} upgrade kagent \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise \
  -n kagent --version 0.3.19 --values /tmp/kagent-reconfig.yaml --wait --timeout 300s 2>&1 | tail -1

rm -f /tmp/mgmt-reconfig.yaml /tmp/kagent-reconfig.yaml

# Refresh JWKS in pre-baked policy (kagent OBO signing keys may have rotated)
info "Refreshing kagent OBO JWKS in access-policy.yaml..."
KAGENT_SVC="kagent"
kubectl --context ${CTX} get svc kagent -n kagent >/dev/null 2>&1 || KAGENT_SVC="kagent-controller"
KAGENT_PORT=$(kubectl --context ${CTX} get svc -n kagent "${KAGENT_SVC}" -o jsonpath='{.spec.ports[?(@.name=="http")].port}' 2>/dev/null)
[[ -z "${KAGENT_PORT}" ]] && KAGENT_PORT=8083

pkill -f "port-forward.*${KAGENT_SVC}.*18083" 2>/dev/null || true
kubectl --context ${CTX} port-forward -n kagent "svc/${KAGENT_SVC}" 18083:${KAGENT_PORT} >/dev/null 2>&1 &
PF_PID=$!
sleep 4
JWKS=$(curl -sf http://localhost:18083/jwks.json 2>/dev/null || true)
kill ${PF_PID} 2>/dev/null || true

if [[ -n "${JWKS}" ]]; then
  JWKS_INLINE=$(echo "${JWKS}" | jq -c .)
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  cat > "${SCRIPT_DIR}/access-policy.yaml" <<EOF
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: admin-only-security-auditor
  namespace: demo
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: agent-security-auditor-waypoint
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
        - issuer: kagent.kagent
          jwks:
            inline: '${JWKS_INLINE}'
    authorization:
      action: Allow
      policy:
        matchExpressions:
          - 'jwt.Groups.exists(g, g == "admins")'
EOF
  ok "access-policy.yaml refreshed"

  # If the policy was already applied, re-apply it with the fresh JWKS
  if kubectl --context ${CTX} get enterpriseagentgatewaypolicy admin-only-security-auditor -n demo >/dev/null 2>&1; then
    kubectl --context ${CTX} apply -f "${SCRIPT_DIR}/access-policy.yaml"
    ok "Policy re-applied with refreshed JWKS"
  fi
else
  warn "Could not refresh JWKS — apply access-policy.yaml manually if policy enforcement breaks"
fi

# Restart port-forward
pkill -f "port-forward.*solo-enterprise-ui.*4000" 2>/dev/null || true
sleep 1
kubectl --kube-context ${CTX} port-forward -n kagent svc/solo-enterprise-ui 4000:80 &>/dev/null &
sleep 3

ok "Reconfigured for ${MAC_IP}"
echo ""
echo "kagent UI: http://localhost:4000 (open in incognito)"
echo "Keycloak:  http://${MAC_IP}:${KEYCLOAK_PORT}"
