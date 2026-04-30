#!/usr/bin/env bash
#
# kagent Enterprise Security Workshop — Pre-Demo Check
#
# Run this before the demo to verify everything is working.
#
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}  $*"; }
fail() { echo -e "${RED}FAIL${NC}  $*"; ERRORS=$((ERRORS+1)); }

ERRORS=0
MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "")
KC_URL="http://${MAC_IP}:8088"
CTX="k3d-kagent-security"

echo "=== Pre-Demo Check ==="
echo ""

# 1. Cluster
kubectl --context ${CTX} get nodes > /dev/null 2>&1 && pass "k3d cluster running" || fail "k3d cluster not running"

# 2. Keycloak
curl -sf "${KC_URL}/realms/kagent-dev" > /dev/null 2>&1 && pass "Keycloak reachable at ${KC_URL}" || fail "Keycloak not reachable at ${KC_URL}"

# 3. Keycloak users can authenticate with groups
for user in admin writer reader; do
  RESULT=$(curl -sf -X POST "${KC_URL}/realms/kagent-dev/protocol/openid-connect/token" \
    -d "username=${user}" -d "password=password" -d "grant_type=password" \
    -d "client_id=kagent-backend" -d "client_secret=hiIXdxOG5epokX92Es36RPEWuq4lORnw" 2>/dev/null)
  if echo "$RESULT" | python3 -c "
import json,sys,base64
d=json.load(sys.stdin)
t=d['access_token'].split('.')[1]+'=='
c=json.loads(base64.urlsafe_b64decode(t))
assert c.get('Groups'), 'no groups'
" 2>/dev/null; then
    pass "User '${user}' authenticates with Groups claim"
  else
    fail "User '${user}' login failed or missing Groups claim"
  fi
done

# 4. kagent pods (check by grepping pod names, not labels)
for pod_prefix in kagent-controller kagent-postgresql solo-enterprise-ui solo-enterprise-telemetry-collector kmcp-enterprise-controller; do
  if kubectl --context ${CTX} get pods -n kagent --no-headers 2>/dev/null | grep "${pod_prefix}" | grep -q "Running"; then
    pass "Pod ${pod_prefix} running"
  else
    fail "Pod ${pod_prefix} not running"
  fi
done

# 5. UI pod (check container count)
UI_READY=$(kubectl --context ${CTX} get pods -n kagent -l app=solo-enterprise-ui -o jsonpath='{.items[0].status.containerStatuses[*].ready}' 2>/dev/null | tr ' ' '\n' | grep -c true 2>/dev/null || echo 0)
[[ "$UI_READY" == "4" ]] && pass "Solo Enterprise UI 4/4 containers ready" || fail "Solo Enterprise UI only ${UI_READY}/4 containers ready"

# 6. Agents accepted
for agent in cluster-assistant security-auditor k8s-explorer; do
  if kubectl --context ${CTX} get agent ${agent} -n demo -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null | grep -q True; then
    pass "Agent '${agent}' accepted"
  else
    fail "Agent '${agent}' not accepted"
  fi
done

# 7. Agent pods running
for agent in cluster-assistant security-auditor k8s-explorer; do
  if kubectl --context ${CTX} get pods -n demo --no-headers 2>/dev/null | grep "${agent}" | grep -q "Running"; then
    pass "Agent pod '${agent}' running"
  else
    fail "Agent pod '${agent}' not running"
  fi
done

# 8. AGW
if kubectl --context ${CTX} get pods -n agentgateway-system --no-headers 2>/dev/null | grep -q "Running"; then
  pass "Agent Gateway running"
else
  fail "Agent Gateway not running"
fi

# 9. UI accessible via port-forward
curl -sf -o /dev/null http://localhost:4000 2>/dev/null && pass "UI accessible at http://localhost:4000" || fail "UI not accessible — run: kubectl --context ${CTX} port-forward -n kagent svc/solo-enterprise-ui 4000:80"

# 10. No existing access policies (clean slate for demo)
POLICY_COUNT=$(kubectl --context ${CTX} get accesspolicies -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
[[ "$POLICY_COUNT" == "0" ]] && pass "No AccessPolicies (clean slate)" || fail "${POLICY_COUNT} AccessPolicies exist — delete for clean demo"

echo ""
if [[ $ERRORS -eq 0 ]]; then
  echo -e "${GREEN}All checks passed. Ready for demo.${NC}"
else
  echo -e "${RED}${ERRORS} check(s) failed. Fix before demo.${NC}"
fi
