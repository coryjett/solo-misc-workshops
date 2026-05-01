#!/usr/bin/env bash
#
# kagent Enterprise Security Workshop — Activate UI AccessPolicy
#
# Patches the EnterpriseAgentgatewayPolicy that kagent auto-generates from
# an AccessPolicy so it actually enforces.
#
# Why this is needed (kagent-enterprise 0.3.19):
#   - kagent generates an HTTPRoute with Service parentRefs only — the AGW
#     controller doesn't recognize that pattern and the auto-generated EAP
#     stays "Attached: False" (no enforcement).
#   - The CEL expression for UserGroup subjects is `jwt.<claim> == "<value>"`,
#     a string comparison against an OIDC array claim that never matches.
#
# This script retargets the EAP at the waypoint Gateway directly and rewrites
# the CEL to `jwt.<claim>.exists(g, g == "<value>")` so the array claim works.
#
# Usage:
#   1. Create an AccessPolicy in the kagent UI (Access Policies → + New)
#      with a UserGroup subject for the "admins" group.
#   2. Run:  ./activate-ui-policy.sh <accesspolicy-name>
#
set -euo pipefail

CTX="${CTX:-k3d-kagent-security}"
NS="${NS:-demo}"
NAME="${1:-}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

[[ -n "${NAME}" ]] || fail "Usage: $0 <accesspolicy-name>"

info "Waiting for kagent to translate AccessPolicy ${NS}/${NAME}..."
EAP="accesspolicy-${NAME}-waypoint"
for i in $(seq 1 30); do
  kubectl --context "${CTX}" get enterpriseagentgatewaypolicy "${EAP}" -n "${NS}" >/dev/null 2>&1 && break
  [[ $i -eq 30 ]] && fail "EnterpriseAgentgatewayPolicy ${EAP} not found — did kagent translate the AccessPolicy?"
  sleep 1
done
ok "Found ${EAP}"

# Look up the agent + waypoint Gateway from the AccessPolicy
AGENT=$(kubectl --context "${CTX}" get accesspolicy "${NAME}" -n "${NS}" -o jsonpath='{.spec.targetRef.name}')
[[ -n "${AGENT}" ]] || fail "Could not read targetRef.name from AccessPolicy"
WAYPOINT="agent-${AGENT}-waypoint"
kubectl --context "${CTX}" get gateway "${WAYPOINT}" -n "${NS}" >/dev/null 2>&1 \
  || fail "Waypoint Gateway ${WAYPOINT} not found — agent must have label kagent.solo.io/waypoint=true"
info "Targeting waypoint Gateway: ${WAYPOINT}"

# Read the broken CEL and convert string-eq to array-exists.
# Source pattern (kagent-generated): jwt.<claim> == "<value>"
# Target pattern (works on OIDC array claim): jwt.<claim>.exists(g, g == "<value>")
OLD_CEL=$(kubectl --context "${CTX}" get enterpriseagentgatewaypolicy "${EAP}" -n "${NS}" \
  -o jsonpath='{.spec.traffic.authorization.policy.matchExpressions[0]}')
NEW_CEL=$(echo "${OLD_CEL}" | sed -E 's|jwt\.([A-Za-z0-9_]+) == "([^"]+)"|jwt.\1.exists(g, g == "\2")|')
info "Rewriting CEL:"
echo "  was: ${OLD_CEL}"
echo "  now: ${NEW_CEL}"

PATCH=$(python3 -c "
import json
print(json.dumps([
  {'op': 'replace', 'path': '/spec/targetRefs/0/kind', 'value': 'Gateway'},
  {'op': 'replace', 'path': '/spec/targetRefs/0/name', 'value': '${WAYPOINT}'},
  {'op': 'replace', 'path': '/spec/traffic/authorization/policy/matchExpressions/0', 'value': '''${NEW_CEL}'''},
]))
")
kubectl --context "${CTX}" patch enterpriseagentgatewaypolicy "${EAP}" -n "${NS}" \
  --type=json -p "${PATCH}" >/dev/null

# Wait for Attached
for i in $(seq 1 15); do
  ATTACHED=$(kubectl --context "${CTX}" get enterpriseagentgatewaypolicy "${EAP}" -n "${NS}" \
    -o jsonpath='{.status.ancestors[?(@.controllerName=="solo.io/enterprise-agentgateway")].conditions[?(@.type=="Attached")].status}' 2>/dev/null | head -c 4)
  [[ "${ATTACHED}" == "True" ]] && { ok "Policy attached and enforcing"; exit 0; }
  sleep 2
done
warn "Policy patched but Attached not yet True — check: kubectl describe enterpriseagentgatewaypolicy ${EAP} -n ${NS}"
