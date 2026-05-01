#!/usr/bin/env bash
#
# kagent Enterprise Security Workshop — Reset
#
# Resets demo state WITHOUT tearing down infrastructure:
#   - Deletes AccessPolicy + EnterpriseAgentgatewayPolicy (clean slate)
#   - Clears kagent chat sessions/messages from Postgres
#   - Restarts the UI port-forward
#
# Keeps: k3d cluster, Keycloak, Istio ambient, AGW, kagent, agents, waypoint.
# Use this between demo runs. Use cleanup.sh for full teardown.
#
set -uo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }

CTX="k3d-kagent-security"

if ! kubectl --context ${CTX} get nodes >/dev/null 2>&1; then
  warn "Cluster ${CTX} not found — nothing to reset. Run setup.sh first."
  exit 0
fi

info "Deleting AccessPolicy + EnterpriseAgentgatewayPolicy..."
kubectl --context ${CTX} delete accesspolicy --all -n demo --ignore-not-found 2>/dev/null
kubectl --context ${CTX} delete enterpriseagentgatewaypolicy --all -n demo --ignore-not-found 2>/dev/null
ok "Policies removed"

info "Clearing kagent chat sessions..."
PG=$(kubectl --context ${CTX} get pods -n kagent -l app.kubernetes.io/component=database -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "${PG}" ]]; then
  kubectl --context ${CTX} exec -n kagent "${PG}" -- psql -U kagent -d kagent -c \
    "TRUNCATE TABLE event, session, feedback, lg_checkpoint, lg_checkpoint_write CASCADE;" >/dev/null 2>&1 \
    && ok "Sessions cleared" \
    || warn "Could not truncate session tables"
else
  warn "Postgres pod not found, skipping session clear"
fi

info "Restarting UI port-forward..."
pkill -f "port-forward.*solo-enterprise-ui.*4000" 2>/dev/null || true
sleep 1
kubectl --context ${CTX} port-forward -n kagent svc/solo-enterprise-ui 4000:80 >/dev/null 2>&1 &
sleep 3
if curl -sf -o /dev/null http://localhost:4000/; then
  ok "UI reachable at http://localhost:4000"
else
  warn "UI port-forward did not come up — re-run manually"
fi

echo ""
echo -e "${GREEN}Demo reset complete.${NC} Open http://localhost:4000 in a NEW incognito window."
echo "  (browser sessions persist OIDC tokens — incognito ensures fresh login)"
echo ""
echo "Run check.sh to verify clean state."
