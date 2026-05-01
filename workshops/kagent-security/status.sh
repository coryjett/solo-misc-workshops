#!/usr/bin/env bash
#
# kagent Enterprise Security Workshop — Status
#
# One-screen view of the runtime stack and demo state. Useful right
# before the demo (so the audience can see the moving parts) and as a
# first pass when something's wrong.
#
set -uo pipefail
set +o pipefail

CTX="${CTX:-k3d-kagent-security}"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'

hdr() { echo -e "\n${BLUE}── $* ──${NC}"; }

if ! kubectl --context ${CTX} get nodes >/dev/null 2>&1; then
  echo -e "${RED}Cluster ${CTX} not reachable. Run setup.sh first.${NC}"
  exit 1
fi

hdr "Cluster"
kubectl --context ${CTX} get nodes -o wide --no-headers \
  | awk '{printf "%-35s %-10s %s\n", $1, $2, $5}'

hdr "Stack pods (one line per workload)"
for ns in istio-system agentgateway-system kagent demo; do
  echo -e "${YELLOW}${ns}:${NC}"
  kubectl --context ${CTX} get pods -n ${ns} --no-headers 2>/dev/null \
    | awk '{printf "  %-60s %-8s %s\n", $1, $2, $3}'
done

hdr "Waypoint Gateway"
kubectl --context ${CTX} get gateway -n demo --no-headers 2>/dev/null \
  | awk '{printf "  %-40s class=%-30s programmed=%s\n", $1, $2, $4}'

hdr "AccessPolicy + EnterpriseAgentgatewayPolicy"
AP=$(kubectl --context ${CTX} get accesspolicy -A --no-headers 2>/dev/null)
EAP=$(kubectl --context ${CTX} get enterpriseagentgatewaypolicy -A --no-headers 2>/dev/null)
if [[ -z "${AP}" && -z "${EAP}" ]]; then
  echo "  (none — clean slate, ready for UI demo)"
else
  [[ -n "${AP}" ]]  && echo "${AP}"  | awk '{printf "  AccessPolicy             %s/%s\n", $1, $2}'
  [[ -n "${EAP}" ]] && echo "${EAP}" | awk '{printf "  EAP %-37s accepted=%-5s attached=%s\n", $1"/"$2, $3, $4}'
fi

hdr "kagent OBO signing key"
POD=$(kubectl --context ${CTX} get pods -n kagent --field-selector=status.phase=Running 2>/dev/null | grep "kagent-controller-" | awk '{print $1}' | head -1)
if [[ -n "${POD}" ]]; then
  pkill -f "port-forward.*kagent-controller.*18083" >/dev/null 2>&1
  kubectl --context ${CTX} port-forward -n kagent "pod/${POD}" 18083:8083 >/dev/null 2>&1 &
  PF=$!
  sleep 2
  KID=$(curl -sf http://localhost:18083/jwks.json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['keys'][0]['kid'])" 2>/dev/null)
  kill ${PF} >/dev/null 2>&1
  wait ${PF} 2>/dev/null
  [[ -n "${KID}" ]] && echo "  kid: ${KID}" || echo "  (could not fetch JWKS)"
else
  echo "  (kagent-controller pod not running)"
fi

hdr "Active config"
echo "  AGW image:    $(kubectl --context ${CTX} get deploy enterprise-agentgateway -n agentgateway-system -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)"
echo "  kagent vers:  $(kubectl --context ${CTX} get deploy -n kagent -l app.kubernetes.io/instance=kagent -o jsonpath='{.items[0].spec.template.spec.containers[0].image}' 2>/dev/null)"
echo "  OBO claims:   $(kubectl --context ${CTX} get cm kagent-enterprise-config -n kagent -o jsonpath='{.data.OBO_CLAIMS_TO_PROPAGATE}' 2>/dev/null)"
echo "  demo ns:      $(kubectl --context ${CTX} get ns demo -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}' 2>/dev/null) (ambient mode)"
echo "  kagent ns:    $(kubectl --context ${CTX} get ns kagent -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}' 2>/dev/null) (ambient mode)"

hdr "Last 5 waypoint requests"
WP=$(kubectl --context ${CTX} get pod -n demo -l gateway.networking.k8s.io/gateway-name=agent-security-auditor-waypoint -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "${WP}" ]]; then
  kubectl --context ${CTX} logs -n demo "${WP}" --tail=10 2>&1 \
    | grep -E "request" \
    | tail -5 \
    | python3 -c "
import re, sys
for line in sys.stdin:
    ts = line[:19]
    m = re.search(r'http\.method=([A-Z]+)', line)
    s = re.search(r'http\.status=([0-9]+)', line)
    j = re.search(r'jwt\.sub=([A-Za-z0-9-]+)', line)
    r = re.search(r'reason=([A-Za-z]+)', line)
    print(f'  {ts}  {(m.group(1) if m else \"-\"):<6} {(s.group(1) if s else \"-\"):<3}  {(j.group(1) if j else \"<no jwt>\"):<40} {r.group(1) if r else \"\"}')"
else
  echo "  (waypoint pod not found)"
fi

hdr "UI port-forward"
if curl -sf -o /dev/null http://localhost:4000/ 2>&1; then
  echo -e "  ${GREEN}up${NC}    http://localhost:4000"
else
  echo -e "  ${RED}down${NC}  start with: kubectl --context ${CTX} port-forward -n kagent svc/solo-enterprise-ui 4000:80 &"
fi

echo ""
