#!/usr/bin/env bash
# Return the demo catalog to its pre-demo state. Idempotent; also the first-time seed.
#   0. make sure the in-cluster skills Git host is up
#   1. withdraw every pending approval request
#   2. delete the demo Deployment and every demo artifact (all tags)
#   3. apply access policies (baseline + teams)
#   4. platform items as admin (no approval); team items submitted by eng-dev / sales-dev,
#      approved by approver, so the approval records and audit trail show the real people
#   5. re-submit the ONE pending item (release-readiness-checker 2.0.0) for the live approval
#   6. register the kagent runtime + deployable MCP (if kagent is installed)
# Usage: ./reset.sh            (about 30 seconds)
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; cd "$DIR"
. ./env.sh >/dev/null
q() { grep -v '^warning: Agent .* deprecated spec.modelProvider' || true; }   # hide the expected model-field warning
api() { curl -s -H "Authorization: Bearer $ARCTL_API_TOKEN" -H 'Content-Type: application/json' "$@"; }

AGENTS="release-readiness-checker incident-triage support-ticket-intake anomaly-detector account-insights-assistant customer-faq-responder"
MCPS="ticketing-mcp incident-db-mcp crm-mcp docs-search-mcp data-masking-mcp everything-reference-mcp customer-records-mcp site-inventory-mcp"

echo "== 0. in-cluster skills Git host (Skill source resolution needs a reachable repo)"
kubectl --context "$KCTX" apply -f skills-git/skills-git.yaml >/dev/null && \
  kubectl --context "$KCTX" -n demo-git rollout status deploy/skills-git --timeout=120s

echo "== 1. withdraw pending requests"
as_user admin >/dev/null
api "$ARE_UI_URL/v0/approve" | python3 -c '
import json,sys
for i in (json.load(sys.stdin).get("items") or []):
    print(i["kind"], i["name"], i["tag"], i.get("namespace","default"))' | while read -r k n t ns; do
  ARE_ACTION=withdraw are_approve "$k" "$n" "$t" "$ns" | python3 -c 'import json,sys; [print("  withdrew",r["kind"],r["name"],r["tag"],r["status"]) for r in json.load(sys.stdin).get("results",[])]'
done

kubectl --context "$KCTX" -n agentgateway-system delete enterpriseagentgatewaypolicy a2a-agent-b-may-call-agent-c --ignore-not-found >/dev/null   # A1 beat 4, if left behind
echo "== 2. delete demo deployment and artifacts"
# every managed Deployment (a UI deploy may have used a generated name); kagent removes its pods
arctl get deployments -o json 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
for i in (d if isinstance(d,list) else d.get("items") or []):
    m=i["metadata"]; print((m.get("namespace") or "default")+"/"+m["name"])' | while read -r dep; do
  arctl delete deployment "$dep" >/dev/null 2>&1 && echo "  deleted deployment $dep"
done
for n in $AGENTS; do arctl delete agent "$n" --all-tags >/dev/null 2>&1 && echo "  deleted agent $n"; done
for n in $MCPS; do arctl delete mcp "$n" --all-tags >/dev/null 2>&1 && echo "  deleted mcp $n"; done
arctl delete skill audit-trail-logging --all-tags >/dev/null 2>&1 && echo "  deleted skill audit-trail-logging"
arctl delete prompt pii-handling-guardrails --all-tags >/dev/null 2>&1 && echo "  deleted prompt pii-handling-guardrails"
arctl delete model claude-sonnet-bedrock --all-tags >/dev/null 2>&1 && echo "  deleted model claude-sonnet-bedrock"

echo "== 3. access policies"
arctl apply -f policies/baseline.yaml
arctl apply -f policies/teams.yaml

echo "== 4a. platform shared items (admin)"
arctl apply -f catalog/platform/shared.yaml | q

approve_all() {   # approve every pending item, as approver
  as_user approver >/dev/null
  # Oldest submission first, one second apart: approval time becomes createdAt, and the UI Tags table
  # badges the most recently created tag as "Latest", so 1.0.0, 1.1.0, latest must land in that order.
  api "$ARE_UI_URL/v0/approve" | python3 -c '
import json,sys
items=sorted(json.load(sys.stdin).get("items") or [], key=lambda i: i.get("submittedAt",""))
for i in items: print(i["kind"], i["name"], i["tag"], i.get("namespace","default"))' | while read -r k n t ns; do
    are_approve "$k" "$n" "$t" "$ns" | python3 -c 'import json,sys; [print("  approver",r["status"],r["kind"],r["name"],r["tag"]) for r in json.load(sys.stdin).get("results",[])]'
    sleep 1
  done
}

echo "== 4b. team MCP servers (submitted by developers, approved by approver)"
as_user eng-dev >/dev/null;   arctl apply -f catalog/engineering/01-mcps.yaml | q
as_user sales-dev >/dev/null; arctl apply -f catalog/sales/01-mcps.yaml | q
approve_all

echo "== 4c. team agents (refs to the MCP servers above must exist first)"
as_user eng-dev >/dev/null
arctl apply -f catalog/engineering/02-agents.yaml 2>&1 | q
arctl apply -f catalog/engineering/03-onprem-byo.yaml 2>&1 | q
as_user sales-dev >/dev/null
arctl apply -f catalog/sales/02-agents.yaml 2>&1 | q
approve_all

echo "== 4d. gateway (Virtual runtime) + the two remote MCP servers it will publish (submitted by developers, approved)"
as_user admin >/dev/null
arctl apply -f catalog/gateway/00-virtual-runtime.yaml | q
as_user eng-dev >/dev/null;   arctl apply -f catalog/gateway/10-remote-mcp-servers.yaml | q
approve_all
# the live step (catalog/gateway/20-expose-records.yaml) is NOT applied here; verify.sh and the demo do it

echo "== 5. the one pending item for the live demo"
as_user eng-dev >/dev/null
arctl apply -f catalog/pending/release-readiness-checker-2.0.0.yaml 2>&1 | q

echo "== 6. kagent runtime + deployable MCP"
if kubectl --context "$KCTX" -n kagent get deploy kagent-controller >/dev/null 2>&1; then
  ./deploy/setup-deploy.sh
  # unregistered agents and MCP servers for the Instances page (registry discovers them within ~90 s)
  kubectl --context "$KCTX" apply -f deploy/shadow-it.yaml >/dev/null && echo "  shadow-IT kagent resources applied"
else
  echo "  kagent not installed (deploy/install-kagent.sh); skipping"
fi

echo "== result"
as_user admin >/dev/null
arctl get agents; echo; arctl get mcps; echo
as_user approver >/dev/null
api "$ARE_UI_URL/v0/approve" | python3 -c '
import json,sys
items=json.load(sys.stdin).get("items") or []
print("pending:", len(items), [(i["kind"],i["name"],i["tag"]) for i in items])'
