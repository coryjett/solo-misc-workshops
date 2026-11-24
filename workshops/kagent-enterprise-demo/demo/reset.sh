#!/usr/bin/env bash
# Back to the start of the demo: no ops-assistant, no egress policy, sample app at 2 replicas,
# RBAC policies applied, every chat deleted. platform-agent and company-assistant stay.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; export KUBECONFIG="$DIR/kubeconfig"
[ "$(kubectl config current-context)" = "kind-kagent-ent" ] || { echo "wrong cluster, stopping" >&2; exit 1; }
kubectl -n kagent delete agent ops-assistant --ignore-not-found --wait
kubectl -n kagent delete agenttemplate ops-assistant writer-test --ignore-not-found
kubectl -n kagent delete egresspolicy allow-example-com --ignore-not-found
kubectl apply -f "$DIR/demo/sample-app.yaml" >/dev/null
kubectl -n shop scale deploy/web --replicas=2 >/dev/null
kubectl apply -f "$DIR/demo/rbac.yaml" >/dev/null
kubectl apply -f "$DIR/demo/company-assistant.yaml" >/dev/null   # gateway-backed agent (beat 4b)
# Chats outlive the Agent object; delete them through the API as the bundled admin.
kubectl -n kagent port-forward svc/kagent-controller 18083:8083 >/dev/null 2>&1 & PF=$!
trap 'kill $PF 2>/dev/null' EXIT
until curl -s -o /dev/null localhost:18083; do sleep 1; done
K=("$DIR/bin/kagent" --config "$DIR/config.yaml" --api-url http://localhost:18083 --gateway-url http://localhost:18083)
n=0
# Chats belong to whoever started them; sign in as each bundled role and delete that role's chats.
for who in admin writer reader norole; do
  "${K[@]}" auth login --user-type "$who" >/dev/null 2>&1 || continue
  for s in $("${K[@]}" agent session list -o json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(" ".join(x["id"] for x in d.get("sessions", [])))' || true); do
    "${K[@]}" agent session delete "$s" >/dev/null && n=$((n+1))
  done
done
"${K[@]}" auth login --user-type admin >/dev/null 2>&1 || true
echo "reset: deleted $n chats; shop/web at $(kubectl -n shop get deploy web -o jsonpath='{.spec.replicas}') replicas; $(kubectl -n kagent get enterprisekagentrbacpolicies --no-headers | wc -l | tr -d ' ') RBAC policies"
