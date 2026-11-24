#!/usr/bin/env bash
# One command for T-10: reset the demo, keep the UI reachable at http://localhost:8001, check health.
# Safe to rerun. The UI port-forward runs detached and reconnects on its own until `demo/start.sh stop`.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; export KUBECONFIG="$DIR/kubeconfig"
PIDF="$DIR/demo/.ui-forward.pid"

stop_forward() {
  if [ -f "$PIDF" ]; then kill "$(cat "$PIDF")" 2>/dev/null || true; rm -f "$PIDF"; fi
  pkill -f "port-forward svc/kagent-ui 8001:8080" 2>/dev/null || true
}
[ "${1:-}" = "stop" ] && { stop_forward; echo "UI port-forward stopped"; exit 0; }

[ "$(kubectl config current-context)" = "kind-kagent-ent" ] || { echo "wrong cluster, stopping" >&2; exit 1; }

echo "== pods"
bad="$(kubectl get pods -A --no-headers | grep -vE 'Running|Completed' || true)"
[ -z "$bad" ] && echo "all running" || { echo "$bad"; echo "some pods are not running" >&2; }

echo "== egress trust for the gateway"
"$DIR/gateway/egress-trust.sh"

echo "== reset"
"$DIR/demo/reset.sh" | tail -1

echo "== UI port-forward"
stop_forward
nohup bash -c "while true; do kubectl --kubeconfig '$KUBECONFIG' -n kagent port-forward svc/kagent-ui 8001:8080 >/dev/null 2>&1; sleep 2; done" >/dev/null 2>&1 &
echo $! > "$PIDF"; disown
for i in $(seq 1 30); do curl -s -o /dev/null localhost:8001 && break; sleep 1; done
code="$(curl -s -o /dev/null -w '%{http_code}' localhost:8001/ || true)"
[ "$code" = 200 ] && echo "UI up: http://localhost:8001 (stays up until: demo/start.sh stop)" || { echo "UI not answering (HTTP $code)" >&2; exit 1; }

echo "== ready. In the UI, check the account menu shows admin (Change role, Admin if not)."
