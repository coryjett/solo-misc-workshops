#!/usr/bin/env bash
# Tears the demo down: stops the UI port-forward, deletes the kind cluster kagent-ent and
# removes local state (kubeconfig, rehearsal installs and screenshots, CLI login).
# Keeps the kit itself (scripts, YAML, runbook, bin/kagent) so ./install.sh rebuilds it.
# Usage: ./teardown.sh        asks before deleting
#        ./teardown.sh -y     no prompt
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "This deletes the kind cluster kagent-ent and everything in it (agents, chats, traces)."
if [ "${1:-}" != "-y" ]; then
  read -r -p "Continue? [y/N] " ans
  [ "$ans" = y ] || [ "$ans" = Y ] || { echo "cancelled"; exit 0; }
fi

[ -x "$DIR/demo/start.sh" ] && "$DIR/demo/start.sh" stop || true

if kind get clusters 2>/dev/null | grep -qx kagent-ent; then
  kind delete cluster --name kagent-ent --kubeconfig "$DIR/kubeconfig"
else
  echo "cluster kagent-ent not found"
fi

rm -f "$DIR/kubeconfig" "$DIR/demo/.ui-forward.pid"
rm -rf "$DIR/demo/rehearse/node_modules" "$DIR/demo/rehearse/shots" "$DIR/demo/rehearse/package-lock.json"
rm -f "$HOME/Library/Application Support/kagent/login.json" "$HOME/Library/Application Support/kagent/login.json.lock"

echo "teardown done. Rebuild with: $DIR/install.sh, then demo/start.sh"
