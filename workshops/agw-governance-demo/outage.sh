#!/usr/bin/env bash
# Simulate the self-hosted model going down (and back), to show the "auto" model failing over to the cloud fallback.
# Usage: ./outage.sh on | off
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
case "$1" in
  on)  kubectl --context "$KCTX" -n agentgateway-system patch agentgatewaymodel local-model --type=merge \
         -p '{"spec":{"baseURL":"https://10.255.255.1/v1"}}' >/dev/null && echo "local model: DOWN (simulated)";;
  off) render "$DIR/gateway/40-models.yaml" | kubectl --context "$KCTX" apply -f - >/dev/null && echo "local model: restored";;
  *)   echo "usage: $0 on|off"; exit 1;;
esac
sleep 6
