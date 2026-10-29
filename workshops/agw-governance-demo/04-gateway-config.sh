#!/usr/bin/env bash
# Applies the gateway configuration in gateway/ (endpoint, MCP federation, identity, tool authz, guardrails, OBO,
# LLM models, prompt guards, logs, traces), rendered with env.sh settings. Also loads LLM provider keys as secrets.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"; K="kubectl --context $KCTX"
load_openai_key
$K create namespace "$TOOLS_NS" --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n agentgateway-system create secret generic local-llm-key --from-literal=Authorization="Bearer ${LOCAL_LLM_KEY:-none}" --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n agentgateway-system create secret generic openai-key --from-literal=Authorization="Bearer $OPENAI_API_KEY" --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n "$TOOLS_NS" create secret generic guard-keys --from-literal=LOCAL_AUTH="Bearer ${LOCAL_LLM_KEY:-none}" --from-literal=OPENAI_AUTH="Bearer $OPENAI_API_KEY" --dry-run=client -o yaml | $K apply -f - >/dev/null
for f in "$DIR"/gateway/*.yaml; do render "$f"; echo "---"; done | $K apply -f - >/dev/null
$K -n agentgateway-system rollout status deploy/mcp-gateway --timeout=180s >/dev/null
$K -n "$TOOLS_NS" rollout status deploy/injection-guard --timeout=180s >/dev/null
echo GATEWAY-CONFIG-APPLIED
