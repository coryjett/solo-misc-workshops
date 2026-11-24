#!/usr/bin/env bash
# Applies the gateway configuration in gateway/ (endpoint, MCP federation, identity, tool authz, guardrails, OBO,
# LLM models, prompt guards, logs, traces), rendered with env.sh settings. Also loads LLM provider keys as secrets.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"; K="kubectl --context $KCTX"
load_openai_key; load_local_llm_key
$K create namespace "$TOOLS_NS" --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n agentgateway-system create secret generic local-llm-key --from-literal=Authorization="Bearer ${LOCAL_LLM_KEY:-none}" --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n agentgateway-system create secret generic openai-key --from-literal=Authorization="Bearer $OPENAI_API_KEY" --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n "$TOOLS_NS" create secret generic guard-keys --from-literal=LOCAL_AUTH="Bearer ${LOCAL_LLM_KEY:-none}" --from-literal=OPENAI_AUTH="Bearer $OPENAI_API_KEY" --dry-run=client -o yaml | $K apply -f - >/dev/null
# HTTPS listener for in-cluster callers that require TLS (kagent agents calling as the signed-in user).
# A lab CA, made once per machine in .secrets/ (gitignored), signs the gateway's in-cluster name.
GW_DNS=mcp-gateway.agentgateway-system.svc.cluster.local
if [ ! -f "$DIR/.secrets/lab-ca.crt" ]; then
  mkdir -p "$DIR/.secrets"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=agentic-demo lab CA" \
    -keyout "$DIR/.secrets/lab-ca.key" -out "$DIR/.secrets/lab-ca.crt" 2>/dev/null
  chmod 600 "$DIR/.secrets/lab-ca.key"
fi
if [ ! -f "$DIR/.secrets/gateway-tls.crt" ]; then
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$GW_DNS" -keyout "$DIR/.secrets/gateway-tls.key" -out "$DIR/.secrets/gateway-tls.csr" 2>/dev/null
  openssl x509 -req -in "$DIR/.secrets/gateway-tls.csr" -CA "$DIR/.secrets/lab-ca.crt" -CAkey "$DIR/.secrets/lab-ca.key" -CAcreateserial \
    -days 825 -extfile <(printf "subjectAltName=DNS:%s,DNS:mcp-gateway.agentgateway-system.svc\nextendedKeyUsage=serverAuth" "$GW_DNS") \
    -out "$DIR/.secrets/gateway-tls.crt" 2>/dev/null
  chmod 600 "$DIR/.secrets/gateway-tls.key"; rm -f "$DIR/.secrets/gateway-tls.csr"
fi
$K -n agentgateway-system create secret tls mcp-gateway-tls --cert="$DIR/.secrets/gateway-tls.crt" --key="$DIR/.secrets/gateway-tls.key" \
  --dry-run=client -o yaml | $K apply -f - >/dev/null
for f in "$DIR"/gateway/*.yaml; do render "$f"; echo "---"; done | $K apply -f - >/dev/null
$K -n agentgateway-system rollout status deploy/mcp-gateway --timeout=180s >/dev/null
$K -n "$TOOLS_NS" rollout status deploy/injection-guard --timeout=180s >/dev/null
echo GATEWAY-CONFIG-APPLIED
