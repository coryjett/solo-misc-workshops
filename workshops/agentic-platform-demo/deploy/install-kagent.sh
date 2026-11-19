#!/usr/bin/env bash
# Install OSS kagent 0.10.1 (controller only, no bundled agents, no license) into the agentic-demo kind cluster.
# Same charts as the ARE v2026.9.0 repo's scripts/kind/install-kagent.sh (make install-kagent,
# KAGENT_EDITION=oss), with one fix: that script disables the bundled agents with
# `agents.<name>.enabled=false`, but chart 0.10.1 uses top-level `<name>.enabled`, so its flags are
# ignored and ten agents (plus grafana-mcp) get installed. The OpenAI secret is a placeholder: the demo
# deploys an MCP server only, which makes no model calls. Idempotent.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; ENV_QUIET=1 . "$DIR/env.sh"
V=0.10.1 NS=kagent
kubectl --context "$KCTX" create namespace $NS --dry-run=client -o yaml | kubectl --context "$KCTX" apply -f -
kubectl --context "$KCTX" -n $NS create secret generic openai-api-key --from-literal=apiKey=placeholder-not-used \
  --dry-run=client -o yaml | kubectl --context "$KCTX" apply -f -
helm upgrade --install kagent-crds oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds --version $V \
  --kube-context "$KCTX" -n $NS --wait --timeout 3m
args=()
for a in k8s kgateway istio promql observability argo-rollouts helm cilium-policy cilium-manager cilium-debug; do
  args+=(--set "${a}-agent.enabled=false")
done
args+=(--set grafana-mcp.enabled=false)
helm upgrade --install kagent oci://ghcr.io/kagent-dev/kagent/helm/kagent --version $V \
  --kube-context "$KCTX" -n $NS \
  --set defaultModelConfig.model=gpt-4o --set defaultModelConfig.provider=openai \
  --set defaultModelConfig.apiKeySecretName=openai-api-key "${args[@]}" --wait --timeout 8m
kubectl --context "$KCTX" -n $NS get pods
