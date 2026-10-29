#!/usr/bin/env bash
# agentgateway Enterprise (CRDs, controller, Solo Enterprise UI) at $AGW_VERSION.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"; K="kubectl --context $KCTX"
load_license
kubectl --context "$KCTX" apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml >/dev/null
helm --kube-context "$KCTX" upgrade -i enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  -n agentgateway-system --create-namespace --version "$AGW_VERSION" --wait >/dev/null
helm --kube-context "$KCTX" upgrade -i enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  -n agentgateway-system --version "$AGW_VERSION" \
  --set-string licensing.licenseKey="$LICENSE_KEY" \
  -f <(render "$DIR/helm-values.yaml") --wait --timeout 6m >/dev/null
$K -n agentgateway-system get pods
echo AGW-READY
