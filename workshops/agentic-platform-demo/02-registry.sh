#!/usr/bin/env bash
# agentregistry Enterprise v2026.9.0 + arctl v2026.9.0 + baseline AccessPolicies. Idempotent.
# License: path from LICENSE_SOURCE in local.env (gitignored). The key goes into a k8s Secret, never into
# helm values or output.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_QUIET=1 . "$DIR/env.sh"
K="kubectl --context $KCTX"
NS=agentregistry-system
CHART=oci://us-docker.pkg.dev/solo-public/agentregistry-enterprise/helm/agentregistry-enterprise

# 1. arctl at the matching version (the previous binary is kept beside it as arctl-<old version>).
CUR="$("$HOME/.arctl/bin/arctl" version 2>/dev/null | awk '/arctl version/{print $3}' || true)"
if [ "$CUR" != "$ARCTL_VERSION" ]; then
  [ -n "$CUR" ] && cp -p "$HOME/.arctl/bin/arctl" "$HOME/.arctl/bin/arctl-$CUR"
  curl -sSL https://storage.googleapis.com/agentregistry-enterprise/install.sh | ARCTL_VERSION="$ARCTL_VERSION" sh
fi
arctl version | head -1

# 2. License secret (chart expects key enterprise-agentregistry-license-key).
load_license
$K create namespace $NS --dry-run=client -o yaml | $K apply -f - >/dev/null
printf '%s' "$LICENSE_KEY" | $K -n $NS create secret generic enterprise-agentregistry-license \
  --from-file=enterprise-agentregistry-license-key=/dev/stdin --dry-run=client -o yaml | $K apply -f - >/dev/null
LIC_SHA="$(printf '%s' "$LICENSE_KEY" | shasum -a 256 | cut -c1-12)"   # restarts the pod when the license changes
unset LICENSE_KEY

# 3. Chart.
helm --kube-context "$KCTX" upgrade --install agentregistry-enterprise "$CHART" \
  --version "$ARE_VERSION" -n $NS -f "$DIR/values.yaml" \
  --set image.tag="$ARE_IMAGE_TAG" \
  --set licensing.createSecret=false \
  --set-string podAnnotations.demo/license-sha="$LIC_SHA" \
  --wait --timeout 10m
$K -n $NS rollout status deploy/agentregistry-enterprise-server --timeout=300s
$K -n $NS get pods

# The chart's service template ignores service.nodePorts at 2026.9.0, so pin the host-mapped
# NodePorts on a separate Service with the same selector.
cat <<EOF | $K apply -f - >/dev/null
apiVersion: v1
kind: Service
metadata: { name: agentregistry-enterprise-nodeport, namespace: $NS }
spec:
  type: NodePort
  selector:
    app.kubernetes.io/component: server
    app.kubernetes.io/instance: agentregistry-enterprise
    app.kubernetes.io/name: agentregistry-enterprise
  ports:
    - { name: http, port: 12121, targetPort: http, nodePort: $ARE_NODE_PORT }
    - { name: mcp,  port: 31313, targetPort: mcp,  nodePort: $MCP_NODE_PORT }
EOF

# 4. API reachable from the Mac, then baseline AccessPolicies as admin.
for i in $(seq 1 30); do curl -sf -m 5 -o /dev/null "$ARE_UI_URL/" && break; sleep 3; done
ARCTL_API_TOKEN="$(are_token admin)" arctl apply -f "$DIR/policies/baseline.yaml"
echo "UI: $ARE_UI_URL"
echo REGISTRY-READY
