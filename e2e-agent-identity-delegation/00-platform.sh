#!/usr/bin/env bash
# Platform bootstrap: kind cluster (optional) + Solo Enterprise for agentgateway + test client.
# Requires: LICENSE_KEY env var (Solo enterprise license).
# Verified on kind + enterprise agentgateway v2026.9.0, 2026-09-16.
set -euo pipefail

: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
AGW_VERSION="${AGW_VERSION:-v2026.9.0}"
CLUSTER="${CLUSTER:-agw-e2e}"

# 1. Cluster (skip with SKIP_KIND=1 to use an existing cluster/context)
if [ -z "${SKIP_KIND:-}" ]; then
  kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER"
fi

# 2. Gateway API CRDs (standard channel) — required by agentgateway
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml

# 3. Solo Enterprise for agentgateway: CRDs then controller (license inline; STS comes later via sts-values.yaml)
helm upgrade -i enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --version "$AGW_VERSION" -n agentgateway-system --create-namespace

helm upgrade -i enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version "$AGW_VERSION" -n agentgateway-system --reuse-values \
  --set licensing.licenseKey="$LICENSE_KEY"

kubectl -n agentgateway-system rollout status deploy -l app.kubernetes.io/name=enterprise-agentgateway --timeout=180s || true
kubectl get gatewayclass enterprise-agentgateway

# 4. Test client pod (its namespace/SA is also the ACTOR identity for the STS demo:
#    system:serviceaccount:wp-a:default — referenced by 00-setup-realm.sh AGENT_SA and 03-api-authz.yaml)
kubectl apply -f 00-client.yaml
kubectl -n wp-a rollout status deploy/sleep --timeout=120s

echo "PLATFORM-READY"
