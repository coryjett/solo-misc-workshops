#!/usr/bin/env bash
# Platform bootstrap: Solo Enterprise for agentgateway + test client, into the current kubeconfig context.
# Requires: LICENSE_KEY env var (Solo enterprise license).
# Verified on kind + enterprise agentgateway v2026.9.0, 2026-09-16.
set -euo pipefail

: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
AGW_VERSION="${AGW_VERSION:-v2026.9.0}"

# 1. Cluster: this script installs into the current kubeconfig context and never creates a cluster.
#    For a local KinD cluster run ./00-kind.sh first.
echo "Installing into context: $(kubectl config current-context)"

# 2. Gateway API CRDs (standard channel), required by agentgateway
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
#    system:serviceaccount:wp-a:default, referenced by the may_act mapper in 00-keycloak.yaml and by 03-api-authz.yaml)
kubectl apply -f 00-client.yaml
kubectl -n wp-a rollout status deploy/sleep --timeout=120s

echo "PLATFORM-READY"
