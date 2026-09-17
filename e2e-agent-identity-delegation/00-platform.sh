#!/usr/bin/env bash
# Gateway API CRDs, Enterprise Agentgateway, and the test client, into the current kubeconfig context. Requires LICENSE_KEY.
set -euo pipefail

: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
AGW_VERSION="${AGW_VERSION:-v2026.9.0}"

echo "Installing into context: $(kubectl config current-context)"

kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml

helm upgrade -i enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --version "$AGW_VERSION" -n agentgateway-system --create-namespace

helm upgrade -i enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version "$AGW_VERSION" -n agentgateway-system --reuse-values \
  --set licensing.licenseKey="$LICENSE_KEY"

kubectl -n agentgateway-system rollout status deploy -l app.kubernetes.io/name=enterprise-agentgateway --timeout=180s || true
kubectl get gatewayclass enterprise-agentgateway

kubectl apply -f 00-client.yaml
kubectl -n wp-a rollout status deploy/sleep --timeout=120s

echo "PLATFORM-READY"
