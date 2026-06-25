#!/bin/bash
# Stand up a local k3d cluster with agentgateway Enterprise for the cedar ext_authz demo.
# No registry needed — the cedar image is built + `k3d image import`ed by the Makefile.
#
# Prereqs: docker, k3d, kubectl, helm, and an agentgateway Enterprise license:
#   export AGENTGATEWAY_LICENSE_KEY=...
#
# Usage: ./k3d-setup.sh
set -euo pipefail

CLUSTER="${CLUSTER:-agw-demo}"
NS="${NS:-agentgateway-system}"
AGW_VERSION="${AGW_VERSION:-v2026.6.1}"  # current Enterprise stable chart (CalVer; note the 'v' prefix)
GWAPI_VERSION="${GWAPI_VERSION:-v1.2.0}"
CHART_REPO="oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts"

if [ -z "${AGENTGATEWAY_LICENSE_KEY:-}" ]; then
  echo "ERROR: export AGENTGATEWAY_LICENSE_KEY=... first" >&2
  exit 1
fi

echo "==> 1/5 create k3d cluster '$CLUSTER' (gateway on localhost:8080)"
k3d cluster create "$CLUSTER" --port "8080:80@loadbalancer" || echo "(cluster may already exist)"

echo "==> 2/5 install upstream Gateway API CRDs ($GWAPI_VERSION)"
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GWAPI_VERSION}/standard-install.yaml"

echo "==> 3/5 install agentgateway Enterprise CRDs ($AGW_VERSION)"
helm upgrade -i enterprise-agentgateway-crds "${CHART_REPO}/enterprise-agentgateway-crds" \
  --namespace "$NS" --create-namespace --version "$AGW_VERSION"

echo "==> 4/5 install agentgateway Enterprise ($AGW_VERSION)"
helm upgrade -i enterprise-agentgateway "${CHART_REPO}/enterprise-agentgateway" \
  --namespace "$NS" --version "$AGW_VERSION" \
  --set agentgateway.enabled=true \
  --set licensing.licenseKey="$AGENTGATEWAY_LICENSE_KEY" \
  --wait

echo "==> 5/5 wait for the controller"
kubectl rollout status -n "$NS" deploy/enterprise-agentgateway --timeout=180s || true

echo
echo "Cluster ready. Next:"
echo "  make keycloak           # deploy the IdP + import the cedar-demo realm"
echo "  make load deploy        # build+import cedar image, apply svc/routes/policies"
echo "  make logs               # watch Cedar decisions"
echo "  make kc-forward         # port-forward Keycloak on :8081, then:"
echo "  ./test/get-token.sh        # grab a token from Keycloak"
