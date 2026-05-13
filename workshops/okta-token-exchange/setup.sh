#!/usr/bin/env bash
# Workshop setup. Run after configuring Okta (see workshop-guide.md Part 1)
# and exporting the OKTA_* and AGENTGATEWAY_LICENSE_KEY env vars.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
NS="okta-tx"

req() { for v in "$@"; do [[ -n "${!v:-}" ]] || { echo "ERROR: $v not set" >&2; exit 1; }; done; }
req OKTA_DOMAIN OKTA_AS_ID OKTA_CLIENT_ID OKTA_CLIENT_SECRET \
    OKTA_TEST_CLIENT_ID OKTA_TEST_USERNAME OKTA_TEST_PASSWORD \
    OKTA_AUDIENCE OKTA_SCOPE AGENTGATEWAY_LICENSE_KEY

echo "==> Okta config"
echo "    Issuer:   https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}"
echo "    Audience: ${OKTA_AUDIENCE}"
echo "    Scope:    ${OKTA_SCOPE}"
echo

echo "==> [1/5] Gateway API CRDs"
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml >/dev/null

echo "==> [2/5] AGW Enterprise"
helm upgrade -i --create-namespace -n agentgateway-system enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  --version v2.2.0 >/dev/null

helm upgrade -i -n agentgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version v2.2.0 \
  --set-string licensing.licenseKey="$AGENTGATEWAY_LICENSE_KEY" \
  --set agentgateway.enabled=true \
  --set tokenExchange.enabled=true \
  --set tokenExchange.issuer="enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777" \
  --set tokenExchange.tokenExpiration=24h \
  --set tokenExchange.subjectValidator.validatorType=remote \
  --set tokenExchange.subjectValidator.remoteConfig.url="https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}/v1/keys" \
  --set tokenExchange.actorValidator.validatorType=k8s \
  --set tokenExchange.apiValidator.validatorType=remote \
  --set tokenExchange.apiValidator.remoteConfig.url="https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}/v1/keys" >/dev/null

kubectl -n agentgateway-system rollout status deployment \
  -l app.kubernetes.io/instance=enterprise-agentgateway --timeout=180s

echo "==> [3/5] Namespace + secret"
kubectl apply -f "$SCRIPT_DIR/k8s/00-namespace.yaml" >/dev/null
envsubst < "$SCRIPT_DIR/k8s/secret.yaml.tpl" | kubectl apply -f - >/dev/null

echo "==> [4/5] Shim + MCP echo"
envsubst < "$SCRIPT_DIR/k8s/10-shim.yaml"    | kubectl apply -f - >/dev/null
envsubst < "$SCRIPT_DIR/k8s/20-mcp-echo.yaml"| kubectl apply -f - >/dev/null
kubectl -n "$NS" rollout status deploy/okta-shim --timeout=120s
kubectl -n "$NS" rollout status deploy/mcp-echo  --timeout=120s

echo "==> [5/5] Gateway + Policies"
envsubst < "$SCRIPT_DIR/k8s/30-agw.yaml" | kubectl apply -f - >/dev/null
kubectl -n "$NS" rollout status deploy/okta-jwks-proxy --timeout=60s

# Wait for the AGW pod that the Gateway resource provisioned
echo "==> Waiting for AGW data plane pod..."
for i in $(seq 1 60); do
  if kubectl -n "$NS" get deploy 2>/dev/null | grep -q workshop-gateway; then
    kubectl -n "$NS" rollout status deploy/workshop-gateway --timeout=120s && break
  fi
  sleep 2
done

echo
echo "==> Done. Validate with:"
echo "    $SCRIPT_DIR/check.sh"
