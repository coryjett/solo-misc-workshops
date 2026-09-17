#!/usr/bin/env bash
# Installs Agentregistry Enterprise into the current context, then registers the kagent runtime.
# Requires: LICENSE_KEY, arctl on PATH (see Step 9), Keycloak realm from 05-setup-realm-registry.sh, kagent from 05-kagent-install.sh.
set -euo pipefail
: "${LICENSE_KEY:?set LICENSE_KEY to your Solo enterprise license key}"
ARE_VERSION="${ARE_VERSION:-2026.8.0}"
DIR="$(cd "$(dirname "$0")" && pwd)"

helm upgrade --install agentregistry-enterprise \
  oci://us-docker.pkg.dev/solo-public/agentregistry-enterprise/helm/agentregistry-enterprise \
  --version "$ARE_VERSION" -n agentregistry-system --create-namespace \
  -f "$DIR/06-registry-values.yaml" \
  --set licensing.createSecret=true --set-string licensing.licenseKey="$LICENSE_KEY" \
  --wait --timeout 8m
kubectl get pods -n agentregistry-system

# shellcheck source=06-registry-env.sh
. "$DIR/06-registry-env.sh"

arctl apply -f - <<YAML
apiVersion: ar.dev/v1alpha1
kind: Secret
metadata:
  name: kagent-oidc
spec:
  type: Opaque
  stringData:
    clientSecret: "agentregistry-secret"
YAML

arctl apply -f - <<YAML
apiVersion: ar.dev/v1alpha1
kind: Runtime
metadata:
  name: kagent
spec:
  type: Kagent
  telemetryEndpoint: http://agentregistry-enterprise-telemetry-collector.agentregistry-system.svc.cluster.local:4318
  config:
    kagentUrl: http://kagent-controller.kagent:8083
    namespace: kagent
    auth:
      oidc:
        issuer: http://keycloak.keycloak.svc.cluster.local:8080/realms/agent-demo
        clientId: agentregistry
        clientSecretRef:
          name: kagent-oidc
          key: clientSecret
YAML
arctl get runtimes
echo REGISTRY-READY
