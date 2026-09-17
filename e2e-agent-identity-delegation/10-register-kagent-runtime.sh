#!/usr/bin/env bash
# Registers the kagent runtime in Agentregistry Enterprise. Works against the lab registry or an existing one.
# Environment (defaults suit the lab; override for an existing installation):
#   ARCTL_API_BASE_URL   registry API, default http://localhost:12121 via port-forward (03-registry-env.sh)
#   KEYCLOAK_ISSUER      issuer the registry uses to authenticate to kagent, default in-cluster realm agentregistry
#   KAGENT_URL           kagent controller management API, default http://kagent-controller.kagent:8083
#   KAGENT_NAMESPACE     namespace kagent materializes workloads in, default kagent
#   AGENTREGISTRY_CLIENT_SECRET  secret of the Keycloak client "agentregistry", default agentregistry-secret
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=03-registry-env.sh
. "$DIR/03-registry-env.sh"
KEYCLOAK_ISSUER="${KEYCLOAK_ISSUER:-http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry}"
KAGENT_URL="${KAGENT_URL:-http://kagent-controller.kagent:8083}"
KAGENT_NAMESPACE="${KAGENT_NAMESPACE:-kagent}"
AGENTREGISTRY_CLIENT_SECRET="${AGENTREGISTRY_CLIENT_SECRET:-agentregistry-secret}"

arctl apply -f - <<YAML
apiVersion: ar.dev/v1alpha1
kind: Secret
metadata:
  name: kagent-oidc
spec:
  type: Opaque
  stringData:
    clientSecret: "${AGENTREGISTRY_CLIENT_SECRET}"
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
    kagentUrl: ${KAGENT_URL}
    namespace: ${KAGENT_NAMESPACE}
    auth:
      oidc:
        issuer: ${KEYCLOAK_ISSUER}
        clientId: agentregistry
        clientSecretRef:
          name: kagent-oidc
          key: clientSecret
YAML
arctl get runtimes
echo RUNTIME-READY
