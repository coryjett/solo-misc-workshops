#!/usr/bin/env bash
# Registers the kagent runtime in the registry. Override KEYCLOAK_ISSUER, KAGENT_URL, KAGENT_NAMESPACE,
# AGENTREGISTRY_CLIENT_SECRET for an existing installation.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
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
