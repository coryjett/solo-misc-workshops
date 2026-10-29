#!/usr/bin/env bash
# Keycloak 26 in dev mode, realm imported at every start from a ConfigMap (so a pod or Mac restart
# never loses users). Exposed on the Mac at http://keycloak.localhost:8080 via NodePort 30080.
# KC_HOSTNAME pins the issuer, so tokens minted from the browser, the CLI or in-cluster all match.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/env.sh"
K="kubectl --context $KCTX"
REALM_FILE="$DIR/.secrets/realm.json"; mkdir -p "$DIR/.secrets"
python3 "$DIR/tools/make_realm.py" "$KC_REALM" "$COMPANY" "http://localhost:${OWUI_HOST_PORT}" "$DIR/.secrets" > "$REALM_FILE"; chmod 600 "$REALM_FILE"
REALM_SHA="$(shasum -a 256 "$REALM_FILE" | cut -c1-16)"

$K create namespace keycloak --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n keycloak create configmap keycloak-realm --from-file=realm.json="$REALM_FILE" \
  --dry-run=client -o yaml | $K apply -f - >/dev/null

cat <<EOF | $K apply -f -
apiVersion: apps/v1
kind: Deployment
metadata: { name: keycloak, namespace: keycloak }
spec:
  replicas: 1
  strategy: { type: Recreate }
  selector: { matchLabels: { app: keycloak } }
  template:
    metadata:
      labels: { app: keycloak }
      annotations: { demo/realm-sha: "${REALM_SHA}" }
    spec:
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:26.0
          args: ["start-dev", "--import-realm"]
          env:
            - { name: KC_BOOTSTRAP_ADMIN_USERNAME, value: admin }
            - { name: KC_BOOTSTRAP_ADMIN_PASSWORD, value: admin }
            - { name: KC_HOSTNAME, value: "${KC_URL}" }
            - { name: KC_HTTP_ENABLED, value: "true" }
            - { name: KC_HEALTH_ENABLED, value: "true" }
          ports: [ { containerPort: 8080, name: http } ]
          volumeMounts: [ { name: realm, mountPath: /opt/keycloak/data/import, readOnly: true } ]
          resources: { requests: { cpu: 250m, memory: 512Mi }, limits: { memory: 1536Mi } }
          readinessProbe:
            httpGet: { path: /realms/${KC_REALM}/.well-known/openid-configuration, port: 8080 }
            initialDelaySeconds: 15
            periodSeconds: 5
            failureThreshold: 60
      volumes: [ { name: realm, configMap: { name: keycloak-realm } } ]
---
apiVersion: v1
kind: Service
metadata: { name: keycloak, namespace: keycloak }
spec:
  type: NodePort
  selector: { app: keycloak }
  ports: [ { name: http, port: 8080, targetPort: 8080, nodePort: ${KC_NODE_PORT} } ]
EOF
$K -n keycloak rollout status deploy/keycloak --timeout=420s

for i in $(seq 1 30); do
  ISS="$(curl -s -m 5 "${OIDC_ISSUER}/.well-known/openid-configuration" | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' 2>/dev/null || true)"
  [ "$ISS" = "$OIDC_ISSUER" ] && break; sleep 3
done
[ "$ISS" = "$OIDC_ISSUER" ] || { echo "issuer from the Mac is '$ISS', expected $OIDC_ISSUER" >&2; exit 1; }
echo "issuer (from Mac): $ISS"
echo KEYCLOAK-READY
