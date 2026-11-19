#!/usr/bin/env bash
# Keycloak 26 in dev mode, realm imported at every start from a ConfigMap (so a pod or Mac restart
# never loses users). Exposed on the Mac at ${KC_URL} via NodePort ${KC_NODE_PORT}.
# KC_HOSTNAME pins the issuer, so tokens minted from the browser, the CLI or in-cluster all match.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_QUIET=1 . "$DIR/env.sh"
K="kubectl --context $KCTX"
REALM_SHA="$(shasum -a 256 "$DIR/agentregistry-enterprise-realm.json" | cut -c1-16)"

$K create namespace keycloak --dry-run=client -o yaml | $K apply -f - >/dev/null
# Realm signing key: generated once per machine into .secrets/ (gitignored) and rendered into the realm,
# so tokens stay valid across Keycloak restarts without a key in the repo.
mkdir -p "$DIR/.secrets" && chmod 700 "$DIR/.secrets"
if [ ! -f "$DIR/.secrets/realm-signing.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=agentic-demo" \
    -keyout "$DIR/.secrets/realm-signing.key" -out "$DIR/.secrets/realm-signing.crt" 2>/dev/null
  chmod 600 "$DIR/.secrets/realm-signing.key"
fi
REALM_RENDERED="$(mktemp)"; trap 'rm -f "$REALM_RENDERED"' EXIT
REALM_KEY="$(openssl pkcs8 -topk8 -nocrypt -in "$DIR/.secrets/realm-signing.key" -outform DER | base64 | tr -d '\n')" \
REALM_CRT="$(openssl x509 -in "$DIR/.secrets/realm-signing.crt" -outform DER | base64 | tr -d '\n')" \
python3 -c 'import os,sys; t=open(sys.argv[1]).read(); t=t.replace("__REALM_PRIVATE_KEY__",os.environ["REALM_KEY"]).replace("__REALM_CERTIFICATE__",os.environ["REALM_CRT"]); open(sys.argv[2],"w").write(t)' \
  "$DIR/agentregistry-enterprise-realm.json" "$REALM_RENDERED"
$K -n keycloak create configmap keycloak-realm --from-file=agentregistry-enterprise-realm.json="$REALM_RENDERED" \
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
  ports:
    - { name: http, port: 8080, targetPort: 8080, nodePort: ${KC_NODE_PORT} }
    - { name: issuer, port: ${KC_HOST_PORT}, targetPort: 8080 }   # pods use the same host:port issuer as the browser
EOF
$K -n keycloak rollout status deploy/keycloak --timeout=420s

for i in $(seq 1 30); do
  ISS="$(curl -s -m 5 "${OIDC_ISSUER}/.well-known/openid-configuration" | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' 2>/dev/null || true)"
  [ "$ISS" = "$OIDC_ISSUER" ] && break; sleep 3
done
[ "$ISS" = "$OIDC_ISSUER" ] || { echo "issuer from the Mac is '$ISS', expected $OIDC_ISSUER" >&2; exit 1; }
echo "issuer (from Mac): $ISS"
echo KEYCLOAK-READY
