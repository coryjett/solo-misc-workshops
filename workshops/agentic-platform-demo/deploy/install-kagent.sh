#!/usr/bin/env bash
# Install Solo Enterprise for kagent (kagent 1.x on Agent Substrate) into the agentic-demo cluster.
# Two steps: `kagent install` (Substrate, a dev Postgres, the controller, default harnesses), then a
# Helm upgrade with deploy/kagent-values.yaml.tmpl (Keycloak sign-in, group-based RBAC, user token
# propagation, the UI on a NodePort). Needs the cluster from 00-cluster.sh (k8s 1.36 + Substrate
# gates) and Keycloak from 01-keycloak.sh. Idempotent: a second run only re-applies the overlay.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; ENV_QUIET=1 . "$DIR/env.sh"
V=2026.11.2 NS=kagent
CHART=oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise
K="kubectl --context $KCTX"

# Enterprise CLI, pinned and checked against the .sha256 published next to it.
BIN="$DIR/.bin/kagent-$V"
if [ ! -x "$BIN" ]; then
  mkdir -p "$DIR/.bin"
  arch="$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"; os="$(uname -s | tr A-Z a-z)"
  url="https://storage.googleapis.com/enterprise-kagent-binaries/v$V/kagent-$os-$arch"
  curl -sfLo "$BIN.tmp" "$url" && want="$(curl -sfL "$url.sha256" | awk '{print $1}')"
  [ "$(shasum -a 256 "$BIN.tmp" | awk '{print $1}')" = "$want" ] || { rm -f "$BIN.tmp"; echo "kagent CLI checksum mismatch" >&2; exit 1; }
  mv "$BIN.tmp" "$BIN"; chmod +x "$BIN"
fi

load_license; load_openai_key
export KAGENT_LICENSE_KEY="$LICENSE_KEY" AGENTGATEWAY_LICENSE_KEY="$LICENSE_KEY"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
KCFG="$TMP/kubeconfig"; kubectl config view --minify --flatten --context "$KCTX" > "$KCFG"

if ! helm --kubeconfig "$KCFG" -n $NS status kagent >/dev/null 2>&1; then
  printf 'install:\n  defaultModelProvider: OpenAI\n' > "$TMP/cli.yaml"
  KUBECONFIG="$KCFG" "$BIN" --config "$TMP/cli.yaml" install
fi

render "$DIR/deploy/kagent-values.yaml.tmpl" > "$TMP/values.yaml"
helm --kubeconfig "$KCFG" upgrade kagent "$CHART" --version $V -n $NS --reuse-values \
  -f "$TMP/values.yaml" --wait --timeout 8m >/dev/null
$K -n $NS rollout status deploy/kagent-controller --timeout=180s >/dev/null
# Token propagation, Substrate side: point the egress proxy at kagent's caller-token provider.
SUB=oci://us-docker.pkg.dev/solo-public/enterprise-substrate-helm/substrate
SUBV="$(helm --kubeconfig "$KCFG" -n ate-system list -f '^substrate$' -o json | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["chart"].removeprefix("substrate-"))')"
helm --kubeconfig "$KCFG" upgrade substrate "$SUB" --version "$SUBV" -n ate-system --reuse-values \
  --set-json 'atenetEgress.extraCredentialProviders=[{"name":"caller-token.kagent.dev","address":"kagent-credential-provider.kagent.svc:8086"}]' \
  --wait --timeout 5m >/dev/null
# The UI on a fixed NodePort (mapped to localhost:${KAGENT_HOST_PORT} by 00-cluster.sh); the chart cannot pin one.
$K apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Service
metadata: { name: kagent-ui-nodeport, namespace: $NS }
spec:
  type: NodePort
  selector: { app.kubernetes.io/component: ui, app.kubernetes.io/instance: kagent }
  ports: [ { name: ui, port: 8080, targetPort: 8080, nodePort: ${KAGENT_NODE_PORT} } ]
YAML
$K -n $NS get pods
