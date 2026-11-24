#!/usr/bin/env bash
# Adds agentgateway Enterprise in front of two company tool servers (customer records, inventory), and
# turns on kagent token propagation so agents call the gateway as the signed-in user. Idempotent.
# Uses only this kit's kubeconfig. Tool servers come from the agentic platform demo's tools image.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; export KUBECONFIG="$DIR/kubeconfig"
[ "$(kubectl config current-context)" = "kind-kagent-ent" ] || { echo "wrong cluster, stopping" >&2; exit 1; }
AGW_VERSION=v2026.11.1 KAGENT_V=2026.11.2
LAB="$DIR/../agentic-platform-demo"
ENVF="$(sed -nE 's/^(export )?OPENAI_ENV_FILE=//p' "$LAB/local.env" | head -1 | tr -d '"'"'"' ')"
LICENSE="$(sed -nE 's/^(export )?SOLO_LICENSE_KEY=//p' "$ENVF" | head -1 | tr -d '"'"'"' \r\n')"
[ -n "$LICENSE" ] || { echo "no license" >&2; exit 1; }

echo "== tool servers"
docker build -q -t agw-demo-tools:1 "$LAB/tools" >/dev/null
docker save agw-demo-tools:1 | docker exec -i kagent-ent-control-plane ctr -n k8s.io images import --all-platforms - >/dev/null
kubectl create namespace demo-tools --dry-run=client -o yaml | kubectl apply -f - >/dev/null
for svc in records-mcp:records.py inventory-mcp:inventory.py; do
  name="${svc%%:*}"; file="${svc#*:}"
  kubectl apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: ${name}, namespace: demo-tools, labels: { app: ${name} } }
spec:
  replicas: 1
  selector: { matchLabels: { app: ${name} } }
  template:
    metadata: { labels: { app: ${name} } }
    spec:
      containers:
        - { name: ${name}, image: agw-demo-tools:1, imagePullPolicy: Never, command: ["python","${file}"],
            ports: [ { containerPort: 8000 } ], readinessProbe: { tcpSocket: { port: 8000 }, periodSeconds: 3 } }
---
apiVersion: v1
kind: Service
metadata: { name: ${name}, namespace: demo-tools }
spec:
  selector: { app: ${name} }
  ports: [ { name: http, port: 8000, targetPort: 8000, appProtocol: agentgateway.dev/mcp } ]
YAML
done

echo "== agentgateway $AGW_VERSION"
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml >/dev/null
helm upgrade -i enterprise-agentgateway-crds oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  -n agentgateway-system --create-namespace --version "$AGW_VERSION" --wait >/dev/null
helm upgrade -i enterprise-agentgateway oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  -n agentgateway-system --version "$AGW_VERSION" --set-string licensing.licenseKey="$LICENSE" --wait --timeout 6m >/dev/null

echo "== gateway TLS (kit CA in .secrets/, gitignored)"
S="$DIR/.secrets"; mkdir -p "$S"; GW_DNS=mcp-gateway.agentgateway-system.svc.cluster.local
[ -f "$S/kit-ca.crt" ] || { openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=kagent demo kit CA" -keyout "$S/kit-ca.key" -out "$S/kit-ca.crt" 2>/dev/null; chmod 600 "$S/kit-ca.key"; }
if [ ! -f "$S/gateway-tls.crt" ]; then
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$GW_DNS" -keyout "$S/gateway-tls.key" -out "$S/gateway-tls.csr" 2>/dev/null
  openssl x509 -req -in "$S/gateway-tls.csr" -CA "$S/kit-ca.crt" -CAkey "$S/kit-ca.key" -CAcreateserial -days 825 \
    -extfile <(printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth" "$GW_DNS") -out "$S/gateway-tls.crt" 2>/dev/null
  chmod 600 "$S/gateway-tls.key"; rm -f "$S/gateway-tls.csr"
fi
kubectl -n agentgateway-system create secret tls mcp-gateway-tls --cert="$S/gateway-tls.crt" --key="$S/gateway-tls.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f "$DIR/gateway/gateway.yaml" >/dev/null

echo "== kagent token propagation"
helm upgrade kagent oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise --version $KAGENT_V -n kagent \
  --reuse-values --set enterprise.tokenPropagation.enabled=true --set controller.substrateClientCertificate.enabled=true --wait --timeout 6m >/dev/null
SUBV="$(helm -n ate-system list -f '^substrate$' -o json | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["chart"].removeprefix("substrate-"))')"
helm upgrade substrate oci://us-docker.pkg.dev/solo-public/enterprise-substrate-helm/substrate --version "$SUBV" -n ate-system --reuse-values \
  --set-json 'atenetEgress.extraCredentialProviders=[{"name":"caller-token.kagent.dev","address":"kagent-credential-provider.kagent.svc:8086"}]' --wait --timeout 5m >/dev/null

"$DIR/gateway/egress-trust.sh"
kubectl -n agentgateway-system rollout status deploy/mcp-gateway --timeout=180s >/dev/null
echo "gateway layer ready"
