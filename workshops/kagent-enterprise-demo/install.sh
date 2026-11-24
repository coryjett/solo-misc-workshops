#!/usr/bin/env bash
# Installs Solo Enterprise for kagent v2026.11.2 (kagent 1.0.1 on Agent Substrate) on the kind cluster
# kagent-ent, using ONLY this folder's kubeconfig (never your default context).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
export KUBECONFIG="$DIR/kubeconfig"
# Substrate needs k8s 1.36+ with the PodCertificateRequest gates (kind-config.yaml)
kind get clusters 2>/dev/null | grep -qx kagent-ent || \
  kind create cluster --name kagent-ent --image kindest/node:v1.36.1 --config "$DIR/kind-config.yaml" --kubeconfig "$DIR/kubeconfig"
[ "$(kubectl config current-context)" = "kind-kagent-ent" ] || { echo "wrong cluster, stopping" >&2; exit 1; }
# Enterprise kagent CLI, pinned and checked against the .sha256 published next to it (bin/ is gitignored).
V=2026.11.2
if [ ! -x "$DIR/bin/kagent" ]; then
  mkdir -p "$DIR/bin"
  arch="$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"; os="$(uname -s | tr A-Z a-z)"
  url="https://storage.googleapis.com/enterprise-kagent-binaries/v$V/kagent-$os-$arch"
  curl -sfLo "$DIR/bin/kagent.tmp" "$url" && want="$(curl -sfL "$url.sha256" | awk '{print $1}')"
  [ "$(shasum -a 256 "$DIR/bin/kagent.tmp" | awk '{print $1}')" = "$want" ] || { rm -f "$DIR/bin/kagent.tmp"; echo "kagent CLI checksum mismatch" >&2; exit 1; }
  mv "$DIR/bin/kagent.tmp" "$DIR/bin/kagent"; chmod +x "$DIR/bin/kagent"
fi
# Keys from the agentic demo's env file (never printed).
LAB="$DIR/../agentic-platform-demo/local.env"   # license and OpenAI key come from the agentic demo's local.env
ENVF="$(sed -nE 's/^(export )?OPENAI_ENV_FILE=//p' "$LAB" | head -1 | tr -d '"'"'"' ')"
val() { sed -nE "s/^(export )?$1=//p" "$ENVF" | head -1 | tr -d '"'"'"' \r\n'; }
export OPENAI_API_KEY="$(val OPENAI_API_KEY)"
export KAGENT_LICENSE_KEY="$(val SOLO_LICENSE_KEY)"
export AGENTGATEWAY_LICENSE_KEY="$KAGENT_LICENSE_KEY"
[ -n "$OPENAI_API_KEY" ] && [ -n "$KAGENT_LICENSE_KEY" ] || { echo "missing OpenAI key or license" >&2; exit 1; }
"$DIR/bin/kagent" --config "$DIR/config.yaml" install
# The chart ships the Kubernetes MCP tools server, the example agent and trace content capture off; the demo uses all three.
helm upgrade kagent oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise --version 2026.11.2 \
  -n kagent --reuse-values --set kagent-tools.enabled=true --set examples.enabled=true --set global.telemetry.captureContent=true --wait --timeout 5m >/dev/null
# agentgateway in front of company tools, and kagent token propagation (beat 4b).
"$DIR/gateway/install.sh"
kubectl get pods -A --no-headers | grep -vE 'Running|Completed' || echo "all pods running"
