#!/usr/bin/env bash
# Shared base setup: k3d cluster + Gateway API CRDs + Agent Gateway Enterprise
# Source helpers first, then source this file.
#
# Ref: https://docs.solo.io/agentgateway/2.2.x/install/helm/

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers.sh"

check_prereqs

# ── k3d cluster ──────────────────────────────────────────────────────────────
info "Creating k3d cluster: ${CLUSTER_NAME}..."
if k3d cluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  warn "Cluster ${CLUSTER_NAME} already exists, reusing"
else
  if ! command -v k3d >/dev/null 2>&1; then
    info "Installing k3d..."
    curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
  fi
  k3d cluster create "${CLUSTER_NAME}" \
    --servers 1 --agents 1 \
    --k3s-arg "--disable=traefik@server:0" \
    --wait
fi
kubectl config use-context "k3d-${CLUSTER_NAME}"
kubectl get nodes
ok "Cluster ready"

# ── Gateway API CRDs ────────────────────────────────────────────────────────
info "Installing Gateway API CRDs ${GATEWAY_API_VERSION}..."
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
ok "Gateway API CRDs installed"

# ── Agent Gateway Enterprise ────────────────────────────────────────────────
info "Installing Enterprise Agentgateway CRDs ${AGW_VERSION}..."
helm upgrade -i --create-namespace \
  --namespace agentgateway-system \
  --version "${AGW_VERSION}" \
  enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds

info "Installing Enterprise Agentgateway ${AGW_VERSION}..."
# Subshell-safe: callers can set HELM_EXTRA_ARGS before sourcing
helm upgrade -i -n agentgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version "${AGW_VERSION}" \
  --set-string licensing.licenseKey="${AGENTGATEWAY_LICENSE_KEY}" \
  --set agentgateway.enabled=true \
  ${AGW_HELM_EXTRA_ARGS:-}

info "Waiting for AGW pods..."
kubectl -n agentgateway-system wait --for=condition=ready pod \
  -l app.kubernetes.io/name=enterprise-agentgateway --timeout=180s
ok "Enterprise Agentgateway deployed"
