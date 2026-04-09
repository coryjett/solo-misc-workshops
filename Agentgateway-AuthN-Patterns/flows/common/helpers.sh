#!/usr/bin/env bash
# Shared helper functions for auth pattern examples
# Source this file: source "$(dirname "$0")/../common/helpers.sh"

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGW_VERSION="${AGW_VERSION:-v2.2.0}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.0}"
CLUSTER_NAME="${CLUSTER_NAME:-agw-auth-patterns}"
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.5.2}"

# Wait for a deployment to be available
wait_for() {
  local ns="$1" resource="$2" timeout="${3:-120s}"
  info "Waiting for ${resource} in ${ns}..."
  kubectl wait -n "$ns" "$resource" --for=condition=Available --timeout="$timeout" 2>/dev/null \
    || kubectl wait -n "$ns" "$resource" --for=condition=Ready --timeout="$timeout" 2>/dev/null \
    || true
}

# Kill port-forward matching a pattern
kill_pf() {
  pkill -f "port-forward.*$1" 2>/dev/null || true
  sleep 1
}

# Get a Keycloak admin token
get_admin_token() {
  local kc_url="${1:-http://localhost:8080}"
  curl -sf -X POST "${kc_url}/realms/master/protocol/openid-connect/token" \
    -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" \
    | jq -r '.access_token'
}

# Get a user token from Keycloak (password grant)
get_user_token() {
  local kc_url="$1" realm="$2" client_id="$3" client_secret="$4" username="$5" password="$6"
  local host_header="${7:-}"
  local extra_args=()
  [[ -n "$host_header" ]] && extra_args+=(-H "Host: ${host_header}")
  curl -sf -X POST "${kc_url}/realms/${realm}/protocol/openid-connect/token" \
    "${extra_args[@]}" \
    -d "username=${username}" -d "password=${password}" -d "grant_type=password" \
    -d "client_id=${client_id}" -d "client_secret=${client_secret}" \
    | jq -r '.access_token'
}

# Decode JWT payload (no verification)
decode_jwt() {
  local payload
  payload=$(echo "$1" | cut -d. -f2 | tr '_-' '/+')
  while [ $((${#payload} % 4)) -ne 0 ]; do payload="${payload}="; done
  echo "$payload" | base64 -d 2>/dev/null | jq .
}

# Upgrade AGW with STS (token exchange) enabled — call AFTER Keycloak realm is ready
enable_sts() {
  local realm="$1"
  local jwks_url="http://keycloak.keycloak.svc.cluster.local:8080/realms/${realm}/protocol/openid-connect/certs"
  info "Upgrading AGW with token exchange (STS) enabled..."
  helm upgrade -i -n agentgateway-system enterprise-agentgateway \
    oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
    --version "${AGW_VERSION}" \
    --set-string licensing.licenseKey="${AGENTGATEWAY_LICENSE_KEY}" \
    --set agentgateway.enabled=true \
    --set tokenExchange.enabled=true \
    --set tokenExchange.issuer=enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777 \
    --set tokenExchange.tokenExpiration=24h \
    --set tokenExchange.subjectValidator.validatorType=remote \
    --set tokenExchange.subjectValidator.remoteConfig.url="${jwks_url}" \
    --set tokenExchange.actorValidator.validatorType=k8s \
    --set tokenExchange.apiValidator.validatorType=remote \
    --set tokenExchange.apiValidator.remoteConfig.url="${jwks_url}"
  info "Waiting for AGW pods with STS..."
  kubectl -n agentgateway-system rollout status deployment/enterprise-agentgateway --timeout=180s
  ok "AGW upgraded with STS"
}

# Check prerequisites
check_prereqs() {
  info "Checking prerequisites..."
  command -v docker  >/dev/null 2>&1 || fail "docker not found"
  command -v kubectl >/dev/null 2>&1 || fail "kubectl not found"
  command -v helm    >/dev/null 2>&1 || fail "helm not found"
  command -v curl    >/dev/null 2>&1 || fail "curl not found"
  command -v jq      >/dev/null 2>&1 || fail "jq not found"
  [[ -n "${AGENTGATEWAY_LICENSE_KEY:-}" ]] || fail "AGENTGATEWAY_LICENSE_KEY not set"
  ok "Prerequisites met"
}
