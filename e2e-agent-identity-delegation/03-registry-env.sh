# Usage: . ./03-registry-env.sh
# Lab default: the registry API is port-forwarded to localhost:12121 and tokens are minted in-cluster so the issuer matches.
# Existing installation: export ARCTL_API_BASE_URL (your registry URL) and KEYCLOAK_URL (your Keycloak base URL, reachable
# from this shell) before sourcing; then no port-forward is opened and tokens are requested directly.
export PATH=$HOME/.arctl/bin:$PATH
export ARCTL_API_BASE_URL="${ARCTL_API_BASE_URL:-http://localhost:12121}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-agentregistry}"
if [ -z "${KEYCLOAK_URL:-}" ]; then
  pgrep -f "port-forward -n agentregistry-system svc/agentregistry-enterprise-server 12121" >/dev/null || \
    (kubectl port-forward -n agentregistry-system svc/agentregistry-enterprise-server 12121:12121 >/tmp/are-pf.log 2>&1 &)
  sleep 2
  ar_token() { kubectl exec -n wp-a deploy/sleep -- curl -s -X POST "http://keycloak.keycloak.svc.cluster.local:8080/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" -d grant_type=password -d client_id=ar-cli-password -d username=$1 -d password="${2:-$1}" -d 'scope=openid profile' | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"; }
else
  ar_token() { curl -s -X POST "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" -d grant_type=password -d client_id=ar-cli-password -d username=$1 -d password="${2:-$1}" -d 'scope=openid profile' | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"; }
fi
export ARCTL_API_TOKEN=$(ar_token "${AR_ADMIN_USER:-admin-user}" "${AR_ADMIN_PASSWORD:-password}")
echo "arctl points at $ARCTL_API_BASE_URL as ${AR_ADMIN_USER:-admin-user}. Use ar_token reader reader or ar_token writer writer for other users."
