#!/bin/bash
# Fetch an access token (client_credentials) from the demo Keycloak realm and print its claims.
# The realm's hardcoded protocol mappers stamp the claims Cedar authorizes on:
#   team=GTM, tier=premium, org=acme, scp=["api.read"]  (plus sub = service account).
#
# Prereq: Keycloak reachable. Port-forward it first (a different local port than the gateway):
#   kubectl port-forward -n keycloak svc/keycloak 8081:8080
#
# Override any of these if you changed the realm/client:
#   KEYCLOAK_URL (default http://localhost:8081)
#   REALM        (default cedar-demo)
#   CLIENT_ID    (default cedar-demo-client)
#   CLIENT_SECRET(default cedar-demo-secret)
#
# Usage:
#   ./get-token.sh            # print claims + token response
#   TOKEN=$(./get-token.sh --raw)   # just the access_token
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8081}"
REALM="${REALM:-cedar-demo}"
CLIENT_ID="${CLIENT_ID:-cedar-demo-client}"
CLIENT_SECRET="${CLIENT_SECRET:-cedar-demo-secret}"

TOKEN_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

# --raw: emit only the token (handy for: TOKEN=$(./get-token.sh --raw))
if [ "${1:-}" = "--raw" ]; then
  echo "$ACCESS_TOKEN"
  exit 0
fi

echo "JWT Token Claims:"
echo "================="
PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d '.' -f2)
PADDING_LENGTH=$((4 - ${#PAYLOAD} % 4))
if [ $PADDING_LENGTH -ne 4 ]; then
  PAYLOAD="${PAYLOAD}$(printf '%*s' $PADDING_LENGTH | tr ' ' '=')"
fi
echo "$PAYLOAD" | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
echo "================="
echo ""
echo "Token response:"
echo "$TOKEN_RESPONSE" | jq 'del(.access_token)'
