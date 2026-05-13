#!/usr/bin/env bash
# End-to-end test. Gets a subject token from Okta, calls AGW, validates
# that the token MCP receives is decorated (different audience/scope).
set -euo pipefail

NS="okta-tx"
req() { for v in "$@"; do [[ -n "${!v:-}" ]] || { echo "ERROR: $v not set" >&2; exit 1; }; done; }
req OKTA_DOMAIN OKTA_AS_ID OKTA_TEST_CLIENT_ID OKTA_TEST_USERNAME OKTA_TEST_PASSWORD OKTA_SCOPE

decode_jwt() { echo "$1" | cut -d. -f2 | base64 -d 2>/dev/null | jq .; }

echo "==> [1/4] Requesting subject token from Okta"
SUBJECT_TOKEN=$(curl -sS -X POST "https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=${OKTA_TEST_USERNAME}" \
  -d "password=${OKTA_TEST_PASSWORD}" \
  -d "scope=openid offline_access ${OKTA_SCOPE}" \
  -d "client_id=${OKTA_TEST_CLIENT_ID}" \
  | jq -r '.access_token // empty')

if [[ -z "$SUBJECT_TOKEN" ]]; then
  echo "ERROR: Could not obtain subject token. Verify OKTA_TEST_* envs and that the password grant"
  echo "       is enabled on the agw-test-subject-client app + the test user is assigned." >&2
  exit 1
fi

echo
echo "==> [2/4] Subject token claims (what AGW receives in Authorization)"
decode_jwt "$SUBJECT_TOKEN" | jq '{iss, aud, scp, sub, exp}'

echo
echo "==> [3/4] Port-forward AGW and call MCP"
pkill -f "port-forward.*workshop-gateway.*8081" 2>/dev/null || true
sleep 1
kubectl -n "$NS" port-forward svc/workshop-gateway 8081:80 >/dev/null 2>&1 &
PF_PID=$!
trap "kill $PF_PID 2>/dev/null || true" EXIT
sleep 2

# initialize
curl -sS -X POST http://localhost:8081/mcp \
  -H "Authorization: Bearer ${SUBJECT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}' >/dev/null

# whoami — echoes the Authorization the backend actually saw
ECHO=$(curl -sS -X POST http://localhost:8081/mcp \
  -H "Authorization: Bearer ${SUBJECT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"whoami","arguments":{}}}' \
  | jq -r '.result.content[0].text')

echo
echo "==> [4/4] Token the MCP backend saw (decorated by Okta during exchange)"
echo "$ECHO" | jq '{audience, issuer, scope, subject}'

echo
echo "==> Compare to the subject token above. Different audience/scope = exchange worked."
echo
echo "==> Shim activity (last 20 lines):"
kubectl -n "$NS" logs deploy/okta-shim --tail=20 2>&1 | sed 's/^/    /'
