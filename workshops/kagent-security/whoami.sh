#!/usr/bin/env bash
#
# kagent Enterprise Security Workshop — whoami
#
# Asks Keycloak for an access token as the given user and decodes the
# `role` and `Groups` claims. Use this to confirm the identity provider
# is sending what the AccessPolicy expects, before suspecting kagent.
#
# Usage: ./whoami.sh [admin|writer|reader]
#
set -uo pipefail
set +o pipefail

USER="${1:-admin}"
PASS="${PASS:-password}"

MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "${MAC_IP}" ]] && { echo "Could not detect LAN IP. Set MAC_IP manually." >&2; exit 1; }

KC_URL="${KC_URL:-http://${MAC_IP}:8088}"
CLIENT_SECRET="${CLIENT_SECRET:-hiIXdxOG5epokX92Es36RPEWuq4lORnw}"

RESULT=$(curl -sf -X POST "${KC_URL}/realms/kagent-dev/protocol/openid-connect/token" \
  -d "username=${USER}" -d "password=${PASS}" -d "grant_type=password" \
  -d "client_id=kagent-backend" -d "client_secret=${CLIENT_SECRET}" 2>/dev/null) \
  || { echo "Token request failed for ${USER}" >&2; exit 1; }

echo "${RESULT}" | python3 -c "
import json, sys, base64
d = json.load(sys.stdin)
t = d['access_token'].split('.')[1]
t += '=' * ((4 - len(t) % 4) % 4)
c = json.loads(base64.urlsafe_b64decode(t))
print(f'user:           ${USER}')
print(f'sub:            {c.get(\"sub\")}')
print(f'role  (string): {c.get(\"role\")!r}')
print(f'Groups (array): {c.get(\"Groups\")!r}')
print(f'iss:            {c.get(\"iss\")}')
print(f'expires in:     {c.get(\"exp\", 0) - c.get(\"iat\", 0)}s')
"
