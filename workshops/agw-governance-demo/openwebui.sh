#!/usr/bin/env bash
# Open WebUI (an open-source chat front end) on http://localhost:$OWUI_HOST_PORT.
# Users sign in with the IdP (Keycloak here); Open WebUI forwards each user's own access token to the gateway
# (auth_type system_oauth), so model access, prompt guards and the audit trail all see the real user.
# Usage: ./openwebui.sh up | down | reset   (reset wipes Open WebUI's local data: users, chats)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
OPEN_WEBUI_OIDC_SECRET="$(cat "$DIR/.secrets/openwebui-client.secret")"   # created by 01-keycloak.sh
[ -f "$DIR/.secrets/webui-secret-key" ] || python3 -c 'import secrets;print(secrets.token_urlsafe(32))' > "$DIR/.secrets/webui-secret-key"
WEBUI_SECRET_KEY="$(cat "$DIR/.secrets/webui-secret-key")"   # fixed, so sign-ins survive restarts
NAME=${CLUSTER}-openwebui; VOL=${CLUSTER}-openwebui-data
case "${1:-up}" in
  down)  docker rm -f $NAME >/dev/null 2>&1 || true; echo "Open WebUI stopped"; exit 0;;
  reset) docker rm -f $NAME >/dev/null 2>&1 || true; docker volume rm $VOL >/dev/null 2>&1 || true; echo "Open WebUI data wiped";;
esac
docker rm -f $NAME >/dev/null 2>&1 || true
docker run -d --name $NAME --restart unless-stopped -p 127.0.0.1:${OWUI_HOST_PORT}:8080 \
  --add-host keycloak.localhost:host-gateway --add-host host.docker.internal:host-gateway \
  -v $VOL:/app/backend/data \
  -e WEBUI_URL=http://localhost:${OWUI_HOST_PORT} -e WEBUI_NAME="${COMPANY} AI (via agentgateway)" \
  -e ENABLE_PERSISTENT_CONFIG=false -e ENABLE_LOGIN_FORM=false -e ENABLE_SIGNUP=false \
  -e ENABLE_OAUTH_SIGNUP=true -e OAUTH_PROVIDER_NAME="${COMPANY} SSO" \
  -e OAUTH_CLIENT_ID=open-webui -e OAUTH_CLIENT_SECRET="$OPEN_WEBUI_OIDC_SECRET" \
  -e OPENID_PROVIDER_URL=${OIDC_ISSUER}/.well-known/openid-configuration \
  -e OPENID_REDIRECT_URI=http://localhost:${OWUI_HOST_PORT}/oauth/oidc/callback -e OAUTH_SCOPES="openid email profile" \
  -e DEFAULT_USER_ROLE=user -e BYPASS_MODEL_ACCESS_CONTROL=true \
  -e ENABLE_OLLAMA_API=false -e ENABLE_OPENAI_API=true \
  -e OPENAI_API_BASE_URL=http://host.docker.internal:${GW_HOST_PORT}/v1 -e OPENAI_API_KEY=unused \
  -e OPENAI_API_CONFIGS='{"0": {"auth_type": "system_oauth"}}' \
  -e ENABLE_TITLE_GENERATION=false -e ENABLE_FOLLOW_UP_GENERATION=false -e ENABLE_TAGS_GENERATION=false \
  -e ENABLE_AUTOCOMPLETE_GENERATION=false -e ENABLE_SEARCH_QUERY_GENERATION=false -e ENABLE_RETRIEVAL_QUERY_GENERATION=false \
  -e ENABLE_CODE_INTERPRETER=false -e ENABLE_MEMORIES=false -e ENABLE_MEMORY_SYSTEM_CONTEXT=false -e ENABLE_NOTES=false \
  -e ENABLE_TOOLS=false -e ENABLE_TOOL_SERVERS=false -e ENABLE_IMAGE_PROMPT_GENERATION=false \
  -e DEFAULT_MODEL_PARAMS='{"function_calling": "legacy"}' -e DEFAULT_MODEL_METADATA='{"capabilities": {"builtin_tools": false}}' \
  -e WEBUI_SECRET_KEY="$WEBUI_SECRET_KEY" \
  -e ENABLE_WEB_SEARCH=false -e ENABLE_EVALUATION_ARENA_MODELS=false -e ENABLE_COMMUNITY_SHARING=false \
  ghcr.io/open-webui/open-webui:main >/dev/null
for i in $(seq 1 90); do curl -s -o /dev/null -m 2 http://localhost:${OWUI_HOST_PORT}/health && break; sleep 2; done
curl -s -m 3 http://localhost:${OWUI_HOST_PORT}/health; echo; echo "Open WebUI: http://localhost:${OWUI_HOST_PORT}"
