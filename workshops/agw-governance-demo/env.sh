# Source me:  . ./env.sh    Settings for the agentgateway governance demo. Every value can be overridden
# by exporting it first (or putting it in ./demo.env). Never echoes secrets.
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-${(%):-%x}}")" && pwd)"; export DEMO_DIR   # always this file's directory, never an inherited value
[ -f "$DEMO_DIR/demo.env" ] && set -a && . "$DEMO_DIR/demo.env" && set +a

export COMPANY="${COMPANY:-Acme}"                       # shown in Open WebUI and the realm display name
export CLUSTER="${CLUSTER:-agw-demo}"
export KCTX="kind-${CLUSTER}"
export KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.33.1}"
export AGW_VERSION="${AGW_VERSION:-v2026.10.1}"
export TOOLS_NS="${TOOLS_NS:-demo-tools}"
export TOOLS_IMAGE="${TOOLS_IMAGE:-agw-demo-tools:1}"

# Host ports (kind extraPortMappings -> NodePorts), bound to 127.0.0.1 only. Change all three if they clash.
export KC_HOST_PORT="${KC_HOST_PORT:-8080}"   KC_NODE_PORT="${KC_NODE_PORT:-30080}"   # Keycloak
export GW_HOST_PORT="${GW_HOST_PORT:-8081}"   GW_NODE_PORT="${GW_NODE_PORT:-30081}"   # agentgateway: MCP + LLM endpoint
export UI_HOST_PORT="${UI_HOST_PORT:-8082}"   UI_NODE_PORT="${UI_NODE_PORT:-30082}"   # Solo Enterprise UI
export OWUI_HOST_PORT="${OWUI_HOST_PORT:-3000}"                                       # Open WebUI

export KC_HOSTNAME=keycloak.localhost
export KC_URL="http://${KC_HOSTNAME}:${KC_HOST_PORT}"
export KC_REALM="${KC_REALM:-demo}"
export OIDC_ISSUER="${KC_URL}/realms/${KC_REALM}"
export MCP_URL="http://localhost:${GW_HOST_PORT}/mcp"
export LLM_URL="http://localhost:${GW_HOST_PORT}/v1/chat/completions"

# LLM providers.
#   Local (self-hosted, OpenAI-compatible): default is Ollama on this Mac. Any OpenAI-compatible server works
#   (vLLM, LM Studio, a GPU box). The key is optional (Ollama ignores it).
export LOCAL_LLM_BASE_URL="${LOCAL_LLM_BASE_URL:-http://host.docker.internal:11434/v1}"
export LOCAL_LLM_MODEL="${LOCAL_LLM_MODEL:-llama3.2}"
#   Secrets come from files/env, never from this file:
#   LOCAL_LLM_KEY (optional), OPENAI_API_KEY (or OPENAI_ENV_FILE=<.env containing OPENAI_API_KEY=>),
#   LICENSE_SOURCE (path to a file holding the Solo license key, or a .env with SOLO_LICENSE_KEY=)

# Access token for a demo user (password = username). Usage: token support-agent
token() {
  local u="${1:-support-agent}"
  curl -s -X POST "${OIDC_ISSUER}/protocol/openid-connect/token" -d grant_type=password -d client_id=mcp-inspector \
    --data-urlencode "username=${u}" --data-urlencode "password=${u}" -d 'scope=openid' |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("access_token") or sys.exit("token error: %s" % d))'
}

load_license() {
  local src="${LICENSE_SOURCE:-}"
  [ -n "$src" ] || src="$(sed -n 's/^LICENSE_SOURCE=//p' "$DEMO_DIR/.license-source" 2>/dev/null)"
  [ -n "${SOLO_LICENSE_KEY:-}" ] && { export LICENSE_KEY="$SOLO_LICENSE_KEY"; return 0; }
  case "$src" in *.env) LICENSE_KEY="$(sed -n 's/^SOLO_LICENSE_KEY=//p' "$src" | tr -d '"'"'"' \r\n')" ;; ?*) LICENSE_KEY="$(tr -d ' \r\n' < "$src")" ;; esac
  [ -n "${LICENSE_KEY:-}" ] || { echo "no license: export SOLO_LICENSE_KEY or LICENSE_SOURCE=<path>" >&2; return 1; }
  export LICENSE_KEY
}

load_openai_key() {
  [ -n "${OPENAI_API_KEY:-}" ] && return 0
  [ -n "${OPENAI_ENV_FILE:-}" ] && OPENAI_API_KEY="$(sed -n 's/^OPENAI_API_KEY=//p' "$OPENAI_ENV_FILE" | head -1 | tr -d '"'"'"' \r\n')"
  [ -n "${OPENAI_API_KEY:-}" ] || { echo "no OpenAI key: export OPENAI_API_KEY or OPENAI_ENV_FILE=<path>" >&2; return 1; }
  export OPENAI_API_KEY
}

# Render a manifest with this file's settings (only the variables listed are substituted).
render() { envsubst '${OIDC_ISSUER} ${KC_REALM} ${TOOLS_NS} ${TOOLS_IMAGE} ${GW_NODE_PORT} ${UI_NODE_PORT} ${LOCAL_LLM_BASE_URL} ${LOCAL_LLM_MODEL}' < "$1"; }
