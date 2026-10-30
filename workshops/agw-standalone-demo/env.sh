# Source me:  . ./env.sh    Settings for the standalone agentgateway governance demo. Never echoes secrets.
# Settings come from the defaults below, then ./demo.env (gitignored; see demo.env.example). Values already
# exported in the shell are deliberately IGNORED for settings (another demo's env.sh may have set them);
# secrets (OPENAI_API_KEY, SOLO_LICENSE_KEY, LICENSE_SOURCE, OPENAI_ENV_FILE, LOCAL_LLM_KEY) are read from the shell.
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-${(%):-%x}}")" && pwd)"; export DEMO_DIR

export COMPANY="Acme"                 # realm display name, user emails
export AGW_VERSION="v2026.10.1"
export AGW_BIN="$HOME/.agentgateway/bin/agentgateway"
export KC_CONTAINER="agw-demo-keycloak"
export KC_REALM="demo"

# Ports (all bound to 127.0.0.1). Change if they clash.
export KC_PORT="8080"                 # Keycloak (the Entra stand-in)
export GW_PORT="4000"                 # agentgateway: MCP (/mcp), LLM (/v1/*), REST (/api/*), UI (/ui)
export ADMIN_PORT="15000"          # agentgateway admin + UI (local only)
export RECORDS_PORT="8101"       # tool servers
export INVENTORY_PORT="8102"
export OPSAPI_PORT="8103"
export GUARD_PORT="8104"           # AI prompt-injection judge (webhook guardrail)


# Self-hosted model: ANY OpenAI-compatible server (vLLM, Ollama, LM Studio, a GPU box, a gateway). Required.
# Set in demo.env: LOCAL_LLM_BASE_URL, LOCAL_LLM_MODEL, and LOCAL_LLM_KEY if the server wants one
# (or LOCAL_LLM_KEYCHAIN=<service> to read the key from the macOS Keychain). See demo.env.example.
export LOCAL_LLM_BASE_URL=""
export LOCAL_LLM_MODEL=""
export LOCAL_LLM_KEYCHAIN=""

# demo.env overrides the defaults above (and may hold the secrets listed at the top).
[ -f "$DEMO_DIR/demo.env" ] && set -a && . "$DEMO_DIR/demo.env" && set +a

export KC_URL="http://localhost:${KC_PORT}"
export OIDC_ISSUER="${KC_URL}/realms/${KC_REALM}"
export GW_URL="http://localhost:${GW_PORT}"
export MCP_URL="${GW_URL}/mcp"
export LLM_URL="${GW_URL}/v1/chat/completions"
export UI_URL="http://localhost:${ADMIN_PORT}/ui"
#   Secrets come from files/env, never from this file:
#   OPENAI_API_KEY (or OPENAI_ENV_FILE=<.env containing OPENAI_API_KEY=>)
#   LICENSE_SOURCE (path to a file holding the Solo license key, or a .env with SOLO_LICENSE_KEY=)

# Access token for a demo user (password = username). Usage: token support-agent
token() {
  local u="${1:-support-agent}"
  curl -s -X POST "${OIDC_ISSUER}/protocol/openid-connect/token" -d grant_type=password -d client_id=mcp-inspector \
    --data-urlencode "username=${u}" --data-urlencode "password=${u}" -d 'scope=openid' |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("access_token") or sys.exit("token error: %s" % d))'
}

load_license() {
  [ -n "${SOLO_LICENSE_KEY:-}" ] && { export ENTERPRISE_AGENTGATEWAY_LICENSE_KEY="$SOLO_LICENSE_KEY"; return 0; }
  local src="${LICENSE_SOURCE:-}"
  [ -n "$src" ] || src="$(sed -n 's/^LICENSE_SOURCE=//p' "$DEMO_DIR/.license-source" 2>/dev/null)"
  case "$src" in *.env) ENTERPRISE_AGENTGATEWAY_LICENSE_KEY="$(sed -n 's/^SOLO_LICENSE_KEY=//p' "$src" | tr -d '"'"'"' \r\n')" ;; ?*) ENTERPRISE_AGENTGATEWAY_LICENSE_KEY="$(tr -d ' \r\n' < "$src")" ;; esac
  [ -n "${ENTERPRISE_AGENTGATEWAY_LICENSE_KEY:-}" ] || { echo "no license: export SOLO_LICENSE_KEY or LICENSE_SOURCE=<path>" >&2; return 1; }
  export ENTERPRISE_AGENTGATEWAY_LICENSE_KEY
}

load_openai_key() {
  [ -n "${OPENAI_API_KEY:-}" ] && return 0
  [ -n "${OPENAI_ENV_FILE:-}" ] && OPENAI_API_KEY="$(sed -n 's/^OPENAI_API_KEY=//p' "$OPENAI_ENV_FILE" | head -1 | tr -d '"'"'"' \r\n')"
  [ -n "${OPENAI_API_KEY:-}" ] || { echo "no OpenAI key: export OPENAI_API_KEY or OPENAI_ENV_FILE=<path>" >&2; return 1; }
  export OPENAI_API_KEY
}

load_local_llm_key() {
  [ -n "$LOCAL_LLM_BASE_URL" ] && [ -n "$LOCAL_LLM_MODEL" ] || { echo "no self-hosted model: set LOCAL_LLM_BASE_URL and LOCAL_LLM_MODEL in demo.env (see demo.env.example)" >&2; return 1; }
  [ -n "${LOCAL_LLM_KEY:-}" ] && return 0
  if [ -n "$LOCAL_LLM_KEYCHAIN" ] && command -v security >/dev/null 2>&1; then   # macOS Keychain, optional
    LOCAL_LLM_KEY="$(security find-generic-password -s "$LOCAL_LLM_KEYCHAIN" -w 2>/dev/null || true)"
  fi
  export LOCAL_LLM_KEY   # may be empty: fine for servers that take no key
}

# Render config.yaml from gateway/config.tmpl.yaml with this file's settings (secrets stay $ENV references).
render() {
  envsubst '${OIDC_ISSUER} ${GW_PORT} ${ADMIN_PORT} ${RECORDS_PORT} ${INVENTORY_PORT} ${OPSAPI_PORT} ${GUARD_PORT} ${LOCAL_LLM_BASE_URL} ${LOCAL_LLM_MODEL} ${DEMO_DIR}' < "$1"
}
