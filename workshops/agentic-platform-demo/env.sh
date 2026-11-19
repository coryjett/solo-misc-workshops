# Source me:  . ./env.sh
# Shared settings for the agentic platform demo (agentregistry Enterprise + agentgateway Enterprise + kagent). Safe to source repeatedly.
# Never echoes secrets.

export DEMO_DIR="${DEMO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)}"
# Machine-specific settings (license path, model endpoints and keys) live in local.env, which is gitignored.
# Copy local.env.example to local.env and fill it in.
[ -f "$DEMO_DIR/local.env" ] && . "$DEMO_DIR/local.env"
export CLUSTER=agentic-demo
export KCTX="kind-${CLUSTER}"
export KIND_NODE_IMAGE="kindest/node:v1.33.1"

export ARE_VERSION=2026.9.0          # helm chart version (no leading v)
export ARE_IMAGE_TAG=v2026.9.0       # server image tag
export ARCTL_VERSION=v2026.9.0

# Host ports (kind extraPortMappings -> NodePorts). Change here and rerun 00-02 if one is taken.
export KC_HOST_PORT=8090      KC_NODE_PORT=30090
export ARE_HOST_PORT=12121    ARE_NODE_PORT=31212
export MCP_HOST_PORT=31313    MCP_NODE_PORT=31313
export GW_HOST_PORT=8081      GW_NODE_PORT=30081    # agentgateway proxy (MCP + LLM endpoint)
export UI_HOST_PORT=8082      UI_NODE_PORT=30082    # Solo Enterprise UI
export AGW_VERSION=v2026.10.1
export TOOLS_NS=demo-tools
export TOOLS_IMAGE=agw-demo-tools:1
export GW_URL="http://localhost:${GW_HOST_PORT}"

# One issuer for browser, CLI and server. *.localhost resolves to loopback on the Mac with no DNS,
# and a CoreDNS rewrite sends keycloak.localhost to the Keycloak Service inside the cluster.
export KC_HOSTNAME=keycloak.localhost
export KC_URL="http://${KC_HOSTNAME}:${KC_HOST_PORT}"
export KC_REALM=agentregistry-enterprise
export OIDC_ISSUER="${KC_URL}/realms/${KC_REALM}"
export ARE_UI_URL="http://localhost:${ARE_HOST_PORT}"

export PATH="$HOME/.arctl/bin:$PATH"
export ARCTL_API_BASE_URL="${ARE_UI_URL}/v0"

# Mint an access token for a realm user (password = username unless given). Usage: are_token eng-dev
are_token() {
  local u="${1:-admin}" p="${2:-${1:-admin}}"
  curl -s -X POST "${OIDC_ISSUER}/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=are-cli \
    --data-urlencode "username=${u}" --data-urlencode "password=${p}" -d 'scope=openid profile email' |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("access_token") or sys.exit("token error: %s" % d))'
}

# Switch arctl identity. Usage: as_user approver
as_user() { ARCTL_API_TOKEN="$(are_token "$@")" && export ARCTL_API_TOKEN && echo "arctl now acting as ${1:-admin}"; }

# Approvals have no arctl subcommand at v2026.9.0; they are in the UI (Catalog) and at /v0/approve.
# are_pending                      list staged items (admins see all, others see their own)
# are_approve <kind> <name> <tag>  approve one item (also: ARE_ACTION=revoke|withdraw)
are_pending() { curl -s -H "Authorization: Bearer ${ARCTL_API_TOKEN:?run as_user first}" "$ARE_UI_URL/v0/approve" | python3 -m json.tool; }
are_approve() {
  curl -s -X POST -H "Authorization: Bearer ${ARCTL_API_TOKEN:?run as_user first}" -H 'Content-Type: application/json' \
    -d "{\"action\":\"${ARE_ACTION:-approve}\",\"items\":[{\"kind\":\"$1\",\"namespace\":\"${4:-default}\",\"name\":\"$2\",\"tag\":\"$3\"}]}" \
    "$ARE_UI_URL/v0/approve" | python3 -m json.tool
}
# Last N audit events from ClickHouse. Usage: are_audit 20
are_audit() {
  kubectl --context "$KCTX" -n agentregistry-system exec agentregistry-enterprise-clickhouse-shard0-0 -- \
    clickhouse-client --password password -d agentregistry -q "SELECT Timestamp, ScopeName, LogAttributes.actor.email AS actor, LogAttributes.event.activity AS activity, LogAttributes.event.action AS action, LogAttributes.resource.kind AS kind, LogAttributes.resource.name AS name, LogAttributes.approval.state AS approval FROM otel_logs_json WHERE ScopeName LIKE 'audit.%' ORDER BY Timestamp DESC LIMIT ${1:-20} FORMAT PrettyCompactMonoBlock"
}

# Inventory answer for "how many agents do we have": distinct names and versions per kind, then agents
# grouped by a label (default runtime; try team, data-class, model, lifecycle). Usage: are_inventory [label]
# Counts only what the current identity may read (as_user admin or auditor for the full picture).
are_inventory() {
  local by="${1:-runtime}"
  for k in agents mcpservers models skills prompts; do
    curl -s -H "Authorization: Bearer ${ARCTL_API_TOKEN:?run as_user first}" "$ARE_UI_URL/v0/$k?limit=500" |
      K="$k" python3 -c 'import json,os,sys; i=json.load(sys.stdin).get("items") or []; print("%-11s %3d distinct, %3d versions" % (os.environ["K"], len({x["metadata"]["name"] for x in i}), len(i)))'
  done
  curl -s -H "Authorization: Bearer $ARCTL_API_TOKEN" "$ARE_UI_URL/v0/agents?limit=500" | BY="$by" python3 -c '
import json,os,sys,collections
by=os.environ["BY"]; seen={}
for x in json.load(sys.stdin).get("items") or []:
    m=x["metadata"]; seen.setdefault(m["name"], set()).add((m.get("labels") or {}).get(by,"(unlabelled)"))
c=collections.Counter(v for s in seen.values() for v in s)
print("agents by %s:" % by, ", ".join("%s=%d" % kv for kv in sorted(c.items())))'
}

# Review a pending request against the newest approved tag of the same artifact (the UI approval card
# shows only name, tag and submitter). Usage: are_review [name] (default release-readiness-checker)
are_review() {
  local n="${1:-release-readiness-checker}"
  { curl -s -H "Authorization: Bearer ${ARCTL_API_TOKEN:?run as_user first}" "$ARE_UI_URL/v0/approve"; echo; \
    curl -s -H "Authorization: Bearer $ARCTL_API_TOKEN" "$ARE_UI_URL/v0/agents?limit=500"; } | N="$n" python3 -c '
import json,os,sys
n=os.environ["N"]; pend_raw,cat_raw=sys.stdin.read().split("\n",1)
pend=[i for i in (json.loads(pend_raw).get("items") or []) if i["name"]==n]
if not pend: sys.exit("no pending request for %s" % n)
p=pend[0]
who={"00000000-0000-0000-0000-0000000001%02d" % i: u for i,u in [(1,"admin"),(2,"approver"),(3,"eng-dev"),(4,"sales-dev"),(5,"auditor")]}
p["submittedBy"]="%s (%s)" % (who.get(p.get("submittedBy"),"?"), p.get("submittedBy"))
cur=sorted([i for i in (json.loads(cat_raw).get("items") or []) if i["metadata"]["name"]==n and i["metadata"]["tag"]!="latest"], key=lambda i:i["metadata"]["createdAt"])
c=cur[-1] if cur else {"metadata":{"tag":"(none)","labels":{}},"spec":{}}
refs=lambda s:sorted("%s:%s" % (r["name"],r.get("tag","")) for r in (s.get("mcpServers") or [])+(s.get("skills") or []))
print("%s  pending %s (submitted by %s at %s)  vs approved %s" % (n,p["tag"],p.get("submittedBy"),p.get("submittedAt","")[:19],c["metadata"]["tag"]))
cl,pl=c["metadata"].get("labels") or {},p.get("labels") or {}
for k in sorted(set(cl)|set(pl)):
    if cl.get(k)!=pl.get(k): print("  label %-12s %s  ->  %s" % (k, cl.get(k,"-"), pl.get(k,"-")))
for a,b,label in [(set(refs(c["spec"])),set(refs(p["spec"])),"refs")]:
    for r in sorted(b-a): print("  + %s %s" % (label,r))
    for r in sorted(a-b): print("  - %s %s" % (label,r))
for k in ("modelProvider","modelName"):
    if c["spec"].get(k)!=p["spec"].get(k): print("  spec.%-10s %s  ->  %s" % (k,c["spec"].get(k),p["spec"].get(k)))
ch=(p.get("annotations") or {}).get("catalog.example/changelog")
if ch: print("  changelog:",ch)'
}

# Load the license into LICENSE_KEY from LICENSE_SOURCE (set in local.env). Prints nothing secret.
load_license() {
  local src
  src="${LICENSE_SOURCE:-}"
  case "$src" in
    *.env) LICENSE_KEY="$(sed -n 's/^SOLO_LICENSE_KEY=//p' "$src" | tr -d '"'"'"' \r\n')" ;;
    ?*)    LICENSE_KEY="$(tr -d ' \r\n' < "$src")" ;;
  esac
  [ -n "${LICENSE_KEY:-}" ] || { echo "no license: set LICENSE_SOURCE=<path> in $DEMO_DIR/local.env" >&2; return 1; }
  export LICENSE_KEY
}

if [ -z "${ENV_QUIET:-}" ]; then
  if curl -s -o /dev/null -m 3 "${OIDC_ISSUER}/.well-known/openid-configuration"; then
    as_user admin >/dev/null 2>&1 && echo "arctl -> $ARCTL_API_BASE_URL as admin. as_user <name> to switch. UI: $ARE_UI_URL"
  else
    echo "Keycloak not reachable at $KC_URL yet; run ./up.sh"
  fi
fi

# ---- agentgateway side (agentgateway demo modules) ----
export MCP_URL="${GW_URL}/mcp"
export LLM_URL="${GW_URL}/v1/chat/completions"
export LOCAL_LLM_BASE_URL="${LOCAL_LLM_BASE_URL:-}"   # OpenAI-compatible self-hosted model, set in local.env
export LOCAL_LLM_MODEL="${LOCAL_LLM_MODEL:-default}"
export OPENAI_ENV_FILE="${OPENAI_ENV_FILE:-}"
# Access token for the gateway as a realm user (password = username). Usage: token eng-dev
token() { are_token "$@"; }
load_openai_key() {
  [ -n "${OPENAI_API_KEY:-}" ] && return 0
  [ -n "${OPENAI_ENV_FILE:-}" ] && OPENAI_API_KEY="$(sed -n 's/^OPENAI_API_KEY=//p' "$OPENAI_ENV_FILE" | head -1 | tr -d '"'"'"' \r\n')"
  [ -n "${OPENAI_API_KEY:-}" ] || { echo "no OpenAI key: export OPENAI_API_KEY or OPENAI_ENV_FILE=<path>" >&2; return 1; }
  export OPENAI_API_KEY
}
load_local_llm_key() { [ -n "${LOCAL_LLM_KEY:-}" ] || { [ -n "${LOCAL_LLM_KEYCHAIN_SERVICE:-}" ] && LOCAL_LLM_KEY="$(security find-generic-password -s "$LOCAL_LLM_KEYCHAIN_SERVICE" -w 2>/dev/null || true)"; }; export LOCAL_LLM_KEY; }
render() { envsubst '${OIDC_ISSUER} ${KC_REALM} ${KC_HOST_PORT} ${TOOLS_NS} ${TOOLS_IMAGE} ${GW_NODE_PORT} ${UI_NODE_PORT} ${LOCAL_LLM_BASE_URL} ${LOCAL_LLM_MODEL}' < "$1"; }
