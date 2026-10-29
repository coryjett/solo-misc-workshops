# agentgateway governance demo

A self-contained, reusable demo of Solo Enterprise for agentgateway governing **both MCP tool traffic and LLM traffic**
through one gateway, on a local kind cluster. Fictional "Acme" data; change `COMPANY` to rebrand.

| Capability | What the audience sees |
|---|---|
| One governed MCP endpoint | Two MCP servers plus a legacy REST API (exposed as MCP tools from its OpenAPI spec) behind one URL |
| Identity-driven tool access | Tool list and tool calls filtered by IdP group (CEL on JWT claims) |
| Data guardrails (MCP) | PII masked in tool results (text and structured output); destructive tools blocked |
| On-Behalf-Of | The backend receives a gateway-minted token for the real user |
| LLM routing | `auto` model: self-hosted model first, cloud fallback on failure; premium model limited by group; per-user model list |
| Prompt-injection defense | Regex rules + an AI judge (webhook guardrail) catch obfuscated and other-language attacks; PII masked in prompts |
| Audit and traces | One readable log for MCP and LLM calls (user, tool or model, tokens, cost, block reason); traces in the Solo UI |
| Front ends | MCP Inspector, Open WebUI with SSO (forwards each user's token), plus `mcp.py` / `chat.py` |

Runbook for presenting: **`DEMO.md`**.

## Prerequisites

- Docker (about 12 GB free RAM for the cluster plus Open WebUI), `kind`, `kubectl`, `helm`, `envsubst`, `python3`, `node`/`npx` (MCP Inspector)
- A Solo license key: `export SOLO_LICENSE_KEY=...` or `export LICENSE_SOURCE=<file with the key>`
- An OpenAI key (premium model, cloud fallback, AI injection judge): `export OPENAI_API_KEY=...` or `OPENAI_ENV_FILE=<.env file>`
- A self-hosted, OpenAI-compatible model. Default: **Ollama** on this Mac (`ollama serve`, `ollama pull llama3.2`).
  Any other server works: `export LOCAL_LLM_BASE_URL=https://host/v1 LOCAL_LLM_MODEL=<name> LOCAL_LLM_KEY=<optional>`

Settings can also go in a `demo.env` file next to `env.sh` (gitignored). See `env.sh` for every option (ports, cluster name, realm, versions).

## Run

```bash
./up.sh                         # cluster, Keycloak, tool servers, agentgateway, gateway config, Open WebUI (idempotent)
./verify.sh                     # every demo claim, PASS/FAIL; must end ALL-PASS
./inspector.sh support-agent    # MCP Inspector at http://127.0.0.1:6274 (re-run with another user to switch)
```

| URL | What |
|---|---|
| http://localhost:8081/mcp | MCP endpoint (Bearer token required) |
| http://localhost:8081/v1/chat/completions | OpenAI-compatible LLM endpoint |
| http://localhost:3000 | Open WebUI (sign in with "Acme SSO") |
| http://localhost:8082 | Solo Enterprise UI (Tracing) |
| http://keycloak.localhost:8080 | Keycloak (admin / admin) |

Users (password = username): `support-agent` (support: customer records + ops API, local models),
`ops-manager` (operations: inventory + ops API, local models), `security-analyst` (security: all tools, plus `gpt-4.1-mini`).

Helpers: `./mcp.py <user> list|call <tool> '<json>'`, `./chat.py <user> <model> "<prompt>"`, `./logs.sh`
(live audit trail), `./outage.sh on|off` (simulate the local model failing), `./down.sh` (delete everything).

## Layout

- `00-04*.sh`, `up.sh`: setup. `gateway/*.yaml`: all gateway configuration, rendered with `env.sh` settings (`render`).
- `tools/`: fictional tool servers (`records.py`, `inventory.py`, `ops_api.py`), the AI injection guard
  (`injection_guard.py`), the realm generator, and the log formatter.
- `.secrets/` (gitignored, created on first run): the realm's fixed signing key, the Open WebUI client secret and session key.

## Troubleshooting

- **`token uses the unknown key`**: Keycloak's signing key changed (only if `.secrets/` was deleted). The controller
  keeps fetched JWKS in a ConfigMap that survives restarts; delete it and restart the controller:
  `kubectl --context kind-agw-demo -n agentgateway-system get cm -o name | grep jwks-store | xargs kubectl --context kind-agw-demo -n agentgateway-system delete`
  then `kubectl --context kind-agw-demo -n agentgateway-system rollout restart deploy/enterprise-agentgateway` (about 75 s to propagate).
- **Docker restart**: `00-cluster.sh` pins the kind node's IP, so the cluster comes back by itself.
- **Local model slow**: the AI judge defaults to OpenAI for that reason (`JUDGE=local` in `gateway/42-injection-guard.yaml` to judge on-prem).
- **Open WebUI prompt sizes**: built-in tools, memories, notes and code interpreter are disabled in `openwebui.sh`; with them on, every chat sends about 4.5k extra tokens.
- **First request during an outage fails**; later ones fail over (the local model is evicted for 30 s).

## Known product notes (v2026.10.1)

- Solo UI tracing: the "User ID" column is empty for agentgateway spans; the user is in the span attributes (`enduser.name`) and the access log.
- Webhook guardrail responses must wrap the decision in `{"action": ...}`; a bare `{}` is treated as unparseable (fail-open passes it).
- Cross-namespace guardrail webhooks need a ReferenceGrant; an unresolved ref takes the model offline (404).
- A model-level retry policy can't target an `AgentgatewayModel`.
