# agentgateway standalone governance demo

Solo Enterprise for agentgateway as **one binary and one config file**, no Kubernetes, no containers on the
critical path: the shape it takes on a VM. One gateway governs LLM traffic, MCP tool traffic and plain API traffic
with one identity policy. Fictional "Acme" data; change `COMPANY` to rebrand.

| Capability | What the audience sees |
|---|---|
| Install and UI | `agentgateway -f config.yaml`; the UI at `:15000/ui` edits that same file (ClickOps now, commit the file for GitOps later) |
| Identity at the door | Every endpoint wants a JWT from the IdP (Keycloak stand-in; one line swaps in Entra). `groups` claim drives everything after |
| Cost and usage | USD budgets per user and per group, request and token rate limits, cost on every log line, UI cost dashboard |
| MCP gate | Three systems behind one `/mcp` (two MCP servers + a REST API via its OpenAPI spec). Tool list and calls filtered by group; destructive tools blocked; tool arguments inspected; PII masked in results; the backend sees the real user's token |
| Prompt inspection | Regex rules, an AI judge (webhook), builtin PII masking before any model sees the prompt |
| LLM routing | `auto`: self-hosted model first, cloud fallback on failure; premium model gated by group; per-user model list |
| Plain API | A REST route under the same JWT policy and group authorization. Nothing AI about it |
| The trail | One readable log: user, group, model asked vs answered, tokens, cost, tool, block reason (`./logs.sh`) |

Runbook for presenting: **`DEMO.md`** (chapters plus two run orders).

## Prerequisites

- macOS or Linux, `curl`, `python3` (3.11+), `node`/`npx` (MCP Inspector), `envsubst`, `lsof`, Docker (Keycloak only)
- A Solo license key: `export SOLO_LICENSE_KEY=...` or `LICENSE_SOURCE=<file with the key>` (also read from `./.license-source`)
- An OpenAI key (premium model, cloud fallback, AI judge): `export OPENAI_API_KEY=...` or `OPENAI_ENV_FILE=<.env>`
- A self-hosted, OpenAI-compatible model. Default: `https://llm.cjett.net/v1`, key from the macOS Keychain item
  `llm-cjett-net`. Any server works: `export LOCAL_LLM_BASE_URL=http://host:port/v1 LOCAL_LLM_MODEL=<name> LOCAL_LLM_KEY=<optional>`

Settings can go in a `demo.env` next to `env.sh` (gitignored). See `env.sh` for every option (ports, realm, versions).
The enterprise binary is installed to `~/.agentgateway/bin` on first run (`curl run.solo.io/agentgateway/install`).

## Run

```bash
./up.sh                         # Keycloak, tool servers, gateway (idempotent)
./verify.sh                     # every demo claim, PASS/FAIL; must end ALL-PASS
./inspector.sh support-agent    # MCP Inspector at http://127.0.0.1:6274 (re-run with another user to switch)
./logs.sh                       # readable audit trail
./down.sh [--purge]             # stop everything (--purge also deletes the DB, rendered config and secrets)
```

| URL | What |
|---|---|
| http://localhost:4000/mcp | MCP endpoint (Bearer token required) |
| http://localhost:4000/v1/chat/completions, /v1/messages | OpenAI- and Anthropic-compatible LLM endpoints |
| http://localhost:4000/api/ops/sites/site-112/hours | plain REST route |
| http://localhost:15000/ui | gateway UI (edits `gateway/config.yaml`) |
| http://localhost:8080 | Keycloak (admin / admin, realm `demo`) |

Users (password = username): `support-agent` (support: customer records + ops API, self-hosted models),
`ops-manager` (operations: inventory + ops API), `security-analyst` (security: all tools, plus `gpt-4.1-mini`).

Helpers: `./mcpcli.py <user> list|call <tool> '<json>'`, `./chat.py <user> <model> "<prompt>"`, `token <user>` after `. ./env.sh`.

## Layout

- `gateway/config.tmpl.yaml`: the whole gateway. Rendered to `gateway/config.yaml` by `gateway.sh` (ports and issuer
  substituted; secrets stay `$ENV` references the binary resolves at start).
- `gateway.sh`, `tools.sh`, `keycloak.sh`: one component each (`start|stop`). `up.sh`/`down.sh` call them.
- `tools/`: fictional backends (`records.py`, `inventory.py`, `ops_api.py`), the AI judge (`injection_guard.py`),
  the realm generator, the log formatter. They run from `.venv/` as plain processes on 127.0.0.1.
- `.run/` (pids, logs, `agentgateway.db`), `.secrets/` (fixed realm signing key): gitignored, created on first run.

## Swapping the IdP for Entra

In `gateway/config.tmpl.yaml`, every `jwtAuth` block: `issuer: https://login.microsoftonline.com/<tenant>/v2.0`,
`jwks.url: https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`, `audiences: [<app client id>]`. The CEL
rules use `jwt.groups`; Entra emits group object IDs unless the app registration is configured to emit group names.

## Known product notes (v2026.10.1)

- OpenAPI targets nest tool arguments by location: `{"path": {"site_id": "..."}}`, `{"query": {...}}`, `{"body": {...}}`.
- `$NAME` anywhere in the config file is expanded from the environment at start, comments included.
- The admin port (15000) always serves the UI; `ui: {}` additionally serves it on the gateway port.
- `mcpAuthorization` filters `tools/list` as well as `tools/call`; a denied call reports `Unknown tool`.
- Budgets are charged after the response from catalog prices; a model with no price is not charged. The self-hosted
  model gets an inline catalog entry here so it is.
- The AI judge is OpenAI by default (`JUDGE=local` in `tools.sh` to judge on the self-hosted model instead).
