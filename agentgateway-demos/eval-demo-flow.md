# Agentgateway eval demo flow (60 min)

Reusable agenda for a full-product agentgateway demo on the hosted demo env
(<https://agentgateway-demo.ai.glooplatform.com/ui/>), built for evaluators
governing autonomous agents. First run: Calendly, 2026-08-27.

**Frame with the prospect's own asks** (this one's, verbatim): observability,
policy enforcement, controls over the agent development loop, SIEM export.
**Arc:** run an agent loop, then progressively govern it.

| # | Catalog item | Min | Answers |
|---|---|---|---|
| 1 | Basic Routing (OpenAI, or Mock for a zero-key opener) — access-log line: model, tokens, latency, identity | 4 | orientation |
| 2 | Multi-Provider Routing (Bedrock) — Claude via Bedrock; live pro-tip: native Bedrock routes record **zero usage without `passthrough: detect`** | 8 | observability, AWS prod path |
| 3 | CrewAI Researcher-Writer — autonomous multi-step run, every LLM + tool call visible ("the black-box loop, opened") | 10 | agent-loop observability |
| 4 | MCP → Tool Modes (Code & Search) + OPA Authorization; Federated MCP in one breath | 9 | "the places it reaches" |
| 5 | Virtual Keys + JWT with Okta — identity on every log line; pro-tip: `jwtAuth.mode` defaults `optional`, set `strict` | 8 | policy + attribution |
| 6 | Advanced Webhook Guardrails — the customer's own policy service inline at the wire | 6 | policy enforcement |
| 7 | Rate Limiting (per-route / token) — runaway loop hits a structured 429 | 5 | loop containment |
| 8 | Generate LLM Load → dashboards → SIEM — access logs (tokens/cost/identity) → OTLP → collector → **their SIEM** | 10 | observability + SIEM |
| 9 | *Encore:* CrewAI Copilot (MCP Auth with OBO Token Exchange) | — | deep identity |

**Cut order if compressed:** 6 → the Okta half of 5 → 1 (open directly on Bedrock).

**Pro-tips to volunteer** (credibility with hands-on evaluators): the
`passthrough: detect` and `jwtAuth strict` items above, plus: cost/budget
features need the model cost catalog configured (file-based, air-gap friendly).

**Prep checklist:** click through the landing page tenant to confirm the
items above are green; AWS session creds for Bedrock
(`aws sso login --profile fe-sso && aws configure export-credentials
--profile fe-sso --format env > creds.env` — note they include a session
token, so the target must accept `AWS_SESSION_TOKEN`).

**Close:** enterprise trial key + lab environment options, next-session offer.
