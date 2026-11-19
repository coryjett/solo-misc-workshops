# Agentic platform demo: modules

Bite-size, industry-neutral modules on one lab (agentregistry Enterprise, agentgateway Enterprise, kagent, Keycloak as the IdP). Pick the modules that match the audience and chain them. Every command in a module was tested on this lab.

**Personas** (password = username): `admin` platform team · `approver` approves registry changes · `eng-dev` engineering developer · `sales-dev` sales developer (also stands in for a partner or restricted user) · `auditor` read-only.

## Modules

| ID | Area | Module | Min |
|---|---|---|---|
| [S0](S0-preflight.md) | Setup | Pre-flight (do before every demo) | - |
| [P1](P1-platform-on-kubernetes.md) | Platform | What it looks like on Kubernetes (containers, control plane, data plane) | 5 |
| [P2](P2-observability.md) | Platform | Observability: one view of MCP, A2A and LLM traffic | 5 |
| [G1](G1-mcp-per-team-tools.md) | MCP | One MCP endpoint, tools filtered per team | 5 |
| [G2](G2-mcp-down-scoped-saas.md) | MCP | Down-scoped SaaS tools (mail and code-hosting stand-ins) | 8 |
| [G3](G3-mcp-guardrails.md) | MCP | Guardrails on tool calls: block destructive tools, mask PII | 4 |
| [G4](G4-token-flow-obo.md) | Identity | Token flow: on-behalf-of, the backend never sees the user's token | 4 |
| [A1](A1-a2a-who-calls-whom.md) | A2A | A2A: who can call whom | 8 |
| [L1](L1-llm-routing-failover.md) | LLM | LLM routing and failover (virtual models) | 5 |
| [L2](L2-llm-access-by-identity.md) | LLM | Model access by identity | 3 |
| [L3](L3-llm-prompt-guard.md) | LLM | Prompt-injection guard and prompt masking | 3 |
| [X1](X1-extension-points.md) | Platform | Extension points: plug your own logic into routing and policy | 5 |
| [R1](R1-registry-catalog.md) | Registry | What exists: catalog and shadow-IT discovery | 6 |
| [R2](R2-registry-team-scoping.md) | Registry | Who sees what in the catalog | 3 |
| [R3](R3-registry-approval.md) | Registry | A change request and its approval | 6 |
| [R4](R4-registry-publish-to-gateway.md) | Registry | Publish an MCP server to the gateway, self-service | 6 |
| [R5](R5-registry-deploy-to-runtime.md) | Registry | Deploy to an agent runtime (kagent) | 5 |
| [R6](R6-audit-trail.md) | Registry | The audit trail | 4 |

## Rehearse or step through a module

```bash
./modules/run-module.sh G2            # runs the module's commands, shows output
./modules/run-module.sh A1 --step     # one command at a time (Enter to continue), useful live
./modules/run-module.sh R4 --cleanup  # undo one module's changes (R3, R4, R5)
./modules/run-module.sh --all         # rehearsal: every module with commands; non-zero exit = something broke
```
Lines whose comment says "refused", "403" or "blocked" are expected refusals.

## Chaining rules

1. Start with **S0** (pre-flight). After that, modules can run in any order: each one sets up what it needs.
2. **R3, R4 and R5 change state** (approve, publish, deploy). Each card's **Cleanup** undoes just that module; `./reset.sh` (about 40 seconds) undoes everything. All other modules leave no state behind.
3. Keep a demo to about 40 minutes of modules; leave the rest for questions.
4. Show refusals in Terminal 2 (the live log), not in the UI.
5. Do it in the CLI, then show the same fact in the UI (each module has an **In the UI** step).

## Suggested chains

| Audience | Chain | Min |
|---|---|---|
| First look, gateway (any industry) | S0 > P1 > G1 > G2 > A1 > L1 > P2 | 40 |
| Security-led | S0 > G1 > G3 > G4 > A1 > L2 > L3 > P2 | 37 |
| Platform / Kubernetes team | S0 > P1 > G1 > G2 > X1 > P2 | 32 |
| AI/agent developers | S0 > G2 > A1 > L1 > L2 > X1 > P2 | 37 |
| Governance and catalog (registry) | S0 > R1 > R2 > R3 > R4 > R5 > R6 | 30 |
| Full platform (gateway + registry) | S0 > R1 > R3 > R4 > G2 > A1 > P2 > R6 | 41 |
| 20-minute executive | S0 > G2 > A1 > P2 | 21 |

## Recovery

| Symptom | Fix |
|---|---|
| 401 everywhere | Keycloak restarted: `./01-keycloak.sh`, retry |
| Agent call hangs | `kubectl --context kind-agentic-demo -n demo-tools rollout restart deploy agent-a agent-b agent-c` |
| Wrong tool counts | `./04-gateway-config.sh` |
| Node NotReady after a Docker restart | `./down.sh && ./up.sh` (about 15 min), then S0 |

## Related modules elsewhere in this repo

These agentic workshops run on their own environments. Reach for one when the audience needs a different deployment mode or a deeper dive than the lab gives. The modules here already cover the core of the older agw-governance-demo, which is superseded.

### Demos and deep dives

| Module | Use when | Needs | Where |
| :--- | :--- | :--- | :--- |
| Standalone gateway (VM / binary) | no Kubernetes, VMs or edge | agentgateway binary, no cluster | [workshops/agw-standalone-demo](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/agw-standalone-demo) |
| Three-product tour (registry, gateway, kagent, shared SSO) | a guided 50 minute build-up story instead of modules | own kind cluster, OpenAI key | [workshops/enterprise-demo](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/enterprise-demo) |
| kagent security | agent runtime RBAC, access policies, kagent UI | own cluster, Keycloak | [workshops/kagent-security](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/kagent-security) |
| End-to-end agent identity and delegation | identity teams want every hop secured, registry plus gateway | own kind cluster, Keycloak | [e2e-agent-identity-delegation](https://github.com/coryjett/solo-misc-workshops/tree/main/e2e-agent-identity-delegation), [workshops/agent-identity-token-exchange](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/agent-identity-token-exchange) |
| On-behalf-of token exchange | OBO with the built-in STS, or an external STS with opaque tokens | any cluster, Keycloak | [workshops/obo-token-exchange](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/obo-token-exchange), [flow13-token-exchange](https://github.com/coryjett/solo-misc-workshops/tree/main/flow13-token-exchange) |
| Okta token exchange | the IdP is Okta and a downstream (data platform) needs its own audience and scope | Okta tenant | [workshops/okta-token-exchange](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/okta-token-exchange) |
| Two credentials on one MCP route | user JWT plus a separate service credential (Snowflake example) | Snowflake account, IdP | [workshops/Snowflake-Token-Exchange-Workshop](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/Snowflake-Token-Exchange-Workshop) |
| External authorization with Cedar | policy-as-code teams, bring-your-own ext_authz | own cluster | [workshops/cedar-extauthz](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/cedar-extauthz) |
| Coding assistants through the gateway | developers' Claude Code LLM calls go through the gateway with per-user OIDC tokens | Okta (or other OIDC), Claude Code | [workshops/claude-code-llm-via-agw-oidc](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/claude-code-llm-via-agw-oidc) |
| Basic OIDC / JWT | first look at JWT auth on a route with Keycloak | any cluster | [workshops/oidc-integration](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/oidc-integration) |

### Reference material (to send, not to demo)

| Module | Use when | Where |
| :--- | :--- | :--- |
| Authentication patterns, with a decision flowchart | "which auth pattern fits us?" | [Agentgateway-AuthN-Patterns](https://github.com/coryjett/solo-misc-workshops/tree/main/Agentgateway-AuthN-Patterns) |
| Deployment models for shared clusters | platform team owns clusters, app teams own namespaces, multi-cluster | [Agentgateway-Deployment-Models](https://github.com/coryjett/solo-misc-workshops/tree/main/Agentgateway-Deployment-Models) |
| Requirements Q&A | answering an RFP or requirements list | [agentgateway-requirements-qa](https://github.com/coryjett/solo-misc-workshops/tree/main/agentgateway-requirements-qa) |
| OBO enablement guide | teaching token exchange from zero | [workshops/obo-token-exchange-enablement](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/obo-token-exchange-enablement) |

## Building a customer walkthrough

A demo is a walkthrough doc: the chain of modules plus one line of framing per module in the customer's words. Copy [WALKTHROUGH-TEMPLATE.md](WALKTHROUGH-TEMPLATE.md), keep it with the customer's notes, and never commit it here (no customer names in this repo).

## Setup

Copy `local.env.example` to `local.env` (gitignored) and fill in the license path and model endpoints, then `./up.sh` (about 15 minutes). `./down.sh` removes the cluster.
