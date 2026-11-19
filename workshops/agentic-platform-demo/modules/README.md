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
./modules/run-module.sh --all         # rehearsal: every module with commands; non-zero exit = something broke
```
Lines whose comment says "refused", "403" or "blocked" are expected refusals.

## Chaining rules

1. Always start with **S0** (pre-flight). Between back-to-back demos, run `./reset.sh`.
2. **P2** (observability) and **R6** (audit) go after the traffic modules they show.
3. **R3** before **R4** if you show both (R4 references the approved change).
4. Keep a demo to about 40 minutes of modules; leave the rest for questions.
5. Show refusals in Terminal 2 (the live log), not in the UI.
6. Do it in the CLI, then show the same fact in the UI (each module has an **In the UI** step): the CLI proves it is automatable, the UI shows operators can see it.

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

Use these when the audience needs a different deployment mode or a deeper dive. They run on their own environments.

| Module | Use when | Where |
|---|---|---|
| Standalone (VM / binary) gateway | No Kubernetes, or VMs and bare metal at the edge | [agw-standalone-demo](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/agw-standalone-demo) |
| Token exchange deep dive | Identity teams: delegation vs impersonation, multi-IdP | [agent-identity-token-exchange](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/agent-identity-token-exchange), [e2e-agent-identity-delegation](https://github.com/coryjett/solo-misc-workshops/tree/main/e2e-agent-identity-delegation) |
| External authorization with Cedar | Policy-as-code teams | [cedar-extauthz](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/cedar-extauthz) |
| kagent security | Agent runtime security (access policies, sandboxing) | [kagent-security](https://github.com/coryjett/solo-misc-workshops/tree/main/workshops/kagent-security) |

## Building a customer walkthrough

A demo is a walkthrough doc: the chain of modules plus one line of framing per module in the customer's words. Copy [WALKTHROUGH-TEMPLATE.md](WALKTHROUGH-TEMPLATE.md), keep it with the customer's notes, and never commit it here (no customer names in this repo).

## Setup

Copy `local.env.example` to `local.env` (gitignored) and fill in the license path and model endpoints, then `./up.sh` (about 15 minutes). `./down.sh` removes the cluster.
