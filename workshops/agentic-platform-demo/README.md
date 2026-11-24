# Agentic Platform Demo

A demo kit for showing someone around the Solo.io agentic platform: **agentgateway Enterprise**, **agentregistry Enterprise** and **Solo Enterprise for kagent**, on one local Kubernetes cluster. It is built for live demos, not as a workshop.

The content is industry-neutral. A demo is a chain of bite-size modules (3 to 8 minutes each) picked for the audience, so the same lab works for a security team, a platform team, AI developers or executives.

**Start here: [the module index](modules/)**: every module, suggested chains per audience, and the rules for chaining them.

For a kagent-first conversation on its own small cluster, see [../kagent-enterprise-demo](../kagent-enterprise-demo): the same product, driven entirely from the kagent UI with built-in role switching.

## What's in the lab

| Piece | What it shows |
|---|---|
| agentgateway Enterprise | One gateway for MCP, A2A and LLM traffic: identity, per-tool authorization, guardrails, on-behalf-of tokens, model routing and failover, access logs and traces |
| agentregistry Enterprise | A catalog of agents, MCP servers and models with owners and data classes, team-scoped access, approvals, publishing to the gateway, audit |
| Solo Enterprise for kagent | Agents on Agent Substrate (gVisor sandboxes) that call models and tools through the gateway as the signed-in user; UI at http://localhost:8084 |
| Solo Enterprise UI | Routes, policies, tracing and dashboards for everything the gateway carries |
| Keycloak | The identity provider (stand-in for Entra ID, Okta or Ping) |
| Stand-in services | MCP servers (customer records, inventory, a REST API exposed as tools, mail/files/meetings, code hosting) and three A2A agents |

**Personas** (password = username): `admin` platform team · `approver` approves registry changes · `eng-dev` engineering developer · `sales-dev` sales developer (also stands in for a partner or restricted user) · `auditor` read-only.

## Modules at a glance

Each module is 3 to 8 minutes and stands on its own after [S0](modules/S0-preflight.md). Full index, suggested chains and chaining rules: [modules/](modules/).

### Setup

Get the lab ready and confirm it works before every demo.

- [S0 · Pre-flight (do before every demo)](modules/S0-preflight.md)

### Platform

How the platform runs on Kubernetes, how to see everything it carries, and where your own logic plugs in.

- [P1 · What it looks like on Kubernetes (containers, control plane, data plane)](modules/P1-platform-on-kubernetes.md) _(5 min)_
- [P2 · Observability: one view of MCP, A2A and LLM traffic](modules/P2-observability.md) _(5 min)_
- [X1 · Extension points: plug your own logic into routing and policy](modules/X1-extension-points.md) _(5 min)_

### MCP

One governed front door for tools: federation, per-user tool access, guardrails and large catalogs.

- [G1 · One MCP endpoint for many systems, including a REST API as tools](modules/G1-mcp-per-team-tools.md) _(3 min)_
- [G2 · Down-scoped SaaS tools (mail and code-hosting stand-ins)](modules/G2-mcp-down-scoped-saas.md) _(8 min)_
- [G3 · Guardrails on tool calls: block destructive tools, mask PII](modules/G3-mcp-guardrails.md) _(4 min)_
- [G5 · Tool search: hundreds of tools without filling the context](modules/G5-mcp-tool-search.md) _(5 min)_

### Identity

How the user's identity flows to backends without handing them the user's token.

- [G4 · Token flow: on-behalf-of, the backend never sees the user's token](modules/G4-token-flow-obo.md) _(4 min)_

### A2A

Agent-to-agent calls through the gateway, with each agent's identity checked on every hop.

- [A1 · A2A: who can call whom](modules/A1-a2a-who-calls-whom.md) _(8 min)_

### Agents

Solo Enterprise for kagent: agents that use models and tools through the gateway as the signed-in user, in sandboxes, with approvals and access by group.

- [K1 · Agents on the platform: kagent behind the gateway](modules/K1-kagent-agents-on-the-platform.md) _(5 min)_
- [K2 · Same agent, different user, different tools](modules/K2-kagent-same-agent-different-user.md) _(4 min)_
- [K3 · Gateway policy follows the agent: PII masking and prompt guard](modules/K3-kagent-gateway-policy-follows-the-agent.md) _(4 min)_
- [K4 · A person approves before the agent changes anything](modules/K4-kagent-approval-before-change.md) _(4 min)_
- [K5 · Who may build agents, who may only use them](modules/K5-kagent-who-may-build-and-use.md) _(4 min)_
- [K6 · Sandboxed agents: no outbound access until a policy allows it](modules/K6-kagent-sandbox-and-egress.md) _(5 min)_
- [K7 · Build an agent in the UI](modules/K7-kagent-build-an-agent.md) _(5 min)_
- [K8 · Follow an agent's work: tracing and analytics](modules/K8-kagent-tracing.md) _(3 min)_
- [K9 · The agent fleet: dashboard and Substrate](modules/K9-kagent-fleet-view.md) _(3 min)_

### LLM

One endpoint for models: routing and failover, access by identity, prompt guards and per-user token budgets.

- [L1 · LLM routing and failover (virtual models)](modules/L1-llm-routing-failover.md) _(5 min)_
- [L2 · Model access by identity](modules/L2-llm-access-by-identity.md) _(3 min)_
- [L3 · Prompt-injection guard and prompt masking](modules/L3-llm-prompt-guard.md) _(3 min)_
- [L4 · Token budgets per user](modules/L4-llm-token-budgets.md) _(4 min)_

### Registry

The catalog of agents, MCP servers and models: ownership, team scoping, approvals, publishing and audit.

- [R1 · What exists: the catalog](modules/R1-registry-catalog.md) _(5 min)_
- [R2 · Who sees what in the catalog](modules/R2-registry-team-scoping.md) _(3 min)_
- [R3 · A change request and its approval](modules/R3-registry-approval.md) _(6 min)_
- [R4 · Publish an MCP server to the gateway, self-service](modules/R4-registry-publish-to-gateway.md) _(6 min)_
- [R6 · The audit trail](modules/R6-audit-trail.md) _(4 min)_

### Ecosystem

Open-source tools beside the platform. Drafts, not rehearsed.

- [D1 · agentdesktop: the AI tools on the developer's laptop, governed (draft)](modules/D1-agentdesktop.md) _(8 min)_
- [D2 · agentshield: who can reach what, beside the gateway (draft)](modules/D2-agentshield.md) _(6 min)_
- [D3 · agentevals: score agents from their OpenTelemetry traces (draft)](modules/D3-agentevals.md) _(5 min)_

## Quick start

Requirements: Docker with enough memory for a single-node cluster running the full stack, `kind`, `kubectl`, `helm`, `python3`, `npx` (for MCP Inspector), a Solo Enterprise license, and an OpenAI-compatible model endpoint for the LLM modules.

```bash
cp local.env.example local.env        # fill in the license path and model endpoints (gitignored)
./up.sh                               # builds everything, about 15 minutes
./verify.sh && ./verify-gateway.sh    # both must end ALL-PASS
./reset.sh                            # back to the demo's starting state
```

Before each demo, run module **S0** (pre-flight). Between back-to-back demos, run `./reset.sh` (about 40 seconds). `./down.sh` removes the cluster.

## Rehearse a module

```bash
./modules/run-module.sh G2            # run a module's commands and show the output
./modules/run-module.sh A1 --step     # one command at a time, useful live
./modules/run-module.sh --all         # rehearse every module that has commands
```

## Building a demo for a specific audience

Copy [`modules/WALKTHROUGH-TEMPLATE.md`](modules/WALKTHROUGH-TEMPLATE.md), pick a chain, and add one line of framing per module in the audience's own words. Keep customer walkthroughs out of this repo.

## Layout

| Path | Contents |
|---|---|
| `modules/` | Module cards, index, walkthrough template, runner |
| `gateway/` | agentgateway configuration (Gateway, routes, backends, policies, models) |
| `catalog/`, `policies/` | Registry catalog and team access policies |
| `tools/` | Stand-in MCP servers, REST API and A2A agents (one image) |
| `deploy/` | Solo Enterprise for kagent install and the lab agent, wired to the gateway |
| `00-*.sh` to `04-*.sh` | Build steps run by `up.sh` |
| `env.sh` | Shared settings and helpers; reads `local.env` |
