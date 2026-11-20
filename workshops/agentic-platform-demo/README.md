# Agentic Platform Demo

A demo kit for showing someone around the Solo.io agentic platform: **agentgateway Enterprise**, **agentregistry Enterprise** and **kagent**, on one local Kubernetes cluster. It is built for live demos, not as a workshop.

The content is industry-neutral. A demo is a chain of bite-size modules (3 to 8 minutes each) picked for the audience, so the same lab works for a security team, a platform team, AI developers or executives.

**Start here: [the module index](modules/)**: every module, suggested chains per audience, and the rules for chaining them.

## What's in the lab

| Piece | What it shows |
|---|---|
| agentgateway Enterprise | One gateway for MCP, A2A and LLM traffic: identity, per-tool authorization, guardrails, on-behalf-of tokens, model routing and failover, access logs and traces |
| agentregistry Enterprise | A catalog of agents, MCP servers and models with owners and data classes, team-scoped access, approvals, publishing to the gateway, deployment to runtimes, audit |
| kagent | An agent runtime the registry deploys to |
| Solo Enterprise UI | Routes, policies, tracing and dashboards for everything the gateway carries |
| Keycloak | The identity provider (stand-in for Entra ID, Okta or Ping) |
| Stand-in services | MCP servers (customer records, inventory, a REST API exposed as tools, mail/files/meetings, code hosting) and three A2A agents |

**Personas** (password = username): `admin` platform team · `approver` approves registry changes · `eng-dev` engineering developer · `sales-dev` sales developer (also stands in for a partner or restricted user) · `auditor` read-only.

## Modules at a glance

| Area | Modules |
|---|---|
| Platform | P1 what it looks like on Kubernetes · P2 observability · X1 extension points |
| MCP | G1 one endpoint for many systems · G2 down-scoped SaaS tools · G3 guardrails · G4 on-behalf-of token flow · G5 tool search for large catalogs |
| A2A | A1 who can call whom |
| LLM | L1 routing and failover · L2 model access by identity · L3 prompt-injection guard · L4 token budgets per user |
| Registry | R1 catalog and discovery · R2 team scoping · R3 approval · R4 publish to the gateway · R5 deploy to a runtime · R6 audit trail |
| Ecosystem (drafts) | D1 agentdesktop · D2 agentshield · D3 agentevals |

Each module card opens with framing to say before showing anything, then what it proves, the commands, the same fact in the UI, what to say, and what not to claim.

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
| `deploy/` | kagent install and unregistered "shadow" agents for discovery |
| `00-*.sh` to `04-*.sh` | Build steps run by `up.sh` |
| `env.sh` | Shared settings and helpers; reads `local.env` |
