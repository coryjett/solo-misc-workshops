# K1 · Agents on the platform: kagent behind the gateway

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [A1](A1-a2a-who-calls-whom.md) · Next: [K2](K2-kagent-same-agent-different-user.md)
<!-- nav:end -->

**Area:** Agents · **Time:** 5 min

## Framing

- Teams are building agents, and each one wires its own model keys and tool access.
- Every agent becomes another unmanaged path to models and company data.
- Next: an agent that gets its model and its tools only through the gateway, as the signed-in user.

**Proves:** A kagent agent (Solo Enterprise for kagent, on Agent Substrate) uses the same governed MCP endpoint and LLM endpoint as people do, and signs in through the same IdP.

**Needs:** [S0](S0-preflight.md). kagent UI at http://localhost:8084.

## Steps

**1. Sign in as eng-dev**

- Open http://localhost:8084. It redirects to Keycloak: `eng-dev` / `eng-dev`.
- Same IdP, same users and groups as the gateway and registry modules.

**2. Walk the agent**

- **Agents**: the Overview diagram. A template (what it does) plus a harness (where it runs) make an agent; each chat runs as a sandboxed session.
- Open **platform-assistant**. Right panel:
  - **Model:** `kagent/via-gateway`
  - **Tools:** `kagent/governed-tools: records_...`, `inventory_...`, `opsapi_...`, `records_delete_customer_record`

**3. Show where those point**

```bash
grep -nE 'baseUrl|url:|tokenPassthrough|requireApproval' deploy/kagent-lab.yaml
```
- `baseUrl` and `url` are the gateway's HTTPS listener: `/v1` for the model, `/mcp` for tools.
- `tokenPassthrough: true`: calls carry the signed-in user's token, not an agent key.
- The token never enters the sandbox. The Substrate egress proxy swaps it in on the way out.

## Say

- The agent has no model key and no direct path to any system. Everything goes through the gateway as the person using it.
- Whatever the platform team set for people (tool access, guardrails, budgets, logs) now covers agents with no extra config.

## Cleanup

None: this module only reads; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [A1](A1-a2a-who-calls-whom.md) · Next: [K2](K2-kagent-same-agent-different-user.md)
<!-- nav:end -->
