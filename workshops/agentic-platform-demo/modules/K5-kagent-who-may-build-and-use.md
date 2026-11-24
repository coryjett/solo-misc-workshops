# K5 · Who may build agents, who may only use them

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K4](K4-kagent-approval-before-change.md) · Next: [K6](K6-kagent-sandbox-and-egress.md)
<!-- nav:end -->

**Area:** Agents · **Time:** 4 min

## Framing

- Not everyone who uses an agent should be able to change what it does.
- Agent platforms often have one admin role, or none.
- Next: three IdP groups, three levels of access in kagent.

**Proves:** `EnterpriseKagentRBACPolicy` maps the same Keycloak groups to kagent access: admins manage everything, writers chat, readers only look.

**Needs:** [S0](S0-preflight.md), [K1](K1-kagent-agents-on-the-platform.md).

## Steps

**1. Show the policies**

```bash
kubectl --context kind-agentic-demo -n kagent get enterprisekagentrbacpolicies
grep -n -A3 'principals' deploy/kagent-lab.yaml
```
- `platform-admins` (are-admins): everything. `agent-users` (are-writers): view and chat. `agent-viewers` (are-readers): view and traces.

**2. auditor (are-readers)**

- Private window, sign in as `auditor`. Open **platform-assistant**.
- **Expect:** "Could not start this conversation · Not authorized".

**3. eng-dev (are-writers)**

- As `eng-dev`: chat works ([K2](K2-kagent-same-agent-different-user.md)).
- **Create**, **AgentTemplate**, name `eng-test`, **Create template**.
- **Expect:** "Could not create the agent template · Not authorized".

## Say

- Groups come from the IdP: Entra ID, Okta, Keycloak. One group change updates access to the registry, the gateway and kagent.

## Cleanup

None.

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K4](K4-kagent-approval-before-change.md) · Next: [K6](K6-kagent-sandbox-and-egress.md)
<!-- nav:end -->
