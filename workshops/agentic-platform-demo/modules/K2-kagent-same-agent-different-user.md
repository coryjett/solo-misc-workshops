# K2 · Same agent, different user, different tools

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K1](K1-kagent-agents-on-the-platform.md) · Next: [K3](K3-kagent-gateway-policy-follows-the-agent.md)
<!-- nav:end -->

**Area:** Agents · **Time:** 4 min

## Framing

- One shared agent usually means one service account with the union of everyone's access.
- That turns the agent into the easiest way around access control.
- Next: one agent, two users, each gets exactly their own tools.

**Proves:** The gateway's per-user tool rules ([G1](G1-mcp-per-team-tools.md)) apply to an agent's tool calls, because the agent calls as the signed-in user.

**Needs:** [S0](S0-preflight.md), [K1](K1-kagent-agents-on-the-platform.md). Use a private browser window per user.

## Steps

**1. eng-dev asks for its tools**

- Sign in as `eng-dev`. **platform-assistant**, **New chat**:
  - `Which company system tools do you have? List their names only.`
- **Expect:** `records_lookup_customer`, `records_account_status`, `records_whoami`, `records_delete_customer_record`, `opsapi_get_site_hours`, `opsapi_get_on_call_staff`.

**2. sales-dev asks the same agent**

- New private window, sign in as `sales-dev`, same message.
- **Expect:** `inventory_check_stock`, `inventory_low_stock`, `opsapi_...`. No `records_` tools.

**3. Show who the gateway saw**

```bash
kubectl --context kind-agentic-demo -n agentgateway-system logs deploy/mcp-gateway --since=10m \
  | grep -E 'protocol=(mcp|llm)' | grep -oE 'protocol=[a-z]+|user="[a-z-]+"|http.status=[0-9]+' | paste - - - | tail -6
```
- Each agent call is logged under the person: `user="eng-dev"`, `user="sales-dev"`.

## Say

- Same agent, same template. The difference comes from the user's groups in Keycloak, checked by the gateway on every call.
- Engineering's rule: records plus the ops API. Sales: inventory plus the ops API. One CEL rule, written once for people and agents.

## Cleanup

None: chats stay in each user's history; only their owner sees them.

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K1](K1-kagent-agents-on-the-platform.md) · Next: [K3](K3-kagent-gateway-policy-follows-the-agent.md)
<!-- nav:end -->
