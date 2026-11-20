# A1 · A2A: who can call whom

<!-- nav:start -->
[All modules](README.md) · [A2A](README.md#a2a) · Previous: [G5](G5-mcp-tool-search.md) · Next: [L1](L1-llm-routing-failover.md)
<!-- nav:end -->

**Area:** A2A · **Time:** 8 min

## Framing

- Teams struggle to manage which agents can communicate with each other.
- Hardcoding access rules inside each agent creates security risks and maintenance headaches.
- Next: users reach one agent; specialists accept only that agent, enforced at the gateway.

**Proves:** Users reach only the front agent; specialists accept only the front agent. Enforced at the gateway, not in the agents.

**Needs:** [S0](S0-preflight.md).

## Steps

**1. Fetch agent-a's card through the gateway**

```bash
UT=$(are_token sales-dev)
curl -s \
  -H "Authorization: Bearer $UT" $GW_URL/a2a/agent-a/.well-known/agent-card.json \
  | python3 -m json.tool
```
- The agent card: name, skills, protocol.
- Its `url` points at the gateway, not the agent's own address.

**2. Try agent-b's card as a user**

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $UT" $GW_URL/a2a/agent-b/.well-known/agent-card.json
```
- `403`: users cannot even read a specialist's card.

**3. Send a task to agent-a**

```bash
a2a_send sales-dev agent-a "Check the status of order 4512"
```
- agent-a calls agent-b and agent-c with its own identity.
- agent-b calling agent-c: `DENIED by gateway (HTTP 403)`.

Editor:
- `gateway/60-a2a.yaml`: two short policies.

## In the UI

- Solo UI **Routes**: `a2a-agent-a/b/c`, Active, with p95 latency.
- Solo UI **Policies**: `a2a-users-reach-agent-a`, `a2a-only-agent-a-calls-specialists`.
- Solo UI **Tracing** (5m): the `POST /a2a/agent-*` hops.

## Expect

```
agent-a handled: Check the status of order 4512
agent-a was called by: are-cli (sales-dev)
  -> agent-b: agent-b handled: ...
     agent-b was called by: agent-a (service-account-agent-a)
       -> agent-c: DENIED by gateway (HTTP 403)
  -> agent-c: agent-c handled: ...
```

## Say

- Each agent has its own identity (client credentials); the gateway decides who may call whom.
- Works for internal agents and for partners calling in (business-to-agent): a partner is just another identity with its own policy.

## Don't claim

- Authorization is per agent route, not per A2A method or skill. No native A2A content guardrails yet (use ext_proc). A2A rate limits count requests, not tokens.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [A2A](README.md#a2a) · Previous: [G5](G5-mcp-tool-search.md) · Next: [L1](L1-llm-routing-failover.md)
<!-- nav:end -->
