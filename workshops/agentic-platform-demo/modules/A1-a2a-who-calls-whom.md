# A1 · A2A: who can call whom

<!-- nav:start -->
[All modules](README.md) · [A2A](README.md#a2a) · Previous: [G5](G5-mcp-tool-search.md) · Next: [K1](K1-kagent-agents-on-the-platform.md)
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
Talking points, hop by hop:
- sales-dev reaches agent-a: allowed, sales-dev is in a user group.
- agent-a calls agent-b and agent-c with its own token, not the user's.
- The "called by" lines show who each agent saw: the user, then `agent-a`.
- agent-b tries agent-c: `DENIED by gateway (HTTP 403)`.
- agent-b's token says `azp: agent-b`; agent-c's route only accepts `agent-a`.
- agent-c never sees that request. The gateway stops it.

Where the policy is:
- `gateway/60-a2a.yaml`, two short policies on the agent routes.
- `a2a-users-reach-agent-a`: user groups may call agent-a.
- `a2a-only-agent-a-calls-specialists`, on agent-b and agent-c routes: one CEL line.

```yaml
matchExpressions:
  - "jwt.azp == 'agent-a'"
```
- `azp` is the client the token was issued to: each agent has its own Keycloak client.
- No code in the agents: a buggy or compromised agent-b still cannot reach agent-c.
- Same policies in the Solo UI under **Policies** (next beat).

The output looks like this:

```text
agent-a handled: Check the status of order 4512
agent-a was called by: are-cli (sales-dev)
  -> agent-b: agent-b handled: ...
     agent-b was called by: agent-a (service-account-agent-a)
       -> agent-c: DENIED by gateway (HTTP 403)
  -> agent-c: agent-c handled: ...
```

**4. Let agent-b call agent-c**

```bash
kubectl --context kind-agentic-demo apply -f modules/files/a1-allow-b-to-c.yaml
a2a_send sales-dev agent-a "Check the status of order 4512"
```
- Wait about 5 seconds after the apply, then send.
- agent-b's hop now reads `agent-c was called by: agent-b`, where it said `DENIED` before.
- One extra policy on agent-c's route: `jwt.azp == 'agent-b'`. No agent change, no redeploy.
- Rules on a route add up: agent-a keeps its access, users still get 403.
- Show it: `modules/files/a1-allow-b-to-c.yaml`.
- Undo it before moving on (Cleanup below).

**5. Same thing in the UI**

- Solo UI **Routes**: `a2a-agent-a/b/c`, Active, with p95 latency.
- Solo UI **Policies**: `a2a-users-reach-agent-a`, `a2a-only-agent-a-calls-specialists`.
- Solo UI **Tracing** (5m): the `POST /a2a/agent-*` hops.

Editor:
- `gateway/60-a2a.yaml`: two short policies.

## Say

- Each agent has its own identity (client credentials); the gateway decides who may call whom.
- Works for internal agents and for partners calling in (business-to-agent): a partner is just another identity with its own policy.

## Don't claim

- Authorization is per agent route, not per A2A method or skill. No native A2A content guardrails yet (use ext_proc). A2A rate limits count requests, not tokens.

## Cleanup

```bash
kubectl --context kind-agentic-demo -n agentgateway-system delete enterpriseagentgatewaypolicy a2a-agent-b-may-call-agent-c --ignore-not-found
```
- Back to the baseline: agent-b to agent-c is denied again. `reset.sh` also removes it.

<!-- nav:start -->
[All modules](README.md) · [A2A](README.md#a2a) · Previous: [G5](G5-mcp-tool-search.md) · Next: [K1](K1-kagent-agents-on-the-platform.md)
<!-- nav:end -->
