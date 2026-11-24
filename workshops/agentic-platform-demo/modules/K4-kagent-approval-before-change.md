# K4 · A person approves before the agent changes anything

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K3](K3-kagent-gateway-policy-follows-the-agent.md) · Next: [K5](K5-kagent-who-may-build-and-use.md)
<!-- nav:end -->

**Area:** Agents · **Time:** 4 min

## Framing

- Read-only agents are easy to approve. Agents that change data are where risk sits.
- A prompt that says "ask first" is a request, not a control.
- Next: the platform stops the agent before a destructive tool runs.

**Proves:** `requireApproval` on one tool binding pauses the agent in the UI; the user approves or rejects, and the reason goes back to the agent.

**Needs:** [S0](S0-preflight.md), [K1](K1-kagent-agents-on-the-platform.md). Signed in as `eng-dev`.

## Steps

**1. Show the binding**

```bash
grep -n -B3 'requireApproval' deploy/kagent-lab.yaml
```
- Only `records_delete_customer_record` needs approval; lookups run freely.

**2. Ask for a delete**

- **New chat:** `Delete the customer record for C-1002.`
- **Expect:** lookups run, then a yellow box: "The agent is asking permission to run a tool", `records_delete_customer_record`.

**3. Reject with a reason**

- **Click:** Reject, type `Not without a change ticket`, **Send rejection**.
- **Expect:** the agent reports the delete was rejected and why.

## Say

- Approval is enforced by the runtime, per tool, and recorded with the session.
- The gateway still applies on top: the delete runs as the user, under their tool rules and guardrails.

## Cleanup

None: nothing was deleted.

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K3](K3-kagent-gateway-policy-follows-the-agent.md) · Next: [K5](K5-kagent-who-may-build-and-use.md)
<!-- nav:end -->
