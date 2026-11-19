# A1 · A2A: who can call whom

**Area:** A2A · **Time:** 8 min

**Proves:** A front agent delegates to specialist agents; users can only reach the front agent, and specialists only accept the front agent. Enforced at the gateway, not in the agents.

**Needs:** S0.

## Steps

```bash
UT=$(are_token sales-dev)
curl -s -H "Authorization: Bearer $UT" $GW_URL/a2a/agent-a/.well-known/agent-card.json | python3 -m json.tool   # card, URL rewritten to the gateway
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $UT" $GW_URL/a2a/agent-b/.well-known/agent-card.json   # 403
MSG='{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"kind":"message","messageId":"m1","role":"user","parts":[{"kind":"text","text":"Check the status of order 4512"}]}}}'
curl -s -H "Authorization: Bearer $UT" -H 'Content-Type: application/json' -d "$MSG" $GW_URL/a2a/agent-a/ | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["parts"][0]["text"])'
```
Editor: `gateway/60-a2a.yaml` (two short policies).

## In the UI

Solo UI **Routes**: `a2a-agent-a/b/c`, Active, with p95 latency. Solo UI **Policies**: `a2a-users-reach-agent-a`, `a2a-only-agent-a-calls-specialists`. Solo UI **Tracing** (5m): the `POST /a2a/agent-*` hops.

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
