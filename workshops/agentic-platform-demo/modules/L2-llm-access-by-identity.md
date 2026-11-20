# L2 · Model access by identity

<!-- nav:start -->
[All modules](README.md) · [LLM](README.md#llm) · Previous: [L1](L1-llm-routing-failover.md) · Next: [L3](L3-llm-prompt-guard.md)
<!-- nav:end -->

**Area:** LLM · **Time:** 3 min

**Proves:** Premium models are locked per group; the same client gets different models depending on who calls.

**Needs:** [S0](S0-preflight.md).

## Steps

```bash
./chat.py eng-dev gpt-4.1-mini 'hi'                                    # 403: not allowed
./chat.py admin gpt-4.1-mini 'In one sentence, what is MCP?'           # allowed
```
Editor:
- `gateway/41-llm-identity.yaml`.

## In the UI

- Solo UI **Dashboard**: admin's gpt-4.1-mini call shows; the refused one does not.
- Show the 403 in Terminal 2.

## Expect

eng-dev gets `model_authorization_denied`; admin gets an answer.

## Say

- Token budgets and rate limits key on the same identity (user, team).

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [LLM](README.md#llm) · Previous: [L1](L1-llm-routing-failover.md) · Next: [L3](L3-llm-prompt-guard.md)
<!-- nav:end -->
