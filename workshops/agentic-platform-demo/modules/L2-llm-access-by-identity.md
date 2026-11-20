# L2 · Model access by identity

<!-- nav:start -->
[All modules](README.md) · [LLM](README.md#llm) · Previous: [L1](L1-llm-routing-failover.md) · Next: [L3](L3-llm-prompt-guard.md)
<!-- nav:end -->

**Area:** LLM · **Time:** 3 min

## Framing

- Organizations need to restrict expensive premium models to specific user groups.
- Enforcing these limits consistently across different applications is challenging to manage.
- Next: the premium model answers one team and refuses another.

**Proves:** Premium models are locked per group; the same client gets different models depending on who calls.

**Needs:** [S0](S0-preflight.md).

## Steps

**1. Ask for the premium model as eng-dev**

```bash
./chat.py eng-dev gpt-4.1-mini 'hi'
```
- `model_authorization_denied`: eng-dev may not use it.

**2. Same model as admin**

```bash
./chat.py admin gpt-4.1-mini 'In one sentence, what is MCP?'
```
- An answer: the admin's group allows it.

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
