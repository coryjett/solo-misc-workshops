# L1 · LLM routing and failover (virtual models)

<!-- nav:start -->
[All modules](README.md) · [LLM](README.md#llm) · Previous: [A1](A1-a2a-who-calls-whom.md) · Next: [L2](L2-llm-access-by-identity.md)
<!-- nav:end -->

**Area:** LLM · **Time:** 5 min

**Proves:** Clients call one model name; the gateway picks the real backend and fails over when one is unhealthy.

**Needs:** [S0](S0-preflight.md).

## Steps

```bash
./chat.py eng-dev auto 'In one sentence, what is an API gateway?'      # "auto" answers from the self-hosted model (~5s)
```
Editor: `gateway/40-models.yaml`: `auto` = failover priorities (self-hosted first, cloud second) + health eviction on 5xx/429.

## In the UI

Solo UI **Dashboard**: token usage by model. Solo UI **Tracing** (5m): the `POST /v1/chat/completions` row with the model that answered.

## Expect

An answer, with "answered by" naming the model.

## Say

- Flip the priorities for edge sites: cloud first, local fallback.
- Conditional and callout routing let an external signal pick the model (see X1).

## Don't claim

- Failover is shown as config, not forced live. Keep prompts short: the self-hosted model is a small lab box.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [LLM](README.md#llm) · Previous: [A1](A1-a2a-who-calls-whom.md) · Next: [L2](L2-llm-access-by-identity.md)
<!-- nav:end -->
