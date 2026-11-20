# L4 · Token budgets per user

<!-- nav:start -->
[All modules](README.md) · [LLM](README.md#llm) · Previous: [L3](L3-llm-prompt-guard.md) · Next: [X1](X1-extension-points.md)
<!-- nav:end -->

**Area:** LLM · **Time:** 4 min

## Framing

- Individual users or teams can exhaust company budgets with unlimited requests.
- Tracking usage accurately is hard when clients manipulate identity headers easily.
- Next: a budget per user, and what happens when it runs out.

**Proves:** A token budget per user, keyed on the verified identity, so changing a header can't reset it.

- Each user has their own counter.
- Adapted from the workshop's [global rate limiting lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/rate-limiting/global-rate-limiting.md).

**Needs:** [S0](S0-preflight.md). Uses its own route localhost:8081/budget (model "budget", the self-hosted model) so no other module is ever rate limited.

## Steps

**1. Spend eng-dev's budget**

```bash
for i in 1 2 3 4; do llm_call eng-dev budget budget "What does an API gateway do?"; done
```
- `x-ratelimit-remaining` drains with each call, then `429 Too Many Requests`.
- `llm_call` is a plain chat completion to `/budget/v1/chat/completions` (see `env.sh`).

**2. Same question as sales-dev**

```bash
llm_call sales-dev budget budget "What does an API gateway do?"
```
- `200 OK` with a full budget: every user has their own counter.

Editor:
- `gateway/43-token-budget.yaml`: 100 input tokens per minute, keyed on `jwt.sub`.
- Attached to the `/budget` route only; same prompt guards as L3.

## In the UI

- Solo UI **Tracing** (5m): `POST /budget/...` rows, 200s then 429s.
- Solo UI **Dashboard**: token usage by model.
- Solo UI **Policies**: `llm-budget-per-user`.

## Expect

- eng-dev: one or two `200`s, then `429`. Remaining shows the budget before each call.
- If a new minute starts mid-loop, remaining jumps back to 100: say that is the window resetting.
- The limiter counts its own estimate of input tokens, not the model's reported usage.
- sales-dev: `200 OK` and its own `x-ratelimit-remaining`.

## Say

- Budgets by user, team (any JWT claim, e.g. jwt.groups) or tier.
- Request-based or token-based.
- Counters live in the gateway's rate limit service so they hold across gateway replicas.
- The claim is verified before counting, unlike a header such as X-User-ID which a client can change.
- Same policy shape works per model or per route.

## Don't claim

- Dollar budgets from this module (cost tracking is separate).
- Output-token limits (this counts input tokens).
- That the count equals the provider's billed tokens (it is the gateway's estimate).

## Cleanup

None: the config is part of the lab and the module only sends requests. Budget counters reset each minute.

<!-- nav:start -->
[All modules](README.md) · [LLM](README.md#llm) · Previous: [L3](L3-llm-prompt-guard.md) · Next: [X1](X1-extension-points.md)
<!-- nav:end -->
