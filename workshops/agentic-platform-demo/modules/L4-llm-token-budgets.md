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

```bash
T=$(are_token eng-dev)
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "eng-dev request $i: HTTP %{http_code}\n" $GW_URL/budget/v1/chat/completions -H "Authorization: Bearer $T" -H 'content-type: application/json' -d '{"model":"budget","max_tokens":20,"messages":[{"role":"user","content":"In one short sentence, what does an API gateway do?"}]}'; done   # a few 200s, then 429
curl -s -D - -o /dev/null $GW_URL/budget/v1/chat/completions -H "Authorization: Bearer $(are_token sales-dev)" -H 'content-type: application/json' -d '{"model":"budget","max_tokens":20,"messages":[{"role":"user","content":"In one short sentence, what does an API gateway do?"}]}' | grep -iE '^HTTP|x-ratelimit'   # sales-dev has its own budget
```
Editor:
- `gateway/43-token-budget.yaml`: 100 input tokens per minute, keyed on `jwt.sub`.
- Attached to the `/budget` route only; same prompt guards as L3.

## In the UI

- Solo UI **Tracing** (5m): `POST /budget/...` rows, 200s then 429s.
- Solo UI **Dashboard**: token usage by model.
- Solo UI **Policies**: `llm-budget-per-user`.

## Expect

- eng-dev: two or three 200s, then 429.
- The limiter counts its own estimate of input tokens (about 28 to 50 a request), not the model's reported usage. Resets each minute.
- sales-dev: `200 OK`, its own budget.
- Headers: `x-ratelimit-limit: 100`, `x-ratelimit-remaining` (before this request), `x-ratelimit-reset` (seconds left).
- Run it twice within a minute and eng-dev starts at 429: say that is the budget working.

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
