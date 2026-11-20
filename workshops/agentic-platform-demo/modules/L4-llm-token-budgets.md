# L4 · Token budgets per user

<!-- nav:start -->
[All modules](README.md) · [LLM](README.md#llm) · Previous: [L3](L3-llm-prompt-guard.md) · Next: [X1](X1-extension-points.md)
<!-- nav:end -->

**Area:** LLM · **Time:** 4 min

**Proves:** A per-user input-token budget enforced at the gateway, keyed on the verified identity (JWT subject), so a user cannot reset it by changing a header; each user has an independent counter. Adapted from the enterprise agentgateway workshop's [global rate limiting lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/rate-limiting/global-rate-limiting.md).

**Needs:** [S0](S0-preflight.md). Uses its own route localhost:8081/budget (model "budget", the self-hosted model) so no other module is ever rate limited.

## Steps

```bash
T=$(are_token eng-dev)
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "eng-dev request $i: HTTP %{http_code}\n" $GW_URL/budget/v1/chat/completions -H "Authorization: Bearer $T" -H 'content-type: application/json' -d '{"model":"budget","max_tokens":20,"messages":[{"role":"user","content":"In one short sentence, what does an API gateway do?"}]}'; done   # a few 200s, then 429
curl -s -D - -o /dev/null $GW_URL/budget/v1/chat/completions -H "Authorization: Bearer $(are_token sales-dev)" -H 'content-type: application/json' -d '{"model":"budget","max_tokens":20,"messages":[{"role":"user","content":"In one short sentence, what does an API gateway do?"}]}' | grep -iE '^HTTP|x-ratelimit'   # sales-dev has its own budget
```
Editor: `gateway/43-token-budget.yaml` (RateLimitConfig: type TOKEN, 100 input tokens per minute, key = CEL jwt.sub; policy attached to the llm-budget route only; the budget model keeps the same prompt guards as L3).

## In the UI

Solo UI Tracing (5m): the POST /budget/v1/chat/completions rows, 200s then 429s. Dashboard: token usage by model. Policies: `llm-budget-per-user`.

## Expect

- eng-dev: two or three 200s, then 429. The limiter counts its own estimate of input tokens (about 28 to 50 per request here), not the usage the model reports. Counters reset on each clock minute.
- sales-dev: `HTTP/1.1 200 OK` with `x-ratelimit-limit: 100`, `x-ratelimit-remaining` (the budget before this request) and `x-ratelimit-reset` (seconds to the next window): a separate budget.
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
