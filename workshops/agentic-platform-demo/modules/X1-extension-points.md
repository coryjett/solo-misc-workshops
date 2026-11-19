# X1 · Extension points: plug your own logic into routing and policy

**Area:** Platform · **Time:** 5 min

**Proves:** When a decision depends on business data (bandwidth, entitlements, budgets), the gateway calls your service instead of you forking the gateway.

**Needs:** Talk track plus config; L3 shows one live callout (the injection-guard webhook).

## Steps

Three hooks, from lightest to heaviest:
1. **Callout router** (virtual model): the gateway calls your HTTP service to choose the model, with a fallback model and a response cache.
2. **Conditional virtual model:** CEL on the request picks the target:
```yaml
virtualModel:
  conditional:
    targets:
      - when: 'request.headers["x-link-tier"] == "high"'   # set by your network or an ext_proc
        modelRef: {name: cloud-model}
      - modelRef: {name: local-model}                        # default: last target, no when
```
3. **ext_proc / ext_authz:** your gRPC or HTTP service sees the request and can set headers, rewrite, allow or deny; results can be cached with a TTL.

## In the UI

Solo UI **Composable MCP** shows the no-code extension path for APIs; the callout and ext_proc hooks are config only.

## Expect

n/a (config walkthrough).

## Say

- Example: route to the cloud model only when a bandwidth API says the link is good; otherwise stay local.

## Don't claim

- The callout router and the conditional example are not wired into this lab; show them as config. Check the release you quote supports them before promising.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.
