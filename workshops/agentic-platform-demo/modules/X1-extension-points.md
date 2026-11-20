# X1 · Extension points: plug your own logic into routing and policy

<!-- nav:start -->
[All modules](README.md) · [Platform](README.md#platform) · Previous: [L4](L4-llm-token-budgets.md) · Next: [R1](R1-registry-catalog.md)
<!-- nav:end -->

**Area:** Platform · **Time:** 5 min

## Framing

- Routing decisions often depend on live business data outside the gateway.
- Hardcoding these complex logic rules into the gateway makes it rigid.
- Next: the hooks where your own service plugs into routing and policy.

**Proves:** When a decision depends on business data (bandwidth, entitlements, budgets), the gateway calls your service instead of you forking the gateway.

**Needs:** Talk track plus config; [L3](L3-llm-prompt-guard.md) shows one live callout (the injection-guard webhook).

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

**Then in the UI**

- Solo UI **Composable MCP**: the no-code path for APIs.
- The callout and ext_proc hooks are config only: show the YAML.

## Say

- Example: route to the cloud model only when a bandwidth API says the link is good; otherwise stay local.

## Don't claim

- The callout router and the conditional example are not wired into this lab; show them as config. Check the release you quote supports them before promising.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [Platform](README.md#platform) · Previous: [L4](L4-llm-token-budgets.md) · Next: [R1](R1-registry-catalog.md)
<!-- nav:end -->
