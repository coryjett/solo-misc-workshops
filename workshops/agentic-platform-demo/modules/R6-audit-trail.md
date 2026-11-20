# R6 · The audit trail

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R5](R5-registry-deploy-to-runtime.md) · Next: [D1](D1-agentdesktop.md)
<!-- nav:end -->

**Area:** Registry · **Time:** 4 min

**Proves:** Every decision and every call has a name on it.

**Needs:** [S0](S0-preflight.md). Works anywhere in a chain: reset seeds the registry events, and the first step sends a fresh tool call. If [R3](R3-registry-approval.md) or [R4](R4-registry-publish-to-gateway.md) ran earlier, their approve and deploy rows show too.

## Steps

```bash
./modules/traffic.sh     # fresh tool calls, including lookup_customer
are_audit 15             # latest registry events: submit, approve (and deploy if R4/R5 ran)
```

Solo UI: **Tracing** > 15m > search `lookup_customer` > open a `tools/call` row: end user, tool, route.


## Expect

Span with the end user; audit rows for submit and approve.

## Say

- Registry events and gateway traces both export over OpenTelemetry.

## Don't claim

- Deploy ("materialize") rows carry no actor today; the approve row has the name.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R5](R5-registry-deploy-to-runtime.md) · Next: [D1](D1-agentdesktop.md)
<!-- nav:end -->
