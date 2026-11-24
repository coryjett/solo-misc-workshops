# R6 · The audit trail

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R4](R4-registry-publish-to-gateway.md) · Next: [D1](D1-agentdesktop.md)
<!-- nav:end -->

**Area:** Registry · **Time:** 4 min

## Framing

- Auditors require clear records of who accessed data and what actions occurred.
- Reconstructing decision chains from disparate logs is time-consuming and incomplete.
- Next: one trail from who approved a change to every call that followed.

**Proves:** Every decision and every call has a name on it.

**Needs:** [S0](S0-preflight.md). Works anywhere in a chain.

- Reset seeds the registry events; the first step sends a fresh tool call.
- If [R3](R3-registry-approval.md) or [R4](R4-registry-publish-to-gateway.md) ran earlier, their rows show too.

## Steps

**1. Send fresh traffic**

```bash
./modules/traffic.sh
```
- Tool calls, including a customer lookup, for the trail.

**2. Show the latest registry events**

```bash
are_audit 15
```
- Rows for submit and approve, with who did it.
- Publish rows too if R4 ran.

Solo UI: **Tracing** > 15m > search `lookup_customer` > open a `tools/call` row: end user, tool, route.

## Say

- Registry events and gateway traces both export over OpenTelemetry.

## Don't claim

- Deploy ("materialize") rows carry no actor today; the approve row has the name.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R4](R4-registry-publish-to-gateway.md) · Next: [D1](D1-agentdesktop.md)
<!-- nav:end -->
