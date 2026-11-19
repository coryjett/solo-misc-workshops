# R6 · The audit trail

**Area:** Registry · **Time:** 4 min

**Proves:** Every decision and every call has a name on it.

**Needs:** S0. Works anywhere in a chain: reset seeds the registry events, and the first step sends a fresh tool call. If R3 or R4 ran earlier, their approve and deploy rows show too.

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
