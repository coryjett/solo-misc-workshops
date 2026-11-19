# R6 · The audit trail

**Area:** Registry · **Time:** 4 min

**Proves:** Every decision and every call has a name on it.

**Needs:** After R3/R4 (and G-modules) for fresh data.

## Steps

Solo UI: **Tracing** > 15m > search `lookup_customer` > open a `tools/call` row: end user, tool, route.
Terminal: `are_audit 15` (registry events: submit, approve, materialize).

## Expect

Span with the end user; audit rows for submit and approve.

## Say

- Registry events and gateway traces both export over OpenTelemetry.

## Don't claim

- Deploy ("materialize") rows carry no actor today; the approve row has the name.
