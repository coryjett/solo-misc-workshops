# P2 · Observability: one view of MCP, A2A and LLM traffic

**Area:** Platform · **Time:** 5 min

**Proves:** Every hop is logged and traced with the caller, the tool or agent, and the outcome.

**Needs:** Run after any traffic modules (G*, A1, L*) so data is fresh.

## Steps

Terminal 2 (from S0) shows one line per hop: `protocol=a2a|mcp|llm`, method, outcome, user, groups, trace id.

Solo UI http://localhost:8082:
1. **Routes:** every agent and tool server is a governed route, with p95 latency.
2. **Tracing** > time range **5m**: MCP rows (`initialize`, `tools/list`, `tools/call`), the LLM call (`POST /v1/chat/completions`), A2A hops (`POST /a2a/agent-a/*`). Open one row for payload and trace id.
3. **Dashboard:** tool requests, token usage by model, totals.

## Expect

Rows for the traffic you just generated.

## Say

- Logs and traces export over OpenTelemetry to the customer's own stack (Grafana, Splunk, Datadog).

## Don't claim

- Refusals (403s) show in the terminal log, not as errors in the UI. Show denials in Terminal 2.
