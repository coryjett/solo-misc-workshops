# G5 · Tool search: hundreds of tools without filling the context

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [G4](G4-token-flow-obo.md) · Next: [A1](A1-a2a-who-calls-whom.md)
<!-- nav:end -->

**Area:** MCP · **Time:** 5 min

## Framing

- Every tool schema lands in the model's context on every turn, before anyone asks anything.
- With hundreds of tools that costs tokens and makes picking the right tool harder.
- Next: agents that look tools up on demand, with the same rules still applied.

**Proves:** Agents see two tools (`get_tool`, `invoke_tool`) instead of every schema, so big catalogs don't fill the context.

- Team rules and guardrails still apply to what they find and call.
- Adapted from the workshop's [MCP tool mode lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/mcp/mcp-tool-mode-search.md).

**Needs:** [S0](S0-preflight.md). Same three systems as [G1](G1-mcp-per-team-tools.md) at a separate path, localhost:8081/search/mcp.

## Steps

```bash
export MCP_URL=$GW_URL/search/mcp
./mcp.py eng-dev list                                   # 2 tools: get_tool, invoke_tool
MCP_URL=$GW_URL/mcp ./mcp.py eng-dev list               # the same user sees 6 tools on /mcp
./mcp.py eng-dev call get_tool '{"name":"records_lookup_customer"}'      # schema of one tool, on demand
./mcp.py sales-dev call get_tool '{"name":"customer"}'                   # a miss lists only the tools sales-dev may use
./mcp.py eng-dev call invoke_tool '{"name":"records_lookup_customer","arguments":{"customer_id":"C-1001"}}'   # DOB and phone masked
./mcp.py eng-dev call invoke_tool '{"name":"records_delete_customer_record","arguments":{"customer_id":"C-1001"}}'   # blocked
./mcp.py sales-dev call invoke_tool '{"name":"records_lookup_customer","arguments":{"customer_id":"C-1001"}}'   # refused: not sales-dev's tool
```
Editor:
- `gateway/44-tool-search.yaml`: `toolMode: Search` on the backend.
- Same team rules as G1, same guardrails as G3, same on-behalf-of as G4.

## In the UI

- MCP Inspector: `./inspector.sh eng-dev http://localhost:8081/search/mcp`: two tools.
- Solo UI **Tracing** (5m): `get_tool` and `invoke_tool` rows.
- Solo UI **Policies**: `tool-search-authz`, `tool-search-guardrails`.

## Expect

- 2 tools vs 6.
- `get_tool`: name, description and argument schema.
- sales-dev miss: `no_match`, plus `available_tools` (inventory and ops only).
- Invoke: `[DOB REDACTED]`, `[PHONE REDACTED]`.
- Delete: "Blocked by policy".
- sales-dev invoking records: HTTP 400 "unknown resource".

## Say

- Search mode pays only for the tools used.
- The gateway still decides who may find and call what.
- A miss tells the agent what it may use, so it recovers without guessing. The workshop also has a Code mode (run_code in a sandboxed JS runtime) for chaining calls.

## Don't claim

- Semantic or fuzzy search: `get_tool` matches tool names, and a miss returns the allowed list.
- That it removes the need for authorization: it does not, the same team rules apply.
- Stateless session routing with several targets: on v2026.11.1 it fails with "unknown service get", so this lab uses stateful sessions.

## Cleanup

None: the config is part of the lab; the module only lists, looks up and calls tools (the delete is blocked).

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [G4](G4-token-flow-obo.md) · Next: [A1](A1-a2a-who-calls-whom.md)
<!-- nav:end -->
