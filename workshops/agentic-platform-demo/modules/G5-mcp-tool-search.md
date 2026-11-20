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

**1. List tools in search mode**

```bash
export MCP_URL=$GW_URL/search/mcp
./mcp.py eng-dev list
```
- Two tools only: `get_tool` and `invoke_tool`.

**2. Same user on /mcp**

```bash
MCP_URL=$GW_URL/mcp ./mcp.py eng-dev list
```
- Standard endpoint lists all six available tools.
- Search mode hides unused tool definitions.

**3. Look up one tool**

```bash
./mcp.py eng-dev call get_tool '{"name":"records_lookup_customer"}'
```
- Gateway returns detailed schema for one tool.
- Agents can discover capabilities on demand.

**4. Search with a partial name**

```bash
./mcp.py sales-dev call get_tool '{"name":"customer"}'
```
- Miss response lists only permitted tools.
- Agent recovers without guessing invalid names.

**5. Call a tool through invoke_tool**

```bash
./mcp.py eng-dev call invoke_tool \
  '{"name":"records_lookup_customer","arguments":{"customer_id":"C-1001"}}'
```
- Tool invocation returns redacted personal data.
- Policy filters output before delivery.

**6. Try a delete through invoke_tool**

```bash
./mcp.py eng-dev call invoke_tool \
  '{"name":"records_delete_customer_record","arguments":{"customer_id":"C-1001"}}'   # blocked
```
- Delete attempt is blocked by policy rules.
- Unauthorized actions are strictly prevented.

**7. Invoke a records tool as sales-dev**

```bash
./mcp.py sales-dev call invoke_tool \
  '{"name":"records_lookup_customer","arguments":{"customer_id":"C-1001"}}'   # refused
```
- HTTP 400 `unknown resource`: not sales-dev's tool.

**8. Same thing in the UI**

- MCP Inspector: `./inspector.sh eng-dev http://localhost:8081/search/mcp`. Then open http://127.0.0.1:6274 and click **Connect**.
- **Tools** > List: two tools.
- Run `get_tool` with `name` `records_lookup_customer`.
- Solo UI **Tracing** (5m): `get_tool` and `invoke_tool` rows.
- Solo UI **Policies**: `tool-search-authz`, `tool-search-guardrails`.

Editor:
- `gateway/44-tool-search.yaml`: `toolMode: Search` on the backend.
- Same team rules as G1, same guardrails as G3, same on-behalf-of as G4.

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
