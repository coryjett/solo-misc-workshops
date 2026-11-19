# G1 · One MCP endpoint, tools filtered per team

**Area:** MCP · **Time:** 5 min

**Proves:** Several MCP servers (including a REST API exposed as tools) behind one URL; each caller sees only the tools their group allows.

**Needs:** S0.

## Steps

```bash
export MCP_URL=$GW_URL/mcp
./mcp.py eng-dev list        # records + ops API tools
./mcp.py sales-dev list      # inventory + ops API tools, no records
./mcp.py none list           # 401: no token, no tools
```
Editor: `gateway/21-tool-authz.yaml` (three CEL lines on group and target).

## In the UI

MCP Inspector as each user: `./inspector.sh eng-dev http://localhost:8081/mcp`, then `./inspector.sh sales-dev ...`: the same tool lists as `mcp.py`, in an MCP client. Solo UI **Policies**: `mcp-tool-authz`. Solo UI **Composable MCP**: the wizard that turns an OpenAPI spec into MCP tools (the UI version of the ops API tools; walk the Import step, don't deploy).

## Expect

eng-dev sees `records_*` and `opsapi_*`; sales-dev sees no records tools; no token is 401.

## Say

- Same URL for everyone; what you get is decided at the gateway from the identity provider's groups.
- Filtering applies to tools/list AND tools/call, so a hidden tool cannot be called either.
- The ops API is a plain REST service turned into MCP tools from its OpenAPI spec, no code.

## Don't claim

- OpenAPI-to-MCP is Enterprise on Kubernetes (OSS has it in standalone only).

## Cleanup

None: this module only reads or calls things; it leaves no state behind.
