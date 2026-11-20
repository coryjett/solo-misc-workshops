# G1 · One MCP endpoint for many systems

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [P2](P2-observability.md) · Next: [G2](G2-mcp-down-scoped-saas.md)
<!-- nav:end -->

**Area:** MCP · **Time:** 3 min

**Proves:** One governed MCP endpoint federates different kinds of backends: two MCP servers and a plain REST API that the gateway turns into MCP tools from its OpenAPI spec, with no code and no MCP server to build. Who sees which system is decided at the gateway (G2 goes deeper on per-person scoping).

**Needs:** [S0](S0-preflight.md).

## Steps

```bash
export MCP_URL=$GW_URL/mcp
./mcp.py eng-dev list                                                   # records_* from an MCP server, opsapi_* from a REST API
./mcp.py eng-dev call opsapi_get_site_hours '{"path":{"site_id":"site-112"}}'   # a REST endpoint, called as an MCP tool
./mcp.py none list                                                      # 401: no token, no tools
```
Editor: `gateway/11-mcp-federation.yaml` (three targets on one backend; `opsapi` is `protocol: OpenAPI` with the spec as a ConfigMap) and `gateway/21-tool-authz.yaml` (which team sees which system: three CEL lines on group and target).

## In the UI

Solo UI **Composable MCP**: the wizard that turns an OpenAPI spec into MCP tools, the UI version of the `opsapi` target (walk the Import step, don't deploy). MCP Inspector: `./inspector.sh eng-dev http://localhost:8081/mcp` lists the same tools; open `opsapi_get_site_hours` to show the schema the gateway generated. Solo UI **Policies**: `mcp-tool-authz`.

## Expect

- eng-dev: 6 tools, `opsapi_*` and `records_*` side by side.
- The call returns `{"site_id":"site-112","hours":"6am-11pm"}`: the REST API answered, the client only spoke MCP.
- No token: 401.

## Say

- Bring the APIs you already have: any REST service with an OpenAPI spec becomes MCP tools at the gateway, no wrapper service to write and run.
- One URL for every system, whether it speaks MCP or REST; clients and agents configure one endpoint.
- The gateway generated the tool schema from the spec: URL parameters arrive grouped under `path`.
- Each team sees only its systems (sales gets inventory instead of records). For per-person, per-action scoping of a SaaS server, see [G2](G2-mcp-down-scoped-saas.md).

## Don't claim

- OpenAPI-to-MCP is Enterprise on Kubernetes (open source has it in standalone only).

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [P2](P2-observability.md) · Next: [G2](G2-mcp-down-scoped-saas.md)
<!-- nav:end -->
