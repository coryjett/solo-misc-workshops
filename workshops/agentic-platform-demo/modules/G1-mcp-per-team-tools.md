# G1 · One MCP endpoint for many systems

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [P2](P2-observability.md) · Next: [G2](G2-mcp-down-scoped-saas.md)
<!-- nav:end -->

**Area:** MCP · **Time:** 3 min

## Framing

- Developers spend weeks building custom wrappers for existing internal APIs.
- Connecting modern AI tools to legacy systems requires complex integration work.
- Next: one endpoint serving MCP servers and a plain REST API as tools, with no code.

**Proves:** One MCP endpoint over different kinds of systems: two MCP servers and a plain REST API.

- The gateway turns the REST API into tools from its OpenAPI spec. No code, no MCP server to build.
- Per-person scoping is G2.

**Needs:** [S0](S0-preflight.md).

## Steps

**1. List eng-dev's tools**

```bash
export MCP_URL=$GW_URL/mcp
./mcp.py eng-dev list
```
- Tools from REST APIs appear alongside native MCP servers.
- Gateway generates schemas directly from OpenAPI specs.

**2. Call the REST API as a tool**

```bash
./mcp.py eng-dev call opsapi_get_site_hours '{"path":{"site_id":"site-112"}}'
```
- REST API responds to an MCP tool call.
- URL parameters go under `path`: the gateway built that schema from the spec.

**3. Try with no token**

```bash
./mcp.py none list   # 401
```
- `401`: no identity, no tools.

**4. Same thing in the UI**

- Solo UI **Composable MCP**: walk the Import step (OpenAPI spec to tools). Don't deploy.
- MCP Inspector: `./inspector.sh eng-dev http://localhost:8081/mcp`. Then open http://127.0.0.1:6274 and click **Connect**.
- **Tools** > `opsapi_get_site_hours`: the generated schema.
- Run it with `site_id` `site-112` inside the `path` field (or `site-205`).
- Solo UI **Policies**: `mcp-tool-authz`.

Editor:
- `gateway/11-mcp-federation.yaml`: three targets on one backend; `opsapi` is `protocol: OpenAPI`.
- `gateway/21-tool-authz.yaml`: which team sees which system (three CEL lines).

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
