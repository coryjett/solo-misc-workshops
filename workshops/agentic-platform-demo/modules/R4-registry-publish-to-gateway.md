# R4 · Publish an MCP server to the gateway, self-service

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R3](R3-registry-approval.md) · Next: [R5](R5-registry-deploy-to-runtime.md)
<!-- nav:end -->

**Area:** Registry · **Time:** 6 min

## Framing

- Publishing new tools usually requires waiting for platform team tickets and delays.
- Self-service publishing risks bypassing essential security and governance policies entirely.
- Next: an approved server becomes a governed gateway route, self-service.

**Proves:** An approved server gets a governed endpoint without a platform ticket; the platform policy attaches itself.

**Needs:** [S0](S0-preflight.md). Admin window.

**Changes state:** publishes customer-records-mcp. Once per reset.

## Steps

Terminal: `pbcopy < catalog/gateway/access-rule.txt`
Registry UI (admin):
- **Catalog** > **customer-records-mcp** > **Deploy**.
- Runtime `mcp-gateway`, Deployment Name `customer-records-mcp`, Path Suffix `/records`.
- **+ Add Policy**: MCP Authorization, Allow, Match Expressions: paste.
- **Deploy MCP Server**.
Solo UI: **Routes** (new `/registry/records` route), **Policies** (`registry-backends-platform` now Active).
Then: `./inspector.sh eng-dev http://localhost:8081/registry/records` (3 tools, PII masked) and `sales-dev` (0 tools).

- Look for: a new route and backend; eng-dev gets 3 tools, sales-dev 0.

## Say

- The platform team built the gateway once; every publish after is self-service.

## Don't claim

- The instance shows "pending" while it serves (status reporting gap for the Virtual runtime, not the data path).

## Cleanup

```bash
as_user admin; arctl delete deployment default/customer-records-mcp
```
- Removes the route, backend and policy it created.

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R3](R3-registry-approval.md) · Next: [R5](R5-registry-deploy-to-runtime.md)
<!-- nav:end -->
