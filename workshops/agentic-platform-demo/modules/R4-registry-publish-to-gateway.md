# R4 · Publish an MCP server to the gateway, self-service

**Area:** Registry · **Time:** 6 min

**Proves:** An approved server gets a governed endpoint without a platform ticket; the platform policy attaches itself.

**Needs:** S0. Admin window.

## Steps

Terminal: `pbcopy < catalog/gateway/access-rule.txt`
Registry UI (admin): **Catalog** > **customer-records-mcp** > **Deploy**: Runtime `mcp-gateway`, Deployment Name `customer-records-mcp`, Path Suffix `/records`, **+ Add Policy**: MCP Authorization, Allow, Match Expressions: paste. **Deploy MCP Server**.
Solo UI: **Routes** (new `/registry/records` route), **Policies** (`registry-backends-platform` now Active).
Then: `./inspector.sh eng-dev http://localhost:8081/registry/records` (3 tools, PII masked) and `sales-dev` (0 tools).

## Expect

New route and backend; eng-dev 3 tools, sales-dev 0.

## Say

- The platform team built the gateway once; every publish after is self-service.

## Don't claim

- The instance shows "pending" while it serves (status reporting gap for the Virtual runtime, not the data path).
