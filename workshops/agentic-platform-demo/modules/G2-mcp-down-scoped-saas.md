# G2 · Down-scoped SaaS tools (mail and code-hosting stand-ins)

**Area:** MCP · **Time:** 8 min

**Proves:** One mail/files/meetings server and one code-hosting server, each user gets a different slice: mail off for some, read-only for others.

**Needs:** S0.

## Steps

```bash
export MCP_URL=$GW_URL/frontdoor/mcp
./mcp.py admin list            # 16 tools
./mcp.py eng-dev list          # 13: read mail but no send_mail; issues and PRs, no merge or delete
./mcp.py sales-dev list        # 9: no mail at all, code read-only
./mcp.py auditor list          # 5: code read-only, no mail server
./mcp.py sales-dev call workiq_send_mail '{"to":"x@example.com","subject":"s","body":"b"}'     # refused
./mcp.py eng-dev call github_merge_pull_request '{"repo":"data-pipeline","number":1}'           # refused
./mcp.py eng-dev call github_create_issue '{"repo":"data-pipeline","title":"Flaky test"}'       # allowed
```
Editor: `gateway/50-frontdoor-mcp.yaml` (four CEL lines on group, server and tool name).

## In the UI

MCP Inspector: `./inspector.sh sales-dev http://localhost:8081/frontdoor/mcp` (9 tools, no mail), then `eng-dev` (13). Solo UI **Policies**: `frontdoor-mcp-tool-authz`. Solo UI **Tracing** (5m): the `tools/call` rows for create_issue.

## Expect

16 / 13 / 9 / 5 tools; send_mail and merge return "Unknown tool"; create_issue returns CREATED.

## Say

- "Mail disabled for this group" is one line of policy.
- These are stand-ins; in production the target is the real remote server (M365, GitHub, a data vendor). Same policy, different host.

## Don't claim

- Per-user OAuth to third-party servers (each user consents once per vendor) is the Connectors feature: implemented on a branch, not released. Do not give a date.
