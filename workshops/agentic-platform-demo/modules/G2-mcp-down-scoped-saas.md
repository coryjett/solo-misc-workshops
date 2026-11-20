# G2 · Down-scoped SaaS tools (mail and code-hosting stand-ins)

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [G1](G1-mcp-per-team-tools.md) · Next: [G3](G3-mcp-guardrails.md)
<!-- nav:end -->

**Area:** MCP · **Time:** 8 min

## Framing

- Users need access to specific data slices, not entire enterprise systems.
- Applying granular permission rules to external services is difficult and error-prone.
- Next: the same mail and code servers, a different slice for each person.

**Proves:** One mail/files/meetings server and one code-hosting server, each user gets a different slice: mail off for some, read-only for others.

**Needs:** [S0](S0-preflight.md).

## Steps

**1. List admin's tools**

```bash
export MCP_URL=$GW_URL/frontdoor/mcp
./mcp.py admin list
```
- Admin sees full set of sixteen tools.
- No restrictions apply to this identity.

**2. List eng-dev's tools**

```bash
./mcp.py eng-dev list
```
- Engineer sees thirteen tools with read mail access.
- Send mail and merge actions are hidden.

**3. List sales-dev's tools**

```bash
./mcp.py sales-dev list
```
- Sales sees nine tools without any mail access.
- Code repositories remain strictly read only.

**4. List the auditor's tools**

```bash
./mcp.py auditor list
```
- 5 tools: code read-only, no mail server at all.

**5. Try send_mail as sales-dev**

```bash
./mcp.py sales-dev call workiq_send_mail \
  '{"to":"x@example.com","subject":"s","body":"b"}'   # refused
```
- HTTP 400 `unknown resource`: for sales-dev the tool does not exist.

**6. Try a merge as eng-dev**

```bash
./mcp.py eng-dev call github_merge_pull_request \
  '{"repo":"data-pipeline","number":1}'   # refused
```
- Same refusal: eng-dev can open PRs, not merge them.

**7. Create an issue as eng-dev**

```bash
./mcp.py eng-dev call github_create_issue \
  '{"repo":"data-pipeline","title":"Flaky test"}'
```
- `CREATED`: writes the policy allows go through.

Editor:
- `gateway/50-frontdoor-mcp.yaml`: four CEL lines on group, server and tool name.

## In the UI

- MCP Inspector: `./inspector.sh sales-dev http://localhost:8081/frontdoor/mcp`: 9 tools, no mail.
- Same for `eng-dev`: 13 tools.
- Solo UI **Policies**: `frontdoor-mcp-tool-authz`.
- Solo UI **Tracing** (5m): the `tools/call` rows for create_issue.

## Expect

- 16 / 13 / 9 / 5 tools.
- send_mail and merge: HTTP 400 "unknown resource" (a hidden tool does not exist for that caller).
- create_issue: CREATED.

## Say

- "Mail disabled for this group" is one line of policy.
- These are stand-ins; in production the target is the real remote server (M365, GitHub, a data vendor). Same policy, different host.

## Don't claim

- Per-user OAuth to third-party servers (each user consents once per vendor) is the Connectors feature: implemented on a branch, not released. Do not give a date.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [G1](G1-mcp-per-team-tools.md) · Next: [G3](G3-mcp-guardrails.md)
<!-- nav:end -->
