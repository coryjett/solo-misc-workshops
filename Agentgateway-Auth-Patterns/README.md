# Agent Gateway Auth Patterns

Comprehensive authorization audit of all authentication and authorization patterns supported by [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/).

All patterns documented in **[agent-gateway-token-flows.md](agent-gateway-token-flows.md)** (single-page reference) and as individual pages linked below.

## Auth Patterns

| # | Pattern | Category | Description |
|---|---|---|---|
| 1 | **[Standard OIDC Authentication](flows/flow-01-oidc-auth.md)** | Inbound | Authorization Code Flow → bearer JWT for all requests |
| 2a | **[OBO Delegation (Dual Identity)](flows/flow-02a-obo-delegation.md)** | Token Exchange | RFC 8693 exchange with `may_act` — STS JWT contains both `sub` (user) and `act` (agent) |
| 2b | **[OBO Impersonation (Token Swap)](flows/flow-02b-obo-impersonation.md)** | Token Exchange | RFC 8693 exchange without actor — STS JWT replaces IdP token, same `sub`, no `act` |
| 3 | **[Elicitation](flows/flow-03-elicitation.md)** | Credential Gathering | Out-of-band OAuth flow to collect upstream API credentials when they don't exist yet |
| 4 | **[Double OAuth Flow](flows/flow-04-double-oauth.md)** | Token Exchange | OIDC bearer + upstream token exchange in a single automated flow |
| 5 | **[Passthrough Token](flows/flow-05-passthrough.md)** | Inbound | Gateway forwards client's existing token as-is — no validation or exchange |
| 6 | **[Static Secret Injection](flows/flow-06-static-secret.md)** | Upstream Auth | Validate inbound JWT, replace with a shared static credential from K8s secret |
| 7 | **[Claim-Based Token Mapping](flows/flow-07-claim-based-mapping.md)** | Upstream Auth | Map JWT claims (sub, team) to per-user/group static tokens via CEL transformation |
| 8 | **[API Key Auth](flows/flow-08-api-key-auth.md)** | Inbound | Authenticate with static API key validated against K8s secrets |
| 9 | **[Basic Auth (RFC 7617)](flows/flow-09-basic-auth.md)** | Inbound | Username/password with APR1-hashed credentials in K8s secrets |
| 10 | **[BYO External Auth](flows/flow-10-byo-ext-auth.md)** | Inbound | Delegate auth to your own gRPC ext auth service (LDAP, SAML, MFA, etc.) |
| 11 | **[MCP OAuth + DCR](flows/flow-11-mcp-oauth-dcr.md)** | Inbound | Dynamic Client Registration for MCP clients (Claude Code, VS Code) + OAuth flow |
| 12 | **[RBAC Tool-Level Access](flows/flow-12-rbac-tool-access.md)** | Authorization | Per-tool access control via CEL expressions on JWT claims (layered on top of any auth flow) |
| 13 | **[Gateway-Mediated Token Exchange](flows/flow-13-gateway-mediated-exchange.md)** | Token Exchange | AGW automatically exchanges client JWT at built-in STS before forwarding — client never calls STS |

Plus a **[Decision Flowchart](flows/decision-flowchart.md)** to help choose the right pattern for a given scenario.

## Reference

- [Agent Gateway Docs](https://docs.solo.io/agentgateway/2.2.x/)
- [Enterprise API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/)
- [OSS API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/)
- [Helm Values Reference](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
