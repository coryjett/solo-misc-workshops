# Agent Gateway Auth Patterns

Comprehensive authorization audit of all authentication and authorization patterns supported by [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/).

All patterns documented in **[agent-gateway-auth-patterns.md](agent-gateway-auth-patterns.md)** (single-page reference) and as individual pages linked below.

## Auth Patterns

| Category | Pattern | Description |
|---|---|---|
| **Inbound** | **[API Key Auth](flows/flow-08-api-key-auth.md)** | Authenticate with static API key validated against K8s secrets |
| | **[Basic Auth (RFC 7617)](flows/flow-09-basic-auth.md)** | Username/password with APR1-hashed credentials in K8s secrets |
| | **[BYO External Auth](flows/flow-10-byo-ext-auth.md)** | Delegate auth to your own gRPC ext auth service (LDAP, SAML, MFA, etc.) |
| | **[MCP OAuth + DCR](flows/flow-11-mcp-oauth-dcr.md)** | Dynamic Client Registration for MCP clients (Claude Code, VS Code) + OAuth flow |
| | **[Passthrough Token](flows/flow-05-passthrough.md)** | Gateway forwards client's existing token as-is — no validation or exchange |
| | **[Standard OIDC Authentication](flows/flow-01-oidc-auth.md)** | Authorization Code Flow → bearer JWT for all requests |
| **Token Exchange** | **[Double OAuth Flow](flows/flow-04-double-oauth.md)** | OIDC bearer + upstream token exchange in a single automated flow |
| | **[Gateway-Mediated Token Exchange](flows/flow-13-gateway-mediated-exchange.md)** | AGW automatically exchanges client JWT at built-in STS before forwarding — client never calls STS |
| | **[OBO Delegation (Dual Identity)](flows/flow-02a-obo-delegation.md)** | RFC 8693 exchange with `may_act` — STS JWT contains both `sub` (user) and `act` (agent) |
| | **[OBO Impersonation (Token Swap)](flows/flow-02b-obo-impersonation.md)** | RFC 8693 exchange without actor — STS JWT replaces IdP token, same `sub`, no `act` |
| **Upstream Auth** | **[Claim-Based Token Mapping](flows/flow-07-claim-based-mapping.md)** | Map JWT claims (sub, team) to per-user/group static tokens via CEL transformation |
| | **[Static Secret Injection](flows/flow-06-static-secret.md)** | Validate inbound JWT, replace with a shared static credential from K8s secret |
| **Credential Gathering** | **[Elicitation](flows/flow-03-elicitation.md)** | Out-of-band OAuth flow to collect upstream API credentials when they don't exist yet |
| **Authorization** | **[RBAC Tool-Level Access](flows/flow-12-rbac-tool-access.md)** | Per-tool access control via CEL expressions on JWT claims (layered on top of any auth flow) |

Plus a **[Decision Flowchart](flows/decision-flowchart.md)** to help choose the right pattern for a given scenario.

## Reference

- [Agent Gateway Docs](https://docs.solo.io/agentgateway/2.2.x/)
- [Enterprise API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/)
- [OSS API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/)
- [Helm Values Reference](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
