# Agent Gateway Auth Patterns

Comprehensive authorization audit of all authentication and authorization patterns supported by [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/).

## Formats

- **[Markdown with Mermaid diagrams](agent-gateway-token-flows.md)** — source of truth, viewable on GitHub with rendered sequence diagrams
- **[PDF with linked TOC](Agent-Gateway-Token-Flows.pdf)** — printable version with rendered diagrams, styled headers, and clickable table of contents

## Auth Patterns

| # | Pattern | Category | Description |
|---|---|---|---|
| 1 | **Standard OIDC Authentication** | Inbound | Authorization Code Flow → bearer JWT for all requests |
| 2a | **OBO Delegation (Dual Identity)** | Token Exchange | RFC 8693 exchange with `may_act` — STS JWT contains both `sub` (user) and `act` (agent) |
| 2b | **OBO Impersonation (Token Swap)** | Token Exchange | RFC 8693 exchange without actor — STS JWT replaces IdP token, same `sub`, no `act` |
| 3 | **Elicitation** | Credential Gathering | Out-of-band OAuth flow to collect upstream API credentials when they don't exist yet |
| 4 | **Double OAuth Flow** | Token Exchange | OIDC bearer + upstream token exchange in a single automated flow |
| 5 | **Passthrough Token** | Inbound | Gateway forwards client's existing token as-is — no validation or exchange |
| 6 | **Static Secret Injection** | Upstream Auth | Validate inbound JWT, replace with a shared static credential from K8s secret |
| 7 | **Claim-Based Token Mapping** | Upstream Auth | Map JWT claims (sub, team) to per-user/group static tokens via CEL transformation |
| 8 | **API Key Auth** | Inbound | Authenticate with static API key validated against K8s secrets |
| 9 | **Basic Auth (RFC 7617)** | Inbound | Username/password with APR1-hashed credentials in K8s secrets |
| 10 | **BYO External Auth** | Inbound | Delegate auth to your own gRPC ext auth service (LDAP, SAML, MFA, etc.) |
| 11 | **MCP OAuth + DCR** | Inbound | Dynamic Client Registration for MCP clients (Claude Code, VS Code) + OAuth flow |
| 12 | **RBAC Tool-Level Access** | Authorization | Per-tool access control via CEL expressions on JWT claims (layered on top of any auth flow) |
| 13 | **Gateway-Mediated Token Exchange** | Token Exchange | AGW automatically exchanges client JWT at built-in STS before forwarding — client never calls STS |

Plus a **Decision Flowchart** to help choose the right pattern for a given scenario.

## Regenerating the PDF

Requires Node.js 18+ and Puppeteer:

```bash
cd token-flow-diagrams
npm install --no-save puppeteer
node generate-pdf.js
```

## Reference

- [Agent Gateway Docs](https://docs.solo.io/agentgateway/2.2.x/)
- [Enterprise API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/)
- [OSS API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/)
- [Helm Values Reference](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
