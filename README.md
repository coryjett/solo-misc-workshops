# solo-misc-workshops

Workshops, walkthroughs, and reference materials for Solo.io products.

## Contents

### Agent Gateway — Token Flow Diagrams

Visual guide covering all authentication and token exchange patterns supported by [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/).

- **[Token Flow Diagrams](token-flow-diagrams/)** — 15 sequence diagrams + decision flowchart
  - [Markdown guide with Mermaid diagrams](token-flow-diagrams/agent-gateway-token-flows.md)
  - [PDF with linked TOC](token-flow-diagrams/Agent-Gateway-Token-Flows.pdf)

| Flow | Description |
|------|-------------|
| 1 | Standard OIDC Authentication |
| 2a | OBO Delegation (dual identity — user + agent) |
| 2b | OBO Impersonation (token swap — user only) |
| 3 | Elicitation (out-of-band credential gathering) |
| 4 | Double OAuth (downstream + upstream in one flow) |
| 5 | Passthrough Token |
| 6 | Static Secret Injection |
| 7 | Claim-Based Token Mapping (CEL) |
| 8 | API Key Auth |
| 9 | Basic Auth (RFC 7617) |
| 10 | BYO External Auth (gRPC) |
| 11 | MCP OAuth + Dynamic Client Registration |
| 12 | RBAC Tool-Level Access Control (CEL) |
| 13 | Gateway-Mediated OIDC + Token Exchange |

### Agent Gateway — OBO Walkthroughs

Step-by-step guides for setting up On-Behalf-Of token exchange with Keycloak and Solo Enterprise for Agent Gateway 2.1.x.

- **[OBO Delegation](OBO-Complete-Guide-Delegation.md)** — STS issues OBO token with both `sub` (user) and `act` (agent). Requires `may_act` claim + actor token.
- **[OBO Impersonation](OBO-Complete-Guide-Impersonation.md)** — STS issues OBO token with `sub` only (no actor). Swaps IdP token for AGW-signed token.

### Agent Gateway — OIDC Integration

- **[OIDC Echo Server](Agentgateway-OIDC-Echo.md)** — OIDC auth with echo backend
- **[OIDC MCP Server](Agentgateway-OIDC-MCP.md)** — OIDC auth for MCP tool access
- **[OIDC MCP + OBO](Agentgateway-OIDC-MCP-OBO.md)** — OIDC auth with OBO token exchange for MCP

### Agent Gateway — MCP Authentication

- **[MCP Authentication API](agentgateway-enterprise/MCP-Authentication.md)** — How agentgateway adapts MCP OAuth traffic for authorization servers (Keycloak well-known endpoint rewriting, token validation, client registration proxying)

### Agent Gateway — Misc

- **[URL Rewrite for OAuth Protected Resource](test.md)** — HTTPRoute rule to rewrite `/.well-known/oauth-protected-resource/mcp` → `/.well-known/oauth-protected-resource` for MCP backends

### Source Repos (Reference)

- **[agentgateway-enterprise](agentgateway-enterprise/)** — Solo Enterprise for Agent Gateway source (enterprise extensions, security, traffic management, plugin architecture)
- **[gloo-gateway](gloo-gateway/)** — Solo Enterprise for kgateway and agentgateway source (Gateway API implementation, design docs, e2e testing)
