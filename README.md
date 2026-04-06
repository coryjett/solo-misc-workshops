# solo-misc-workshops

Workshops, walkthroughs, and reference materials for Solo.io products.

## Contents

### Agent Gateway — Authentication Patterns

Comprehensive audit of all authentication patterns supported by [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/) — OIDC, OBO delegation/impersonation, elicitation, passthrough, static secrets, claim-based mapping, API key, basic auth, ext auth, MCP OAuth + DCR, mTLS, and gateway-mediated token exchange.

- **[Authentication Patterns guide with diagrams](Agentgateway-AuthN-Patterns/)**

### Agent Gateway — OBO Token Exchange Enablement

Deep-dive enablement on OBO token exchange — how the built-in STS works, delegation vs impersonation, gateway-mediated vs agent-initiated exchange, external IdP/STS provider integration (Keycloak, Okta, Entra ID, Google Cloud STS, Auth0, Ory Hydra, PingFederate), and downstream policy enforcement.

- **[OBO Token Exchange Enablement](obo-token-exchange-enablement/OBO-Token-Exchange.md)**

### Agent Gateway — Authorization Patterns

Comprehensive audit of all authorization patterns supported by [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/) — RBAC (MCP tool-level and LLM route access), rate limiting (LLM and MCP), guardrails (regex, moderation, Bedrock, Model Armor, webhook, multi-layered), and CORS.

- **[Authorization Patterns guide with diagrams](Agentgateway-AuthZ-Patterns/)**

### Agent Gateway — OBO Walkthroughs

Step-by-step guides for setting up On-Behalf-Of token exchange with Keycloak and Solo Enterprise for Agent Gateway 2.1.x.

- **[OBO Delegation](obo-token-exchange/OBO-Complete-Guide-Delegation.md)** — STS issues OBO token with both `sub` (user) and `act` (agent). Requires `may_act` claim + actor token.
- **[OBO Impersonation](obo-token-exchange/OBO-Complete-Guide-Impersonation.md)** — STS issues OBO token with `sub` only (no actor). Swaps IdP token for AGW-signed token.

### Agent Gateway — OIDC Integration

- **[OIDC Echo Server](oidc-integration/Agentgateway-OIDC-Echo.md)** — OIDC auth with echo backend
- **[OIDC MCP Server](oidc-integration/Agentgateway-OIDC-MCP.md)** — OIDC auth for MCP tool access
- **[OIDC MCP + OBO](obo-token-exchange/Agentgateway-OIDC-MCP-OBO.md)** — OIDC auth with OBO token exchange for MCP

### Agent Gateway — Gateway-Mediated Token Exchange

- **[Flow 13: Gateway-Mediated OIDC + Token Exchange with MCP](flow13-token-exchange/flow13-gateway-mediated-token-exchange/)** — End-to-end workshop: Keycloak OIDC auth with `ExchangeOnly` mode on `EnterpriseAgentgatewayPolicy`, AGW built-in STS (RFC 8693) automatically exchanges client JWT before forwarding to MCP backend — the client never calls the STS directly. Token-logging MCP server proves the STS-exchanged token (with `sub` + `act`) is what reaches the backend via `kubectl logs` and an `echo_token` tool. Covers `EnterpriseAgentgatewayParameters` (STS_URI/STS_AUTH_TOKEN), all three STS validators (subject/actor/api), and StreamableHTTP backend protocol.
- **[Flow 13b: External STS with Opaque Token Exchange](flow13-token-exchange/flow13b-external-sts-opaque-token/)** — Variant using an external RFC 8693-compliant STS that returns opaque tokens instead of JWTs. MCP server resolves identity via RFC 7662 introspection. Demonstrates the trade-off between self-contained JWTs and revocable opaque tokens.

### Agent Gateway — MCP Authentication

- **[MCP Authentication API](agentgateway-enterprise/MCP-Authentication.md)** — How agentgateway adapts MCP OAuth traffic for authorization servers (Keycloak well-known endpoint rewriting, token validation, client registration proxying)

### Agent Gateway — Misc

- **[URL Rewrite for OAuth Protected Resource](test.md)** — HTTPRoute rule to rewrite `/.well-known/oauth-protected-resource/mcp` → `/.well-known/oauth-protected-resource` for MCP backends

### Source Repos (Reference)

- **[agentgateway-enterprise](agentgateway-enterprise/)** — Solo Enterprise for Agent Gateway source (enterprise extensions, security, traffic management, plugin architecture)
- **[gloo-gateway](gloo-gateway/)** — Solo Enterprise for kgateway and agentgateway source (Gateway API implementation, design docs, e2e testing)
