# OBO Token Exchange — Enablement

Zero-to-implementation enablement on On-Behalf-Of (OBO) token exchange with [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/). Designed to take someone from no knowledge of token exchange to being able to implement and troubleshoot it.

## Who This Is For

- SEs and SAs who need to understand, demo, or implement OBO token exchange
- Anyone evaluating Agent Gateway's security capabilities for agentic architectures

## Learning Path

| Step | Topic | What You'll Learn |
|------|-------|-------------------|
| 1 | Prerequisites | OAuth 2.0, JWTs, OIDC, JWKS caching — the building blocks |
| 2 | Why Token Exchange? | The problem it solves (forwarded tokens vs shared service accounts) |
| 3 | Overview + Architecture | High-level diagram, how the built-in STS fits in |
| 4 | Delegation vs Impersonation | The two exchange modes and when to use each |
| 5 | Gateway-Mediated vs Agent-Initiated | Who calls the STS — zero code changes vs full control |
| 6 | End-to-End Walkthrough | Concrete scenario: Alice, an agent, and an MCP server |
| 7 | STS Configuration | Copy-paste deployment examples (5 scenarios) |
| 8 | Hands-on Labs | [Flow 13](../flow13-token-exchange/flow13-gateway-mediated-token-exchange/) (JWT) or [Flow 13b](../flow13-token-exchange/flow13b-external-sts-opaque-token/) (opaque) |
| 9 | Customer Conversations | Discovery questions, pattern selection, objection handling |
| 10 | Provider Integration | Okta, Entra ID, Keycloak, and 4 other providers |
| 11 | Troubleshooting | Common errors, debug commands, checklist |

## What's Covered

**[OBO Token Exchange](OBO-Token-Exchange.md)** — Single comprehensive guide covering:

**Foundations**
- Prerequisites — OAuth 2.0, JWT structure and validation, OIDC, JWKS caching (5-min default refresh), what an STS is
- Why token exchange matters for agentic architectures

**Core Concepts**
- How the built-in STS works (RFC 8693)
- Delegation (dual identity with `sub` + `act`) vs Impersonation (token swap)
- Gateway-mediated vs agent-initiated exchange
- Audience, scopes, and claim generation
- Three STS validators (subject, actor, API)

**Implementation**
- 5 deployment examples with copy-paste YAML (built-in STS + gateway-mediated, agent-initiated, non-MCP backend, external STS, elicitation + exchange)
- Downstream policy enforcement with CEL RBAC examples
- End-to-end walkthrough with Mermaid sequence diagrams

**Operational**
- Troubleshooting guide — exchange not triggering, STS 400/401, downstream rejection, CEL RBAC denials
- Debug commands (`kubectl exec`, JWT decoding, JWKS verification)
- Debugging checklist (7-step ordered process)

**Customer-Facing**
- Customer conversation guide — 8 discovery questions, pattern decision tree, 5 scenario-based recommendations, objection handling
- JWT vs opaque token trade-offs (FAQ)

**Provider Integration**
- External IdP/STS provider guide — Keycloak, Okta, Entra ID, Google Cloud STS, Auth0, Ory Hydra, PingFederate
- Provider comparison table and integration decision tree

## Related Workshops

- [Flow 13: Gateway-Mediated Token Exchange (JWT)](../flow13-token-exchange/flow13-gateway-mediated-token-exchange/) — Hands-on lab with Keycloak and AGW built-in STS
- [Flow 13b: External STS with Opaque Tokens](../flow13-token-exchange/flow13b-external-sts-opaque-token/) — Variant using an external STS that returns opaque tokens
- [OBO Delegation Walkthrough](../obo-token-exchange/OBO-Complete-Guide-Delegation.md) — Step-by-step Keycloak OBO delegation setup
- [OBO Impersonation Walkthrough](../obo-token-exchange/OBO-Complete-Guide-Impersonation.md) — Step-by-step Keycloak OBO impersonation setup

## References

- [Agent Gateway OBO Docs](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 7662 — Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [Setting up A2A OAuth User Delegation (Blog)](https://www.solo.io/blog/setting-up-a2a-oauth-user-delegation)
- [MCP Authorization Patterns for Upstream API Calls (Blog)](https://www.solo.io/blog/mcp-authorization-patterns)
