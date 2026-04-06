# OBO Token Exchange — Enablement

Educational deep-dive on On-Behalf-Of (OBO) token exchange with [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/).

## What's Covered

- **[OBO Token Exchange](OBO-Token-Exchange.md)** — Comprehensive guide covering:
  - Why token exchange matters for agentic architectures
  - How the built-in STS works (RFC 8693)
  - Delegation (dual identity with `sub` + `act`) vs Impersonation (token swap)
  - Gateway-mediated vs agent-initiated exchange
  - Audience, scopes, and claim generation
  - STS configuration and deployment examples
  - Downstream policy enforcement
  - End-to-end walkthrough
  - JWT vs opaque token trade-offs
  - External IdP/STS provider integration guide (Keycloak, Okta, Entra ID, Google Cloud STS, Auth0, Ory Hydra, PingFederate)

## Related Workshops

- [Flow 13: Gateway-Mediated Token Exchange (JWT)](../flow13-token-exchange/flow13-gateway-mediated-token-exchange/) — Hands-on lab with Keycloak and AGW built-in STS
- [Flow 13b: External STS with Opaque Tokens](../flow13-token-exchange/flow13b-external-sts-opaque-token/) — Variant using an external STS that returns opaque tokens
- [OBO Delegation Walkthrough](../obo-token-exchange/OBO-Complete-Guide-Delegation.md) — Step-by-step Keycloak OBO delegation setup
- [OBO Impersonation Walkthrough](../obo-token-exchange/OBO-Complete-Guide-Impersonation.md) — Step-by-step Keycloak OBO impersonation setup

## References

- [Agent Gateway OBO Docs](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 7662 — Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
