# Flow 2b: OBO Impersonation (Token Swap)

Agent exchanges the user's JWT for a new OBO token via RFC 8693, but without an actor token. The STS validates the user JWT, then issues a new JWT (signed by Agent Gateway) with the same `sub` and scopes --- no `act` claim. Downstream services trust the Agent Gateway issuer and see only the user's identity. The original IdP token is replaced, keeping user identity consistent without passing IdP tokens through the stack.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/)
> **API:** [Helm tokenExchange values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

### How it works

1. **User sends request with JWT** → Agent
2. **Agent sends RFC 8693 token exchange request** → `POST /token` (`grant_type=token-exchange`, `subject_token=user JWT`) — no actor token → Agent Gateway STS
3. **STS validates the user JWT** against the IdP's JWKS endpoint
4. **STS issues a new OBO token** (signed by AGW) with the same `sub` and scopes — no `act` claim → Agent
5. **Agent calls the MCP tool server** with the OBO token → MCP Tool Server
6. **MCP tool server enforces policies** on the user identity only (agent identity is not tracked)
7. **MCP tool server returns the response** → Agent
8. **Agent returns the result** → User

![Diagram](../images/2b-obo-impersonation.png)

Back to [Auth Patterns overview](../README.md)
