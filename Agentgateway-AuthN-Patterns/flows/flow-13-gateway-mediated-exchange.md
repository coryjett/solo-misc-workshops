# Gateway-Mediated OIDC + Token Exchange

Agent Gateway handles OIDC authentication, then automatically exchanges the IdP token via RFC 8693 before forwarding to the agent. The agent never sees the original IdP token — it trusts only the STS issuer. The client never calls the STS directly; the gateway handles the exchange transparently.

Two variants depending on STS deployment:

### Variant A: Built-in STS

Uses AGW's built-in token exchange server (`enterprise-agentgateway:7777`). Configured via `ExchangeOnly` mode on `EnterpriseAgentgatewayPolicy`. The STS validates the user JWT (JWKS) and agent identity (K8s SA token), then issues a new JWT with both `sub` (user) and `act` (agent). Best for environments where AGW owns the trust domain.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/)
> **API:** [Helm tokenExchange values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

![Built-in STS](../images/13-gateway-mediated-builtin.png)

### Variant B: External STS (Entra ID)

Uses Microsoft Entra ID (Azure AD) as an external token exchange provider. The gateway exchanges the IdP token via Entra's OBO flow (`urn:ietf:params:oauth:grant-type:jwt-bearer`). Configured via `EntraTokenExchangeConfig` on the policy. Currently Entra is the only supported external provider; generic RFC 8693 external STS is not yet supported.

![External STS](../images/13-gateway-mediated-external.png)

Back to [Auth Patterns overview](../README.md)
