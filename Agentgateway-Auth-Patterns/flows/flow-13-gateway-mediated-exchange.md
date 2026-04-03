# Flow 13: Gateway-Mediated OIDC + Token Exchange

Agent Gateway handles OIDC authentication, then exchanges the IdP token with an external RFC 8693 Security Token Service (STS) before forwarding to the agent. The agent never sees the original IdP token — it trusts only the STS issuer. Decouples the IdP from downstream services and works with any compliant STS.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/)
> **API:** [Helm tokenExchange values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

```mermaid
sequenceDiagram
    participant User
    participant AGW as Agent Gateway<br/>(Proxy)
    participant IdP as OIDC Provider
    participant STS as External STS<br/>(RFC 8693)
    participant Agent as Agent / MCP Server

    Note over User,Agent: Phase 1: OIDC Authentication (at the Gateway)
    User->>AGW: Request (no token)
    AGW-->>User: 302 Redirect to IdP /authorize<br/>(client_id, redirect_uri, scope, state)
    User->>IdP: Login prompt
    IdP->>User: Credentials
    User->>IdP: Submit credentials
    IdP-->>AGW: 302 Callback with authorization code
    AGW->>IdP: POST /token (code, client_secret)
    IdP-->>AGW: User JWT (access_token + id_token)

    Note over User,Agent: Phase 2: RFC 8693 Token Exchange (external STS)
    AGW->>STS: POST /token<br/>(grant_type=urn:ietf:params:oauth:grant-type:token-exchange,<br/>subject_token=user JWT,<br/>subject_token_type=urn:ietf:params:oauth:token-type:jwt)
    STS->>STS: Validate user JWT<br/>Issue exchanged token
    STS-->>AGW: New token (signed by STS)

    Note over User,Agent: Phase 3: Forward to Agent
    AGW->>Agent: Request + Authorization: Bearer [exchanged token]<br/>(original IdP token never forwarded)
    Agent->>Agent: Validate token (trusts STS issuer)
    Agent-->>AGW: Response
    AGW-->>User: Result

    Note over AGW: Agent never sees the original IdP token.<br/>Token exchange via external RFC 8693 STS.<br/>Works with any OIDC provider + any compliant STS.
```

Back to [Auth Patterns overview](../README.md)
