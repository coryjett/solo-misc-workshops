# Flow 6: Static Secret Injection (Shared Credential)

Gateway validates inbound auth (JWT or API key), then replaces it with a static backend credential from a Kubernetes secret. All users share the same upstream token.

> **Docs:** [API Keys --- Manage API Keys](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
> **API:** [AIBackend](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#aibackend)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant K8s as K8s Secret<br/>(opaque token)
    participant Backend as Upstream API

    Client->>AGW: Request + Authorization: Bearer [user JWT]
    AGW->>AGW: Validate JWT (jwtAuthentication)
    AGW->>K8s: Read secretRef / inline key
    K8s-->>AGW: Static opaque token
    AGW->>Backend: Request + Authorization: Bearer [opaque token]
    Backend-->>AGW: Response
    AGW-->>Client: Response

    Note over AGW,K8s: Configured via AgentgatewayBackend:<br/>policies.auth.secretRef or policies.auth.key
```

Back to [Auth Patterns overview](../README.md)
