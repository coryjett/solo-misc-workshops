# Flow 8: API Key Auth (Inbound)

Clients authenticate with a static API key instead of OIDC. Gateway validates the key against Kubernetes secrets (by label selector or name).

> **Docs:** [API Key Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/apikey/)
> **API:** [APIKeyAuthentication](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#apikeyauthentication)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant K8s as K8s Secrets<br/>(API Keys)
    participant Backend as Backend

    Client->>AGW: Request + Authorization: Bearer [API key]
    AGW->>K8s: Lookup secret (by label selector or name)
    K8s-->>AGW: Secret found, compare key

    alt Key valid
        AGW->>Backend: Forward request
        Backend-->>AGW: Response
        AGW-->>Client: 200 OK
    else Key invalid
        AGW-->>Client: 401 Unauthorized
    end
```

Back to [Auth Patterns overview](../README.md)
