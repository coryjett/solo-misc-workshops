# Flow 5: Passthrough Token

Client already has the correct token (from its own OIDC flow or API key). Gateway forwards it directly to the backend --- no validation or exchange performed.

> **Docs:** [API Keys --- Passthrough Token](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
> **API:** [AIBackend](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#aibackend)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant Backend as Backend (LLM / MCP / API)

    Note over Client: Client already authenticated<br/>(has token from its own OIDC flow or API key)
    Client->>AGW: Request + Authorization: Bearer [token]
    AGW->>AGW: Passthrough (no validation/exchange)
    AGW->>Backend: Forward request with same token
    Backend-->>AGW: Response
    AGW-->>Client: Response
```
![Diagram](../images/5-passthrough.png)

Back to [Auth Patterns overview](../README.md)
