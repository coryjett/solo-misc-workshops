# Flow 3: Elicitation (Credential Gathering for Upstream APIs)

When the agent needs to call an upstream API requiring OAuth credentials that don't exist yet. The gateway returns an elicitation URL; the user completes an out-of-band OAuth flow to provide the credentials.

> **Docs:** [Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/elicitations/) · [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/)
> **API:** [TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode)

```mermaid
sequenceDiagram
    participant User
    participant AGW as Agent Gateway Proxy
    participant STS as Token Exchange Server
    participant UI as Enterprise UI
    participant ExtIdP as External OAuth Provider
    participant API as Upstream API

    User->>AGW: Request (needs upstream OAuth token)
    AGW->>STS: Request upstream token
    STS-->>AGW: Elicitation URL (status: PENDING)
    AGW-->>User: Return elicitation URL

    User->>UI: Open elicitation URL
    UI->>ExtIdP: Redirect for OAuth authorization
    ExtIdP->>User: Login/consent prompt
    User->>ExtIdP: Authorize
    ExtIdP->>UI: Redirect with authorization code
    UI->>STS: Complete elicitation (code)
    STS->>STS: Store token (status: COMPLETED)

    User->>AGW: Retry original request
    AGW->>STS: Fetch stored token
    STS-->>AGW: Upstream OAuth token
    AGW->>API: Forward request + inject token
    API-->>AGW: Response
    AGW-->>User: Result
```

Back to [Auth Patterns overview](../README.md)
