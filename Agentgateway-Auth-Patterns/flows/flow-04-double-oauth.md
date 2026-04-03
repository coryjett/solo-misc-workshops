# Flow 4: Double OAuth Flow (OIDC Bearer --> Upstream Token Exchange)

User authenticates via OIDC (gets bearer JWT), then that token is exchanged for a different upstream token (could be opaque). Combines downstream and upstream OAuth in a single automated flow.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/elicitations/)

```mermaid
sequenceDiagram
    participant Client
    participant Issuer as OAuth Issuer (Controller)
    participant DownstreamIdP as Downstream IdP (OIDC)
    participant UpstreamSTS as Upstream STS
    participant Elicit as Elicitation Endpoint

    Note over Client,Elicit: Phase 1: Get Downstream Bearer Token (OIDC)
    Client->>Issuer: GET /authorize (client_id, redirect_uri, state, resource)
    Issuer-->>Client: 302 -> Downstream authorize URL
    Client->>Issuer: GET /callback/downstream (state, code)
    Issuer->>DownstreamIdP: POST /token (exchange code)
    DownstreamIdP-->>Issuer: downstream-access-token (Bearer JWT) + id_token

    Note over Client,Elicit: Phase 2: Exchange for Upstream Token (Opaque)
    Issuer-->>Client: 307 -> Upstream authorize URL
    Client->>Issuer: GET /callback/upstream (state, code)
    Issuer->>UpstreamSTS: POST /token (exchange code)
    UpstreamSTS-->>Issuer: upstream-token (opaque)
    Issuer-->>Client: 302 -> redirect_uri?code=AUTH_CODE

    Note over Client,Elicit: Phase 3: Retrieve Tokens
    Client->>Issuer: POST /token (grant_type=authorization_code, code)
    Issuer-->>Client: downstream-access-token (Bearer JWT)

    Client->>Elicit: POST /elicitations/oauth2/token<br/>(subject_token=K8s SA, resource)
    Elicit-->>Client: upstream-token (opaque)
```
![Diagram](../images/4-double-oauth.png)

Back to [Auth Patterns overview](../README.md)
