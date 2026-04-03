# Flow 10: BYO External Auth (gRPC Ext Auth Service)

Delegate authentication to your own external authorization service via gRPC. The gateway sends auth check requests to your service, which returns allow/deny decisions. Supports custom logic, enterprise IdPs, or multi-factor checks.

> **Docs:** [External Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/)
> **API:** [EnterpriseAgentgatewayExtAuth](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewayextauth)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant ExtAuth as External Auth Service<br/>(gRPC)
    participant Backend as Backend

    Client->>AGW: Request + credentials
    AGW->>ExtAuth: gRPC CheckRequest<br/>(headers, path, method)
    ExtAuth->>ExtAuth: Custom auth logic<br/>(LDAP, SAML, MFA, etc.)

    alt Authorized
        ExtAuth-->>AGW: OK + optional headers
        AGW->>Backend: Forward request<br/>(+ injected headers from ext auth)
        Backend-->>AGW: Response
        AGW-->>Client: 200 OK
    else Denied
        ExtAuth-->>AGW: Denied + status code
        AGW-->>Client: 401/403 Unauthorized
    end

    Note over AGW,ExtAuth: Configured via EnterpriseAgentgatewayPolicy:<br/>traffic.extAuth with gRPC service reference
```
![Diagram](../images/10-byo-ext-auth.png)

Back to [Auth Patterns overview](../README.md)
