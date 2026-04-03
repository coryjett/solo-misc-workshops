# Flow 9: Basic Auth (RFC 7617)

Clients authenticate with username and password (Base64-encoded in the Authorization header). Gateway validates credentials against hashed values stored in Kubernetes secrets. Useful for legacy integrations or simple service-to-service auth.

> **Docs:** [Basic Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/basic/)
> **API:** [BasicAuthentication](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#basicauthentication)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant K8s as K8s Secret<br/>(hashed credentials)
    participant Backend as Backend

    Client->>AGW: Request + Authorization: Basic [base64 user:pass]
    AGW->>AGW: Decode Base64 credentials
    AGW->>K8s: Read secret with hashed passwords
    AGW->>AGW: Verify password hash (APR1)

    alt Credentials valid
        AGW->>Backend: Forward request<br/>(credential stripped or replaced)
        Backend-->>AGW: Response
        AGW-->>Client: 200 OK
    else Credentials invalid
        AGW-->>Client: 401 Unauthorized
    end

    Note over AGW,K8s: Configured via EnterpriseAgentgatewayPolicy:<br/>traffic.basicAuth with K8s secretRef
```
![Diagram](../images/9-basic-auth.png)

Back to [Auth Patterns overview](../README.md)
