# Flow 1: Standard OIDC Authentication

User authenticates via OIDC provider (Authorization Code Flow), receives a bearer JWT, and uses it for all subsequent requests to the Agent Gateway.

> **Docs:** [JWT Auth for MCP Services](https://docs.solo.io/agentgateway/2.2.x/mcp/mcp-access/) · [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) · [Set up Keycloak as IdP](https://docs.solo.io/agentgateway/2.2.x/security/extauth/oauth/keycloak/)
> **API:** [JWTAuthentication](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#jwtauthentication)

```mermaid
sequenceDiagram
    participant User
    participant App as Application
    participant IdP as OIDC Provider

    User->>App: GET /auth/login
    App->>IdP: 302 Redirect to /authorize<br/>(client_id, redirect_uri, scope=openid profile email)
    IdP->>User: Login prompt
    User->>IdP: Credentials
    IdP->>App: 302 Callback with authorization code
    App->>IdP: POST /token<br/>(code, client_secret)
    IdP-->>App: Bearer JWT (access_token + id_token)
    App-->>User: Session created
```

Back to [Auth Patterns overview](../README.md)
