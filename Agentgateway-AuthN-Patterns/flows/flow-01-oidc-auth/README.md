# Flow 1: Standard OIDC Authentication

Client obtains a JWT from an external OIDC provider (e.g., via Authorization Code Flow) and presents it as a bearer token. The gateway validates the JWT against the provider's JWKS endpoint — it does not participate in the OIDC flow itself. A separate `OidcPolicy` exists for gateway-initiated Authorization Code Flow.

> **Docs:** [JWT Auth for MCP Services](https://docs.solo.io/agentgateway/2.2.x/mcp/mcp-access/) · [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) · [Set up Keycloak as IdP](https://docs.solo.io/agentgateway/2.2.x/security/extauth/oauth/keycloak/)
> **API:** [JWTAuthentication](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#jwtauthentication)

### How it works

1. **User requests a resource** → `GET /auth/login` → Agent Gateway
2. **Gateway returns 302 redirect** to the OIDC provider's `/authorize` endpoint (with `client_id`, `redirect_uri`, `scope=openid profile email`)
3. **OIDC provider presents login prompt** → User
4. **User submits credentials** → OIDC Provider
5. **OIDC provider returns 302 callback** with an authorization code → Agent Gateway
6. **Gateway exchanges the code for tokens** → `POST /token` (with `code`, `client_secret`) → OIDC Provider
7. **OIDC provider returns Bearer JWT** (access_token + id_token) → Agent Gateway
8. **Gateway creates the session** and returns the result to the user

![Diagram](../../images/1-oidc-auth.png)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

Back to [Auth Patterns overview](../../README.md)
