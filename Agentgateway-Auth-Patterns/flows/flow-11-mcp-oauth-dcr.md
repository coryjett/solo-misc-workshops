# Flow 11: MCP OAuth with Dynamic Client Registration

MCP clients (like Claude Code, VS Code extensions) that don't have pre-registered OAuth credentials use Dynamic Client Registration (DCR) to register themselves, then complete a standard OAuth flow. Enables zero-configuration MCP client onboarding.

> **Docs:** [About MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/about/) · [Set up Keycloak for MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/keycloak/)

```mermaid
sequenceDiagram
    participant MCPClient as MCP Client<br/>(Claude Code / VS Code)
    participant AGW as Agent Gateway<br/>(OAuth Server)
    participant IdP as Identity Provider

    Note over MCPClient,IdP: Phase 1: Dynamic Client Registration
    MCPClient->>AGW: GET /.well-known/oauth-authorization-server
    AGW-->>MCPClient: Authorization server metadata<br/>(registration_endpoint, authorize, token)
    MCPClient->>AGW: POST /register<br/>(client_name, redirect_uris, grant_types)
    AGW-->>MCPClient: client_id + client_secret (dynamic)

    Note over MCPClient,IdP: Phase 2: Standard OAuth Authorization
    MCPClient->>AGW: GET /authorize<br/>(client_id, redirect_uri, code_challenge)
    AGW->>IdP: Redirect to IdP login
    IdP->>MCPClient: Login + consent
    MCPClient->>IdP: Credentials
    IdP->>AGW: Callback with code
    AGW-->>MCPClient: Redirect with authorization code

    Note over MCPClient,IdP: Phase 3: Token Exchange
    MCPClient->>AGW: POST /token<br/>(code, client_id, code_verifier)
    AGW-->>MCPClient: Access token (Bearer JWT)
```
![Diagram](../images/11-mcp-oauth.png)

Back to [Auth Patterns overview](../README.md)
