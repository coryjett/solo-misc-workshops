# Flow 11: MCP OAuth with Dynamic Client Registration

MCP clients (like Claude Code, VS Code extensions) that don't have pre-registered OAuth credentials use Dynamic Client Registration (DCR) to register themselves, then complete a standard OAuth flow. Enables zero-configuration MCP client onboarding.

> **Docs:** [About MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/about/) · [Set up Keycloak for MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/keycloak/)

### How it works

**Phase 1 — Initialization**

1. **MCP client connects** to the MCP server → Agentgateway Proxy
2. **Proxy returns `401 Unauthorized`** with a resource metadata endpoint URL

**Phase 2 — Discovery**

3. **Client fetches resource metadata** → `GET /.well-known/oauth-protected-resource/mcp` → Proxy returns required scopes
4. **Client fetches authorization server metadata** → `GET /.well-known/oauth-authorization-server` → Proxy fetches auth server endpoints from the IdP and returns modified metadata (with AGW as the registration endpoint)

**Phase 3 — Dynamic Client Registration**

5. **Client registers itself** → `POST /register` (with `redirect_uris`) → Proxy registers the MCP client with the IdP
6. **IdP returns `client_id`** → Proxy → Client

**Phase 4 — Authentication (OAuth Flow)**

7. **Client initiates OAuth flow** (with `client_id`) → IdP presents login page
8. **User submits credentials** → IdP returns authorization code
9. **Client exchanges code for token** → IdP returns JWT access token

**Phase 5 — MCP Server Access**

10. **Client connects with `Bearer JWT`** → Agentgateway Proxy
11. **Proxy validates the JWT** (fetches JWKS from IdP)
12. **Proxy forwards the authenticated request** → MCP Server
13. **MCP server returns tools, prompts, resources** → Proxy → Client

![Diagram](../images/11-mcp-oauth.png)

Back to [Auth Patterns overview](../README.md)
