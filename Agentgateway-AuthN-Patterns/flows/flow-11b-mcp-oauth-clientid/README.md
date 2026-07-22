# Flow 11b: MCP OAuth with a Pre-Registered Client (mock DCR / `clientId` short-circuit)

A variant of [Flow 11 (MCP OAuth + DCR)](../flow-11-mcp-oauth-dcr/) for identity providers that **don't implement RFC 7591 Dynamic Client Registration** (e.g. authentik) or where you must pin a **specific pre-registered application** (e.g. an Entra middle-tier/OBO app). DCR-only MCP clients (Claude Code, MCP Inspector, VS Code) still expect a `/register` step — so setting `clientId` makes agentgateway **inject its own `registration_endpoint`** into the authorization-server metadata and **answer registration itself** with the configured public client, without calling the IdP and without a management/API key.

> **Docs:** [About MCP Auth](https://docs.solo.io/agentgateway/latest/mcp/auth/about/) · [Set up MCP Auth](https://docs.solo.io/agentgateway/latest/mcp/auth/setup/)

### How it works

**Phase 1 — Initialization**

1. **MCP client connects** to the MCP server → Agentgateway Proxy
2. **Proxy returns `401 Unauthorized`** with a resource-metadata endpoint URL

**Phase 2 — Discovery**

3. **Client fetches resource metadata** → `GET /.well-known/oauth-protected-resource/mcp` → Proxy returns required scopes
4. **Client fetches authorization-server metadata** → `GET /.well-known/oauth-authorization-server` → Proxy fetches the IdP's real endpoints and returns modified metadata **with a `registration_endpoint` injected pointing back at the gateway**

**Phase 3 — Mock Dynamic Client Registration** *(the short-circuit)*

5. **Client registers itself** → `POST /register` (with `redirect_uris`)
6. **Proxy answers directly** — no IdP call. It returns `201 Created` with the configured `client_id`, `token_endpoint_auth_method: none` (public client + PKCE), and the client's `redirect_uris` echoed back

**Phase 4 — Authentication (OAuth Flow)**

7. **Client initiates OAuth** (pre-registered `client_id` + PKCE) → IdP presents login
8. **User submits credentials** → IdP returns authorization code
9. **Client exchanges code for token** → IdP returns JWT access token

**Phase 5 — MCP Server Access**

10. **Client connects with `Bearer JWT`** → Agentgateway Proxy
11. **Proxy validates the JWT** (fetches JWKS from the IdP)
12. **Proxy forwards the authenticated request** → MCP Server
13. **MCP server returns tools, prompts, resources** → Proxy → Client

![Diagram](../../images/11b-mcp-oauth-clientid.png)

> Diagram source: [`../../diagrams/11b-mcp-oauth-clientid.mmd`](../../diagrams/11b-mcp-oauth-clientid.mmd)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

Back to [Auth Patterns overview](../../README.md)
