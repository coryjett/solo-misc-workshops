# Flow 11b: MCP OAuth mock DCR / `clientId` short-circuit — Working Example

Setting `mcpAuthentication.clientId` makes agentgateway answer client registration itself — injecting a `registration_endpoint` into the authorization-server metadata and returning the pre-registered **public** client on `POST /register` — instead of proxying DCR to the IdP. This example deploys the full infrastructure with `clientId` set and verifies the mock-DCR response, then confirms authenticated MCP access. The MCP server's `whoami` tool shows the authenticated user identity from the JWT.

> This example uses the shared **Keycloak** (with `clientId` set) to demonstrate the mechanism on the same infra as every other flow. In production you use the identical config for IdPs that lack DCR entirely (**authentik**) or require a pinned application (**Entra** middle-tier/OBO app).

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- Optional: Node.js 18+ for MCP Inspector

## Run

```bash
./setup.sh
```

## What the example asserts

1. **Unauthenticated → 401** with a resource-metadata URL
2. **AS metadata carries an injected `registration_endpoint`** pointing back at the gateway
3. **Mock DCR** — `POST` to that endpoint returns the pre-registered `client_id` with `token_endpoint_auth_method: none` (public client + PKCE), **without any call to Keycloak**
4. **Authenticated MCP access** with a Bearer JWT → `whoami` returns the caller's identity

## Full flow with MCP Inspector

```bash
npx @modelcontextprotocol/inspector@latest
# URL: http://localhost:8888/mcp
# Transport: Streamable HTTP
```

The inspector will "register" (the gateway answers with the pre-registered client — no IdP DCR call), then prompt you to log in.

## Configuration notes

The one functional change from [Flow 11](../../flow-11-mcp-oauth-dcr/) is `clientId` on the MCP authentication block:

```yaml
backend:
  mcp:
    authentication:
      issuer: "<idp-issuer>"
      clientId: "<pre-registered-public-client-id>"   # ← short-circuits DCR
      audiences:
      - "<pre-registered-public-client-id>"
      provider: Keycloak        # or: authentik: {} / entra for real deployments
      # ... jwks, resourceMetadata as in Flow 11
```

The mock registration response is deterministic (`crates/agentgateway/src/mcp/auth.rs` → `build_mock_dcr_response`):

```json
{
  "client_id": "<pre-registered client id>",
  "client_id_issued_at": 0,
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "redirect_uris": ["<echoed from the request>"]
}
```

### Requirements & gotchas

- **The pre-registered client must be PUBLIC** (`token_endpoint_auth_method: none`) with **PKCE** — a confidential client will mismatch the mock response.
- **Redirect URIs must cover your MCP clients** (authentik supports regex redirect URIs, handy for MCP clients' many localhost callback ports).
- **authentik** has no RFC 8707 and sets `aud` to the client ID, so set `audiences` to the pre-registered client ID; `clientId` is **required** (authentik has no DCR endpoint).
- **Entra / OBO** — pin the middle-tier (gateway) app via `clientId` so DCR clients don't self-register against Entra.
- **IdPs *with* DCR** (Keycloak, Okta, Descope) — the gateway can proxy real DCR, but that needs the operator's management key (Okta SSWS, Descope management key). Setting `clientId` skips DCR and is usually simpler.

### IdP support matrix

| IdP | DCR | Registration handling |
|---|---|---|
| **authentik** | ✗ (no RFC 7591) | **Mock** — gateway injects `registration_endpoint` and answers with the pre-registered client (`clientId` required) |
| **Entra ID** | ✗ (use pinned app) | **Mock** — pin the middle-tier app via `clientId` |
| **Keycloak** | ✓ | Proxied to `clients-registrations/openid-connect` (`clientId` optional — used here to demo the mock path) |
| **Okta** | ✓ (SSWS token) | Proxied to `oauth2/v1/clients` (`clientId` recommended) |
| **Descope** | ✓ (mgmt key) | Proxied to management DCR endpoint (`clientId` recommended) |

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 11b description](../README.md) · [Auth Patterns overview](../../../README.md)
