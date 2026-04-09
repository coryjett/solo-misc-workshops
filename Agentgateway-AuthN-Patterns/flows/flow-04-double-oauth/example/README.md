# Flow 4: Double OAuth — Working Example

Two sequential OAuth flows: OIDC authentication (Phase 1) + upstream credential gathering via elicitation (Phase 2).

**Note:** Phase 2 completion requires the Solo Enterprise UI. This example demonstrates the OIDC auth and elicitation trigger.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

## Key config

```yaml
# Default mode (empty = both exchange + elicit)
tokenExchange: {}
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# Phase 1: Get a JWT from Keycloak (OIDC)
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow04-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# Phase 2: Send MCP request — triggers token exchange + elicitation
curl -s --max-time 10 -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

### Completing the elicitation (Enterprise UI)

If the gateway needs upstream OAuth credentials, the Phase 2 response includes a `PENDING` status with an elicitation URL. To complete the second OAuth flow:

1. **Copy the elicitation URL** from the response JSON
2. **Open the URL** in your browser — this loads the Solo Enterprise UI
3. **Authorize access** — the Enterprise UI redirects you to the upstream OAuth provider. Log in and grant access.
4. **Return to the Enterprise UI** — once the provider redirects back, the Enterprise UI completes the elicitation and the STS stores the upstream token (status: `COMPLETED`)
5. **Retry the original request** (Phase 3) — the gateway now has the upstream token and forwards it to the MCP server:

```bash
# Phase 3: Retry after completing elicitation — gateway injects the upstream token
curl -s --max-time 10 -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 4 description](../README.md) · [Auth Patterns overview](../../../README.md)
