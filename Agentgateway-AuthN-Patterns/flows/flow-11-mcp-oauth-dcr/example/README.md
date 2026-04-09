# Flow 11: MCP OAuth + Dynamic Client Registration — Working Example

MCP clients register dynamically via DCR, complete OAuth, then connect with a JWT. This example deploys the full infrastructure and tests both the discovery endpoints and authenticated MCP access. The MCP server's `whoami` tool shows the authenticated user identity from the JWT.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- Optional: Node.js 18+ for MCP Inspector

## Run

```bash
./setup.sh
```

## Full DCR flow with MCP Inspector

After setup, connect with an MCP client to test the full DCR + OAuth flow:

```bash
npx @modelcontextprotocol/inspector@latest
# URL: http://localhost:8888/mcp
# Transport: Streamable HTTP
```

The inspector will discover the OAuth endpoints, register dynamically, and prompt you to log in via Keycloak.

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# Unauthenticated → 401 (with resource metadata URL)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/mcp

# Fetch OAuth protected resource metadata
curl -s http://localhost:8888/.well-known/oauth-protected-resource/mcp | jq .

# Get a JWT from Keycloak (simulating completed OAuth flow)
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow11-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# Authenticated MCP initialize → 200
curl -s --max-time 10 -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 11 description](../README.md) · [Auth Patterns overview](../../../README.md)
