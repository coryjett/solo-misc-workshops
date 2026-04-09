# Flow 3: Elicitation — Working Example

Demonstrates the elicitation trigger: when no upstream OAuth token is available, the gateway returns a `PENDING` status with an elicitation URL. The MCP server's `echo_token` tool shows the token it received, so you can verify the token exchange after completing the elicitation.

**Note:** Completing the elicitation (the user opening the URL and authorizing access) requires the Solo Enterprise UI. This example shows the trigger mechanism only.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

## Key config

```yaml
tokenExchange:
  mode: ElicitOnly    # Only elicit, don't try exchange first
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow03-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# No JWT → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/mcp

# Valid JWT → MCP response or elicitation URL (PENDING status)
curl -s --max-time 10 -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

### Completing the elicitation (Enterprise UI)

When the gateway needs upstream OAuth credentials it doesn't have yet, the response includes a `PENDING` status with an elicitation URL. To complete the flow:

1. **Copy the elicitation URL** from the response JSON
2. **Open the URL** in your browser — this loads the Solo Enterprise UI
3. **Authorize access** — the Enterprise UI redirects you to the upstream OAuth provider (e.g., GitHub). Log in and grant access.
4. **Return to the Enterprise UI** — once the provider redirects back, the Enterprise UI completes the elicitation and the STS stores the upstream token (status: `COMPLETED`)
5. **Retry the original request** — the gateway now has the upstream token and forwards it to the MCP server:

```bash
# Retry after completing elicitation — gateway injects the stored upstream token
curl -s --max-time 10 -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 3 description](../README.md) · [Auth Patterns overview](../../../README.md)
