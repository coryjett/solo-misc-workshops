# Flow 3: Elicitation — Working Example

Demonstrates the elicitation trigger: when no upstream OAuth token is available, the gateway returns a `PENDING` status with an elicitation URL.

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

After `setup.sh` completes, the gateway is port-forwarded to `localhost:8888`:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow03-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# No JWT → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/mcp

# Valid JWT → MCP response (token exchange succeeds) or elicitation URL
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
