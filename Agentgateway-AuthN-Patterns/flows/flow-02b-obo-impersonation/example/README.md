# Flow 2b: OBO Impersonation — Working Example

Same as Flow 2a but without an actor token. The STS issues a JWT with the same `sub` and scopes but no `act` claim. The original IdP token is replaced.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

## Key difference from 2a

In impersonation mode, the exchanged token has no `act` claim — downstream services see only the user's identity. The agent identity is not tracked.

## Testing

After `setup.sh` completes, the gateway is port-forwarded to `localhost:8888`. The script automatically calls the `whoami` MCP tool and verifies no `act` claim is present. You can also test manually:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow02b-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# Initialize MCP session
curl -s --max-time 10 -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 2b description](../README.md) · [Auth Patterns overview](../../../README.md)
