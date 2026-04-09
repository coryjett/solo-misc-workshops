# Flow 13: Gateway-Mediated Token Exchange — Working Example

AGW handles OIDC authentication, automatically exchanges the Keycloak JWT at the built-in STS, and forwards the STS-signed token to the MCP server. The client never calls the STS directly.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

The MCP server's `echo_token` tool confirms whether it received a Keycloak token or an STS token. The server also logs every incoming token's issuer.

## Key config

```yaml
# Helm: enable built-in STS
tokenExchange:
  enabled: true
  issuer: "enterprise-agentgateway....:7777"

# Policy: automatic exchange
tokenExchange:
  mode: ExchangeOnly
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow13-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# Initialize MCP session (gateway exchanges token via STS first)
curl -s --max-time 10 -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 13 description](../README.md) · [Auth Patterns overview](../../../README.md)
