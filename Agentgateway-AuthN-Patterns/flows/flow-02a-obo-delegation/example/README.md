# Flow 2a: OBO Delegation — Working Example

Gateway-mediated OBO token exchange. Client sends a Keycloak JWT, AGW automatically exchanges it at the built-in STS, and the MCP server receives an STS-signed JWT with `sub` (user) + `act` (agent).

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster, installs Enterprise Agentgateway **with STS enabled**
2. Deploys Keycloak + a token-logging MCP server
3. Configures `ExchangeOnly` token exchange mode
4. Tests that the MCP server receives an STS-signed token (not the original Keycloak JWT)

## Key config

```yaml
# Helm: enable built-in STS
tokenExchange:
  enabled: true
  issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"

# EnterpriseAgentgatewayParameters: STS endpoint for data plane
env:
- name: STS_URI
  value: http://enterprise-agentgateway....:7777/token

# Policy: automatic exchange
tokenExchange:
  mode: ExchangeOnly
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow02a-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# Initialize MCP session (gateway exchanges token via STS)
curl -s --max-time 10 -X POST http://localhost:8888/mcp \
  -H "Authorization: Bearer ${USER_JWT}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 2a description](../README.md) · [Auth Patterns overview](../../../README.md)
