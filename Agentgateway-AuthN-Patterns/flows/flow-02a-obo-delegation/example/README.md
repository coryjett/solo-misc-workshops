# Flow 2a: OBO Delegation — Working Example

Gateway-mediated OBO token exchange. The client sends a Keycloak JWT, AGW's built-in STS automatically exchanges it, and the MCP server receives an STS-signed token (not the original Keycloak JWT).

> **Impersonation, not dual-identity delegation.** The *gateway-mediated* exchange never sends an `actor_token`, so the STS issues a token carrying the user's `sub` only — it does **not** add an `act` (agent) claim. That makes this example functionally the same exchange as [flow-02b (impersonation)](../../flow-02b-obo-impersonation/). **True delegation** — a dual-identity token with both `sub` (user) and `act` (agent) — requires an **agent-initiated** RFC 8693 call that supplies the agent's `actor_token` (and a `may_act` claim on the user JWT). That agent-initiated flow is described in the [Flow 2a overview](../README.md); the gateway does not produce it automatically.

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
4. Tests that the MCP server receives an STS-signed token (not the original Keycloak JWT) — i.e. the exchange occurred. It does **not** assert an `act` claim, because the gateway-mediated path is impersonation (see note above).

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
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/agw-demo/protocol/openid-connect/token" \
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
