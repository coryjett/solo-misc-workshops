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

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 13 description](../README.md) · [Auth Patterns overview](../../../README.md)
