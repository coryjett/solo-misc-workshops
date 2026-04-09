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

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 2a description](../README.md) · [Auth Patterns overview](../../../README.md)
