# Flow 6: Static Secret Injection — Working Example

Gateway validates inbound JWT, then replaces it with a static opaque token from a Kubernetes secret before forwarding to the backend. All users share the same upstream credential.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster, installs Enterprise Agentgateway, deploys Keycloak
2. Deploys a token-inspecting backend that reports whether it received a JWT or opaque token
3. Creates a K8s secret with a static upstream API key
4. Creates Gateway + AgentgatewayBackend (with `secretRef`) + JWT policy
5. Tests: no JWT (401), valid JWT (200 + backend confirms opaque token received)

## Key config

```yaml
# AgentgatewayBackend — inject static secret
policies:
  auth:
    secretRef:
      name: upstream-api-key
      namespace: default

# EnterpriseAgentgatewayPolicy — inbound JWT validation
traffic:
  jwtAuthentication: ...
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [API Keys — Manage API Keys](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
- [BackendAuth API](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#backendauth)

Back to [Flow 6 description](../README.md) · [Auth Patterns overview](../../../README.md)
