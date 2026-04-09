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

## Testing

After `setup.sh` completes, the gateway is port-forwarded to `localhost:8888`:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow06-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# No JWT → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Valid JWT → 200 (backend receives opaque token, not the JWT)
curl -s -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/
# Response: is_opaque=true, the JWT was swapped for a static secret
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [API Keys — Manage API Keys](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
- [BackendAuth API](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#backendauth)

Back to [Flow 6 description](../README.md) · [Auth Patterns overview](../../../README.md)
