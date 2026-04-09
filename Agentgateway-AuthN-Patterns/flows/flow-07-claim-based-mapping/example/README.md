# Flow 7: Claim-Based Token Mapping — Working Example

Gateway validates inbound JWT, extracts a claim, and uses it to select a per-group opaque token to inject into the upstream request.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster, installs Enterprise Agentgateway, deploys Keycloak
2. Deploys a token-inspecting backend
3. Creates Gateway + AgentgatewayBackend (with inline `key`) + JWT policy
4. Tests that the backend receives a mapped token instead of the original JWT

## Key config

```yaml
# AgentgatewayBackend — inject mapped key
policies:
  auth:
    key: "mapped-default-token"

# EnterpriseAgentgatewayPolicy — inbound JWT validation
traffic:
  jwtAuthentication: ...
```

## Testing

After `setup.sh` completes, the gateway is port-forwarded to `localhost:8888`:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow07-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# Valid JWT → 200 (backend receives a mapped token based on JWT claims)
curl -s -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [CEL Transformations](https://docs.solo.io/agentgateway/2.2.x/traffic-management/transformations/)
- [JWT Auth for MCP Services](https://docs.solo.io/agentgateway/2.2.x/mcp/mcp-access/)

Back to [Flow 7 description](../README.md) · [Auth Patterns overview](../../../README.md)
