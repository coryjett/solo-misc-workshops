# Flow 5: Passthrough Token — Working Example

Gateway validates the inbound JWT, then re-attaches it to the outbound request via passthrough backend auth. The backend receives the original token.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster, installs Enterprise Agentgateway, deploys Keycloak
2. Deploys a token-inspecting backend that decodes the received JWT
3. Creates Gateway + AgentgatewayBackend (with `passthrough: {}`) + JWT policy
4. Tests: no JWT (401), valid JWT (200 + backend confirms original token received)

## Key config

```yaml
# AgentgatewayBackend — passthrough backend auth
policies:
  auth:
    passthrough: {}

# EnterpriseAgentgatewayPolicy — inbound JWT validation
traffic:
  jwtAuthentication:
    issuer: "http://keycloak.../realms/flow05-realm"
    jwks: ...
```

## Testing

After `setup.sh` completes, the gateway is port-forwarded to `localhost:8888`:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow05-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# No JWT → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Valid JWT → 200 (backend receives the original token)
curl -s -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [API Keys — Passthrough Token](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
- [BackendAuth API](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#backendauth)

Back to [Flow 5 description](../README.md) · [Auth Patterns overview](../../../README.md)
