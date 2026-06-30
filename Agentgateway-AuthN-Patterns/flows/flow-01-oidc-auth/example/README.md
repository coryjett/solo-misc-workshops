# Flow 1: Standard OIDC Authentication — Working Example

Client obtains a JWT from Keycloak (via password grant for simplicity) and presents it as a bearer token. The gateway validates the JWT against Keycloak's JWKS endpoint.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster and installs Enterprise Agentgateway
2. Deploys Keycloak with a realm, client, and test user
3. Deploys an echo backend
4. Creates a Gateway + HTTPRoute + `EnterpriseAgentgatewayPolicy` with `jwtAuthentication`
5. Tests: no JWT (401), invalid JWT (401), valid Keycloak JWT (200)

## Key config

```yaml
traffic:
  jwtAuthentication:
    providers:
    - issuer: "http://keycloak.keycloak.svc.cluster.local:8080/realms/agw-demo"
      audiences:
      - account
      - agw-client
      jwks:
        remote:
          backendRef:
            name: keycloak
            kind: Service
            namespace: keycloak
            port: 8080
          jwksPath: "realms/agw-demo/protocol/openid-connect/certs"
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/agw-demo/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# No JWT → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Valid JWT → 200
curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [JWT Auth](https://docs.solo.io/agentgateway/latest/security/jwt/setup/)
- [JWTAuthentication API](https://docs.solo.io/agentgateway/latest/reference/api/solo/#jwtauthentication)

Back to [Flow 1 description](../README.md) · [Auth Patterns overview](../../../README.md)
