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
jwtAuthentication:
  issuer: "http://keycloak.keycloak.svc.cluster.local:8080/realms/flow01-realm"
  jwks:
    backendRef:
      name: keycloak
      kind: Service
      namespace: keycloak
      port: 8080
    jwksPath: "realms/flow01-realm/protocol/openid-connect/certs"
  audiences:
  - account
  - agw-client
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/)
- [JWTAuthentication API](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#jwtauthentication)

Back to [Flow 1 description](../README.md) · [Auth Patterns overview](../../../README.md)
