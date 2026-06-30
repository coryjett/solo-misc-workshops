# Flow 12: Multi-Header Auth — Working Example

Two independent `jwtAuthentication` policies on the same HTTPRoute, each pulling its credential from a different header and validating against its own JWKS. Both must succeed for the request to reach the backend.

## Prerequisites

- Docker, kubectl, helm, curl, jq, **openssl**, **python3** (with the `cryptography` package — `pip install cryptography` if not already present)
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

> **Version requirement:** AGW Enterprise `v2026.5.0-beta.1` or later (the `traffic.jwtAuthentication.location` field doesn't exist on the older `v2.x.x` charts, so the second policy would fail to apply). This example inherits the shared default `AGW_VERSION=v2026.6.2`, which satisfies the requirement; override via `export AGW_VERSION=…`.

## Run

```bash
./setup.sh
```

This script:

1. Creates a k3d cluster and installs Enterprise Agentgateway at the shared default `v2026.6.2`
2. Generates two ES256 keypairs (`issuer-a`, `issuer-b`), builds a JWKS for each, and signs a 24-hour demo JWT per issuer (saved under `.workload/`)
3. Deploys an echo backend that reports whether each header reached it
4. Creates a Gateway + HTTPRoute, then applies **two** `EnterpriseAgentgatewayPolicy` objects:
   - **Policy A** (`flow-12-jwt-a`) — default location (`Authorization: Bearer …`), validates against `issuer-a`'s JWKS
   - **Policy B** (`flow-12-jwt-b`) — `location.header.name=x-second-token`, validates against `issuer-b`'s JWKS
5. Tests six scenarios — both valid → 200; either missing → 401; tokens swapped between headers → 401

## What gets created

| Resource | Purpose |
|---|---|
| `Gateway/flow-12-gateway` | Agentgateway listener |
| `HTTPRoute/flow-12-route` | Routes `/` to the echo backend |
| `EnterpriseAgentgatewayPolicy/flow-12-jwt-a` | Validates JWT in `Authorization` header (issuer-a's JWKS) |
| `EnterpriseAgentgatewayPolicy/flow-12-jwt-b` | Validates JWT in `x-second-token` header (issuer-b's JWKS) |
| `Deployment/echo-backend` | Reports back whether each auth header reached the backend |
| `.workload/issuer-{a,b}.{priv,pub}.pem`, `.jwks.json`, `.jwt` | Generated keypairs, JWKS, and 24h demo tokens (gitignored) |

## Key config

```yaml
# Policy A — default location is Authorization with Bearer prefix
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: flow-12-route
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
      - issuer: https://issuer-a.local
        audiences: [audience-a]
        jwks: { inline: '<JWKS A JSON>' }
---
# Policy B — explicit custom header location
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: flow-12-route
  traffic:
    jwtAuthentication:
      mode: Strict
      location:
        header:
          name: x-second-token
      providers:
      - issuer: https://issuer-b.local
        audiences: [audience-b]
        jwks: { inline: '<JWKS B JSON>' }
```

## Testing

After `setup.sh` finishes, the gateway is port-forwarded to `localhost:8888`:

```bash
TOKEN_A=$(cat .workload/issuer-a.jwt)
TOKEN_B=$(cat .workload/issuer-b.jwt)

# Both valid → 200, headers stripped before reaching the backend
curl -s -H "Authorization: Bearer $TOKEN_A" \
     -H "x-second-token: $TOKEN_B" \
     http://localhost:8888/ | jq
# {
#   "message": "Hello from echo backend",
#   "authorization_header_visible": false,   ← stripped after JWT validation
#   "x_second_token_visible": false           ← stripped after JWT validation
# }

# Missing either token → 401
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN_A" http://localhost:8888/
curl -s -o /dev/null -w "%{http_code}\n" -H "x-second-token: $TOKEN_B" http://localhost:8888/

# Tokens swapped between headers → 401 (issuer-A's JWT can't validate against issuer-B's JWKS)
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN_B" -H "x-second-token: $TOKEN_A" http://localhost:8888/
```

## Cleanup

```bash
source ../../common/cleanup.sh
rm -rf .workload
```

## Docs

- [JWT Auth setup](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/)
- [`AuthorizationLocation` API](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#authorizationlocation)
- [`JWTAuthentication` API](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#jwtauthentication)

Back to [Flow 12 description](../README.md) · [Auth Patterns overview](../../../README.md)
