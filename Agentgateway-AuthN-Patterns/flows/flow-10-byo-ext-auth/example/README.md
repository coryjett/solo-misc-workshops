# Flow 10: BYO External Auth — Working Example

Delegates authentication to a custom external authorization service using the Envoy `ext_authz` HTTP protocol. The gateway sends check requests, and the service returns allow/deny.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster and installs Enterprise Agentgateway
2. Deploys an echo backend and a simple HTTP ext_authz service
3. The ext auth service checks for `x-auth-token: allow-me` header
4. Creates a Gateway + HTTPRoute + `EnterpriseAgentgatewayPolicy` with `extAuth`
5. Tests: no token (403), wrong token (403), valid token (200)

## Key config

```yaml
extAuth:
  backendRef:
    name: ext-auth-service
    namespace: default
    port: 9001
  http: {}
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# No token → 403
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Wrong token → 403
curl -s -o /dev/null -w "%{http_code}" -H "x-auth-token: deny-me" http://localhost:8888/

# Valid token → 200
curl -s -o /dev/null -w "%{http_code}" -H "x-auth-token: allow-me" http://localhost:8888/
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [BYO Ext Auth Service](https://docs.solo.io/agentgateway/2.2.x/security/extauth/byo-ext-auth-service/)
- [EnterpriseAgentgatewayExtAuth API](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewayextauth)

Back to [Flow 10 description](../README.md) · [Auth Patterns overview](../../../README.md)
