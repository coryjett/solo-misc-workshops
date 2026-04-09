# Flow 9: Basic Auth (RFC 7617) — Working Example

Clients authenticate with username and password (Base64-encoded). The gateway validates credentials against APR1-hashed values in a Kubernetes secret.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster and installs Enterprise Agentgateway
2. Deploys an echo backend
3. Generates an APR1 password hash via `htpasswd`
4. Creates a Kubernetes secret with the htpasswd file
5. Creates a Gateway + HTTPRoute + `EnterpriseAgentgatewayPolicy` with `basicAuthentication`
6. Tests: no creds (401), wrong password (401), valid creds (200)

## Key config

```yaml
basicAuthentication:
  secretRef:
    name: basic-auth-htpasswd
    namespace: default
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# No credentials → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Wrong password → 401
curl -s -o /dev/null -w "%{http_code}" -u "testuser:wrongpass" http://localhost:8888/

# Valid credentials → 200
curl -s -o /dev/null -w "%{http_code}" -u "testuser:testpassword" http://localhost:8888/
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [Basic Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/basic/)
- [BasicAuthentication API](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#basicauthentication)

Back to [Flow 9 description](../README.md) · [Auth Patterns overview](../../../README.md)
