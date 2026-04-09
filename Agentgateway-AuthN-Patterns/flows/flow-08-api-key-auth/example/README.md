# Flow 8: API Key Auth — Working Example

Clients authenticate with a static API key stored in a Kubernetes secret. The gateway validates the key by label selector and forwards the request if valid.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster
2. Installs Enterprise Agentgateway ([Helm install docs](https://docs.solo.io/agentgateway/2.2.x/install/helm/))
3. Deploys an echo backend
4. Creates a Kubernetes secret with an API key (labeled `agw-auth: api-key`)
5. Creates a Gateway + HTTPRoute + `EnterpriseAgentgatewayPolicy` with `apiKeyAuthentication`
6. Tests: no key (401), wrong key (401), valid key (200)

## What gets created

| Resource | Purpose |
|---|---|
| `Secret/user-api-key` | Stores the API key, labeled for discovery |
| `EnterpriseAgentgatewayPolicy/flow-08-api-key-policy` | API key auth via `k8sSecretApikeyStorage` with label selector |
| `Gateway/flow-08-gateway` | Agentgateway listener |
| `HTTPRoute/flow-08-route` | Routes all traffic to the echo backend |

## Key config

```yaml
apiKeyAuthentication:
  k8sSecretApikeyStorage:
    labelSelector:
      agw-auth: api-key
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# No API key → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Wrong API key → 401
curl -s -o /dev/null -w "%{http_code}" -H "x-api-key: wrong-key" http://localhost:8888/

# Valid API key → 200
curl -s -o /dev/null -w "%{http_code}" -H "x-api-key: my-secret-api-key-12345" http://localhost:8888/
```

## Cleanup

```bash
source ../common/cleanup.sh
```

## Docs

- [API Key Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/apikey/)
- [APIKeyAuthentication API](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#apikeyauthentication)

Back to [Flow 8 description](../README.md) · [Auth Patterns overview](../../../README.md)
