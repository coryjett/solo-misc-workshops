# Flow 8: API Key Auth (Inbound)

Clients authenticate with a static API key instead of OIDC. Gateway validates the key against Kubernetes secrets (by label selector or name).

> **Docs:** [API Key Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/apikey/)
> **API:** [APIKeyAuthentication](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#apikeyauthentication)

### How it works

1. **Client sends request** with `Authorization: Bearer <API-key>` → Agentgateway Proxy
2. **Proxy looks up the key** in Kubernetes secrets (by label selector or secret name)
3. **Proxy compares the provided key** against the stored secret value
4. **If the key is valid:** Proxy forwards the request to the backend → Backend responds → Proxy returns `200 OK` to the client
5. **If the key is invalid:** Proxy returns `401 Unauthorized` to the client

![Diagram](../../images/8-api-key-auth.png)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

### Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# No API key → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Wrong API key → 401
curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer wrong-key" http://localhost:8888/

# Valid API key → 200
curl -s -H "Authorization: Bearer my-secret-api-key-12345" http://localhost:8888/
```

Back to [Auth Patterns overview](../../README.md)
