# Flow 10: BYO External Auth (gRPC Ext Auth Service)

Delegate authentication to your own external authorization service using the Envoy `ext_authz` gRPC protocol (supports both gRPC and HTTP). The gateway sends `CheckRequest` RPCs to your service, which returns allow/deny decisions. Supports custom logic, enterprise IdPs, or multi-factor checks.

> **Docs:** [BYO Ext Auth Service](https://docs.solo.io/agentgateway/2.2.x/security/extauth/byo-ext-auth-service/)
> **API:** [EnterpriseAgentgatewayExtAuth](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewayextauth)

### How it works

1. **Client sends request** to a protected route → Agentgateway Proxy
2. **Proxy sends a gRPC `CheckRequest`** (with headers, path, method) → External Auth Service
3. **External auth service runs custom authorization logic** (check headers, tokens, database lookups, etc.)
4. **If authorized:** Auth service returns `ALLOW` (optionally injecting headers) → Proxy forwards the request to the backend → Backend responds → Proxy returns `200 OK` to the client
5. **If not authorized:** Auth service returns `DENY` (with status code and message) → Proxy returns `403 Forbidden` to the client

![Diagram](../../images/10-byo-ext-auth.png)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

### Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`:

```bash
# No auth token → 403
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Wrong token → 403
curl -s -o /dev/null -w "%{http_code}" -H "x-auth-token: wrong" http://localhost:8888/

# Valid token → 200
curl -s -H "x-auth-token: super-secret-token" http://localhost:8888/
```

Back to [Auth Patterns overview](../../README.md)
