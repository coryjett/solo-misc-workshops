# Flow 10: BYO External Auth (HTTP Ext Auth Service)

Delegate authentication to your own external authorization service using the Envoy `ext_authz` protocol — **this example uses the HTTP variant** (gRPC is also supported). The gateway sends ext_authz requests to your service, which returns allow/deny decisions. Supports custom logic, enterprise IdPs, or multi-factor checks.

> **Docs:** [BYO Ext Auth Service](https://docs.solo.io/agentgateway/latest/security/extauth/byo-ext-auth-service/)
> **API:** [EnterpriseAgentgatewayExtAuth](https://docs.solo.io/agentgateway/latest/reference/api/solo/#enterpriseagentgatewayextauth)

### How it works

1. **Client sends request** to a protected route → Agentgateway Proxy
2. **Proxy sends an HTTP ext_authz request** (with headers, path, method) → External Auth Service
3. **External auth service runs custom authorization logic** (check headers, tokens, database lookups, etc.)
4. **If authorized:** Auth service returns `ALLOW` (optionally injecting headers) → Proxy forwards the request to the backend → Backend responds → Proxy returns `200 OK` to the client
5. **If not authorized:** Auth service returns `DENY` (with status code and message) → Proxy returns `403 Forbidden` to the client

![Diagram](../../images/10-byo-ext-auth.png)

> Diagram source: [`../../diagrams/10-byo-ext-auth.mmd`](../../diagrams/10-byo-ext-auth.mmd)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

Back to [Auth Patterns overview](../../README.md)
