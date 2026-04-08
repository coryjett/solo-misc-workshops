# Flow 6: Static Secret Injection (Shared Credential)

Inbound auth (JWT or API key policy) validates the client independently. A separate backend auth policy (`secretRef`) injects a static credential from a Kubernetes secret into the outbound `Authorization` header. These are two independent policy layers — inbound validation and backend credential injection are configured separately. All users share the same upstream token.

> **Docs:** [API Keys — Manage API Keys](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
> **API:** [BackendAuth](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#backendauth)

### How it works

1. **Client sends request** with `Authorization: Bearer <user-JWT>` → Agentgateway Proxy
2. **Proxy validates the inbound JWT** via `jwtAuthentication` policy (JWKS verification)
3. **Proxy reads the static opaque token** from the Kubernetes secret (via `secretRef` or inline `key`)
4. **Proxy replaces the `Authorization` header** with the static opaque token
5. **Proxy forwards the request** with `Authorization: Bearer <opaque-token>` → Upstream API
6. **Upstream API responds** → Agentgateway Proxy
7. **Proxy returns the response** → Client

![Diagram](../images/6-static-secret.png)

Back to [Auth Patterns overview](../README.md)
