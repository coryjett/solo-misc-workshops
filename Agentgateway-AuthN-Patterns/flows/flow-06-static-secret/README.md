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

![Diagram](../../images/6-static-secret.png)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

### Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`. Get a JWT and test:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow06-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# No JWT → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Valid JWT → 200 (backend receives opaque token, not the JWT)
curl -s -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/
# Response shows is_opaque: true — the JWT was swapped for a static secret
```

Back to [Auth Patterns overview](../../README.md)
