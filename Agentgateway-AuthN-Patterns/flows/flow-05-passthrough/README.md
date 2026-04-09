# Flow 5: Passthrough Token

Inbound auth policies (JWT, API key) validate and strip the client's original `Authorization` header. Passthrough backend auth re-attaches the validated token to the outbound request so it is forwarded to the backend as-is. Useful for federated identity environments where clients are already authenticated to the upstream provider.

> **Docs:** [API Keys — Passthrough Token](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
> **API:** [BackendAuth](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#backendauth)

### How it works

1. **Client sends request** with `Authorization: Bearer <token>` (obtained from its own OIDC flow or API key) → Agentgateway Proxy
2. **Proxy passes the token through** without validation or exchange (passthrough mode)
3. **Proxy forwards the request** to the backend (LLM / MCP / API) with the same `Authorization` header intact
4. **Backend responds** → Agentgateway Proxy
5. **Proxy returns the response** → Client

![Diagram](../../images/5-passthrough.png)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

### Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8888`. Get a JWT and test:

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow05-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# No JWT → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/

# Valid JWT → 200 (backend receives the original token, passthrough)
curl -s -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/
```

Back to [Auth Patterns overview](../../README.md)
