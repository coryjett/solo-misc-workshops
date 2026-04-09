# Gateway-Mediated OIDC + Token Exchange

Agent Gateway handles OIDC authentication, then automatically exchanges the IdP token via RFC 8693 before forwarding to the agent. The agent never sees the original IdP token — it trusts only the STS issuer. The client never calls the STS directly; the gateway handles the exchange transparently.

Two variants depending on STS deployment:

### Variant A: Built-in STS

Uses AGW's built-in token exchange server (`enterprise-agentgateway:7777`). Configured via `ExchangeOnly` mode on `EnterpriseAgentgatewayPolicy`. The STS validates the user JWT (JWKS) and agent identity (K8s SA token), then issues a new JWT with both `sub` (user) and `act` (agent). Best for environments where AGW owns the trust domain.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/)
> **API:** [Helm tokenExchange values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

#### How it works

**Phase 1 — OIDC Authentication (at the Gateway)**

1. **User sends request** (no token) → Agent Gateway (Proxy)
2. **Gateway returns 302 redirect** to the IdP's `/authorize` endpoint (with `client_id`, `redirect_uri`, `scope`, `state`)
3. **IdP presents login prompt** → User submits credentials → IdP
4. **IdP returns 302 callback** with authorization code → Agent Gateway
5. **Gateway exchanges the code** → `POST /token` (with `code`, `client_secret`) → IdP
6. **IdP returns user JWT** (access_token + id_token) → Agent Gateway

**Phase 2 — Token Exchange (built-in STS)**

7. **Gateway sends RFC 8693 token exchange request** → `POST /token` (`grant_type=token-exchange`, `subject_token=user JWT`, `actor_token=K8s SA token`) → AGW Built-in STS
8. **STS validates the user JWT** (JWKS), validates the actor token (K8s), and issues an exchanged token
9. **STS returns a new token** (signed by AGW STS) containing `sub` (user) and `act` (agent) → Gateway

**Phase 3 — Forward to Agent**

10. **Gateway forwards the request** with `Authorization: Bearer <exchanged token>` → Agent / MCP Server (original IdP token is never forwarded)
11. **Agent validates the token** (trusts AGW STS issuer)
12. **Agent responds** → Gateway → User

![Built-in STS](../../images/13-gateway-mediated-builtin.png)

### Variant B: External STS (RFC 8693)

Uses an external RFC 8693-compliant token exchange provider (e.g., Microsoft Entra ID, or any custom STS via `STS_URI`). The gateway exchanges the IdP token via the external STS. The agent never sees the original IdP token.

#### How it works

**Phase 1 — OIDC Authentication (at the Gateway)**

1. **User sends request** (no token) → Agent Gateway (Proxy)
2. **Gateway returns 302 redirect** to the IdP's `/authorize` endpoint (with `client_id`, `redirect_uri`, `scope`, `state`)
3. **IdP presents login prompt** → User submits credentials → IdP
4. **IdP returns 302 callback** with authorization code → Agent Gateway
5. **Gateway exchanges the code** → `POST /token` (with `code`, `client_secret`) → IdP
6. **IdP returns user JWT** (access_token + id_token) → Agent Gateway

**Phase 2 — Token Exchange (external STS)**

7. **Gateway sends RFC 8693 token exchange request** → `POST /token` (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token=user JWT`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt`) → External STS
8. **External STS validates the user JWT** and issues an exchanged token
9. **STS returns a new token** (signed by the external STS) → Gateway

**Phase 3 — Forward to Agent**

10. **Gateway forwards the request** with `Authorization: Bearer <exchanged token>` → Agent / MCP Server (original IdP token is never forwarded)
11. **Agent validates the token** (trusts the external STS issuer)
12. **Agent responds** → Gateway → User

![External STS](../../images/13-gateway-mediated-external.png)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

### Interactive testing with MCP Inspector

After running `setup.sh`, you can explore the MCP server interactively using [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
# Get a JWT from Keycloak
USER_JWT=$(curl -s -X POST "http://localhost:8080/realms/flow13-realm/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=agw-client&client_secret=agw-client-secret&username=testuser&password=testuser&scope=openid" \
  | jq -r '.access_token')

# Launch MCP Inspector web UI
mcp-inspector --server-url http://localhost:8888/mcp --transport http \
  --header "Authorization: Bearer ${USER_JWT}"
```

Back to [Auth Patterns overview](../../README.md)
