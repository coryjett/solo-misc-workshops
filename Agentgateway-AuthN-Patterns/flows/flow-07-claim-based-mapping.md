# Flow 7: Claim-Based Token Mapping (JWT Claim --> Static Opaque Token)

Validate the inbound OIDC JWT, inspect a claim (sub, team, tier), then use a CEL transformation to inject a per-user or per-group static opaque token. Enables differentiated backend access based on identity attributes.

> **Docs:** [CEL Transformations](https://docs.solo.io/agentgateway/2.2.x/traffic-management/transformations/) · [JWT Auth for MCP Services](https://docs.solo.io/agentgateway/2.2.x/mcp/mcp-access/)
> **API:** [EnterpriseAgentgatewayPolicyBackend](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaybackendpolicy) · [EnterpriseAgentgatewayPolicyTraffic](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaytrafficpolicy)

### How it works

1. **Client sends request** with `Authorization: Bearer <OIDC-JWT>` → Agentgateway Proxy
2. **Proxy validates the JWT** via `jwtAuthentication` policy (JWKS verification)
3. **Proxy extracts a claim** from the validated JWT (e.g., `jwt.sub`, `jwt.team`)
4. **Proxy evaluates a CEL transformation** that maps the claim value to a static opaque token (e.g., `jwt.team == "engineering"` → `opaque-token-eng`, else → `opaque-token-default`)
5. **Proxy forwards the request** with `Authorization: Bearer <mapped-opaque-token>` → Upstream API
6. **Upstream API responds** → Agentgateway Proxy
7. **Proxy returns the response** → Client

![Diagram](../images/7-claim-based-mapping.png)

Back to [Auth Patterns overview](../README.md)
