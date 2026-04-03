# Flow 7: Claim-Based Token Mapping (JWT Claim --> Static Opaque Token)

Validate the inbound OIDC JWT, inspect a claim (sub, team, tier), then use a CEL transformation to inject a per-user or per-group static opaque token. Enables differentiated backend access based on identity attributes.

> **Docs:** [CEL Transformations](https://docs.solo.io/agentgateway/2.2.x/traffic-management/transformations/) · [JWT Auth for MCP Services](https://docs.solo.io/agentgateway/2.2.x/mcp/mcp-access/)
> **API:** [EnterpriseAgentgatewayPolicyTraffic](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaytrafficpolicy)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant Backend as Upstream API

    Client->>AGW: Request + Authorization: Bearer [OIDC JWT]
    AGW->>AGW: 1. Validate JWT (jwtAuthentication)
    AGW->>AGW: 2. Extract claim (e.g., jwt.sub, jwt.team)
    AGW->>AGW: 3. CEL transformation:<br/>jwt.team == 'engineering'<br/>? 'Bearer opaque-token-eng'<br/>: 'Bearer opaque-token-default'
    AGW->>Backend: Request + Authorization: Bearer [mapped opaque token]
    Backend-->>AGW: Response
    AGW-->>Client: Response

    Note over AGW: EnterpriseAgentgatewayPolicy config:
    Note over AGW: traffic.jwtAuthentication (validate)
    Note over AGW: traffic.transformation.request.set (map claim -> token)
```
![Diagram](../images/7-claim-based-mapping.png)

Back to [Auth Patterns overview](../README.md)
