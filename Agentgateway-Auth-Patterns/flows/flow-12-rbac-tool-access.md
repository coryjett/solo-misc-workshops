# Flow 12: RBAC Tool-Level Access Control

After authentication (via any flow), apply per-tool authorization using CEL expressions evaluated against JWT claims. Controls which users or groups can invoke specific MCP tools.

> **Docs:** [Control Access to Tools](https://docs.solo.io/agentgateway/2.2.x/mcp/tool-access/)
> **API:** [EnterpriseAgentgatewayPolicyTraffic (rbac)](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaytrafficpolicy)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant MCP as MCP Tool Server

    Client->>AGW: Authenticated request<br/>(Bearer JWT from Flow 1, 2a, or 11)
    AGW->>AGW: Extract JWT claims<br/>(sub, groups, roles, team)

    alt Tool: "deploy-production"
        AGW->>AGW: CEL: 'platform-eng' in jwt.groups
        Note over AGW: Only platform engineers<br/>can deploy to production
    else Tool: "read-logs"
        AGW->>AGW: CEL: jwt.role in ['engineer', 'sre']
        Note over AGW: Engineers and SREs<br/>can read logs
    else Tool: "query-data"
        AGW->>AGW: CEL: true (allow all authenticated)
    end

    alt CEL evaluates to true
        AGW->>MCP: Forward tool call
        MCP-->>AGW: Tool response
        AGW-->>Client: Response
    else CEL evaluates to false
        AGW-->>Client: 403 Forbidden
    end

    Note over AGW: Configured via EnterpriseAgentgatewayPolicy:<br/>traffic.rbac with CEL expressions per tool
```

Back to [Auth Patterns overview](../README.md)
