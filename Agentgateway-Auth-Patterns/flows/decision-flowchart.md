# Decision Flowchart: How Should This Request Be Authenticated?

> **Docs:** [Security Overview](https://docs.solo.io/agentgateway/2.2.x/security/) · [OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/) · [External Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/) · [MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/about/)
> **API:** [Enterprise API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/)

```mermaid
flowchart TD
    Start(["How should this request<br/>be authenticated?"]) --> Q1{"Does the client<br/>already have valid<br/>credentials?"}

    Q1 -->|"Yes, forward as-is"| F5["Flow 5: Passthrough"]
    Q1 -->|No| Q2{"What type of<br/>credentials are needed?"}

    Q2 -->|"User login (interactive)"| Q_LOGIN{"What auth method?"}
    Q2 -->|"Agent/service acting<br/>for a user"| Q_OBO{"Need agent identity<br/>tracked separately?"}
    Q2 -->|"Backend/upstream<br/>credential needed"| Q_UPSTREAM{"Is the upstream<br/>credential static<br/>or dynamic?"}
    Q2 -->|"MCP client connecting<br/>to MCP server"| Q_MCP{"Client type?"}

    %% Login methods
    Q_LOGIN -->|"OIDC / OAuth"| Q_OIDC{"Where does token<br/>exchange happen?"}
    Q_LOGIN -->|"Username / password"| F9["Flow 9: Basic Auth"]
    Q_LOGIN -->|"Pre-shared key"| F8["Flow 8: API Key Auth"]
    Q_LOGIN -->|"Custom / enterprise IdP"| F10["Flow 10: BYO Ext Auth"]

    %% OIDC sub-paths
    Q_OIDC -->|"Client/app handles OIDC,<br/>passes JWT to gateway"| F1["Flow 1: OIDC Auth"]
    Q_OIDC -->|"Gateway handles OIDC +<br/>exchanges token before agent"| F13["Flow 13: Gateway-Mediated<br/>OIDC + Token Exchange"]

    %% OBO paths
    Q_OBO -->|"Yes, dual identity<br/>(audit + fine-grained policy)"| F2a["Flow 2a: OBO Delegation"]
    Q_OBO -->|"No, act as the user<br/>(downstream sees user only)"| F2b["Flow 2b: OBO Impersonation"]

    %% Upstream credential
    Q_UPSTREAM -->|"Static, shared<br/>across all users"| F6["Flow 6: Static Secret"]
    Q_UPSTREAM -->|"Static, per-user/group<br/>(map by JWT claim)"| F7["Flow 7: Claim-Based Mapping"]
    Q_UPSTREAM -->|"Dynamic, requires<br/>OAuth exchange"| Q_DYN{"Is user present<br/>to authorize?"}

    Q_DYN -->|"Yes"| F3["Flow 3: Elicitation"]
    Q_DYN -->|"Need both downstream<br/>+ upstream tokens"| F4["Flow 4: Double OAuth"]

    %% MCP clients
    Q_MCP -->|"Dynamic client<br/>(Claude Code, VS Code)"| F11["Flow 11: MCP OAuth + DCR"]
    Q_MCP -->|"Static client<br/>(service / known app)"| F1

    %% RBAC overlay
    F1 --> Q_RBAC{"Need per-tool<br/>access control?"}
    F2a --> Q_RBAC
    F11 --> Q_RBAC
    F13 --> Q_RBAC
    Q_RBAC -->|Yes| F12["Flow 12: RBAC Tool Access"]
    Q_RBAC -->|No| Done(["Done"])

    style F2a fill:#e0f2fe,stroke:#0064c8
    style F2b fill:#fef3c7,stroke:#d97706
    style F12 fill:#f3e8ff,stroke:#7c3aed
    style F11 fill:#ecfdf5,stroke:#059669
    style F13 fill:#fef0c7,stroke:#d97706
```
![Diagram](../images/decision-flowchart.png)

Back to [Auth Patterns overview](../README.md)
