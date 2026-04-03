# Flow 2a: OBO Delegation (Dual Identity)

Agent exchanges the user's JWT for a delegated OBO token via RFC 8693 Token Exchange. The user's JWT must include a `may_act` claim authorizing the agent. The STS validates both the user JWT and the agent's K8s service account token, then issues a new JWT (signed by Agent Gateway) containing both `sub` (user) and `act` (agent). Downstream services trust the Agent Gateway issuer and can enforce policies on both identities.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/)
> **API:** [Helm tokenExchange values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

```mermaid
sequenceDiagram
    participant User
    participant Agent
    participant STS as Agent Gateway STS
    participant MCP as MCP Tool Server

    User->>Agent: Request with user JWT<br/>(contains may_act claim)
    Agent->>STS: POST /token<br/>(grant_type=token-exchange,<br/>subject_token=user JWT,<br/>actor_token=agent K8s SA token)
    STS->>STS: Validate user JWT (JWKS)<br/>Validate actor token (K8s)<br/>Verify may_act authorizes actor
    STS-->>Agent: New OBO token (signed by AGW)<br/>(sub=user, act.sub=agent)
    Agent->>MCP: Call with OBO token
    MCP->>MCP: Policies check both<br/>sub (user) + act (agent)
    MCP-->>Agent: Response
    Agent-->>User: Result

    Note over STS: OBO token is a NEW JWT signed by AGW.<br/>Original IdP token is replaced.<br/>sub: user-123, act.sub: agent-k8s-sa
```

Back to [Auth Patterns overview](../README.md)
