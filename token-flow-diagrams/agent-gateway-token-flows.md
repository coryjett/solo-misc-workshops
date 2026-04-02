# Agent Gateway Token Flows & Exchange Possibilities

> **Documentation:** [docs.solo.io/agentgateway/2.2.x](https://docs.solo.io/agentgateway/2.2.x/) | **API Reference:** [Enterprise API](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/) · [OSS API](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/) · [Helm Values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

---

## Flow 1: Standard OIDC Authentication

User authenticates via OIDC provider (Authorization Code Flow), receives a bearer JWT, and uses it for all subsequent requests to the Agent Gateway.

> **Docs:** [JWT Auth for MCP Services](https://docs.solo.io/agentgateway/2.2.x/mcp/mcp-access/) · [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) · [Set up Keycloak as IdP](https://docs.solo.io/agentgateway/2.2.x/security/extauth/oauth/keycloak/)
> **API:** [JWTAuthentication](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#jwtauthentication)

```mermaid
sequenceDiagram
    participant User
    participant App as Application
    participant IdP as OIDC Provider

    User->>App: GET /auth/login
    App->>IdP: 302 Redirect to /authorize<br/>(client_id, redirect_uri, scope=openid profile email)
    IdP->>User: Login prompt
    User->>IdP: Credentials
    IdP->>App: 302 Callback with authorization code
    App->>IdP: POST /token<br/>(code, client_secret)
    IdP-->>App: Bearer JWT (access_token + id_token)
    App-->>User: Session created
```

---

## Flow 2a: OBO Delegation (Dual Identity)

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

---

## Flow 2b: OBO Impersonation (Token Swap)

Agent exchanges the user's JWT for a new OBO token via RFC 8693, but without an actor token. The STS validates the user JWT, then issues a new JWT (signed by Agent Gateway) with the same `sub` and scopes — no `act` claim. Downstream services trust the Agent Gateway issuer and see only the user's identity. The original IdP token is replaced, keeping user identity consistent without passing IdP tokens through the stack.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/)
> **API:** [Helm tokenExchange values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

```mermaid
sequenceDiagram
    participant User
    participant Agent
    participant STS as Agent Gateway STS
    participant MCP as MCP Tool Server

    User->>Agent: Request with user JWT
    Agent->>STS: POST /token<br/>(grant_type=token-exchange,<br/>subject_token=user JWT)
    STS->>STS: Validate user JWT (JWKS)
    STS-->>Agent: New OBO token (signed by AGW)<br/>(sub=user, same scopes, no act claim)
    Agent->>MCP: Call with OBO token
    MCP->>MCP: Policies check user identity<br/>(agent identity not tracked)
    MCP-->>Agent: Response
    Agent-->>User: Result

    Note over STS: OBO token is a NEW JWT signed by AGW.<br/>Original IdP token is replaced.<br/>Downstream trusts AGW issuer, not original IdP.
```

---

## Flow 3: Elicitation (Credential Gathering for Upstream APIs)

When the agent needs to call an upstream API requiring OAuth credentials that don't exist yet. The gateway returns an elicitation URL; the user completes an out-of-band OAuth flow to provide the credentials.

> **Docs:** [Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/elicitations/) · [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/)
> **API:** [TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode)

```mermaid
sequenceDiagram
    participant User
    participant AGW as Agent Gateway Proxy
    participant STS as Token Exchange Server
    participant UI as Enterprise UI
    participant ExtIdP as External OAuth Provider
    participant API as Upstream API

    User->>AGW: Request (needs upstream OAuth token)
    AGW->>STS: Request upstream token
    STS-->>AGW: Elicitation URL (status: PENDING)
    AGW-->>User: Return elicitation URL

    User->>UI: Open elicitation URL
    UI->>ExtIdP: Redirect for OAuth authorization
    ExtIdP->>User: Login/consent prompt
    User->>ExtIdP: Authorize
    ExtIdP->>UI: Redirect with authorization code
    UI->>STS: Complete elicitation (code)
    STS->>STS: Store token (status: COMPLETED)

    User->>AGW: Retry original request
    AGW->>STS: Fetch stored token
    STS-->>AGW: Upstream OAuth token
    AGW->>API: Forward request + inject token
    API-->>AGW: Response
    AGW-->>User: Result
```

---

## Flow 4: Double OAuth Flow (OIDC Bearer → Upstream Token Exchange)

User authenticates via OIDC (gets bearer JWT), then that token is exchanged for a different upstream token (could be opaque). Combines downstream and upstream OAuth in a single automated flow.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/elicitations/)

```mermaid
sequenceDiagram
    participant Client
    participant Issuer as OAuth Issuer (Controller)
    participant DownstreamIdP as Downstream IdP (OIDC)
    participant UpstreamSTS as Upstream STS
    participant Elicit as Elicitation Endpoint

    Note over Client,Elicit: Phase 1: Get Downstream Bearer Token (OIDC)
    Client->>Issuer: GET /authorize (client_id, redirect_uri, state, resource)
    Issuer-->>Client: 302 -> Downstream authorize URL
    Client->>Issuer: GET /callback/downstream (state, code)
    Issuer->>DownstreamIdP: POST /token (exchange code)
    DownstreamIdP-->>Issuer: downstream-access-token (Bearer JWT) + id_token

    Note over Client,Elicit: Phase 2: Exchange for Upstream Token (Opaque)
    Issuer-->>Client: 307 -> Upstream authorize URL
    Client->>Issuer: GET /callback/upstream (state, code)
    Issuer->>UpstreamSTS: POST /token (exchange code)
    UpstreamSTS-->>Issuer: upstream-token (opaque)
    Issuer-->>Client: 302 -> redirect_uri?code=AUTH_CODE

    Note over Client,Elicit: Phase 3: Retrieve Tokens
    Client->>Issuer: POST /token (grant_type=authorization_code, code)
    Issuer-->>Client: downstream-access-token (Bearer JWT)

    Client->>Elicit: POST /elicitations/oauth2/token<br/>(subject_token=K8s SA, resource)
    Elicit-->>Client: upstream-token (opaque)
```

---

## Flow 5: Passthrough Token

Client already has the correct token (from its own OIDC flow or API key). Gateway forwards it directly to the backend — no validation or exchange performed.

> **Docs:** [API Keys — Passthrough Token](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
> **API:** [AIBackend](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#aibackend)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant Backend as Backend (LLM / MCP / API)

    Note over Client: Client already authenticated<br/>(has token from its own OIDC flow or API key)
    Client->>AGW: Request + Authorization: Bearer <token>
    AGW->>AGW: Passthrough (no validation/exchange)
    AGW->>Backend: Forward request with same token
    Backend-->>AGW: Response
    AGW-->>Client: Response
```

---

## Flow 6: Static Secret Injection (Shared Credential)

Gateway validates inbound auth (JWT or API key), then replaces it with a static backend credential from a Kubernetes secret. All users share the same upstream token.

> **Docs:** [API Keys — Manage API Keys](https://docs.solo.io/agentgateway/2.2.x/llm/api-keys/)
> **API:** [AIBackend](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#aibackend)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant K8s as K8s Secret<br/>(opaque token)
    participant Backend as Upstream API

    Client->>AGW: Request + Authorization: Bearer <user JWT>
    AGW->>AGW: Validate JWT (jwtAuthentication)
    AGW->>K8s: Read secretRef / inline key
    K8s-->>AGW: Static opaque token
    AGW->>Backend: Request + Authorization: Bearer <opaque token>
    Backend-->>AGW: Response
    AGW-->>Client: Response

    Note over AGW,K8s: Configured via AgentgatewayBackend:<br/>policies.auth.secretRef or policies.auth.key
```

---

## Flow 7: Claim-Based Token Mapping (JWT Claim → Static Opaque Token)

Validate the inbound OIDC JWT, inspect a claim (sub, team, tier), then use a CEL transformation to inject a per-user or per-group static opaque token. Enables differentiated backend access based on identity attributes.

> **Docs:** [CEL Transformations](https://docs.solo.io/agentgateway/2.2.x/traffic-management/transformations/) · [JWT Auth for MCP Services](https://docs.solo.io/agentgateway/2.2.x/mcp/mcp-access/)
> **API:** [EnterpriseAgentgatewayPolicyTraffic](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaytrafficpolicy)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant Backend as Upstream API

    Client->>AGW: Request + Authorization: Bearer <OIDC JWT>
    AGW->>AGW: 1. Validate JWT (jwtAuthentication)
    AGW->>AGW: 2. Extract claim (e.g., jwt.sub, jwt.team)
    AGW->>AGW: 3. CEL transformation:<br/>jwt.team == 'engineering'<br/>? 'Bearer opaque-token-eng'<br/>: 'Bearer opaque-token-default'
    AGW->>Backend: Request + Authorization: Bearer <mapped opaque token>
    Backend-->>AGW: Response
    AGW-->>Client: Response

    Note over AGW: EnterpriseAgentgatewayPolicy config:
    Note over AGW: traffic.jwtAuthentication (validate)
    Note over AGW: traffic.transformation.request.set (map claim -> token)
```

---

## Flow 8: API Key Auth (Inbound)

Clients authenticate with a static API key instead of OIDC. Gateway validates the key against Kubernetes secrets (by label selector or name).

> **Docs:** [API Key Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/apikey/)
> **API:** [APIKeyAuthentication](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#apikeyauthentication)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant K8s as K8s Secrets<br/>(API Keys)
    participant Backend as Backend

    Client->>AGW: Request + Authorization: Bearer <API key>
    AGW->>K8s: Lookup secret (by label selector or name)
    K8s-->>AGW: Secret found, compare key

    alt Key valid
        AGW->>Backend: Forward request
        Backend-->>AGW: Response
        AGW-->>Client: 200 OK
    else Key invalid
        AGW-->>Client: 401 Unauthorized
    end
```

---

## Flow 9: Basic Auth (RFC 7617)

Clients authenticate with username and password (Base64-encoded in the Authorization header). Gateway validates credentials against hashed values stored in Kubernetes secrets. Useful for legacy integrations or simple service-to-service auth.

> **Docs:** [Basic Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/basic/)
> **API:** [BasicAuthentication](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#basicauthentication)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant K8s as K8s Secret<br/>(hashed credentials)
    participant Backend as Backend

    Client->>AGW: Request + Authorization: Basic <base64(user:pass)>
    AGW->>AGW: Decode Base64 credentials
    AGW->>K8s: Read secret with hashed passwords
    AGW->>AGW: Verify password hash (APR1)

    alt Credentials valid
        AGW->>Backend: Forward request<br/>(credential stripped or replaced)
        Backend-->>AGW: Response
        AGW-->>Client: 200 OK
    else Credentials invalid
        AGW-->>Client: 401 Unauthorized
    end

    Note over AGW,K8s: Configured via EnterpriseAgentgatewayPolicy:<br/>traffic.basicAuth with K8s secretRef
```

---

## Flow 10: BYO External Auth (gRPC Ext Auth Service)

Delegate authentication to your own external authorization service via gRPC. The gateway sends auth check requests to your service, which returns allow/deny decisions. Supports custom logic, enterprise IdPs, or multi-factor checks.

> **Docs:** [External Auth](https://docs.solo.io/agentgateway/2.2.x/security/extauth/)
> **API:** [EnterpriseAgentgatewayExtAuth](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewayextauth)

```mermaid
sequenceDiagram
    participant Client
    participant AGW as Agent Gateway Proxy
    participant ExtAuth as External Auth Service<br/>(gRPC)
    participant Backend as Backend

    Client->>AGW: Request + credentials
    AGW->>ExtAuth: gRPC CheckRequest<br/>(headers, path, method)
    ExtAuth->>ExtAuth: Custom auth logic<br/>(LDAP, SAML, MFA, etc.)

    alt Authorized
        ExtAuth-->>AGW: OK + optional headers
        AGW->>Backend: Forward request<br/>(+ injected headers from ext auth)
        Backend-->>AGW: Response
        AGW-->>Client: 200 OK
    else Denied
        ExtAuth-->>AGW: Denied + status code
        AGW-->>Client: 401/403 Unauthorized
    end

    Note over AGW,ExtAuth: Configured via EnterpriseAgentgatewayPolicy:<br/>traffic.extAuth with gRPC service reference
```

---

## Flow 11: MCP OAuth with Dynamic Client Registration

MCP clients (like Claude Code, VS Code extensions) that don't have pre-registered OAuth credentials use Dynamic Client Registration (DCR) to register themselves, then complete a standard OAuth flow. Enables zero-configuration MCP client onboarding.

> **Docs:** [About MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/about/) · [Set up Keycloak for MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/keycloak/)

```mermaid
sequenceDiagram
    participant MCPClient as MCP Client<br/>(Claude Code / VS Code)
    participant AGW as Agent Gateway<br/>(OAuth Server)
    participant IdP as Identity Provider

    Note over MCPClient,IdP: Phase 1: Dynamic Client Registration
    MCPClient->>AGW: GET /.well-known/oauth-authorization-server
    AGW-->>MCPClient: Authorization server metadata<br/>(registration_endpoint, authorize, token)
    MCPClient->>AGW: POST /register<br/>(client_name, redirect_uris, grant_types)
    AGW-->>MCPClient: client_id + client_secret (dynamic)

    Note over MCPClient,IdP: Phase 2: Standard OAuth Authorization
    MCPClient->>AGW: GET /authorize<br/>(client_id, redirect_uri, code_challenge)
    AGW->>IdP: Redirect to IdP login
    IdP->>MCPClient: Login + consent
    MCPClient->>IdP: Credentials
    IdP->>AGW: Callback with code
    AGW-->>MCPClient: Redirect with authorization code

    Note over MCPClient,IdP: Phase 3: Token Exchange
    MCPClient->>AGW: POST /token<br/>(code, client_id, code_verifier)
    AGW-->>MCPClient: Access token (Bearer JWT)
```

---

## Flow 12: RBAC Tool-Level Access Control

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

---

## Flow 13: Gateway-Mediated OIDC + Token Exchange

Agent Gateway handles OIDC authentication, then exchanges the IdP token with an external RFC 8693 Security Token Service (STS) before forwarding to the agent. The agent never sees the original IdP token — it trusts only the STS issuer. Decouples the IdP from downstream services and works with any compliant STS.

> **Docs:** [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Set up JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/)
> **API:** [Helm tokenExchange values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)

```mermaid
sequenceDiagram
    participant User
    participant AGW as Agent Gateway<br/>(Proxy)
    participant IdP as OIDC Provider
    participant STS as External STS<br/>(RFC 8693)
    participant Agent as Agent / MCP Server

    Note over User,Agent: Phase 1: OIDC Authentication (at the Gateway)
    User->>AGW: Request (no token)
    AGW-->>User: 302 Redirect to IdP /authorize<br/>(client_id, redirect_uri, scope, state)
    User->>IdP: Login prompt
    IdP->>User: Credentials
    User->>IdP: Submit credentials
    IdP-->>AGW: 302 Callback with authorization code
    AGW->>IdP: POST /token (code, client_secret)
    IdP-->>AGW: User JWT (access_token + id_token)

    Note over User,Agent: Phase 2: RFC 8693 Token Exchange (external STS)
    AGW->>STS: POST /token<br/>(grant_type=urn:ietf:params:oauth:grant-type:token-exchange,<br/>subject_token=user JWT,<br/>subject_token_type=urn:ietf:params:oauth:token-type:jwt)
    STS->>STS: Validate user JWT<br/>Issue exchanged token
    STS-->>AGW: New token (signed by STS)

    Note over User,Agent: Phase 3: Forward to Agent
    AGW->>Agent: Request + Authorization: Bearer <exchanged token><br/>(original IdP token never forwarded)
    Agent->>Agent: Validate token (trusts STS issuer)
    Agent-->>AGW: Response
    AGW-->>User: Result

    Note over AGW: Agent never sees the original IdP token.<br/>Token exchange via external RFC 8693 STS.<br/>Works with any OIDC provider + any compliant STS.
```

---

## Decision Flowchart: How Should This Request Be Authenticated?

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
