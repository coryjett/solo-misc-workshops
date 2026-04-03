# OBO Token Exchange in Agent Gateway

> **Documentation:** [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/) · [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Helm Values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
> **API:** [TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode) · [TokenExchangeCfg](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangecfg) · [EnterpriseAgentgatewayPolicy](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaytrafficpolicy)
> **Standard:** [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)

---

## Overview

Solo Enterprise for Agent Gateway includes a **built-in Security Token Service (STS)** that implements RFC 8693 (OAuth 2.0 Token Exchange). The STS runs on the control plane at port `7777` and enables agents and services to act on behalf of users through token delegation — without requiring your identity provider (IdP) to natively support RFC 8693.

The STS supports two exchange modes that differ in whether the **agent's identity** is preserved in the resulting token:

| Mode | Actor Token | `act` Claim | Use Case |
|---|---|---|---|
| **Delegation** | Required (K8s SA token) | Present (`sub` + `iss` of agent) | Policies need both user AND agent identity |
| **Impersonation** | Not provided | Absent | Downstream sees only the user, agent is transparent |

Both modes work identically across MCP and non-MCP (LLM, HTTP) downstreams — the STS generates the same JWT structure regardless of backend type. The difference is in how the data plane proxy is configured to trigger the exchange.

---

## How the STS Works

### Architecture

```
                          ┌──────────────────────────────┐
                          │  Control Plane (:7777)       │
                          │  ┌────────────────────────┐  │
  User JWT ──►  Agent ──► │  │  Built-in STS          │  │
                          │  │  - Subject Validator    │  │
                          │  │  - Actor Validator      │  │
                          │  │  - API Validator        │  │
                          │  └────────────────────────┘  │
                          └──────────┬───────────────────┘
                                     │ OBO JWT
                                     ▼
                             Downstream Service
                            (MCP / LLM / HTTP)
```

### Token Exchange Request (RFC 8693)

There are two ways to call the STS, depending on who performs the exchange:

**Gateway-mediated exchange** — the data plane proxy calls the STS automatically (`ExchangeOnly` mode). It sends only the subject token and resource — **no actor token**. This means gateway-mediated exchange always produces **impersonation-style** tokens (no `act` claim):

```
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <sts-auth-token>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user-jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=<upstream-service-name>      # becomes the "aud" claim (e.g., service/default/mcp-backend.default.svc.cluster.local:8080)
```

**Agent-initiated exchange** — the agent calls the STS directly. For **delegation**, it includes both the subject token and actor token. For **impersonation**, it omits the actor token:

```
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <api-auth-token>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user-jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&actor_token=<k8s-sa-token>            # present for delegation, omit for impersonation
&actor_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=<upstream-service-name>      # optional — sets the "aud" claim
```

The proxy auto-sets `resource` to the upstream Kubernetes service name. When an agent calls the STS directly, it can set `resource`, `audience`, and/or `scope` per RFC 8693.

---

## Delegation (Dual Identity)

Delegation preserves **both** the user's identity and the agent's identity in the OBO token. The downstream service can enforce policies that reference either or both principals.

### Requirements

1. The **subject token** (user JWT from IdP) must contain a `may_act` claim authorizing the specific agent
2. The **actor token** (K8s service account JWT) must be provided in the exchange request
3. The STS validates that the actor token's `sub` and `iss` match the `may_act` claim in the subject token

### Flow

```
User ──► Agent ──► AGW STS ──► Downstream
         │         │
         │         ├─ Validate subject token (JWKS)
         │         ├─ Validate actor token (K8s TokenReview)
         │         ├─ Cross-validate: actor matches may_act
         │         └─ Issue OBO JWT with sub + act
         │
         └─ K8s SA token (actor identity)
```

### OBO Token Claims (Delegation)

```json
{
  "iss": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777",
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "act": {
    "sub": "system:serviceaccount:agentgateway-system:my-agent",
    "iss": "https://kubernetes.default.svc.cluster.local"
  },
  "aud": "service/default/mcp-backend.default.svc.cluster.local:8080",
  "scope": "openid profile email",
  "exp": 1712275200,
  "iat": 1712188800
}
```

**Key claims:**

| Claim | Source | Description |
|---|---|---|
| `iss` | STS config | The STS issuer — downstream services trust this issuer, not the original IdP |
| `sub` | Subject token | The user's identity, copied from the original IdP JWT |
| `act` | Actor token | Nested object with the agent's `sub` and `iss` from its K8s SA token |
| `aud` | Exchange request | The target service — set from `resource` parameter (auto-populated by proxy to upstream service name) |
| `scope` | Subject token | Scopes from the original user JWT, preserved as-is |
| `exp` | STS config | Expiration based on `tokenExchange.tokenExpiration` (default: 24h) |
| `iat` | STS | Timestamp when the STS issued the token |

### The `may_act` Claim

The `may_act` claim in the user's JWT is the authorization mechanism that prevents arbitrary agents from performing delegation. The STS **rejects** the exchange if the actor doesn't match.

**Structure in the subject token:**

```json
{
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "may_act": {
    "sub": "system:serviceaccount:agentgateway-system:my-agent",
    "iss": "https://kubernetes.default.svc.cluster.local"
  },
  ...
}
```

**How to add `may_act` to your IdP tokens:**

In Keycloak, use a `hardcoded-claim` protocol mapper. First, extract the agent's K8s SA token identity:

```bash
# Get the actor's sub and iss from its K8s SA token
ACTOR_TOKEN=$(kubectl create token my-agent -n agentgateway-system --duration=3600s)
MAY_ACT_SUB=$(echo "$ACTOR_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.sub')
MAY_ACT_ISS=$(echo "$ACTOR_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.iss')

# Build the may_act JSON
MAY_ACT_JSON=$(jq -nc --arg sub "$MAY_ACT_SUB" --arg iss "$MAY_ACT_ISS" \
  '{sub: $sub, iss: $iss}')
```

Then create the mapper in Keycloak (via API or admin console):

```json
{
  "name": "may-act",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-hardcoded-claim-mapper",
  "config": {
    "claim.name": "may_act",
    "claim.value": "{\"sub\":\"system:serviceaccount:agentgateway-system:my-agent\",\"iss\":\"https://kubernetes.default.svc.cluster.local\"}",
    "jsonType.label": "JSON",
    "access.token.claim": "true",
    "id.token.claim": "false"
  }
}
```

### Validation Flow (Delegation)

```
Subject Token                          Actor Token
     │                                      │
     ▼                                      ▼
┌─────────────────┐                ┌─────────────────┐
│ Subject         │                │ Actor            │
│ Validator       │                │ Validator        │
│ (remote/JWKS)   │                │ (k8s)            │
│                 │                │                  │
│ ✓ Signature     │                │ ✓ TokenReview    │
│ ✓ Issuer        │                │ ✓ SA exists      │
│ ✓ Expiration    │                │ ✓ Extract sub/iss│
│ ✓ Extract sub   │                └────────┬─────────┘
│ ✓ Extract       │                         │
│   may_act       │                         │
└────────┬────────┘                         │
         │                                  │
         └──────────┬───────────────────────┘
                    │
                    ▼
          ┌─────────────────┐
          │ Cross-validate: │
          │ actor.sub ==    │
          │ may_act.sub     │
          │ actor.iss ==    │
          │ may_act.iss     │
          └────────┬────────┘
                   │ ✓ Match
                   ▼
          ┌─────────────────┐
          │ Issue OBO JWT   │
          │ sub + act       │
          └─────────────────┘
```

---

## Impersonation (Token Swap)

Impersonation replaces the IdP token with an STS-signed token containing **only the user's identity**. The agent is transparent — downstream services see only the user. No `may_act` claim is required.

### Flow

```
User ──► Agent ──► AGW STS ──► Downstream
                   │
                   ├─ Validate subject token (JWKS)
                   └─ Issue OBO JWT with sub only (no act)
```

### OBO Token Claims (Impersonation)

```json
{
  "iss": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777",
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "aud": "service/default/mcp-backend.default.svc.cluster.local:8080",
  "scope": "openid profile email",
  "exp": 1712275200,
  "iat": 1712188800
}
```

**No `act` claim.** The STS simply re-signs the user's identity under its own issuer. This is useful when:

- Downstream services don't need to know which agent made the call
- You want to unify trust domains (downstream trusts AGW STS, not the original IdP)
- Your IdP tokens contain claims that shouldn't leak to downstream services

### When to Use Each Mode

| Scenario | Mode |
|---|---|
| Audit trail must show which agent acted | **Delegation** |
| Policy decisions depend on agent identity (e.g., "Agent X can read but not write") | **Delegation** |
| Agent is transparent — downstream only cares about the user | **Impersonation** |
| Replace IdP token to avoid leaking IdP-specific claims downstream | **Impersonation** |
| IdP doesn't support custom claims like `may_act` | **Impersonation** |

---

## MCP vs Non-MCP Downstreams

The STS itself is **backend-agnostic** — it generates the same JWT regardless of whether the downstream is an MCP server, LLM provider, or HTTP API. The difference is in how the data plane proxy triggers the exchange.

### MCP Downstreams

For MCP backends, token exchange is configured via `EnterpriseAgentgatewayPolicy` with `tokenExchange.mode` on the backend section. The data plane proxy automatically exchanges the client's JWT at the STS before forwarding to the MCP server.

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-obo-policy
  namespace: agentgateway-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: mcp
  backend:
    tokenExchange:
      mode: ExchangeOnly    # or ElicitationOnly, or omit for both
```

**MCP authentication** on the backend validates the OBO token against the **STS issuer** (not the original IdP):

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-jwt-policy
  namespace: agentgateway-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: mcp
  backend:
    mcp:
      authentication:
        issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        jwks:
          backendRef:
            name: enterprise-agentgateway
            namespace: agentgateway-system
            port: 7777
          jwksPath: .well-known/jwks.json
    tokenExchange:
      mode: ExchangeOnly
```

**Key behavior:** The MCP server never sees the original IdP token. It receives only the STS-signed OBO JWT. CEL-based RBAC policies on MCP tools can reference both `sub` (user) and `act.sub` (agent) from the OBO token for fine-grained access control.

### Non-MCP Downstreams (LLM / HTTP)

For non-MCP backends (LLM providers, HTTP APIs, agent-to-agent), the token exchange is performed by the **agent itself** using the `agentsts-adk` Python package or a direct call to the STS `/token` endpoint. The data plane proxy does not automatically trigger the exchange — the agent is responsible for calling the STS and using the resulting OBO token.

```yaml
# JWT policy on a non-MCP route validates OBO tokens from the STS
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: llm-jwt-policy
  namespace: agentgateway-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: openai
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
      - issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        jwks:
          inline: '<STS JWKS>'
```

### Gateway-Mediated Exchange (ExchangeOnly)

A third option exists where the **gateway itself** performs the exchange transparently — the client sends its IdP JWT, and the proxy automatically exchanges it at the STS before forwarding to the backend. This works for both MCP and non-MCP routes via the `ExchangeOnly` mode on `EnterpriseAgentgatewayPolicy`:

```yaml
backend:
  tokenExchange:
    mode: ExchangeOnly
```

In this mode, the data plane proxy uses:
- `STS_URI` — the STS endpoint URL (auto-configured from Helm)
- `STS_AUTH_TOKEN` — a token to authenticate the proxy's own calls to the STS (validated by the API Validator)

**Important:** Gateway-mediated exchange is always **impersonation-style**. The proxy sends only `subject_token` and `resource` to the STS — it does **not** send an `actor_token`. This means the resulting OBO JWT will have a `sub` claim (user) but **no `act` claim** (agent). If you need delegation (dual identity with `act`), the agent must call the STS directly with both the subject token and its own K8s SA token as the actor token.

The client never calls the STS directly. This is the simplest integration path and works well when the gateway owns the trust boundary and downstream services don't need to know which agent made the call.

### Comparison

| Aspect | Gateway-Mediated (`ExchangeOnly`) | Agent-Initiated |
|---|---|---|
| Who calls the STS? | Data plane proxy (automatic) | Agent application (explicit) |
| Client awareness | None — transparent | Agent must integrate STS SDK (`agentsts-adk`) |
| Token in flight to backend | OBO JWT only | OBO JWT only |
| Backend type | MCP or non-MCP | Any (LLM, HTTP, A2A) |
| Delegation support? | **No** — always impersonation (no `act` claim) | **Yes** — include actor token for delegation |
| Agent SDK required? | No | Yes |

---

## Audience, Scopes, and Claim Generation

### How `aud` (Audience) Is Set

The `aud` claim in the OBO token identifies the intended recipient of the token — the downstream service that should accept it. It is derived from the `resource` parameter in the token exchange request.

**Gateway-mediated exchange:** When the data plane proxy performs the exchange (`ExchangeOnly` mode), it automatically sets `resource` to the **upstream service name** from the route configuration. This is the Kubernetes service DNS name in the format:

```
service/default/mcp-backend.default.svc.cluster.local:8080
```

The STS uses this value as the `aud` claim in the OBO token. This means the OBO token is scoped to a specific backend — a token issued for `mcp-backend` cannot be replayed against `other-backend`.

**Agent-initiated exchange:** When an agent calls the STS directly, it can set `resource` (or `audience` per RFC 8693) to whatever value is appropriate for the target service. The RFC distinguishes between the two:
- `resource` — A URI identifying the target service (becomes `aud`)
- `audience` — The logical name of the target service (also becomes `aud`)

In practice, AGW's built-in STS treats `resource` as the primary parameter for setting `aud`.

**Audience validation downstream:** When a downstream service validates the OBO token, it should check that the `aud` claim matches its own identity. In AGW, the MCP authentication policy can be configured with an `audiences` list:

```yaml
backend:
  mcp:
    authentication:
      issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
      audiences:
      - "service/default/mcp-backend.default.svc.cluster.local:8080"
      - "http://localhost:8888/mcp"    # alternative audience for local dev
```

If the `aud` claim in the OBO token doesn't match any configured audience, the request is rejected.

### How Scopes Are Handled (Token Downscoping)

The STS handles scopes according to RFC 8693 Section 2.1 — it can **preserve** or **narrow** the scopes from the original subject token, but never **expand** them.

#### Default Behavior (No `scope` Parameter)

When no `scope` parameter is included in the exchange request (this is the default for gateway-mediated exchanges), the STS preserves the original scopes from the subject token:

```
Subject Token (from IdP)           OBO Token (from STS)
─────────────────────────          ─────────────────────
scope: "openid profile             scope: "openid profile
        email read write"                   email read write"
```

#### Downscoping (With `scope` Parameter)

When the exchange request includes a `scope` parameter, the STS issues a token with only the **intersection** of the requested scopes and the original scopes. Per RFC 8693:

> The requested scope MUST NOT include any scope not originally granted by the resource owner.

```
Subject Token          Exchange Request         OBO Token
─────────────          ────────────────         ─────────
scope: "openid    +    scope: "openid     ──►   scope: "openid
  profile email          profile"                  profile"
  read write"          (narrower)                (downscoped)
```

If the request asks for a scope not present in the original token, the STS rejects the request with an OAuth error.

#### Why Downscope?

Downscoping follows the **principle of least privilege**:

| Scenario | Downscoped Scope | Why |
|---|---|---|
| Agent only needs to read data | `scope: "read"` (drop `write`) | Prevent unintended mutations |
| MCP tool only needs profile info | `scope: "openid profile"` (drop `email`) | Minimize data exposure |
| LLM backend doesn't need identity | `scope: ""` (empty) | Token is just for auth, not claims |

#### Scope in MCP vs Non-MCP

The scope handling is identical regardless of backend type. However, in practice:

- **MCP backends** — Scopes are less commonly used because MCP tool access is typically controlled by CEL-based RBAC (referencing `sub`, `act`, `groups` claims) rather than OAuth scopes
- **Non-MCP backends** — Scopes are more relevant because traditional APIs (REST, GraphQL) often use scope-based authorization (e.g., `read:users`, `write:orders`)

### Claim Generation Summary

| Claim | Delegation | Impersonation | Source |
|---|---|---|---|
| `iss` | STS issuer | STS issuer | `tokenExchange.issuer` Helm value |
| `sub` | User's `sub` | User's `sub` | Copied from subject token |
| `act` | `{sub, iss}` of agent | **Not present** | Extracted from actor token |
| `aud` | Target resource | Target resource | `resource` parameter in exchange request (auto-set by proxy to upstream service name) |
| `scope` | Preserved or downscoped | Preserved or downscoped | From subject token; narrowed if `scope` parameter is in exchange request |
| `exp` | STS-configured TTL | STS-configured TTL | `tokenExchange.tokenExpiration` (default: 24h) |
| `iat` | Current time | Current time | Set by STS at issuance |

### Claims NOT Copied

The STS does **not** blindly copy all claims from the subject token. IdP-specific claims like `azp` (authorized party), `realm_access`, `resource_access`, `session_state`, `nonce`, `auth_time`, `acr`, and custom IdP claims are **not** carried over to the OBO token.

The OBO token is a **clean JWT from the STS trust domain** with only the standard claims listed above. This is by design:

- **Security:** Prevents leaking internal IdP structure to downstream services
- **Trust boundary:** The OBO token represents a new trust assertion from the STS, not a forwarded copy of the IdP token
- **Simplicity:** Downstream services only need to trust the STS issuer and validate a small, well-defined set of claims

---

## STS Configuration

### Helm Values

```yaml
tokenExchange:
  enabled: true                          # Enable the built-in STS
  issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
  tokenExpiration: 24h                   # OBO token TTL

  subjectValidator:                      # Validates the user's JWT
    validatorType: remote                # remote | k8s | static
    remoteConfig:
      url: "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/certs"

  actorValidator:                        # Validates the agent's identity
    validatorType: k8s                   # K8s TokenReview API

  apiValidator:                          # Validates calls TO the STS itself
    validatorType: remote                # Prevents unauthorized STS access
    remoteConfig:
      url: "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/certs"
```

### Three STS Validators

| Validator | Purpose | Common Type | What It Validates |
|---|---|---|---|
| **Subject** | Validates the user's JWT (the token being exchanged) | `remote` (JWKS) | Signature, issuer, expiration, `may_act` (delegation) |
| **Actor** | Validates the agent's identity token | `k8s` | K8s SA token via TokenReview API |
| **API** | Validates the caller's auth to the STS `/token` endpoint | `remote` or `k8s` | Prevents unauthorized parties from calling the STS |

**Validator types:**

- **`remote`** — Validates JWT signatures against a remote JWKS endpoint (e.g., Keycloak, Auth0, Okta). Requires `remoteConfig.url`.
- **`k8s`** — Validates Kubernetes service account tokens via the K8s TokenReview API. No additional config needed.
- **`static`** — Validates against a static JWKS loaded from a file or inline.

### Data Plane Environment Variables

When `tokenExchange.enabled: true`, the control plane automatically configures the data plane proxy with:

| Env Var | Description |
|---|---|
| `STS_URI` | The STS endpoint URL (e.g., `http://enterprise-agentgateway:7777/token`) |
| `STS_AUTH_TOKEN` | A token the proxy uses to authenticate its own calls to the STS (validated by the API Validator) |

These are set automatically via `EnterpriseAgentgatewayParameters` — no manual configuration needed.

---

## Downstream Policy Enforcement

### CEL RBAC with OBO Claims

Downstream services (or AGW policies) can reference OBO token claims in CEL expressions for fine-grained access control:

**Delegation — policy on both user and agent:**

```yaml
# Only allow agent "data-fetcher" to call the "query_database" MCP tool
spec:
  backend:
    mcp:
      rbac:
      - tool: "query_database"
        celExpression: >-
          claims.act != null &&
          claims.act.sub == "system:serviceaccount:agentgateway-system:data-fetcher"
```

**Delegation — restrict by user group AND agent:**

```yaml
# Only premium users via approved agents
spec:
  backend:
    mcp:
      rbac:
      - tool: "premium_tool"
        celExpression: >-
          claims.groups.exists(g, g == 'premium') &&
          claims.act.sub.startsWith('system:serviceaccount:agentgateway-system:')
```

**Impersonation — policy on user only:**

```yaml
# Standard user-based RBAC (no act claim available)
spec:
  backend:
    mcp:
      rbac:
      - tool: "admin_tool"
        celExpression: >-
          claims.groups.exists(g, g == 'admin')
```

### Audit Trail

With delegation, audit logs capture the full call chain:

```
User "alice" (sub: f47ac10b-...)
  → via Agent "data-fetcher" (act.sub: system:serviceaccount:...:data-fetcher)
  → called MCP tool "query_database"
```

With impersonation, only the user identity is visible:

```
User "alice" (sub: f47ac10b-...)
  → called MCP tool "query_database"
```

---

## Microsoft Entra ID (Azure AD) OBO

Agent Gateway also supports **Microsoft Entra ID OBO** as an alternative to the built-in STS. This uses Azure AD's native `urn:ietf:params:oauth:grant-type:jwt-bearer` grant type instead of RFC 8693.

Configured via `EnterpriseAgentgatewayPolicy`:

```yaml
backend:
  tokenExchange:
    entra:
      tenantId: "<azure-ad-tenant-id>"
      secretName: "entra-client-secret"    # K8s Secret with client_id, client_secret, scope
```

The token endpoint is derived automatically: `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`

Parameters sent:
- `grant_type`: `urn:ietf:params:oauth:grant-type:jwt-bearer`
- `assertion`: the incoming access token
- `requested_token_use`: `on_behalf_of`
- `client_id`, `client_secret`, `scope`: from the referenced K8s Secret

---

## Reference

- [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/)
- [OBO Token Exchange Setup](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/)
- [Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/elicitations/)
- [Enterprise API — TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode)
- [Enterprise API — TokenExchangeCfg](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangecfg)
- [Helm Values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Setting up A2A OAuth User Delegation (Blog)](https://www.solo.io/blog/setting-up-a2a-oauth-user-delegation)
- [MCP Authorization Patterns for Upstream API Calls (Blog)](https://www.solo.io/blog/mcp-authorization-patterns)
