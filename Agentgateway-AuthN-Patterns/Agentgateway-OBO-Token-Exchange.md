# OBO Token Exchange in Agent Gateway

> **Documentation:** [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/) · [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Helm Values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
> **API:** [TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode) · [TokenExchangeCfg](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangecfg) · [EnterpriseAgentgatewayPolicy](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaytrafficpolicy)
> **Standard:** [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)

---

## Glossary

| Term | JWT Claim | What It Means |
|---|---|---|
| **OBO (On-Behalf-Of)** | — | A pattern where a service (the agent) acts on behalf of a user. The resulting token proves both "who the user is" and optionally "which agent is acting for them." |
| **STS (Security Token Service)** | — | A server that exchanges one token for another. You give it a user's JWT, and it gives you back a new JWT signed by the STS. AGW has one built in at port `7777`. |
| **Subject Token** | — | The user's original JWT from the identity provider (Keycloak, Okta, Auth0, etc.). This is the token being exchanged — it represents "who the user is." The `sub` (subject) claim in the OBO token comes from this token. |
| **Actor Token** | — | The agent's identity token — a Kubernetes service account JWT. Automatically mounted by K8s into every pod at `/var/run/secrets/kubernetes.io/serviceaccount/token`. This represents "which agent is making the call." Only used in delegation. |
| **Subject** | `sub` | The user's identity — carried from the subject token into the OBO token. Example: `"sub": "user-123"`. |
| **Actor** | `act` | Nested object identifying the agent that is acting on behalf of the user. Only present in delegation tokens. Example: `"act": { "sub": "system:serviceaccount:ns:sa" }`. |
| **Issuer** | `iss` | Who signed the token. In OBO tokens, this is the STS (e.g. `"iss": "enterprise-agentgateway.agentgateway-system.svc.cluster.local"`), not the original IdP. Downstream services trust this issuer. |
| **Audience** | `aud` | Who the token is intended for. Set by the `resource` parameter during exchange. Example: `"aud": "mcp-server.default.svc.cluster.local"`. Downstream services should verify this matches their own identity. |
| **May Act** | `may_act` | A claim in the user's JWT that explicitly authorizes a specific agent to perform delegation. Without it, the STS rejects delegation requests. Example: `"may_act": { "sub": "system:serviceaccount:ns:sa" }`. |
| **Scope** | `scope` | Space-delimited permissions in the OBO token. Can be downscoped during exchange (request fewer than the original token granted). Example: `"scope": "read:data write:data"`. |
| **Delegation** | `sub` + `act` | An exchange that preserves both identities. The OBO token contains `sub` (user) + `act` (agent). Downstream can enforce policies on both. |
| **Impersonation** | `sub` only | An exchange that preserves only the user's identity. The OBO token contains `sub` (user) with no `act` claim. The agent is invisible to downstream. |
| **OBO Token** | — | The new JWT issued by the STS after exchange. Signed by the STS (not the original IdP). This is what the downstream service receives. |
| **Gateway-Mediated** | — | The proxy (data plane) calls the STS automatically — your agent doesn't need to know the STS exists. Always produces impersonation tokens. |
| **Agent-Initiated** | — | The agent calls the STS directly. Required for delegation (dual identity). |

## Table of Contents

1. [Glossary](#glossary)
2. [Why Token Exchange?](#why-token-exchange)
3. [Overview](#overview)
4. [How the STS Works](#how-the-sts-works)
5. [Delegation (Dual Identity)](#delegation-dual-identity)
6. [Impersonation (Token Swap)](#impersonation-token-swap)
7. [Gateway-Mediated vs Agent-Initiated Exchange](#gateway-mediated-vs-agent-initiated-exchange)
   - [Gateway-Mediated Exchange (ExchangeOnly)](#gateway-mediated-exchange-exchangeonly)
   - [Agent-Initiated Exchange (Delegation)](#agent-initiated-exchange-delegation)
   - [How the Agent Discovers the STS](#how-the-agent-discovers-the-sts)
8. [Audience, Scopes, and Claim Generation](#audience-scopes-and-claim-generation)
9. [STS Configuration](#sts-configuration)
10. [Downstream Policy Enforcement](#downstream-policy-enforcement)
11. [End-to-End Walkthrough](#end-to-end-walkthrough)
12. [Reference](#reference)

---

## Why Token Exchange?

Without token exchange, you have two bad options for authenticating agent-to-service calls:

**Option 1: Forward the user's IdP token directly.** The agent passes the user's Keycloak/Okta JWT straight to the downstream MCP server or API.

Problems:
- The downstream must trust and validate tokens from **every** IdP in your organization
- The user's token may contain sensitive IdP-specific claims (`realm_access`, `session_state`) that leak to downstream services
- There's no way to know **which agent** made the call — was it the chat agent? The data pipeline? A rogue script?
- Tokens can be replayed against any service — they aren't scoped to a specific downstream

**Option 2: Use a shared service account.** The agent authenticates with its own static credential, ignoring the user's identity entirely.

Problems:
- All requests look like they came from the same "service account" — you lose all user attribution
- No per-user access control is possible downstream
- Audit logs are useless — you can't tell who did what

**Token exchange solves both problems.** The STS takes the user's IdP token and issues a new, clean JWT that:
- Is signed by a **single trusted issuer** (the STS) — downstream services only need to trust one issuer
- Contains the **user's identity** (`sub`) so per-user policies and audit trails work
- Optionally contains the **agent's identity** (`act`) so you can enforce per-agent policies
- Is **scoped to a specific downstream** (`aud`) so it can't be replayed against other services
- **Strips IdP-specific claims** so internal IdP structure doesn't leak

---

## Overview

Solo Enterprise for Agent Gateway includes a **built-in Security Token Service (STS)** that implements RFC 8693 (OAuth 2.0 Token Exchange). The STS runs on the control plane at port `7777` and enables agents and services to act on behalf of users through token delegation — without requiring your identity provider (IdP) to natively support RFC 8693.

The STS supports two exchange modes that differ in whether the **agent's identity** is preserved in the resulting token:

| Mode | Actor Token | `act` Claim | Use Case |
|---|---|---|---|
| **Delegation** | Required (K8s SA token) | Present (`sub` + `iss` of agent) | Policies need both user AND agent identity |
| **Impersonation** | Not provided | Absent | Downstream sees only the user, agent is transparent |

Both modes work identically across MCP and non-MCP (LLM, HTTP) downstreams — the STS generates the same JWT structure regardless of backend type. The difference is in who calls the STS — the proxy (gateway-mediated) or the agent (agent-initiated).

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
POST /oauth2/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <sts-auth-token>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user-jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=<upstream-service-name>      # becomes the "aud" claim (e.g., service/default/mcp-backend.default.svc.cluster.local:8080)
```

**Agent-initiated exchange** — the agent calls the STS directly. For **delegation**, it includes both the subject token and actor token. For **impersonation**, it omits the actor token:

```
POST /oauth2/token HTTP/1.1
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

## Gateway-Mediated vs Agent-Initiated Exchange

The STS itself is **backend-agnostic** — it generates the same JWT regardless of whether the downstream is an MCP server, LLM provider, or HTTP API. The real question is **who calls the STS**, and that depends on whether you need delegation:

| Need delegation (`act` claim)? | Who calls the STS | Your agent changes |
|---|---|---|
| **No** — downstream only needs user identity | Data plane proxy (automatic) | None — configure `ExchangeOnly` on the policy |
| **Yes** — downstream policies reference agent identity | Agent calls STS directly | Agent must be initialized with STS `well_known_uri` |

### Gateway-Mediated Exchange (ExchangeOnly)

The simplest path. The **proxy** automatically exchanges the client's JWT at the STS before forwarding to the backend — your agent sends the user's IdP JWT and the proxy swaps it for an OBO token transparently. No agent code changes required.

**This works for both MCP and non-MCP backends** (LLM, HTTP, A2A). The only limitation is that the proxy does not send an `actor_token`, so the resulting OBO JWT is always **impersonation-style** (no `act` claim).

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: obo-policy
  namespace: agentgateway-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: mcp          # works the same for non-MCP routes
  backend:
    tokenExchange:
      mode: ExchangeOnly    # or ElicitationOnly, or omit for both
```

The proxy is **auto-configured** with the STS connection via `EnterpriseAgentgatewayParameters`:

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: agw-params
  namespace: agentgateway-system
spec:
  env:
  - name: STS_URI
    value: http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/oauth2/token
  - name: STS_AUTH_TOKEN
    value: /var/run/secrets/sts-tokens/sts-token
```

The Gateway references this via `infrastructure.parametersRef`, and the control plane injects the env vars into the proxy pod automatically:
- **`STS_URI`** — the STS `/oauth2/token` endpoint URL
- **`STS_AUTH_TOKEN`** — path to a token file the proxy uses to authenticate its own calls to the STS (validated by the API Validator). Falls back to `/var/run/secrets/sts-tokens/sts-token` if not set.

**For MCP backends**, the downstream MCP authentication policy validates the OBO token against the **STS issuer** (not the original IdP):

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

**For non-MCP backends**, use a JWT authentication policy on the route's `traffic` section instead:

```yaml
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

**Key behavior:** The downstream never sees the original IdP token — it receives only the STS-signed OBO JWT. For MCP backends, CEL-based RBAC policies on MCP tools can reference `sub` (user) from the OBO token for access control.

### Agent-Initiated Exchange (Delegation)

When your downstream policies need to know **which agent** made the call (not just which user), the agent must call the STS directly. This is the only way to get an OBO token with both `sub` (user) and `act` (agent) claims — because the agent must provide its own K8s SA token as the `actor_token`.

This works for **any backend type** (MCP, LLM, HTTP, A2A).

#### How the Agent Discovers the STS

The agent discovers the STS token endpoint via **OAuth Authorization Server Metadata** ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)). The AGW STS exposes a well-known endpoint at:

```
http://enterprise-agentgateway.<namespace>.svc.cluster.local:7777/.well-known/oauth-authorization-server
```

**Example response** (from a live AGW STS):

```json
{
  "grant_types_supported": [
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "issuer": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777",
  "subject_types_supported": [
    "public"
  ],
  "token_endpoint": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/oauth2/token",
  "token_endpoint_auth_methods_supported": [
    "none"
  ],
  "token_expiration": 86400,
  "token_types_supported": [
    "urn:ietf:params:oauth:token-type:jwt"
  ]
}
```

The SDK reads `token_endpoint` from this response to know where to send exchange requests. Note the token endpoint path is `/oauth2/token` (not `/token`). The `token_endpoint` value omits the scheme — the SDK automatically prepends it from the `well_known_uri`.

The STS also exposes its **JWKS** (public signing keys) at `/.well-known/jwks.json` — downstream services use this to validate OBO token signatures.

The `agentsts-adk` SDK ([PyPI](https://pypi.org/project/agentsts-adk/)) wraps this discovery. You pass the `well_known_uri` at initialization, and the SDK fetches the `token_endpoint` automatically:

```python
from agentsts.adk import ADKSTSIntegration, ADKTokenPropagationPlugin

# Initialize with the STS well-known URI
sts = ADKSTSIntegration(
    well_known_uri="http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/.well-known/oauth-authorization-server",
    # Actor token: defaults to /var/run/secrets/kubernetes.io/serviceaccount/token (auto-mounted by K8s)
    # Or override with a custom path:
    # service_account_token_path="/path/to/custom/token",
    # Or provide a dynamic fetch callback:
    # fetch_actor_token=lambda: get_fresh_token(),
)

# Use as a Google ADK plugin — automatically exchanges tokens before MCP tool calls
plugin = ADKTokenPropagationPlugin(sts_integration=sts)
plugin.add_to_agent(my_agent)
```

**How the SDK handles tokens:**

| Token | Source | Details |
|---|---|---|
| **Subject token** (user JWT) | `session.state["headers"]["Authorization"]` | Extracted automatically from the ADK session's request headers. Custom source via `get_subject_token` callback. |
| **Actor token** (agent identity) | K8s SA token file | Defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token` (auto-mounted by K8s in every pod). Override via `service_account_token_path` or `fetch_actor_token` callback for dynamic fetching. |

The plugin hooks into Google ADK's `before_run_callback` — before each agent run, it extracts the user's JWT from the session, exchanges it at the STS (with the actor token for delegation), caches the OBO token, and injects it as an `Authorization: Bearer` header on outbound MCP tool calls. Token caching respects JWT `exp` claims with a 5-second buffer.

**Without the SDK**, you can call the STS directly via HTTP. Fetch `/.well-known/oauth-authorization-server` to discover the `token_endpoint`, or call `/oauth2/token` directly if you already know the STS address. The STS is reachable within the cluster via K8s DNS at `enterprise-agentgateway.<namespace>.svc.cluster.local:7777`.

### Comparison

| Aspect | Gateway-Mediated (`ExchangeOnly`) | Agent-Initiated |
|---|---|---|
| Who calls the STS? | Data plane proxy (automatic) | Agent application (explicit) |
| Agent code changes? | **None** — transparent to the agent | Must initialize SDK with `well_known_uri` or call STS `/oauth2/token` directly |
| Backend type | MCP or non-MCP | Any (MCP, LLM, HTTP, A2A) |
| Delegation (`act` claim)? | **No** — always impersonation | **Yes** — include actor token |
| STS discovery | Auto-configured via `EnterpriseAgentgatewayParameters` | SDK fetches `/.well-known/oauth-authorization-server` → `token_endpoint` |
| When to use | Downstream only needs user identity | Downstream policies reference agent identity |

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
| **API** | Validates the caller's auth to the STS `/oauth2/token` endpoint | `remote` or `k8s` | Prevents unauthorized parties from calling the STS |

**Validator types:**

- **`remote`** — Validates JWT signatures against a remote JWKS endpoint (e.g., Keycloak, Auth0, Okta). Requires `remoteConfig.url`.
- **`k8s`** — The STS does **not** validate the token locally. Instead, it sends the token to the Kubernetes API server via `POST /apis/authentication.k8s.io/v1/tokenreviews`. K8s verifies the token signature, checks expiration, confirms the service account exists, and returns the validated identity (`sub`, `iss`). The STS then uses that identity for the `act` claim. No additional config needed — the STS uses its own in-cluster credentials to call the K8s API.
- **`static`** — Validates against a static JWKS loaded from a file or inline.

### Data Plane Environment Variables

When `tokenExchange.enabled: true` and gateway-mediated exchange is configured, the control plane injects `STS_URI` and `STS_AUTH_TOKEN` into the proxy pod via `EnterpriseAgentgatewayParameters`. See [Gateway-Mediated Exchange (ExchangeOnly)](#gateway-mediated-exchange-exchangeonly) for the full YAML and details.

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

## End-to-End Walkthrough

Now that you understand the building blocks, here's a concrete scenario showing how they fit together. Alice uses a chat agent that calls an MCP tool to query a customer database.

### Scenario: Gateway-Mediated (Impersonation)

Alice's agent routes through Agent Gateway. The gateway handles everything — Alice's agent doesn't know the STS exists.

```
1. Alice logs into the chat app → gets a Keycloak JWT
   Token contains: sub="alice", scope="openid profile", realm_access={...}

2. Alice's agent sends a request to the MCP server via Agent Gateway
   Authorization: Bearer <alice's-keycloak-jwt>

3. Agent Gateway intercepts the request (ExchangeOnly mode)
   → Proxy extracts Alice's JWT from the Authorization header
   → Proxy calls the STS: POST /oauth2/token
     - subject_token = alice's Keycloak JWT
     - resource = "service/default/mcp-backend.default.svc.cluster.local:8080"
   → STS validates Alice's JWT against Keycloak's JWKS
   → STS issues a new OBO JWT:
     {
       "iss": "enterprise-agentgateway....:7777",  ← STS issuer (not Keycloak)
       "sub": "alice",                              ← Alice's identity preserved
       "aud": "service/default/mcp-backend...",     ← scoped to this backend
       "scope": "openid profile",                   ← scopes preserved
       "exp": 1712275200                            ← 24h from now
     }
     No "act" claim — the agent is invisible.

4. Agent Gateway forwards the request to the MCP server
   Authorization: Bearer <sts-signed-obo-jwt>
   (Alice's original Keycloak JWT is gone — MCP server never sees it)

5. MCP server validates the OBO JWT
   → Checks issuer = STS ✓ (only needs to trust one issuer)
   → Checks aud matches its own identity ✓
   → Reads sub = "alice" → applies Alice's permissions
   → Returns data to Alice's agent
```

**Result:** Alice's identity flows through cleanly, the MCP server trusts one issuer, and no IdP-specific claims leaked. But there's no record of which agent made the call.

### Scenario: Agent-Initiated (Delegation)

Same setup, but now the organization wants audit trails showing which agent accessed data on behalf of which user. The agent calls the STS directly.

```
1. Alice logs in → gets a Keycloak JWT (same as before)
   This time, Alice's token also contains:
   "may_act": {
     "sub": "system:serviceaccount:default:chat-agent",
     "iss": "https://kubernetes.default.svc.cluster.local"
   }
   (Added by Keycloak admin — authorizes the chat-agent to act for Alice)

2. The chat-agent receives Alice's request and her JWT

3. The chat-agent calls the STS directly (not via the proxy):
   POST http://enterprise-agentgateway:7777/oauth2/token
     - subject_token = Alice's Keycloak JWT (with may_act)
     - actor_token = chat-agent's own K8s service account JWT
   → STS validates Alice's JWT (JWKS) ✓
   → STS validates the agent's K8s SA token (TokenReview) ✓
   → STS checks: does may_act.sub match actor.sub? ✓
   → STS issues an OBO JWT:
     {
       "iss": "enterprise-agentgateway....:7777",
       "sub": "alice",
       "act": {                                      ← agent identity included
         "sub": "system:serviceaccount:default:chat-agent",
         "iss": "https://kubernetes.default.svc.cluster.local"
       },
       "aud": "service/default/mcp-backend...",
       "scope": "openid profile"
     }

4. The chat-agent sends the OBO JWT to the MCP server
   Authorization: Bearer <sts-signed-obo-jwt-with-act>

5. MCP server validates the OBO JWT
   → sub = "alice" → applies Alice's permissions ✓
   → act.sub = "chat-agent" → checks agent is allowed to call this tool ✓
   → Audit log: "alice via chat-agent called query_database"
```

**Result:** Full audit trail, per-agent policies, and Alice's identity preserved. The trade-off: the agent needs to know about the STS and integrate with it.

---

## Reference

- [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/)
- [OBO Token Exchange Setup](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/)
- [Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/elicitations/)
- [Enterprise API — TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode)
- [Enterprise API — TokenExchangeCfg](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangecfg)
- [Helm Values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Microsoft Entra ID OBO](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) — AGW also supports Azure AD's native `jwt-bearer` grant as an alternative to the built-in STS
- [Setting up A2A OAuth User Delegation (Blog)](https://www.solo.io/blog/setting-up-a2a-oauth-user-delegation)
- [MCP Authorization Patterns for Upstream API Calls (Blog)](https://www.solo.io/blog/mcp-authorization-patterns)
