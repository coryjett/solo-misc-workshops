# OBO Token Exchange in Agent Gateway

> **Documentation:** [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/) · [OBO Token Exchange](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) · [Helm Values](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
> **API:** [TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode) · [TokenExchangeCfg](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangecfg) · [EnterpriseAgentgatewayPolicy](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaytrafficpolicy)
> **Standard:** [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)

---

## Learning Path

This guide takes you from foundational concepts to implementation. If you're new to token exchange, read in order. If you already understand OAuth/JWT basics, skip to [Why Token Exchange?](#why-token-exchange).

| Step | Section | What You'll Learn |
|------|---------|-------------------|
| 1 | [Prerequisites](#prerequisites) | OAuth 2.0, JWTs, OIDC — the building blocks |
| 2 | [Why Token Exchange?](#why-token-exchange) | The problem token exchange solves |
| 3 | [Overview](#overview) | How AGW's built-in STS fits in |
| 4 | [Delegation vs Impersonation](#delegation-dual-identity) | The two exchange modes and when to use each |
| 5 | [Gateway-Mediated vs Agent-Initiated](#gateway-mediated-vs-agent-initiated-exchange) | Who calls the STS and why it matters |
| 6 | [End-to-End Walkthrough](#end-to-end-walkthrough) | Concrete scenario with Alice, an agent, and an MCP server |
| 7 | [STS Configuration](#sts-configuration) | Copy-paste deployment examples |
| 8 | **Hands-on labs** | [Flow 13](../flow13-token-exchange/flow13-gateway-mediated-token-exchange/) (JWT) or [Flow 13b](../flow13-token-exchange/flow13b-external-sts-opaque-token/) (opaque) |
| 9 | [Customer Conversation Guide](#customer-conversation-guide) | Discovery questions, pattern selection, objection handling |
| 10 | [External IdP / STS Provider Guide](#external-idp--sts-provider-guide) | Integrating with Okta, Entra ID, etc. |
| 11 | [Troubleshooting](#troubleshooting) | Common errors and how to fix them |

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Why Token Exchange?](#why-token-exchange)
3. [Overview](#overview)
   - [The Big Picture](#the-big-picture)
   - [How Token Exchange Relates to JWT Auth and MCP Auth](#how-token-exchange-relates-to-jwt-auth-and-mcp-auth)
4. [How the STS Works](#how-the-sts-works)
5. [Delegation (Dual Identity)](#delegation-dual-identity)
6. [Impersonation (Token Swap)](#impersonation-token-swap)
7. [Gateway-Mediated vs Agent-Initiated Exchange](#gateway-mediated-vs-agent-initiated-exchange)
   - [Gateway-Mediated Exchange (ExchangeOnly)](#gateway-mediated-exchange-exchangeonly)
   - [Agent-Initiated Exchange](#agent-initiated-exchange)
   - [How the Agent Discovers the STS](#how-the-agent-discovers-the-sts)
8. [Audience, Scopes, and Claim Generation](#audience-scopes-and-claim-generation)
9. [STS Configuration](#sts-configuration)
   - [Deployment Examples](#deployment-examples)
10. [Downstream Policy Enforcement](#downstream-policy-enforcement)
11. [End-to-End Walkthrough](#end-to-end-walkthrough)
12. [Troubleshooting](#troubleshooting)
13. [Customer Conversation Guide](#customer-conversation-guide)
14. [FAQ: Why JWTs and Not Opaque Tokens?](#faq-why-jwts-and-not-opaque-tokens)
15. [External IdP / STS Provider Guide](#external-idp--sts-provider-guide)
16. [Glossary](#glossary)
17. [Reference](#reference)

---

## Prerequisites

This section covers the foundational concepts you need to understand before diving into token exchange. If you're already comfortable with OAuth 2.0, JWTs, and OIDC, skip to [Why Token Exchange?](#why-token-exchange).

### What Is OAuth 2.0?

OAuth 2.0 is an authorization framework that lets applications access resources on behalf of a user without the user sharing their password. Instead of handing over credentials, the user logs in to an **authorization server** (like Keycloak, Okta, or Entra ID), which issues a **token** — a temporary credential that proves the user said "yes, this app can act for me."

The key participants:

| Role | What It Does | Example |
|------|-------------|---------|
| **Resource Owner** | The user who owns the data | Alice |
| **Client** | The app requesting access | A chat agent, Claude Code, VS Code |
| **Authorization Server** | Issues tokens after the user authenticates | Keycloak, Okta, Entra ID |
| **Resource Server** | The API that holds the data | An MCP server, a REST API |

The most common flow for web/desktop apps is the **Authorization Code Flow**:

```
1. User clicks "Login" → app redirects to authorization server
2. User enters credentials → authorization server validates
3. Authorization server redirects back with a one-time "code"
4. App exchanges the code for tokens (access token + refresh token)
5. App uses the access token to call APIs
```

> **Further reading:** [OAuth 2.0 Simplified](https://www.oauth.com/) · [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)

### What Is a JWT?

A **JSON Web Token (JWT)** is a compact, URL-safe way to represent claims (statements about a user) as a signed JSON object. Most OAuth 2.0 access tokens in modern systems are JWTs.

A JWT has three parts separated by dots: `Header.Payload.Signature`

```
eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2tleWNsb2FrLmV4YW1wbGUuY29tIiwic3ViIjoiYWxpY2UiLCJleHAiOjE3MTIxOTI0MDB9.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
│              │                                                                                                            │
└─ Header      └─ Payload (claims)                                                                                          └─ Signature
   (algorithm)    (who, what, when)                                                                                            (proves it's authentic)
```

Each part is Base64URL-encoded JSON. You can decode the payload to see the claims:

```json
{
  "iss": "https://keycloak.example.com/realms/my-realm",   // Issuer — who signed this token
  "sub": "alice",                                           // Subject — who this token is about
  "aud": "my-app",                                          // Audience — who this token is for
  "exp": 1712192400,                                        // Expiration — when it expires (Unix timestamp)
  "iat": 1712188800,                                        // Issued At — when it was created
  "scope": "openid profile email"                           // Scopes — what permissions were granted
}
```

**Why JWTs matter for token exchange:** The STS takes a JWT from one issuer (your IdP) and produces a new JWT from a different issuer (the STS itself). The downstream service only needs to trust the STS's signing key — it doesn't need to know about your IdP.

**How JWT validation works:** The receiver fetches the issuer's public keys from a **JWKS (JSON Web Key Set)** endpoint (e.g., `https://keycloak.example.com/.well-known/jwks.json`), then verifies the token's signature cryptographically. This is a **local operation** — no network call to the issuer per request. If the signature matches, the issuer matches, and the token isn't expired, it's valid.

**JWKS caching and refresh:** The gateway does **not** call the IdP on every request. It caches the JWKS keys and refreshes them periodically:

```
Timeline:
  t=0     Gateway starts, fetches JWKS from IdP ──► caches keys locally
  t=0-5m  All JWT validation uses cached keys (no network calls)
  t=5m    Cache expires ──► next request triggers a JWKS refetch
  t=5m+   New keys cached, validation continues locally
```

In Solo Enterprise for Agent Gateway (Envoy-based data plane):
- **Default cache duration: 5 minutes** — after 5 minutes, the cached JWKS expires and is refetched on the next request
- Configurable via `cacheDuration` on the `RemoteJwks` spec (e.g., `cacheDuration: 10m` for less frequent refetching)
- **`asyncFetch` option:** Pre-fetches JWKS in the main thread before the listener activates, so keys are ready when the first request arrives (avoids pausing initial requests). When enabled, refetching also happens in the background when the cache expires.
- **Key rotation:** When an IdP rotates its signing keys, the new keys are picked up on the next cache refresh (within the `cacheDuration` window). There's no per-request overhead — hundreds of thousands of requests are validated against the same cached keyset.

This is a critical difference from opaque tokens: JWT validation is a **local cryptographic check** (microseconds, no availability dependency), while opaque token introspection requires a **network round-trip to the IdP on every request** (milliseconds + the IdP must be available).

> **Try it:** Paste any JWT into [jwt.io](https://jwt.io) to decode it. · **Spec:** [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

### What Is OIDC?

**OpenID Connect (OIDC)** is an identity layer built on top of OAuth 2.0. While OAuth 2.0 only handles **authorization** ("can this app access this resource?"), OIDC adds **authentication** ("who is this user?").

OIDC introduces:
- An **ID Token** — a JWT that contains the user's identity (name, email, etc.)
- A **UserInfo endpoint** — an API the app can call to get more user details
- A **discovery document** — a well-known URL (`/.well-known/openid-configuration`) that tells the client where all the endpoints are

In the context of Agent Gateway and token exchange, OIDC is how the **user authenticates initially** — the Authorization Code Flow produces a JWT that the STS then exchanges.

> **Further reading:** [OpenID Connect Explained](https://connect2id.com/learn/openid-connect)

### What Is an STS?

A **Security Token Service (STS)** is a server that exchanges one token for another. You send it a token you already have (the **subject token**), and it gives you back a new token with different properties — different issuer, different claims, different audience.

**RFC 8693** defines the standard protocol for token exchange. The request looks like:

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<the-token-you-have>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
```

The STS validates the subject token (checks signature, issuer, expiration), then issues a new token signed with its own key.

**Agent Gateway has a built-in STS** on the control plane at port `7777`. You can also use an external STS (Keycloak, Okta, PingFederate, etc.) — the protocol is the same.

### Key Concepts Summary

Before proceeding, make sure you're comfortable with these:

| Concept | One-liner |
|---------|-----------|
| **OAuth 2.0** | Framework for delegated authorization — apps get tokens instead of passwords |
| **JWT** | Signed JSON token with claims (`sub`, `iss`, `aud`, `exp`) — verifiable without calling the issuer |
| **JWKS** | Public key endpoint the receiver uses to verify JWT signatures locally |
| **OIDC** | Identity layer on OAuth 2.0 — adds "who is this user?" to "what can they access?" |
| **STS** | Server that exchanges one token for another — takes an IdP token, issues an OBO token |
| **Claims** | Key-value pairs inside a JWT — `sub` (who), `iss` (signed by), `aud` (intended for), `exp` (valid until) |
| **IdP** | Identity Provider — the system users log into (Keycloak, Okta, Entra ID, Auth0) |

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

### The Big Picture

Here's the high-level architecture showing how all the pieces fit together:

```
                                      AGENT GATEWAY CLUSTER
                                ┌────────────────────────────────────────────────────────┐
                                │                                                        │
  ┌──────────┐                  │  ┌──────────────────────┐    ┌─────────────────────┐   │   ┌──────────────┐
  │          │   1. Login       │  │   DATA PLANE         │    │  CONTROL PLANE      │   │   │              │
  │  User    │ ◄───────────►    │  │   (Proxy)            │    │                     │   │   │  Downstream  │
  │          │   (OIDC/OAuth)   │  │                      │    │  ┌───────────────┐  │   │   │  Service     │
  └────┬─────┘                  │  │  Receives client JWT │    │  │  Built-in STS │  │   │   │  (MCP, API)  │
       │                        │  │         │            │    │  │  (:7777)      │  │   │   │              │
       │ 2. Request + JWT       │  │         │ 3. Exchange│    │  │               │  │   │   │  Validates   │
       ▼                        │  │         ▼            │    │  │  Validates    │  │   │   │  OBO JWT     │
  ┌──────────┐                  │  │  ┌──────────────┐    │    │  │  user JWT     │  │   │   │  against     │
  │          │  ──────────────► │  │  │ Calls STS    │ ───┼──► │  │  (JWKS)       │  │   │   │  STS JWKS    │
  │  Agent   │                  │  │  │ with user    │    │    │  │               │  │   │   │              │
  │          │                  │  │  │ JWT as       │ ◄──┼─── │  │  Issues       │  │   │   │  sub=alice   │
  └──────────┘                  │  │  │ subject_token│    │    │  │  OBO JWT      │  │   │   │  act=agent   │
                                │  │  └──────┬───────┘    │    │  │  (sub+act)    │  │   │   │  (if deleg.) │
                                │  │         │            │    │  └───────────────┘  │   │   │              │
                                │  │         │ 4. Forward │    │                     │   │   └──────────────┘
                                │  │         │    OBO JWT │    │  JWKS at            │   │          ▲
                                │  │         ▼            │    │  /.well-known/      │   │          │
                                │  │  ───────────────────────────────────────────────┼───┼──────────┘
                                │  │                      │    │  jwks.json          │   │   5. OBO JWT
                                │  └──────────────────────┘    └─────────────────────┘   │
                                │                                                        │
                                └────────────────────────────────────────────────────────┘

  ┌──────────────┐
  │              │
  │  IdP         │  Keycloak, Okta, Entra ID, Auth0 — issues the original user JWT
  │  (External)  │  STS fetches its JWKS to validate user tokens
  │              │
  └──────────────┘
```

**The flow in five steps:**

1. **User authenticates** with an Identity Provider (Keycloak, Okta, etc.) via OIDC → gets a JWT
2. **Agent sends a request** to Agent Gateway with the user's JWT in the `Authorization` header
3. **Gateway proxy exchanges the token** — calls the built-in STS with the user's JWT as the `subject_token`
4. **STS validates and issues an OBO JWT** — verifies the user's JWT against the IdP's JWKS, then signs a new token with `sub` (user) and optionally `act` (agent)
5. **Downstream receives the OBO JWT** — validates it against the STS's JWKS (one issuer to trust, not every IdP)

The result: the downstream service never sees the original IdP token, trusts a single issuer, and gets clean claims without IdP-specific noise.

The STS supports two exchange modes that differ in whether the **agent's identity** is preserved in the resulting token:

| Mode | Actor Token | `act` Claim | Use Case |
|---|---|---|---|
| **Delegation** | Required (K8s SA token) | Present (`sub` + `iss` of agent) | Policies need both user AND agent identity |
| **Impersonation** | Not provided | Absent | Downstream sees only the user, agent is transparent |

Both modes work identically across MCP and non-MCP (LLM, HTTP) downstreams — the STS generates the same JWT structure regardless of backend type. The difference is in who calls the STS — the proxy (gateway-mediated) or the agent (agent-initiated).

### How Token Exchange Relates to JWT Auth and MCP Auth

Token exchange is **not** an authentication method — it's a **token transformation layer**. It takes a JWT the client already has and swaps it for an OBO JWT before the request reaches the downstream. But there's important nuance in how it interacts with [JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) and [MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/setup/).

**There are two separate concerns:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  1. CLIENT-SIDE                     2. GATEWAY-SIDE                         │
│     "How does the client            "What does the gateway do                │
│      get a token?"                   with that token?"                       │
│                                                                             │
│  ┌───────────────────────┐          ┌────────────────────────────────────┐  │
│  │ MCP OAuth + DCR       │          │                                    │  │
│  │ OIDC (Auth Code Flow) │ ──JWT──► │ Option A: JWT Auth / MCP Auth      │  │
│  │ API Key               │          │   (validate + forward as-is)       │  │
│  │ mTLS                  │          │                                    │  │
│  │                       │          │ Option B: Token exchange            │  │
│  │                       │          │   (STS validates + issues OBO JWT)  │  │
│  └───────────────────────┘          └────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**The overlap:** [JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) and token exchange both validate JWTs — they use the same mechanism (`issuer`, `audiences`, `jwks` fields on `EnterpriseAgentgatewayPolicy`). The difference is **what issuer they trust** and **where in the flow they sit**:

| Scenario | Who validates the IdP JWT? | `mcp.authentication` issuer | What does the downstream receive? |
|---|---|---|---|
| **[JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) only** (no exchange) | `mcp.authentication` or `traffic.jwtAuthentication` policy | IdP (Keycloak, Okta, etc.) | Original IdP JWT — downstream must trust the IdP |
| **Token exchange only** | STS `subjectValidator` (during exchange) | STS (`enterprise-agentgateway:7777`) | OBO JWT — downstream trusts only the STS |
| **JWT Auth + token exchange** | Both validate the IdP JWT (redundant) | STS | OBO JWT — double validation, not harmful |

The key insight: **when token exchange is enabled, the STS's `subjectValidator` already validates the IdP JWT**. A separate [JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) policy is not required — the exchange itself handles validation. Adding one isn't wrong, but it's redundant.

The `mcp.authentication` block you see in the token exchange examples (e.g., Example 1 Step 4) is the **same** [`JWTAuthentication`](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#jwtauthentication) mechanism documented in the [JWT Auth setup guide](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) — it's just configured to trust the **STS issuer** instead of the IdP issuer, because after the exchange, the downstream only sees OBO tokens signed by the STS.

What token exchange does **not** replace is the **client-side auth flow** — how the client obtains the JWT in the first place. [MCP OAuth + DCR](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/about/), OIDC Authorization Code Flow, etc. are about client registration and token acquisition. Token exchange is about what the gateway does with that token after it arrives.

**Example: MCP OAuth + DCR with token exchange**

1. MCP client (Claude Code, VS Code) discovers the gateway, registers via DCR, completes OAuth → gets IdP JWT *(client-side — [MCP Auth](https://docs.solo.io/agentgateway/2.2.x/mcp/auth/setup/))*
2. Client sends MCP request with IdP JWT → gateway
3. Gateway proxy intercepts, calls STS with IdP JWT as `subject_token`
4. STS validates IdP JWT (`subjectValidator`), issues OBO JWT *(gateway-side — token exchange)*
5. Proxy forwards request with OBO JWT → MCP backend
6. MCP backend validates OBO JWT against STS issuer (`mcp.authentication` — same mechanism as [JWT Auth](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/), different issuer)

MCP Auth handles step 1 (how the client gets the token). Token exchange handles steps 3-5 (what the gateway does with it). Step 6 uses the same JWT validation mechanism as JWT Auth, just pointed at the STS.

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

<details>
<summary><strong>How to add <code>may_act</code> to your IdP tokens (Keycloak example)</strong></summary>

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

</details>

<details>
<summary><strong>Validation Flow (Delegation) — detailed diagram</strong></summary>

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

</details>

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

> **Try it yourself:** The [Flow 13 lab](../flow13-token-exchange/flow13-gateway-mediated-token-exchange/) demonstrates gateway-mediated impersonation end-to-end. The `echo_token` MCP tool lets you inspect the OBO token and verify there's no `act` claim.

---

## Gateway-Mediated vs Agent-Initiated Exchange

The STS itself is **backend-agnostic** — it generates the same JWT regardless of whether the downstream is an MCP server, LLM provider, or HTTP API. The real question is **who calls the STS**, and that depends on whether you need delegation:

| Scenario | Who calls the STS | Your agent changes |
|---|---|---|
| Downstream only needs user identity, zero code changes | Data plane proxy (automatic) | None — configure `ExchangeOnly` on the policy |
| Need delegation (`act` claim) for audit trails or per-agent policies | Agent calls STS directly | Agent must be initialized with STS `well_known_uri` |
| Need agent control over exchange (custom scopes, audience) without delegation | Agent calls STS directly (omit actor token) | Agent must be initialized with STS `well_known_uri` |

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
    value: /var/run/secrets/xds-tokens/xds-token
```

The Gateway references this via `infrastructure.parametersRef`, and the control plane injects the env vars into the proxy pod automatically:
- **`STS_URI`** — the STS `/oauth2/token` endpoint URL
- **`STS_AUTH_TOKEN`** — path to a token file the proxy uses to authenticate its own calls to the STS (validated by the API Validator). Falls back to `/var/run/secrets/sts-tokens/sts-token` if the file exists, otherwise disabled.

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

### Agent-Initiated Exchange

The agent calls the STS directly instead of relying on the proxy. This is required for **delegation** (to get both `sub` and `act` claims), but also supports **impersonation** when the agent needs control over the exchange (custom scopes, audience) without needing an `act` claim.

- **Delegation:** Include `actor_token` (K8s SA JWT) → OBO token has `sub` + `act`. Requires `may_act` in the user's JWT.
- **Impersonation:** Omit `actor_token` → OBO token has `sub` only. Same result as gateway-mediated, but agent controls the exchange parameters.

This works for **any backend type** (MCP, LLM, HTTP, A2A).

#### How the Agent Discovers the STS

The agent discovers the STS token endpoint via **OAuth Authorization Server Metadata** ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)). The AGW STS exposes a well-known endpoint at:

```
http://enterprise-agentgateway.<namespace>.svc.cluster.local:7777/.well-known/oauth-authorization-server
```

<details>
<summary><strong>Example response</strong> (from a live AGW STS)</summary>

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

</details>

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
| Delegation (`act` claim)? | **No** — always impersonation (proxy never sends actor token) | **Optional** — include actor token for delegation, omit for impersonation |
| STS discovery | Auto-configured via `EnterpriseAgentgatewayParameters` | SDK fetches `/.well-known/oauth-authorization-server` → `token_endpoint` |
| When to use | Downstream only needs user identity; zero agent code changes | Agent needs control over exchange (delegation for audit trails, or impersonation with custom scopes/audience) |

> **Try it yourself:** [Flow 13](../flow13-token-exchange/flow13-gateway-mediated-token-exchange/) walks through gateway-mediated exchange (zero agent code changes). [Flow 13b](../flow13-token-exchange/flow13b-external-sts-opaque-token/) shows the same flow with an external STS returning opaque tokens — demonstrating the JWT vs opaque trade-off in practice.

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

The STS handles scopes according to RFC 8693 Section 2.1 — it can **preserve** or **narrow** the scopes from the original subject token, but never **expand** them. By default (no `scope` parameter), scopes are preserved as-is.

<details>
<summary><strong>Downscoping details and examples</strong></summary>

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

</details>

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

### Deployment Examples

Every token exchange deployment requires **three things**: (1) the STS itself (Helm values), (2) the proxy-to-STS connection (Gateway + Parameters), and (3) the per-route policy (EnterpriseAgentgatewayPolicy). Below are complete, copy-pasteable examples for each scenario.

#### Summary: What to deploy for each scenario

| Scenario | Result | Helm `tokenExchange` | `EnterpriseAgentgatewayParameters` | `EnterpriseAgentgatewayPolicy` |
|---|---|---|---|---|
| [**Built-in STS + gateway-mediated**](#example-1-built-in-sts--gateway-mediated-exchange-impersonation) | Impersonation (always) | `enabled: true` + validators | `STS_URI` + `STS_AUTH_TOKEN` → Gateway `parametersRef` | `tokenExchange.mode: ExchangeOnly` + `mcp.authentication` with STS issuer |
| [**Built-in STS + agent-initiated**](#example-2-built-in-sts--agent-initiated-exchange) | Delegation or impersonation | `enabled: true` + validators | Not needed (agent calls STS directly) | `mcp.authentication` with STS issuer + optional `rbac` on `act` (no `tokenExchange` on policy) |
| [**Built-in STS + non-MCP backend**](#example-3-built-in-sts--non-mcp-backend-llm--http-api) | Impersonation (always) | `enabled: true` + validators | `STS_URI` + `STS_AUTH_TOKEN` → Gateway `parametersRef` | `tokenExchange.mode: ExchangeOnly` + `traffic.jwtAuthentication` with STS issuer |
| [**External STS**](#example-4-external-sts) | Impersonation (always) | Not needed | `STS_URI` pointing to external STS → Gateway `parametersRef` | `tokenExchange.mode: ExchangeOnly` + `mcp.authentication` with external issuer |
| **External STS + agent-initiated** | Depends on external STS | Not needed | Not needed (agent calls external STS directly) | `mcp.authentication` with external STS issuer (no `tokenExchange` on policy) |
| [**Elicitation + exchange**](#example-5-elicitation--exchange-double-oauth) | Impersonation + credential gathering | `enabled: true` + `elicitation.secretName` | `STS_URI` + `STS_AUTH_TOKEN` → Gateway `parametersRef` | `tokenExchange: {}` (no mode = both) |

**Notes:**
- **Agent-initiated** supports both delegation (include `actor_token` → `act` claim in OBO JWT) and impersonation (omit `actor_token` → no `act` claim). The infrastructure deployment is identical — the difference is in the agent code.
- **External STS + agent-initiated** requires no AGW-specific configuration. The agent calls the external STS directly, and AGW only validates the resulting OBO token on the downstream policy. The external STS controls whether delegation is supported.

---

<details>
<summary><strong><a id="example-1-built-in-sts--gateway-mediated-exchange-impersonation"></a>Example 1: Built-in STS + Gateway-Mediated Exchange (Impersonation)</strong></summary>

The simplest setup. The built-in STS runs on the control plane, and the proxy swaps tokens automatically. No agent code changes needed.

> **Note:** This example shows the token exchange configuration only. Clients still need a way to obtain an IdP JWT (via [MCP OAuth + DCR](flows/flow-11-mcp-oauth-dcr.md), [OIDC](flows/flow-01-oidc-auth.md), etc.). The STS's `subjectValidator` validates the IdP JWT during exchange — a separate `JWTAuthentication` policy is not required but can be added. See [How Token Exchange Relates to Inbound Auth](#how-token-exchange-relates-to-jwt-auth-and-mcp-auth).

**Step 1 — Enable the built-in STS (Helm values):**

```yaml
# values.yaml for enterprise-agentgateway Helm chart
tokenExchange:
  enabled: true
  issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
  tokenExpiration: 24h

  subjectValidator:                      # Validates the user's IdP JWT
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs"

  actorValidator:                        # Validates agent K8s SA tokens (delegation only)
    validatorType: k8s

  apiValidator:                          # Validates the proxy's auth to the STS
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs"
```

**Step 2 — Tell the proxy where the STS is (Gateway + Parameters):**

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: agw-params
  namespace: default
spec:
  env:
  - name: STS_URI
    value: http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/oauth2/token
  - name: STS_AUTH_TOKEN
    value: /var/run/secrets/xds-tokens/xds-token    # proxy's own auth token file
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:                                   # Links to the Parameters above
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: agw-params
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
```

The controller reads `EnterpriseAgentgatewayParameters` (referenced by `infrastructure.parametersRef` on the Gateway) and injects `STS_URI` and `STS_AUTH_TOKEN` as env vars into the proxy pod it spawns.

**Step 3 — Route traffic to the MCP backend:**

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: mcp-backend
  namespace: default
spec:
  mcp:
    targets:
    - name: my-mcp-server
      static:
        host: mcp-server.default.svc.cluster.local
        path: /mcp
        port: 80
        protocol: StreamableHTTP
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: mcp-route
  namespace: default
spec:
  parentRefs:
  - name: my-gateway
    namespace: default
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /mcp
    backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: mcp-backend
```

**Step 4 — Enable token exchange + downstream auth on the route:**

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-obo-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:                                # Downstream validates OBO tokens
        mode: Strict
        issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        audiences:
        - "service/default/mcp-server.default.svc.cluster.local:80"
        jwks:
          backendRef:
            name: enterprise-agentgateway
            namespace: agentgateway-system
            port: 7777
          jwksPath: .well-known/jwks.json
    tokenExchange:
      mode: ExchangeOnly                             # Gateway-mediated (impersonation)
```

**What happens at runtime:**
1. Client sends request with IdP JWT → proxy intercepts
2. Proxy calls built-in STS at `STS_URI` with `subject_token` + `resource` (no `actor_token`)
3. STS validates IdP JWT (subject validator), issues OBO JWT with `sub` only
4. Proxy replaces the Authorization header with the OBO JWT
5. MCP backend validates the OBO JWT against the STS issuer and JWKS

</details>

---

<details>
<summary><strong><a id="example-2-built-in-sts--agent-initiated-exchange"></a>Example 2: Built-in STS + Agent-Initiated Exchange</strong></summary>

Same STS, but the agent calls it directly. This supports **both** delegation and impersonation — the difference is whether the agent includes its K8s SA token as the `actor_token`:

- **With `actor_token`** → delegation: OBO JWT has `sub` (user) + `act` (agent). Requires `may_act` claim in the user's IdP JWT.
- **Without `actor_token`** → impersonation: OBO JWT has `sub` (user) only. Useful when the agent wants control over exchange (custom scopes, audience) without needing an `act` claim.

Requires the `agentsts-adk` SDK or direct HTTP calls.

> **Note:** This example shows the token exchange configuration only. Clients still need a way to obtain an IdP JWT (via [MCP OAuth + DCR](flows/flow-11-mcp-oauth-dcr.md), [OIDC](flows/flow-01-oidc-auth.md), etc.). The agent receives the user's JWT and exchanges it directly with the STS. See [How Token Exchange Relates to Inbound Auth](#how-token-exchange-relates-to-jwt-auth-and-mcp-auth).

**Step 1 — Enable the built-in STS (Helm values):**

```yaml
# values.yaml for enterprise-agentgateway Helm chart
tokenExchange:
  enabled: true
  issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
  tokenExpiration: 24h

  subjectValidator:                      # Validates the user's IdP JWT
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs"

  actorValidator:                        # Validates agent K8s SA tokens (delegation only)
    validatorType: k8s

  apiValidator:                          # Validates the proxy's auth to the STS
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs"
```

**Step 2 — No `EnterpriseAgentgatewayParameters` needed.** The agent calls the STS directly — it doesn't go through the proxy for the exchange. The agent discovers the STS via the well-known endpoint.

**Step 3a — Agent code for delegation (Python with `agentsts-adk`):**

```python
from agentsts.adk import ADKSTSIntegration, ADKTokenPropagationPlugin

sts = ADKSTSIntegration(
    well_known_uri="http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/.well-known/oauth-authorization-server",
    # Actor token auto-read from /var/run/secrets/kubernetes.io/serviceaccount/token
)

plugin = ADKTokenPropagationPlugin(sts_integration=sts)
plugin.add_to_agent(my_agent)
```

**Step 3b — Agent code for impersonation (omit actor token):**

```python
sts = ADKSTSIntegration(
    well_known_uri="http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/.well-known/oauth-authorization-server",
    fetch_actor_token=lambda: None,    # No actor token → impersonation
)
```

Or via direct HTTP (no SDK):

```bash
curl -X POST http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=<user-jwt>" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt"
  # No actor_token parameter → impersonation
```

**Step 4 — Downstream policy:**

For **delegation**, validate both `sub` and `act`:

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-delegation-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        jwks:
          backendRef:
            name: enterprise-agentgateway
            namespace: agentgateway-system
            port: 7777
          jwksPath: .well-known/jwks.json
      rbac:                                          # Per-agent tool access control
      - tool: "query_database"
        celExpression: >-
          claims.act != null &&
          claims.act.sub == "system:serviceaccount:default:chat-agent"
```

For **impersonation** (agent omits actor token), the policy is simpler — no RBAC on `act` since there is no agent identity:

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-impersonation-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        jwks:
          backendRef:
            name: enterprise-agentgateway
            namespace: agentgateway-system
            port: 7777
          jwksPath: .well-known/jwks.json
```

**Note:** No `tokenExchange.mode` is set on either policy — the proxy is not performing the exchange. The agent handles it directly and sends the OBO JWT in the request.

</details>

---

<details>
<summary><strong><a id="example-3-built-in-sts--non-mcp-backend-llm--http-api"></a>Example 3: Built-in STS + Non-MCP Backend (LLM / HTTP API)</strong></summary>

Token exchange works the same for non-MCP backends. The difference is how the downstream validates the OBO token — use `traffic.jwtAuthentication` instead of `backend.mcp.authentication`.

> **Note:** This example shows the token exchange configuration only. Clients still need a way to obtain an IdP JWT (via [MCP OAuth + DCR](flows/flow-11-mcp-oauth-dcr.md), [OIDC](flows/flow-01-oidc-auth.md), etc.). The STS's `subjectValidator` validates the IdP JWT during exchange — a separate `JWTAuthentication` policy is not required but can be added. See [How Token Exchange Relates to Inbound Auth](#how-token-exchange-relates-to-jwt-auth-and-mcp-auth).

**Step 1 — Enable the built-in STS (Helm values):**

```yaml
# values.yaml for enterprise-agentgateway Helm chart
tokenExchange:
  enabled: true
  issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
  tokenExpiration: 24h

  subjectValidator:
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs"

  actorValidator:
    validatorType: k8s

  apiValidator:
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs"
```

**Step 2 — Tell the proxy where the STS is (Gateway + Parameters):**

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: agw-params
  namespace: default
spec:
  env:
  - name: STS_URI
    value: http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/oauth2/token
  - name: STS_AUTH_TOKEN
    value: /var/run/secrets/xds-tokens/xds-token
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: agw-params
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
```

**Step 3 — Route to a non-MCP backend:**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: api-route
  namespace: default
spec:
  parentRefs:
  - name: my-gateway
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /api
    backendRefs:
    - name: my-api-service
      port: 8080
```

**Step 4 — Policy with JWT auth on the traffic section:**

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: api-obo-policy
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: api-route
  traffic:
    jwtAuthentication:                               # Validates OBO token on non-MCP route
      mode: Strict
      providers:
      - issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
        jwks:
          backendRef:
            name: enterprise-agentgateway
            namespace: agentgateway-system
            port: 7777
          jwksPath: .well-known/jwks.json
  backend:
    tokenExchange:
      mode: ExchangeOnly
```

</details>

---

<details>
<summary><strong><a id="example-4-external-sts"></a>Example 4: External STS</strong></summary>

Instead of the built-in STS, you point the proxy at an external RFC 8693-compliant STS (e.g., a corporate STS, Okta Custom Authorization Server, or a cloud provider's token exchange endpoint).

**Step 1 — No `tokenExchange` in Helm values** (the built-in STS is not used). You still need `tokenExchange.enabled: true` in the Helm chart if it's required for the CRDs, but the validators are unused — the external STS handles validation.

**Step 2 — Point the proxy at the external STS:**

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: external-sts-params
  namespace: default
spec:
  env:
  - name: STS_URI
    value: https://sts.example.com/oauth2/token       # Your external STS endpoint
  - name: STS_AUTH_TOKEN
    value: /var/run/secrets/sts-tokens/sts-token       # Auth token for the external STS
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: external-sts-params
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
```

**Step 3 — Policy:** `mcp.authentication` is **always required** — AGW must validate the inbound IdP JWT so it can extract it for exchange. What `mcp.authentication` points at depends on what the external STS returns:

- **External STS returns JWTs:** `mcp.authentication` points at the **IdP issuer** (Keycloak, Okta, etc.) to validate the inbound JWT. AGW then also validates the exchanged JWT downstream if you add a second policy or the same policy trusts the external STS issuer.
- **External STS returns opaque tokens:** `mcp.authentication` points at the **IdP issuer** to validate the inbound JWT. AGW cannot validate the opaque token downstream — the MCP server must handle introspection. See [Option B in the FAQ](#faq-why-jwts-and-not-opaque-tokens) and the [Flow 13b lab](../flow13-token-exchange/flow13b-external-sts-opaque-token/).

Example policy (external STS returns JWTs):

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-external-sts-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "https://idp.example.com"              # IdP issuer (validates inbound JWT)
        jwks:
          url: "https://idp.example.com/.well-known/jwks.json"
    tokenExchange:
      mode: ExchangeOnly
```

Example policy (external STS returns opaque tokens — e.g., [Flow 13b](../flow13-token-exchange/flow13b-external-sts-opaque-token/)):

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-external-sts-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "https://idp.example.com"              # IdP issuer (validates inbound JWT)
        audiences:
        - account
        - my-client-id
        jwks:
          backendRef:                                    # Or use url: for external JWKS
            name: keycloak
            kind: Service
            namespace: keycloak
            port: 8080
          jwksPath: realms/my-realm/protocol/openid-connect/certs
    tokenExchange:
      mode: ExchangeOnly
```

</details>

---

<details>
<summary><strong><a id="example-5-elicitation--exchange-double-oauth"></a>Example 5: Elicitation + Exchange (Double OAuth)</strong></summary>

When the upstream API requires separate OAuth credentials that may not exist yet. The gateway first elicits the credentials (user completes an OAuth flow), then exchanges the token on subsequent requests.

**Step 1 — Helm values include an elicitation secret:**

```yaml
tokenExchange:
  enabled: true
  issuer: "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
  tokenExpiration: 24h
  elicitation:
    secretName: "elicitation-oauth-secret"             # K8s secret with OAuth client credentials
  subjectValidator:
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs"
  actorValidator:
    validatorType: k8s
  apiValidator:
    validatorType: remote
    remoteConfig:
      url: "http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs"
```

**Step 2 — Policy with default mode (both elicitation and exchange):**

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: double-oauth-policy
  namespace: default
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-backend
  backend:
    tokenExchange: {}                                  # No mode = both elicitation + exchange
```

When `mode` is omitted (or set to `TOKEN_EXCHANGE_MODE_UNSPECIFIED`), the gateway does both: elicit credentials if missing, then exchange the token on every request.

</details>

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

```mermaid
sequenceDiagram
    participant U as User (Alice)
    participant A as Agent
    participant P as AGW Proxy
    participant S as AGW Built-in STS
    participant IdP as OIDC Provider<br/>(Keycloak)
    participant M as MCP Server

    Note over U,IdP: Phase 1: User Authentication
    U->>IdP: Login (Authorization Code Flow)
    IdP-->>U: JWT (sub=alice, scope=openid profile,<br/>realm_access, session_state)

    Note over U,M: Phase 2: Request + Gateway-Mediated Exchange
    U->>A: Request with JWT
    A->>P: Authorization: Bearer <alice's JWT>
    Note right of P: Reads STS_URI + STS_AUTH_TOKEN<br/>from env (injected by<br/>EnterpriseAgentgatewayParameters)
    P->>S: POST /oauth2/token<br/>subject_token=<alice's JWT><br/>resource=service/default/mcp-backend...<br/>(no actor_token)
    Note right of S: API Validator: verify proxy auth ✓<br/>Subject Validator: fetch IdP JWKS,<br/>verify signature, issuer, exp ✓<br/>Extract sub=alice, scope=openid profile<br/>No actor_token → impersonation mode
    S-->>P: OBO JWT (iss=STS, sub=alice,<br/>aud=mcp-backend, no act claim)

    Note over P,M: Phase 3: Forward to Downstream
    P->>M: Authorization: Bearer <OBO JWT><br/>(original IdP JWT replaced)
    Note right of M: Fetch STS JWKS from /.well-known/jwks.json<br/>Verify signature ✓, iss=STS ✓, aud=self ✓<br/>sub=alice → apply permissions
    M-->>A: Response
    A-->>U: Result
```

<details>
<summary><strong>Step-by-step details</strong></summary>

```
1. Alice logs into the chat app
   → Browser redirects to Keycloak (Authorization Code Flow)
   → Alice authenticates (username/password, SSO, etc.)
   → Keycloak issues a JWT:
     {
       "iss": "https://keycloak.example.com/realms/my-realm",
       "sub": "alice",
       "scope": "openid profile",
       "realm_access": { "roles": ["user"] },   ← IdP-specific (will NOT leak downstream)
       "session_state": "abc123",                ← IdP-specific (will NOT leak downstream)
       "exp": 1712192400
     }

2. Alice's agent sends a request to the MCP server via Agent Gateway
   Authorization: Bearer <alice's-keycloak-jwt>

3. Agent Gateway proxy intercepts the request (ExchangeOnly mode is configured)
   → Proxy reads STS_URI from its environment (injected by EnterpriseAgentgatewayParameters)
   → Proxy reads STS_AUTH_TOKEN from the mounted file (/var/run/secrets/xds-tokens/xds-token)
   → Proxy extracts Alice's JWT from the Authorization header
   → Proxy calls the STS:
     POST http://enterprise-agentgateway:7777/oauth2/token
     Authorization: Bearer <sts-auth-token>         ← proxy's own auth to the STS
     Content-Type: application/x-www-form-urlencoded

     grant_type=urn:ietf:params:oauth:grant-type:token-exchange
     &subject_token=<alice's-keycloak-jwt>
     &subject_token_type=urn:ietf:params:oauth:token-type:jwt
     &resource=service/default/mcp-backend.default.svc.cluster.local:8080
     (no actor_token — gateway-mediated never sends one)

4. STS processes the exchange
   → API Validator: validates the proxy's auth token (remote JWKS or k8s) ✓
   → Subject Validator: fetches Keycloak's JWKS from the configured remote URL
   → Subject Validator: verifies Alice's JWT signature, issuer, expiration ✓
   → Subject Validator: extracts sub="alice", scope="openid profile"
   → No actor_token provided → impersonation mode (no act claim)
   → STS signs a new OBO JWT with its own private key:
     {
       "iss": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777",
       "sub": "alice",                              ← preserved from Alice's JWT
       "aud": "service/default/mcp-backend.default.svc.cluster.local:8080",
       "scope": "openid profile",                   ← preserved from Alice's JWT
       "exp": 1712275200,                            ← 24h from now (STS-configured TTL)
       "iat": 1712188800
     }
     No "act" — the agent is invisible.
     No "realm_access", "session_state" — IdP claims are stripped.

5. Agent Gateway forwards the request to the MCP server
   Authorization: Bearer <sts-signed-obo-jwt>
   (Alice's original Keycloak JWT is replaced — MCP server never sees it)

6. MCP server validates the OBO JWT
   → Fetches STS public keys from /.well-known/jwks.json
   → Verifies signature against STS JWKS ✓
   → Checks iss = STS issuer ✓ (only needs to trust this one issuer)
   → Checks aud = "service/default/mcp-backend..." matches its own identity ✓
   → Reads sub = "alice" → applies Alice's permissions
   → Returns data to Alice's agent
```

**Result:** Alice's identity flows through cleanly, the MCP server trusts one issuer, and no IdP-specific claims leaked. But there's no record of which agent made the call.

</details>

### Scenario: Agent-Initiated (Delegation)

Same setup, but now the organization wants audit trails showing which agent accessed data on behalf of which user. The agent calls the STS directly.

```mermaid
sequenceDiagram
    participant U as User (Alice)
    participant A as Agent Pod<br/>(chat-agent)
    participant S as AGW Built-in STS
    participant K as K8s API Server
    participant IdP as OIDC Provider<br/>(Keycloak)
    participant M as MCP Server

    Note over U,IdP: Phase 1: User Authentication
    U->>IdP: Login (Authorization Code Flow)
    IdP-->>U: JWT (sub=alice, may_act={sub=chat-agent SA})

    Note over A,S: Phase 2: STS Discovery + Token Exchange
    U->>A: Request with JWT
    Note right of A: Read SA token from<br/>/var/run/secrets/kubernetes.io/<br/>serviceaccount/token<br/>(auto-mounted by K8s)
    A->>S: GET /.well-known/oauth-authorization-server
    S-->>A: { token_endpoint: ".../oauth2/token" }
    A->>S: POST /oauth2/token<br/>subject_token=<alice's JWT><br/>actor_token=<K8s SA JWT>

    Note over S,K: Phase 3: STS Validation
    Note right of S: Subject Validator (remote/JWKS):<br/>Fetch IdP JWKS, verify signature ✓<br/>Extract sub=alice, may_act ✓
    S->>K: POST /apis/authentication.k8s.io/<br/>v1/tokenreviews<br/>{ spec: { token: <SA JWT> } }
    K-->>S: Authenticated ✓<br/>sub=system:serviceaccount:default:chat-agent<br/>iss=https://kubernetes.default.svc.cluster.local
    Note right of S: Cross-validate:<br/>may_act.sub == actor.sub ✓<br/>may_act.iss == actor.iss ✓

    S-->>A: OBO JWT (iss=STS, sub=alice,<br/>act={sub=chat-agent}, aud=mcp-backend)
    Note right of A: SDK caches OBO token<br/>(respects exp with 5s buffer)

    Note over A,M: Phase 4: Forward to Downstream
    A->>M: Authorization: Bearer <OBO JWT>
    Note right of M: Fetch STS JWKS ✓<br/>Verify signature ✓, iss=STS ✓, aud=self ✓<br/>sub=alice → user permissions ✓<br/>act.sub=chat-agent → agent allowed ✓<br/>Audit: alice via chat-agent
    M-->>A: Response
    A-->>U: Result
```

<details>
<summary><strong>Step-by-step details</strong></summary>

```
1. Alice logs in → gets a Keycloak JWT (same as before)
   This time, the Keycloak admin has added a hardcoded claim mapper, so
   Alice's token also contains:
   "may_act": {
     "sub": "system:serviceaccount:default:chat-agent",
     "iss": "https://kubernetes.default.svc.cluster.local"
   }
   (This authorizes the chat-agent service account to act on Alice's behalf)

2. The chat-agent pod receives Alice's request and her JWT
   → The agent's K8s service account token is already mounted in the pod
     at /var/run/secrets/kubernetes.io/serviceaccount/token (auto-mounted by K8s)
   → The agentsts-adk SDK reads this file automatically

3. The SDK discovers the STS
   → Fetches http://enterprise-agentgateway:7777/.well-known/oauth-authorization-server
   → Reads the token_endpoint from the response: ".../oauth2/token"

4. The SDK calls the STS directly (not via the proxy):
   POST http://enterprise-agentgateway:7777/oauth2/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
   &subject_token=<alice's-keycloak-jwt>
   &subject_token_type=urn:ietf:params:oauth:token-type:jwt
   &actor_token=<chat-agent's-k8s-sa-jwt>           ← read from mounted file
   &actor_token_type=urn:ietf:params:oauth:token-type:jwt

5. STS processes the exchange
   → Subject Validator (remote/JWKS):
     → Fetches Keycloak's JWKS
     → Verifies Alice's JWT signature, issuer, expiration ✓
     → Extracts sub="alice", scope="openid profile"
     → Extracts may_act claim ✓
   → Actor Validator (k8s):
     → Sends the SA token to K8s API server:
       POST /apis/authentication.k8s.io/v1/tokenreviews
       { "spec": { "token": "<chat-agent's-k8s-sa-jwt>" } }
     → K8s verifies the SA token signature, checks expiration,
       confirms the service account exists ✓
     → K8s returns: sub="system:serviceaccount:default:chat-agent",
       iss="https://kubernetes.default.svc.cluster.local"
   → Cross-validation:
     → may_act.sub == actor.sub? "system:serviceaccount:default:chat-agent" ✓
     → may_act.iss == actor.iss? "https://kubernetes.default.svc.cluster.local" ✓
   → STS signs a new OBO JWT:
     {
       "iss": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777",
       "sub": "alice",
       "act": {
         "sub": "system:serviceaccount:default:chat-agent",
         "iss": "https://kubernetes.default.svc.cluster.local"
       },
       "aud": "service/default/mcp-backend.default.svc.cluster.local:8080",
       "scope": "openid profile",
       "exp": 1712275200,
       "iat": 1712188800
     }

6. The SDK caches the OBO token (respects exp with 5s buffer)
   → Injects it as Authorization: Bearer on outbound MCP tool calls

7. The chat-agent sends the request to the MCP server
   Authorization: Bearer <sts-signed-obo-jwt-with-act>

8. MCP server validates the OBO JWT
   → Fetches STS public keys from /.well-known/jwks.json
   → Verifies signature ✓
   → Checks iss = STS issuer ✓
   → Checks aud matches its own identity ✓
   → sub = "alice" → applies Alice's permissions ✓
   → act.sub = "system:serviceaccount:default:chat-agent"
     → CEL RBAC: checks agent is allowed to call this tool ✓
   → Audit log: "alice via chat-agent called query_database"
```

**Result:** Full audit trail, per-agent policies, and Alice's identity preserved. The trade-off: the agent needs to know about the STS and integrate with the SDK.

</details>

---

## Troubleshooting

Common errors you'll encounter when setting up token exchange, what causes them, and how to fix them.

### Exchange Never Triggers (Token Passes Through Unchanged)

**Symptom:** The downstream MCP server receives the original IdP JWT instead of an OBO token. No exchange happens.

**Causes and fixes:**

| Cause | How to Verify | Fix |
|-------|--------------|-----|
| Missing `mcp.authentication` on the policy | `kubectl get enterpriseagentgatewaypolicies -o yaml` — no `authentication` block | Add `mcp.authentication` with the IdP issuer and JWKS. AGW needs this to parse the Authorization header and extract the JWT for exchange. |
| Missing `tokenExchange.mode` on the policy | Policy has no `tokenExchange` section | Add `tokenExchange: { mode: ExchangeOnly }` to the policy |
| `STS_URI` not configured | Check `EnterpriseAgentgatewayParameters` exists and is referenced by the Gateway | Create the Parameters resource with `STS_URI` and link it via `infrastructure.parametersRef` on the Gateway |
| Parameters not linked to Gateway | Gateway has no `infrastructure.parametersRef` | Add `parametersRef` pointing to your `EnterpriseAgentgatewayParameters` |
| Proxy pod not restarted after config change | Proxy pod still has old env vars | `kubectl rollout restart deployment` on the proxy (or delete the Gateway and recreate) |

**Debug steps:**
```bash
# 1. Check if the proxy has STS env vars
kubectl exec -n agentgateway-system deploy/agentgateway-proxy -- env | grep STS

# 2. Check policy status
kubectl get enterpriseagentgatewaypolicies -o yaml | grep -A5 tokenExchange

# 3. Look at proxy logs for exchange attempts
kubectl logs -n agentgateway-system deploy/agentgateway-proxy | grep -i "token exchange\|sts\|exchange"
```

### STS Returns 400 (Bad Request)

**Symptom:** The proxy calls the STS, but the STS rejects the exchange with a 400 error.

| Cause | Error Message | Fix |
|-------|--------------|-----|
| Subject token expired | `"error": "invalid_grant"` | The user's IdP JWT has expired. The client needs to refresh it before making the request. |
| Subject token signature invalid | `"error": "invalid_grant"` | The `subjectValidator` JWKS URL is wrong or unreachable. Verify it points to the correct IdP JWKS endpoint. |
| Subject token issuer mismatch | `"error": "invalid_grant"` | The `subjectValidator` expects tokens from issuer A, but the token is from issuer B. Check the JWKS URL matches the IdP. |
| Missing `may_act` claim (delegation) | `"error": "invalid_grant"` | The subject token doesn't contain a `may_act` claim authorizing the actor. Add a hardcoded claim mapper in your IdP. |
| `may_act` doesn't match actor | `"error": "invalid_grant"` | The `may_act.sub` or `may_act.iss` in the subject token doesn't match the actor token's identity. Verify the K8s SA name and issuer URL. |
| Wrong `grant_type` | `"error": "unsupported_grant_type"` | The STS received a non-RFC-8693 request. If using Entra ID, note it uses `jwt-bearer` not `token-exchange`. |

**Debug steps:**
```bash
# 1. Decode the subject token to check claims
echo "<jwt>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# 2. Check may_act claim exists (delegation only)
echo "<jwt>" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.may_act'

# 3. Check the actor token identity
ACTOR=$(kubectl create token my-agent -n default --duration=60s)
echo "$ACTOR" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{sub, iss}'

# 4. Verify the subjectValidator JWKS URL is reachable from the STS pod
kubectl exec -n agentgateway-system deploy/enterprise-agentgateway -- \
  curl -s http://keycloak.keycloak.svc.cluster.local:8080/realms/my-realm/protocol/openid-connect/certs | jq .keys[0].kid
```

### STS Returns 401/403 (Unauthorized)

**Symptom:** The proxy or agent can't authenticate to the STS endpoint.

| Cause | Fix |
|-------|-----|
| `STS_AUTH_TOKEN` file doesn't exist | Verify the token file path. Default: `/var/run/secrets/xds-tokens/xds-token`. Check if it's mounted in the proxy pod. |
| `STS_AUTH_TOKEN` is expired or invalid | The token file may contain a stale token. Check if the token volume mount is configured correctly. |
| API Validator rejects the caller's token | The `apiValidator` in Helm values is configured to validate against a specific JWKS. Ensure the proxy's auth token is signed by a key in that JWKS. |

### Downstream Rejects the OBO Token

**Symptom:** The exchange succeeds (STS returns an OBO token), but the downstream MCP server rejects it with 401.

| Cause | How to Verify | Fix |
|-------|--------------|-----|
| Wrong issuer in `mcp.authentication` | Decode the OBO token — check `iss` | Set `mcp.authentication.issuer` to the STS issuer (e.g., `enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777`) |
| JWKS endpoint unreachable from downstream | `curl` the JWKS URL from the MCP server pod | Ensure the MCP server can reach the STS at port 7777. Check K8s DNS and network policies. |
| Audience mismatch | Decode the OBO token — check `aud` | The `aud` claim must match one of the `audiences` configured in `mcp.authentication`. Check the `resource` parameter format. |
| OBO token expired | Decode the OBO token — check `exp` | Increase `tokenExchange.tokenExpiration` in Helm values. Default is 24h. |

**Debug steps:**
```bash
# 1. Check what the downstream actually received
# (if you control the MCP server, log the Authorization header)
kubectl logs deploy/mcp-server | grep -i "auth\|token\|jwt"

# 2. Decode the OBO token to verify claims
echo "<obo-jwt>" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss, sub, aud, act, exp}'

# 3. Verify the STS JWKS is reachable from the MCP server
kubectl exec deploy/mcp-server -- curl -s \
  http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/.well-known/jwks.json | jq .keys[0].kid
```

### CEL RBAC Denies Access

**Symptom:** The OBO token is valid, but a CEL RBAC rule rejects the request.

| Cause | Fix |
|-------|-----|
| Policy checks `claims.act` but token has no `act` (impersonation) | Either switch to agent-initiated delegation (include actor token), or update the CEL expression to not require `act` |
| Wrong K8s SA name in CEL expression | `claims.act.sub` is the full K8s SA path: `system:serviceaccount:{namespace}:{name}`. Verify namespace and name match. |
| `groups` claim missing from OBO token | The STS only copies `sub`, `scope`, and optionally `act`. It does not copy `groups` from the IdP token. If you need groups-based RBAC, add group claims to the STS configuration. |

### Debugging Checklist

When something isn't working, check these in order:

```
1. Does the proxy have STS_URI and STS_AUTH_TOKEN?
   → kubectl exec proxy -- env | grep STS

2. Is mcp.authentication configured on the policy?
   → kubectl get enterpriseagentgatewaypolicies -o yaml

3. Is the subjectValidator JWKS URL reachable from the STS?
   → kubectl exec enterprise-agentgateway -- curl <jwks-url>

4. Is the user's JWT valid (not expired, correct issuer)?
   → Decode it: echo "<jwt>" | cut -d. -f2 | base64 -d | jq '{iss, sub, exp}'

5. Does the OBO token have the right claims?
   → Decode it the same way, check iss, sub, aud, act

6. Can the downstream reach the STS JWKS?
   → kubectl exec mcp-server -- curl <sts-jwks-url>

7. Does the aud match what the downstream expects?
   → Compare OBO token aud with mcp.authentication.audiences
```

> **Hands-on debugging:** The [Flow 13 lab](../flow13-token-exchange/flow13-gateway-mediated-token-exchange/) includes an `echo_token` MCP tool that returns the exact token the MCP server received — useful for verifying that exchange happened and the claims are correct.

---

## Customer Conversation Guide

Use this section to qualify whether token exchange is the right pattern for a customer's architecture, and which mode to recommend.

### Discovery Questions

Ask these early in the conversation to understand the customer's requirements:

| Question | Why It Matters |
|----------|---------------|
| **"Do your downstream services need to know who the user is?"** | If no — passthrough or static secrets may be sufficient. If yes — token exchange is needed. |
| **"Do your downstream services need to know which agent made the call?"** | If yes — delegation (dual identity with `sub` + `act`). If no — impersonation is simpler. |
| **"How many identity providers do you have?"** | Multiple IdPs is the strongest driver for token exchange — it unifies trust into a single STS issuer instead of every downstream trusting every IdP. |
| **"Do you need per-user audit trails on downstream services?"** | If yes — you need the user's identity in the token. Token exchange preserves `sub` while cleaning up IdP-specific claims. |
| **"Does your IdP support RFC 8693?"** | Determines whether to use the built-in STS, the IdP as an external STS, or a hybrid approach. See the [Provider Guide](#external-idp--sts-provider-guide). |
| **"Do you have any token revocation requirements?"** | If they need instant revocation — discuss opaque tokens (external STS) or short-lived JWTs. See [FAQ: Why JWTs?](#faq-why-jwts-and-not-opaque-tokens). |
| **"Are your agents running in Kubernetes?"** | K8s service account tokens are the natural actor token for delegation. Non-K8s agents need a different actor identity strategy. |
| **"Do you want zero code changes to your agents?"** | If yes — gateway-mediated (`ExchangeOnly`) is the answer. Agent never knows the STS exists. |

### When to Recommend Each Pattern

```
                  Does the downstream need to know WHO the user is?
                  │
                  ├─ NO → Does the downstream need any auth at all?
                  │        │
                  │        ├─ NO → Passthrough (no auth)
                  │        │
                  │        └─ YES → Static Secret Injection
                  │                 (validate inbound JWT, replace with shared API key)
                  │
                  └─ YES → Does the downstream need to know WHICH AGENT made the call?
                           │
                           ├─ NO → Token Exchange: Impersonation
                           │       │
                           │       ├─ Want zero agent code changes?
                           │       │   └─ YES → Gateway-Mediated (ExchangeOnly)
                           │       │
                           │       └─ Agent needs custom scopes/audience?
                           │           └─ YES → Agent-Initiated (omit actor token)
                           │
                           └─ YES → Token Exchange: Delegation
                                    │
                                    └─ Agent-Initiated (include actor token)
                                       Requires: may_act claim in IdP token
                                                 + K8s SA token as actor
```

### Pattern Comparison for Customer Discussions

| Pattern | User Identity? | Agent Identity? | Code Changes? | Complexity | Best For |
|---------|---------------|-----------------|---------------|------------|----------|
| **Passthrough** | IdP-dependent | No | None | Lowest | Downstream already trusts the IdP, no multi-IdP, no token cleanup needed |
| **Static Secret** | No | No | None | Low | Downstream uses a shared API key (no per-user access control needed) |
| **Impersonation (gateway-mediated)** | Yes | No | None | Medium | Most common — per-user identity downstream, zero agent changes |
| **Impersonation (agent-initiated)** | Yes | No | SDK/HTTP | Medium | Agent needs control over scopes or audience |
| **Delegation** | Yes | Yes | SDK/HTTP | Highest | Audit trails, per-agent policies, multi-agent environments |

### Common Customer Scenarios

**Scenario 1: "We have Okta for SSO and want our agents to call internal MCP tools with user context."**

→ **Recommendation:** Gateway-mediated impersonation with AGW built-in STS.
- Okta as IdP (inbound auth), AGW STS for exchange
- `subjectValidator` points to Okta's JWKS
- Zero agent code changes — proxy handles everything
- Downstream MCP servers trust one issuer (the STS)

**Scenario 2: "We need audit trails showing which agent accessed data on behalf of which user."**

→ **Recommendation:** Agent-initiated delegation.
- Requires `may_act` claim in user tokens (IdP configuration)
- Agent integrates with `agentsts-adk` SDK
- OBO tokens include both `sub` (user) and `act` (agent)
- CEL RBAC can enforce per-agent policies

**Scenario 3: "We have multiple IdPs (Okta for employees, Azure AD for partners) and want a unified trust model."**

→ **Recommendation:** Gateway-mediated impersonation with AGW built-in STS.
- Configure `subjectValidator` with multiple JWKS sources (or use a single IdP federation point)
- All downstream services trust one issuer (the STS) regardless of which IdP the user came from
- Eliminates the N×M trust problem (N IdPs × M downstreams)

**Scenario 4: "We need instant token revocation for compliance."**

→ **Recommendation:** Either short-lived JWTs (simplest) or external STS with opaque tokens (most control).
- **Short-lived JWTs:** Set `tokenExchange.tokenExpiration` to `5m`. Tokens expire fast, no introspection needed. Gap: 5-minute replay window.
- **Opaque tokens:** Use Ory Hydra or PingFederate as external STS. MCP servers call introspection per request. Trade-off: network call per request, STS availability dependency.

**Scenario 5: "Our agents are not in Kubernetes."**

→ **Recommendation:** Gateway-mediated impersonation (no actor token needed) or agent-initiated with a custom actor identity.
- Gateway-mediated doesn't need an actor token — works with any agent platform
- For delegation: the agent needs any JWT the STS can validate as an actor. Options: a short-lived JWT from a dedicated IdP client, a custom token service, or application-level API keys mapped to agent identities.

### Objection Handling

| Objection | Response |
|-----------|----------|
| "We already forward tokens — why add complexity?" | Token exchange is about trust boundaries. Forwarding works with one IdP and one downstream. At scale (multiple IdPs, multiple downstreams, multiple agents), each downstream must trust every IdP. Token exchange collapses this to one trust relationship. Also, forwarding leaks IdP-specific claims (`realm_access`, `session_state`) to every downstream. |
| "Can't we just use mutual TLS instead?" | mTLS authenticates the **connection** (which service is calling), not the **user**. Token exchange authenticates the **user** (who requested the action). They're complementary — you can use mTLS between agent and gateway, and token exchange for user identity propagation. |
| "Our IdP already does token exchange — why use AGW's STS?" | If your IdP supports RFC 8693, you can use it as an external STS (`STS_URI` → IdP endpoint). AGW's built-in STS is useful when: (a) your IdP doesn't support RFC 8693 (Auth0, older Okta), (b) you want the STS colocated with the gateway for latency, (c) you want to avoid IdP vendor lock-in on the exchange logic. |
| "This seems like overkill for our use case." | Start with the simplest pattern. If your agent calls one downstream and the IdP token is fine as-is, use passthrough. Token exchange becomes valuable when you add: multiple agents, multiple downstreams, audit requirements, or multi-IdP environments. It's a spectrum — you can start simple and add exchange later without changing downstream services (just add the policy). |
| "What about performance? Isn't an extra hop slow?" | The built-in STS runs in-cluster (microseconds of network latency). JWT signing is ~1ms. The bigger cost is NOT using exchange — without it, every downstream independently validates against every IdP's JWKS. With exchange, downstreams cache one JWKS. Also, gateway-mediated exchange adds no latency from the agent's perspective — the proxy handles it in the request path. |

---

## FAQ: Why JWTs and Not Opaque Tokens?

The built-in STS always issues **JWTs** (signed, self-contained tokens) — not opaque tokens (random strings that require introspection). This is a deliberate design choice.

### JWT vs Opaque Token

| | JWT | Opaque Token |
|---|---|---|
| **Contains claims?** | Yes — `iss`, `sub`, `act`, `aud`, `scope` embedded in the token | No — just a random reference string |
| **Validation** | Local — verify signature against JWKS (no network call) | Remote — call the issuer's introspection endpoint on every request |
| **Revocation** | Hard — token is valid until `exp` (no revocation list by default) | Easy — delete from issuer's store, next introspection fails |
| **Size** | Larger (~500-1000 chars) | Smaller (~32-64 chars) |
| **Privacy** | Claims visible to anyone with the token (base64-encoded, not encrypted) | Claims stay at the issuer |

**Why AGW uses JWTs:** The gateway sits in the hot path — every MCP request passes through it. JWT validation is a local cryptographic check (microseconds) against cached JWKS keys — the gateway fetches the IdP's public keys once and caches them for **5 minutes** (default, configurable via `cacheDuration`). During that window, every JWT is validated locally with zero network calls. When the cache expires, keys are refetched on the next request. Opaque token introspection, by contrast, requires a network round-trip to the STS on **every single request** (milliseconds + availability dependency). For a gateway handling high-throughput agent traffic, local validation with cached keys is critical.

### Can I Use Opaque Tokens with an External STS?

**Partially.** If you use an external STS that issues opaque tokens, AGW's proxy will forward whatever token the STS returns. However, AGW's downstream validation (`mcp.authentication`, `traffic.jwtAuthentication`) only supports **JWKS-based JWT validation** — it cannot call an introspection endpoint. So you have two options:

**Option A: External STS issues JWTs (recommended)**

The external STS issues JWTs signed with its own key. AGW validates them via JWKS like normal. You get the benefits of an external STS (separate trust domain, custom claim logic) with local validation.

**Option B: External STS issues opaque tokens, MCP server handles introspection**

Skip AGW's downstream auth and let the MCP server validate opaque tokens itself:

```
┌────────┐   IdP JWT    ┌─────────────┐  opaque token  ┌─────────────┐
│ Client │─────────────►│ Agent       │───────────────►│ MCP Server  │
│        │              │ Gateway     │                │             │
└────────┘              │             │                │ Calls STS   │
                        │ Exchanges   │                │ introspect  │
                        │ at external │                │ endpoint    │
                        │ STS         │                │ per request │
                        └──────┬──────┘                └──────┬──────┘
                               │                              │
                        ┌──────▼──────┐                       │
                        │ External    │◄──────────────────────┘
                        │ STS         │  POST /introspect
                        │             │  token=<opaque>
                        │ Issues      │  → { active: true,
                        │ opaque      │    sub: "alice", ... }
                        │ tokens      │
                        └─────────────┘
```

Configuration changes vs the standard flow:

1. **`EnterpriseAgentgatewayParameters`** — `STS_URI` points to the external STS token exchange endpoint
2. **`EnterpriseAgentgatewayPolicy`** — set `tokenExchange.mode: ExchangeOnly` and **keep `mcp.authentication` pointing at the IdP issuer** (e.g., Keycloak). AGW needs `mcp.authentication` to validate and parse the **inbound** IdP JWT so it can extract it for exchange. Without it, AGW doesn't read the Authorization header and the exchange never triggers. After the exchange, AGW forwards the opaque token to the MCP server without further validation (it can't validate opaque tokens via JWKS).
3. **MCP server** — must call the external STS introspection endpoint (`POST /introspect` per [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)) on every request to validate the opaque token and extract claims

> **See also:** [Flow 13b: External STS with Opaque Token Exchange](../flow13-token-exchange/flow13b-external-sts-opaque-token/) — end-to-end lab demonstrating this pattern with a Python STS, including the `mcp.authentication` + `tokenExchange` policy configuration.

**Trade-offs of Option B:**

- AGW validates the inbound IdP JWT but does not enforce auth on the exchanged opaque token downstream — the MCP server is responsible for introspection
- Every MCP server needs introspection logic + network access to the external STS
- A network call per request on the hot path (introspection latency + STS availability dependency)
- If the external STS goes down, all token validation fails (no local fallback)
- Every MCP server must implement introspection independently (or use a shared library/sidecar)

**If you need easy revocation** (the main reason to want opaque tokens), consider **short-lived JWTs** instead — set `tokenExchange.tokenExpiration` to a short duration (e.g., `5m`). You get the same practical benefit (tokens expire quickly, limiting the replay window) without needing introspection infrastructure.

---

## External IdP / STS Provider Guide

This section covers how to integrate AGW token exchange with common identity providers. Each provider has different capabilities and configuration requirements.

### Provider Comparison

| Provider | RFC 8693 Token Exchange | OBO Grant Type | Token Format | Introspection (RFC 7662) | AGW Integration |
|---|---|---|---|---|---|
| **AGW Built-in STS** | Yes | — | JWT | No (JWKS only) | Native — Examples 1-3 above |
| **Keycloak** | Yes | — | JWT | Yes | Fully compatible — used in all lab examples |
| **Okta** | Yes (Custom Auth Server) | — | JWT | Yes | Fully compatible — see below |
| **Microsoft Entra ID** | No — uses `jwt-bearer` | `urn:ietf:params:oauth:grant-type:jwt-bearer` | JWT | No | Requires AGW's native Entra support — see below |
| **Auth0** | No | — | JWT | No | Use as IdP only (inbound auth), not as external STS |
| **Google Cloud STS** | Yes | — | OAuth access token | No | Specialized for GCP workload identity — see below |
| **PingFederate** | Yes | — | JWT or reference token | Yes | Compatible — similar to Keycloak setup |
| **Ory Hydra** | Yes | — | JWT or opaque | Yes | Fully compatible — only OSS STS with native opaque tokens |

---

### Keycloak

Keycloak is used throughout this doc and the lab examples. It supports RFC 8693 natively and is the simplest external STS to integrate with AGW.

**As IdP (inbound auth):** Standard OIDC — Authorization Code Flow or Direct Access Grant. Configure `mcp.authentication` or `subjectValidator` with the Keycloak realm's JWKS URL.

**As external STS:** Point `STS_URI` at Keycloak's token endpoint. Keycloak validates the subject token and issues a new JWT signed by the realm's key.

**Key details:**
- Token endpoint: `https://{host}/realms/{realm}/protocol/openid-connect/token`
- JWKS: `https://{host}/realms/{realm}/protocol/openid-connect/certs`
- Token exchange must be enabled per-client (disabled by default): Admin Console → Clients → {client} → Settings → "token-exchange" fine-grained permission
- Always returns JWTs (no opaque token option)
- Supports `may_act` via hardcoded claim mapper (see [Delegation section](#delegation-dual-identity))

**AGW configuration:** See [Example 1](#example-1-built-in-sts--gateway-mediated-exchange-impersonation) (as IdP) or [Example 4](#example-4-external-sts) (as external STS).

> **Labs:** [Flow 13: Gateway-Mediated Token Exchange](../flow13-token-exchange/flow13-gateway-mediated-token-exchange/) · [Flow 13b: External STS with Opaque Tokens](../flow13-token-exchange/flow13b-external-sts-opaque-token/)

---

### Okta

Okta supports RFC 8693 token exchange on **Custom Authorization Servers** (requires the API Access Management product in production). The Org Authorization Server does not support token exchange.

> **Docs:** [Set up OAuth 2.0 On-Behalf-Of Token Exchange](https://developer.okta.com/docs/guides/set-up-token-exchange/main/) · [Authorization Servers](https://developer.okta.com/docs/concepts/auth-servers/)

**As IdP (inbound auth):** Standard OIDC. Configure `mcp.authentication` or `subjectValidator` with the Custom Authorization Server's JWKS URL.

**As external STS:** Point `STS_URI` at the Custom Authorization Server's token endpoint. Okta validates the subject token against access policies and issues a new JWT.

**Key details:**
- Token endpoint: `https://{yourOktaDomain}/oauth2/{authServerId}/v1/token`
- JWKS: `https://{yourOktaDomain}/oauth2/{authServerId}/v1/keys`
- Discovery: `https://{yourOktaDomain}/oauth2/{authServerId}/.well-known/oauth-authorization-server`
- Default Custom Authorization Server uses `default` as the `authServerId`
- Always returns JWTs from Custom Authorization Servers
- Token exchange grant type must be enabled on the service app: Admin Console → Applications → {service app} → General → Grant type → Advanced → Token Exchange
- Requires access policies and rules on the authorization server that allow the service app + scopes
- Supports **trusted servers** for cross-authorization-server exchange (one auth server trusts tokens from another)
- Client authentication: Base64-encoded `client_id:client_secret` in the `Authorization: Basic` header

**Okta-specific exchange request parameters:**

```
POST https://{yourOktaDomain}/oauth2/{authServerId}/v1/token
Authorization: Basic {base64(client_id:client_secret)}
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token={access_token_from_IdP}
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&scope=api:access:read api:access:write
&audience={authorization_server_audience}
```

**Okta setup checklist:**

1. Create a **Custom Authorization Server** (or use `default`) with custom scopes
2. Create a **native app** for the client (Authorization Code + PKCE)
3. Create a **service app** (API Services) for the middle-tier service (AGW proxy or agent)
4. Enable **Token Exchange** grant type on the service app
5. Create **access policies** + rules that allow the service app to request the custom scopes
6. If using a second authorization server, add the first as a **trusted server**

**AGW configuration (Okta as external STS):**

```yaml
# EnterpriseAgentgatewayParameters
spec:
  env:
  - name: STS_URI
    value: https://{yourOktaDomain}/oauth2/{authServerId}/v1/token

# EnterpriseAgentgatewayPolicy
spec:
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "https://{yourOktaDomain}/oauth2/{authServerId}"  # Okta IdP issuer
        jwks:
          url: "https://{yourOktaDomain}/oauth2/{authServerId}/v1/keys"
    tokenExchange:
      mode: ExchangeOnly
```

> **Note:** When Okta is both the IdP and the external STS (same or different Custom Authorization Servers), `mcp.authentication` and `STS_URI` may point to the same Okta domain. The `mcp.authentication` validates the inbound JWT so AGW can extract it; the `STS_URI` is where AGW sends the exchange request.

---

### Microsoft Entra ID (Azure AD)

Entra ID does **not** support RFC 8693 (`urn:ietf:params:oauth:grant-type:token-exchange`). Instead, it uses its own OBO grant type: `urn:ietf:params:oauth:grant-type:jwt-bearer`. This means you cannot point AGW's `STS_URI` at Entra's token endpoint — AGW sends RFC 8693 requests, which Entra will reject with `unsupported_grant_type`.

> **Docs:** [Microsoft identity platform and OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow) · [AGW Entra OBO support](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/)

**Entra's `jwt-bearer` grant (not RFC 8693):**

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&client_id={middle_tier_client_id}
&client_secret={middle_tier_client_secret}
&assertion={user_access_token}
&scope=https://graph.microsoft.com/.default
&requested_token_use=on_behalf_of
```

Key differences from RFC 8693:
- Uses `assertion` instead of `subject_token`
- Uses `requested_token_use=on_behalf_of` instead of `subject_token_type`
- Requires `client_secret` or `client_assertion` (certificate) — the middle-tier app must authenticate
- Always returns JWTs
- No `actor_token` concept — the middle-tier app's identity is implicit from `client_id`

**AGW integration options:**

**Option A: AGW's native Entra support (recommended)**

AGW has built-in support for Entra's `jwt-bearer` grant type. See the [AGW docs on Entra OBO](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/obo/) for configuration.

**Option B: Entra as IdP only + AGW built-in STS**

Use Entra as the IdP (inbound auth) and AGW's built-in STS for the exchange. The `subjectValidator` is configured with Entra's JWKS:

```yaml
# Helm values
tokenExchange:
  enabled: true
  subjectValidator:
    validatorType: remote
    remoteConfig:
      url: "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
```

```yaml
# EnterpriseAgentgatewayPolicy
spec:
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "https://login.microsoftonline.com/{tenant}/v2.0"
        audiences:
        - "{client_id}"            # App registration's Application (client) ID
        jwks:
          url: "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
    tokenExchange:
      mode: ExchangeOnly
```

**Entra-specific notes:**
- Tenant can be a GUID, `common`, `organizations`, or `consumers`
- JWKS URL: `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys`
- Issuer format: `https://login.microsoftonline.com/{tenant}/v2.0` (v2.0 endpoint) or `https://sts.windows.net/{tenant}/` (v1.0)
- Entra access tokens include `oid` (object ID) in addition to `sub` — the `sub` is a pairwise identifier (different per app), while `oid` is the user's unique directory ID
- Multi-tenant apps: set `audiences` to include both the client ID and `api://{client_id}`

---

### Google Cloud STS

Google Cloud STS supports RFC 8693 but is specialized for **workload identity federation** — exchanging external identity tokens (from AWS, Azure, OIDC providers) for Google Cloud access tokens. It is not a general-purpose STS.

> **Docs:** [STS API reference](https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token) · [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)

**Key details:**
- Token endpoint: `https://sts.googleapis.com/v1/token`
- Uses `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693 compliant)
- Returns Google OAuth 2.0 access tokens (opaque to external consumers)
- `audience` must be a full GCP resource name (workload identity pool provider)
- Primarily for authenticating workloads running outside GCP to access GCP APIs

**AGW integration:** Google Cloud STS is typically not used as an external STS for AGW token exchange. Instead, use Google as an **IdP** via OIDC:

```yaml
# Helm values — subjectValidator trusts Google OIDC
tokenExchange:
  subjectValidator:
    validatorType: remote
    remoteConfig:
      url: "https://www.googleapis.com/oauth2/v3/certs"
```

If your agents need GCP API access with user context, consider having the agent exchange tokens directly with Google Cloud STS (agent-initiated, outside of AGW).

---

### Auth0

Auth0 does **not** support RFC 8693 token exchange. It cannot be used as an external STS with AGW.

> **Note:** Auth0's "Token Exchange" feature (if available) refers to Native SSO or impersonation flows, not RFC 8693.

**AGW integration:** Auth0 works as an **IdP only** (inbound auth):

```yaml
# Helm values — subjectValidator trusts Auth0
tokenExchange:
  subjectValidator:
    validatorType: remote
    remoteConfig:
      url: "https://{yourAuth0Domain}/.well-known/jwks.json"

# EnterpriseAgentgatewayPolicy
spec:
  backend:
    mcp:
      authentication:
        issuer: "https://{yourAuth0Domain}/"     # Note trailing slash
        audiences:
        - "{api_identifier}"                      # Auth0 API audience
        jwks:
          url: "https://{yourAuth0Domain}/.well-known/jwks.json"
```

For token exchange, use AGW's built-in STS or another RFC 8693-compliant external STS.

---

### Ory Hydra

Ory Hydra is the only open-source provider that supports RFC 8693 token exchange **and** native opaque tokens. This makes it the best production alternative to the custom Python STS in the [Flow 13b lab](../flow13-token-exchange/flow13b-external-sts-opaque-token/).

> **Docs:** [Ory Hydra](https://www.ory.sh/docs/hydra/) · [Token Exchange](https://www.ory.sh/docs/oauth2-oidc/token-exchange)

**Key details:**
- Token endpoint: `https://{hydra-public}/oauth2/token`
- JWKS: `https://{hydra-public}/.well-known/jwks.json`
- Supports RFC 8693 (`urn:ietf:params:oauth:grant-type:token-exchange`)
- Can issue **opaque tokens** (reference tokens) natively — no custom code needed
- Supports RFC 7662 introspection (`POST /oauth2/introspect`) for opaque tokens
- Open source (Apache 2.0)

**AGW configuration (Hydra as external STS with opaque tokens):**

```yaml
# EnterpriseAgentgatewayParameters
spec:
  env:
  - name: STS_URI
    value: https://{hydra-public}/oauth2/token

# EnterpriseAgentgatewayPolicy — mcp.authentication validates inbound IdP JWT
spec:
  backend:
    mcp:
      authentication:
        mode: Strict
        issuer: "https://{idp-issuer}"           # Your IdP (Keycloak, Okta, etc.)
        jwks:
          url: "https://{idp-issuer}/.well-known/jwks.json"
    tokenExchange:
      mode: ExchangeOnly
```

The MCP server introspects opaque tokens at `https://{hydra-admin}/oauth2/introspect`. Same pattern as the Flow 13b lab, but with a production-grade STS.

---

### PingFederate / Ping Identity

PingFederate supports RFC 8693 token exchange and can issue both JWTs and **reference tokens** (opaque). It also supports RFC 7662 introspection.

> **Docs:** [PingFederate Token Exchange](https://docs.pingidentity.com/pingfederate/latest/administrators_reference_guide/pf_c_tokenExchangeProcessorPolicies.html)

**Key details:**
- Token endpoint: `https://{pingfederate}/as/token.oauth2`
- JWKS: `https://{pingfederate}/pf/JWKS`
- Supports RFC 8693 with configurable token exchange processor policies
- Can issue reference tokens (opaque) via access token manager configuration
- Supports RFC 7662 introspection
- Token exchange must be enabled via processor policies in the admin console

**AGW configuration:** Same pattern as Keycloak or Okta — configure `STS_URI` to PingFederate's token endpoint and `mcp.authentication` to the IdP's JWKS.

---

### Integration Decision Tree

```
Does your IdP support RFC 8693 token exchange?
│
├─ YES (Keycloak, Okta, Ory Hydra, PingFederate, Google Cloud STS)
│   │
│   ├─ Do you want the IdP to be the external STS?
│   │   │
│   │   ├─ YES → Example 4: STS_URI → IdP token endpoint
│   │   │         mcp.authentication → same IdP (validates inbound JWT)
│   │   │
│   │   └─ NO → Examples 1-3: Use AGW built-in STS
│   │            subjectValidator → IdP JWKS (validates inbound JWT)
│   │
│   └─ Do you need opaque tokens?
│       │
│       ├─ YES → Ory Hydra or PingFederate (native opaque)
│       │         or custom STS (Flow 13b lab)
│       │         MCP server must implement RFC 7662 introspection
│       │
│       └─ NO → Any RFC 8693 provider works (JWT exchange)
│
├─ NO, uses jwt-bearer (Entra ID)
│   │
│   ├─ Use AGW's native Entra support (Option A, recommended)
│   │
│   └─ Or use Entra as IdP only + AGW built-in STS (Option B)
│
└─ NO, no token exchange support (Auth0)
    │
    └─ Use as IdP only + AGW built-in STS
```

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
| **Agent-Initiated** | — | The agent calls the STS directly. Supports both delegation (with actor token) and impersonation (without). Required for delegation; optional for impersonation when the agent needs control over exchange parameters. |

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
