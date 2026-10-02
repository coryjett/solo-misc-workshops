# Pre-configuration for the token exchange working session

Solo.io

The configuration that needs to be in place before the workshop, so the time is spent on the
flows rather than on setup.

Most of it is Okta. Allow about 30 minutes, plus whatever your change process requires.

---

## Read this first: one thing to verify before anything else

The flow this workshop builds:

```
user -> agentgateway -> Keycloak (authenticate, get user token)
                     -> Okta  (exchange that token, get an OBO token)
                     -> MCP servers
```

**Okta's documentation does not describe that exchange.** Okta documents token exchange
"within a single authorization server or between other authorization servers **under the
same Okta tenant**." A subject token issued by a *different* IdP (Keycloak, or Auth0) is
neither documented as supported nor documented as prohibited.

**Measured on a live Okta tenant, with a control:**

| Subject token issued by | Result |
|---|---|
| Okta, same authorization server | **Exchanged successfully** |
| Keycloak | `invalid_request: 'subject_token' is invalid` |

The Okta-issued token passes subject validation and is exchanged; the Keycloak one is refused
before policy evaluation. The refusal is about who issued the token, not about the request.
Okta also accepts only `access_token` and `id_token` subject token types: declaring the token
as `urn:ietf:params:oauth:token-type:jwt` returns `'subject_token_type' is invalid or not
supported`.

So the exchange works, but only for tokens Okta issued. Run Step 0 against your own tenant to
confirm the same holds there, particularly if you have inbound federation configured, which
is the one condition that might change the answer.

- **If it works** run the flow exactly as drawn
- **If it does not**, which is the expected result, use the appendix in `WORKSHOP.md`: your IdP
  issues the subject token and agentgateway's built-in STS performs the exchange

---

## Step 0a — Confirm the grant is enabled (do this first)

**Do not use the authorization server's discovery metadata for this.** Okta does not list
`urn:ietf:params:oauth:grant-type:token-exchange` in `grant_types_supported` even on a tenant
where the exchange works. Measured: a tenant that performs the exchange successfully still
omits it from discovery. The grant is enabled per application and per access policy rule, not
advertised at the server.

The three real gates, all required:

1. **API Access Management** — Security → API shows an **Authorization Servers** tab
2. **The grant on the service app** — Applications → your API Services app → General → Edit →
   Grant type → Advanced → **Token Exchange**
3. **The grant in the access policy rule** — Security → API → Authorization Servers → your
   server → Access Policies → rule → Edit → **Grant type is** → Token Exchange

Also untick **Require Demonstrating Proof of Possession (DPoP)** on the service app unless you
intend to send DPoP proofs; new API Services apps may have it on, and the exchange fails with
`invalid_dpop_proof`.

With all three in place, Step 0 below is the real test.

## Step 0 — Optional: confirm the cross-IdP result on your tenant

**Expected result: refused.** Measured with a control on a live Okta tenant, an Okta-issued
subject token is exchanged successfully while one issued by a different IdP comes back
`invalid_request: 'subject_token' is invalid`, rejected before policy evaluation.

Two minutes, and only worth running if you have **inbound federation** configured, which is
the one condition that might change the answer for you. It needs A3 and A4 in place.

```bash
# SUBJECT_TOKEN = a JWT issued by Keycloak/Auth0 for a test user
curl -s -X POST "https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}/v1/token" \
  -u "${OKTA_CLIENT_ID}:${OKTA_CLIENT_SECRET}" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="${SUBJECT_TOKEN}" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience="api://mcp-demo" \
  -d scope="mcp.access" | jq .
```

Send us whatever comes back. If it succeeds, Okta can be the exchange point for cross-IdP
flows on your tenant and Part 3 widens accordingly.

---

## Part A — Okta configuration

### A1. Custom Authorization Server

**Security → API → Authorization Servers → Add Authorization Server**

| Field | Value |
|---|---|
| Name | `mcp-demo` |
| Audience | `api://mcp-demo` |
| Description | RFC 8693 token exchange for agentgateway |

Copy the **Issuer URI**. It looks like `https://<your-domain>.okta.com/oauth2/aus<XYZ>`.
You need the `aus<XYZ>` segment.

> **Licensing gate:** custom authorization servers require the **API Access Management**
> feature. If **Security → API** has no **Authorization Servers** tab, your Okta edition does
> not include it.
>
> **The tab is necessary but not sufficient.** It gives you custom authorization servers; the
> token-exchange grant still has to be enabled on the service app (A4) and in the access
> policy rule (A3) before any exchange will run. See Step 0a.

### A2. Scope

On that authorization server, **Scopes → Add Scope**

| Field | Value |
|---|---|
| Name | `mcp.access` |
| Default scope | yes |
| Include in public metadata | yes |

### A3. Enable the Token Exchange grant

> **Only needed for Part 3**, where Okta performs the exchange. Skip A3 and A4 if the built-in
> STS is doing the exchange, which is required for any flow crossing identity providers.

**Access Policies → Add Policy** (or edit Default), assigned to all clients, then **Add Rule**:

| Field | Value |
|---|---|
| Rule name | `token-exchange-allowed` |
| Grant type is | **Token Exchange** and **Client Credentials** |
| User is | the test user from A5, or any user |
| Scopes | `mcp.access` |

> If **Token Exchange** does not appear as a grant option, that is the API Access Management
> gate from A1.

### A4. Exchange client

> **Only needed for Part 3.** See the note on A3.

**Applications → Create App Integration → OIDC → API Services**

| Field | Value |
|---|---|
| App name | `agw-token-exchange-client` |
| Client authentication | Client secret |
| Grant types | **Client Credentials**, **Token Exchange** (under Advanced) |
| Require DPoP | **off** — new API Services apps may default to on, and the exchange then fails with `invalid_dpop_proof` |

Assign it to the A3 access policy rule. Please send us the Client ID and Client Secret.

### A5. Test subject client and test user

**Applications → Create App Integration → OIDC → Native Application**

| Field | Value |
|---|---|
| App name | `agw-test-subject-client` |
| Grant types | **Authorization Code**, **Resource Owner Password** |
| Sign-in redirect URI | `http://localhost:8080/callback` (unused, required field) |

Native apps are public, so there is no secret. Please send us the Client ID.

Then **Directory → People → Add Person**:

| Field | Value |
|---|---|
| First / last name, email | anything |
| Password | set a known one, e.g. `Pass123!` |
| Activation | **Activate immediately. Do not require email verification, and do not leave the user needing a password reset on first login.** |

Assign the user to `agw-test-subject-client`, and to the A3 access policy rule if you scoped
that rule to specific users. **Do not use a real employee account.**

> **This is the step that most often costs a session.** A user left in a pending or
> password-reset state authenticates fine in a browser but is refused for the direct grant
> the workshop uses, and the error does not say so clearly. Verify with A7 below.

### A6. Confirm the test user can actually mint a token

Thirty seconds, and it catches the A5 problem up front rather than mid-workshop.
Uses the values you are about to send us in A7:

```bash
curl -s -X POST "https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}/v1/token" \
  -d grant_type=password \
  -d client_id="${OKTA_TEST_CLIENT_ID}" \
  -d username="${OKTA_TEST_USERNAME}" \
  -d password="${OKTA_TEST_PASSWORD}" \
  -d scope="openid ${OKTA_SCOPE}" | jq 'keys'
```

Expect a response containing `access_token`. If you get `invalid_grant`, the account is not
fully activated (see A5) or the direct-grant flow is not enabled on
`agw-test-subject-client`.

### A7. Values to send back

```
OKTA_DOMAIN=              # e.g. example.okta.com
OKTA_AS_ID=               # the aus<XYZ> from A1
OKTA_CLIENT_ID=           # from A4
OKTA_CLIENT_SECRET=       # from A4  <- send over your preferred secure channel
OKTA_TEST_CLIENT_ID=      # from A5
OKTA_TEST_USERNAME=       # from A5
OKTA_TEST_PASSWORD=       # from A5  <- same
OKTA_AUDIENCE=api://mcp-demo
OKTA_SCOPE=mcp.access
```

Please send secrets through the shared Slack channel or whatever your team prefers, not
email.

---

## Part B — Auth0, if you want it in scope

Auth0 can stand in for the second IdP instead of a second Keycloak realm. For that you need
an Auth0 tenant with:

- An **API** registered with identifier `api://mcp-demo` (or tell us yours)
- An **Application** (Machine to Machine) authorized against that API, and its client ID and secret
- A test user with a known password
- Confirmation of whether your Auth0 tenant has **token exchange** enabled

Otherwise Okta plus two Keycloak realms gives the same multi-IdP proof with less setup.

---

## Part C — What the lab deploys

Nothing to configure. Listed so you know what is stood up:

- Enterprise agentgateway with the STS enabled
- Keycloak (two realms, to stand in for two IdPs)
- A small translator service between the gateway and Okta. **Why it exists:** the gateway
  speaks RFC 8693 directly, but it does not authenticate to Okta with a client secret or add
  Okta's `audience` and `scope` parameters. The translator adds those. It is about sixty lines and we provide it
- Two MCP servers and a backing API, to prove per-server authorization and audience binding

### Confirm your Agentgateway version

```bash
helm -n agentgateway-system get metadata enterprise-agentgateway | awk '/^VERSION:/{print $2}'
```

The workshop is written against **v2026.9.0**, which is what `00-platform.sh` installs.
`preserveToken` in the JWT policy needs v2026.9.0 or later, so on an older build one manifest
needs a one-line change.

## What the workshop proves

| Capability | What is demonstrated |
|---|---|
| Agent identity | Every hop authorizes on a JWT claim; the agent has its own identity separate from the user |
| Token exchange | An OBO token carrying **subject = user** and **actor = agent**, distinctly inspectable |
| Claim mapping | Which claims survive the exchange, and which do not. See the open question below |
| Consent across multiple MCP servers | One consent per capability grant rather than per server |

### One behaviour worth examining

The STS mints a clean delegated token rather than forwarding a copy of your IdP's token, so
IdP-specific claims including `groups` are not carried over. This is documented, deliberate
behaviour, and it means downstream authorization keys on `sub` and `act`. Part 6 covers the
reasoning and the one thing worth confirming: whether any existing service expects a group
claim inside the token.
