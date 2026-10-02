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

It may still work in your tenant if you have inbound federation configured. **Step 0 below is
a single curl that answers it.** Run it before configuring anything else:

- **If it works** we run the flow exactly as drawn
- **If it does not** run the same proof with Okta issuing the subject token, per the appendix
  in `WORKSHOP.md`, and record the cross-IdP limitation as a finding

Either way the outcomes are the same. Only the exchange point differs.

---

## Step 0a — The ten-second check (do this first)

Before configuring anything, ask the authorization server what grants it supports. No auth,
no clicking, and it answers whether the rest of Part A is worth doing:

```bash
OKTA_DOMAIN=<your-domain>.okta.com
OKTA_AS_ID=default          # or your custom aus... id once it exists

curl -s "https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}/.well-known/oauth-authorization-server" \
  | jq '.grant_types_supported'
```

Look for `urn:ietf:params:oauth:grant-type:token-exchange`.

- **Present** — Part 3 can run as drawn, with Okta performing the exchange. Continue with A1
  through A5.
- **Absent** — Okta cannot be the exchange point on this tenant, whatever the access policy
  says. Skip A3 and A4 entirely and use the appendix path in `WORKSHOP.md`: Okta issues the
  subject token, agentgateway's STS performs the exchange. That needs A1, A2 and A5 only.

Either way the delegation outcomes are the same. Only the exchange point differs.

---

## Step 0 — The five-minute test

Needs: a user token from Keycloak (or Auth0), and the Okta custom authorization server from
Part A below.

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

Send us whatever comes back, success or error. An `invalid_grant` naming the issuer is a
perfectly useful answer.

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
> **The tab is necessary but not sufficient.** Measured on a live Okta tenant that has API
> Access Management and a working custom authorization server: the token-exchange grant was
> still absent org-wide, and did not appear as an option in A3. Run the one-line metadata
> check below before doing any of the configuration in this document.

### A2. Scope

On that authorization server, **Scopes → Add Scope**

| Field | Value |
|---|---|
| Name | `mcp.access` |
| Default scope | yes |
| Include in public metadata | yes |

### A3. Enable the Token Exchange grant

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

**Applications → Create App Integration → OIDC → API Services**

| Field | Value |
|---|---|
| App name | `agw-token-exchange-client` |
| Client authentication | Client secret |
| Grant types | **Client Credentials**, **Token Exchange** |

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
