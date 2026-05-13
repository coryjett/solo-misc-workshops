# Workshop Guide — Okta Token Exchange via AGW

Step-by-step. Part 1 is Okta admin clicks; Part 2 is `kubectl apply`; Part 3 is testing. Read [`WHY-SHIM.md`](./WHY-SHIM.md) first if you haven't.

---

## Part 1 — Configure Okta

Your tenant's runtime domain drops `-admin` from the admin URL:
`integrator-9380202-admin.okta.com` → `integrator-9380202.okta.com`.

### 1.1 Create a Custom Authorization Server

Okta admin → **Security → API → Authorization Servers → Add Authorization Server**

| Field | Value |
|---|---|
| Name | `snowflake-mcp` |
| Audience | `api://snowflake-mcp` |
| Description | RFC 8693 token exchange workshop |

After save, copy the **Issuer URI** (e.g. `https://integrator-9380202.okta.com/oauth2/aus<XYZ>`). The `aus<XYZ>` segment goes in `OKTA_AS_ID`.

### 1.2 Add a scope

That auth server → **Scopes → Add Scope**

| Field | Value |
|---|---|
| Name | `snowflake.access` |
| Description | Access to Snowflake MCP |
| Default scope | ✅ |
| Include in public metadata | ✅ |

### 1.3 Enable Token Exchange in the access policy

That auth server → **Access Policies → Add Policy** (or edit Default)

- Name: `allow-token-exchange`
- Assign to: All clients (or specifically the client from 1.4)

**Add Rule**:

| Field | Value |
|---|---|
| Rule name | `token-exchange-allowed` |
| Grant type is | ✅ **Token Exchange**, ✅ Client Credentials (for testing) |
| User is | Any user (or pick the test user from 1.5) |
| Scopes | `snowflake.access` |

> If "Token Exchange" isn't a grant option, your Okta tenant doesn't have API Access Management. The **integrator** SKU has it.

### 1.4 Register the exchange client (credentials the shim will present)

**Applications → Applications → Create App Integration → OIDC – OpenID Connect → API Services**

| Field | Value |
|---|---|
| App name | `agw-token-exchange-client` |
| Client authentication | Client secret |
| Allowed grant types | ✅ Client Credentials, ✅ Token Exchange |

Save and copy:
- `Client ID` → `OKTA_CLIENT_ID`
- `Client Secret` → `OKTA_CLIENT_SECRET`

Back at **Authorization Server → Access Policies → your rule** make sure this client is assigned to the policy.

### 1.5 Register a public client for testing (to obtain a subject token)

**Applications → Create App Integration → OIDC → Native Application**

| Field | Value |
|---|---|
| App name | `agw-test-subject-client` |
| Allowed grant types | ✅ Authorization Code, ✅ Resource Owner Password (Direct Auth) |
| Sign-in redirect URI | `http://localhost:8080/callback` (unused, required by Okta) |
| Controlled access | Allow everyone or assign the test user |

Copy `Client ID` → `OKTA_TEST_CLIENT_ID`.

### 1.6 Create a test user

**Directory → People → Add Person**

- First/last name + email
- Set a known password (e.g. `Pass123!`)
- Activate immediately, no email verification

Assign the user to `agw-test-subject-client` (and to the access policy rule from 1.3 if you scoped it).

### 1.7 Export the variables

```bash
export OKTA_DOMAIN="integrator-9380202.okta.com"
export OKTA_AS_ID="aus<XYZ>"                              # from 1.1
export OKTA_CLIENT_ID="<from 1.4>"
export OKTA_CLIENT_SECRET="<from 1.4>"
export OKTA_TEST_CLIENT_ID="<from 1.5>"
export OKTA_TEST_USERNAME="<test user email>"
export OKTA_TEST_PASSWORD="Pass123!"
export OKTA_AUDIENCE="api://snowflake-mcp"
export OKTA_SCOPE="snowflake.access"
export AGENTGATEWAY_LICENSE_KEY="<your license>"
```

---

## Part 2 — Deploy

### 2.1 Run setup

```bash
./setup.sh
```

This script:
1. Creates the `okta-tx` namespace
2. Creates a Secret with `OKTA_CLIENT_ID` / `OKTA_CLIENT_SECRET`
3. Applies the shim (Python translator) Deployment + Service
4. Applies the MCP-echo Deployment + Service (echoes inbound Authorization)
5. Installs AGW Enterprise with `tokenExchange.enabled=true` and Okta JWKS as the subject validator
6. Applies Gateway / Backend / HTTPRoute / EnterpriseAgentgatewayPolicy
7. Substitutes your env vars into the manifest templates

Watch for `condition=Available` on all deployments.

### 2.2 What got applied

```bash
kubectl -n okta-tx get gw,httproute,agentgatewaybackend,enterpriseagentgatewaypolicy
kubectl -n okta-tx get deploy,svc,secret
```

You should see:
- `gateway/workshop-gateway` (status: Ready)
- `httproute/mcp-route`
- `agentgatewaybackend/mcp-backend`
- `enterpriseagentgatewaypolicy/validate-inbound-okta-jwt` (mcp authentication, attaches to HTTPRoute)
- `enterpriseagentgatewaypolicy/exchange-at-okta-via-shim` (`tokenExchange.mode: ExchangeOnly`, attaches to the AgentgatewayBackend)
- `deploy/okta-shim` (the translator)
- `deploy/mcp-echo` (the backend)
- `secret/okta-client` (client_id + client_secret)

---

## Part 3 — Test

### 3.1 Run the check script

```bash
./check.sh
```

The script:
1. Fetches a subject token from Okta via Resource Owner Password (`OKTA_TEST_USERNAME` + `OKTA_TEST_PASSWORD`)
2. Decodes the subject token and prints its claims
3. Port-forwards the workshop Gateway
4. Calls the MCP backend through AGW with `Authorization: Bearer $SUBJECT_TOKEN`
5. Decodes the Authorization the **backend** received and prints its claims

Successful output looks like:

```
=== Subject token (from Okta direct) ===
  iss: https://integrator-9380202.okta.com/oauth2/aus<XYZ>
  aud: api://default
  scp: ["openid","snowflake.access"]
  sub: <user id>

=== AGW called shim called Okta ===
Shim logs:
  [shim] -> Okta /token  audience=api://snowflake-mcp  scope=snowflake.access
  [shim] <- Okta status=200

=== Token the MCP backend saw ===
  iss: https://integrator-9380202.okta.com/oauth2/aus<XYZ>
  aud: api://snowflake-mcp                   ← decorated by Okta during exchange
  scp: ["snowflake.access"]                  ← scope from the exchange request
  sub: <same user id>
```

The before/after `aud` and `scp` is the proof — Okta minted a new token via RFC 8693, decorated for Snowflake.

### 3.2 Manually walk through the flow

```bash
# Get subject token
SUBJECT_TOKEN=$(curl -sS -X POST "https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=${OKTA_TEST_USERNAME}" \
  -d "password=${OKTA_TEST_PASSWORD}" \
  -d "scope=openid offline_access ${OKTA_SCOPE}" \
  -d "client_id=${OKTA_TEST_CLIENT_ID}" \
  | jq -r '.access_token')

# Inspect it
echo "$SUBJECT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Port-forward
kubectl -n okta-tx port-forward svc/workshop-gateway 8080:80 &

# Call MCP through AGW
curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer ${SUBJECT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}' | jq .

curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer ${SUBJECT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"whoami","arguments":{}}}' \
  | jq -r '.result.content[0].text' | jq .
```

### 3.3 Watch the shim do its job

```bash
kubectl -n okta-tx logs -f deploy/okta-shim
```

Each request logs:
- The grant type and subject token type AGW sent (verbatim — this is the data plane's request to STS_URI)
- The Basic auth + audience + scope the shim added
- Okta's status code and (if 4xx) the error body

This is the workshop's main learning moment — you see what AGW alone would have sent (which Okta rejects) and what the shim adds to make it work.

---

## Part 4 — Cleanup

```bash
./cleanup.sh
```

Removes the namespace and AGW chart. The Okta-side resources stay — delete them via the admin console if you want to fully reset.
