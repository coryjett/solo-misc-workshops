# Token Exchange Workshop — Agent Identity and Delegation

Solo.io

Agent identity, token exchange, claim mapping, and consent across multiple MCP servers.

**Steps 0 and 3 require a real Okta tenant with the token-exchange grant.** Parts 1, 2 and 4
run entirely on in-cluster Keycloak and agentgateway's built-in STS. The appendix covers using
a real external IdP as the subject issuer when it cannot perform the exchange itself.

Work through **`PRECONFIG.md`** first, starting with Step 0a, which decides whether the Okta
parts can run at all on your tenant.

**Target version: Enterprise Agentgateway `v2026.9.0`**, which is what `00-platform.sh`
installs. Everything here is written against it. Confirm your version first:

```bash
helm -n agentgateway-system get metadata enterprise-agentgateway | awk '/^VERSION:/{print $2}'
```

If it reports something else, adjust accordingly. Two things are version-sensitive: `preserveToken` in the JWT policy requires **v2026.9.0 or later** (on
v2026.8.x and earlier the API server rejects it as an unknown field), and the built-in STS
configuration shape should be confirmed against whatever you are running.

For reference, the current release at time of writing is **v2026.9.3**. Upgrading is not
required.

---

## What we will build

```
                      ┌──────────────┐
  user ──(1) auth────▶│   Keycloak   │   realm idp-a  (identity provider 1)
                      │   two realms │   realm idp-b  (identity provider 2)
                      └──────┬───────┘
                             │ user JWT
                             ▼
                   ┌────────────────────┐
                   │   agentgateway     │ (2) validate user JWT, authorize user→agent
                   │                    │ (3) exchange for an on-behalf-of token
                   │   STS :7777        │─────────────┐
                   └─────────┬──────────┘             │ RFC 8693
                             │                        ▼
                             │                 ┌─────────────┐
                             │                 │ translator  │──▶ Okta /v1/token
                             │                 │    STS      │    (adds client auth,
                             │                 └─────────────┘     audience, scope)
                             │ OBO token: sub=user, act=agent
                             ▼
                   ┌──────────────────┐
                   │  mcp-a    mcp-b  │ (4) per-server authorization, audience binding
                   └────────┬─────────┘
                            ▼
                      ┌──────────┐
                      │   API    │ (5) accepts only STS-issued delegated tokens
                      └──────────┘
```

The flow: the user authenticates at your
identity provider, the gateway exchanges that token for one carrying **`Subject: User`** and
**`Actor: Agent`**, and downstream services accept only the exchanged token.

### Two exchange paths

| Path | Exchange performed by | Status |
|---|---|---|
| **A** | agentgateway's built-in STS | Validated end to end on controller v2026.9.0 with Keycloak 26 |
| **B** | Your Okta authorization server, via a translator | Validated against a live Okta tenant using an Okta-issued subject token |

We build both. Path A establishes the delegation model quickly; Path B puts your own
authorization server at the centre of it.

### One thing to confirm first

On the 09-29 call we sketched Keycloak issuing the user token and **Okta** performing the
exchange. Okta's documentation describes token exchange "within a single authorization server
or between other authorization servers under the same Okta tenant." A subject token issued by
a **different** identity provider is not described either way.

Worth being precise about what this does and does not affect. **It only applies when Okta is
the exchange point.** If the exchange is performed by agentgateway's own STS, a token issued
by a different provider is a configuration matter: the STS `subjectValidator` validates
against any JWKS endpoint it can reach, so Keycloak, Auth0, Okta and Entra are all acceptable
issuers.

So there are two viable architectures, and the choice is yours rather than a constraint:

- **Exchange at the gateway's STS** — multiple providers is configuration, available today
- **Exchange at your Okta authorization server** — puts your own authorization server at the
  centre of it, which security reviews often prefer, though it only exchanges tokens it
  issued
  Keycloak-issued token

**This is already settled, measured with a control against a live Okta tenant.** An
Okta-issued subject token is exchanged successfully; a subject token from a different IdP is
refused with `invalid_request: 'subject_token' is invalid`, before policy evaluation. So Okta
can be the exchange point only where Okta also issued the inbound token. Anything that crosses
identity providers has to be exchanged by the built-in STS. `PRECONFIG.md` keeps the one-curl
confirmation if you want to re-run it on your own tenant.

---

## Part 1 — The delegation chain (20 min)

Builds on the end-to-end workshop from the previous session. Platform, identity provider,
and per-hop authorization.

```bash
export LICENSE_KEY=<solo-enterprise-license-key>
./00-platform.sh                 # Gateway API CRDs, Enterprise Agentgateway, test client
kubectl apply -f 00-keycloak.yaml
kubectl exec -i -n keycloak deploy/keycloak -- bash < 00-setup-realm.sh   # realm, users, groups, may_act
```

```bash
kubectl apply -f 01-agent-authz.yaml   # user -> agent, JWT + group-based CEL authorization
kubectl apply -f 02-mcp-authz.yaml     # agent -> MCP, per-server authorization

# The gateway is reached by Service DNS from inside the cluster, so no LoadBalancer or
# port-forward is needed anywhere in this workshop.
export GW=e2e-gw.agent-identity.svc.cluster.local:8080
```

Mint the user tokens. Keycloak is in-cluster, so these run from the test pod. `mint` is reused
in Parts 2 and 4, so define it once:

```bash
mint() {   # mint <username> [realm]
  kubectl exec -n wp-a deploy/sleep -- curl -s -X POST \
    "http://keycloak.keycloak.svc.cluster.local:8080/realms/${2:-demo}/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=demo-client -d client_secret=demo-secret \
    -d username="$1" -d password=pw \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"
}

export ALICE_JWT=$(mint alice)
export BOB_JWT=$(mint bob)
export USER_JWT=$ALICE_JWT     # Parts 2 and 6 refer to the same token by this name
```

Verify:

```bash
# alice is in the permitted group, bob is not. The route path is /agent-x, not /agent.
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'alice: %{http_code}\n' \
  -H "Authorization: Bearer $ALICE_JWT" http://$GW/agent-x
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'bob:   %{http_code}\n' \
  -H "Authorization: Bearer $BOB_JWT"   http://$GW/agent-x
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'none:  %{http_code}\n' \
  http://$GW/agent-x
```

Expected: `alice: 200`, `bob: 403`, `none: 401`.

The authorization decision is made on a claim inside the signed token, not on a header the
caller supplied. This addresses the header-spoofing concern at this hop.

---

## Part 2 — Exchange for a delegated token (20 min)

Enable the built-in STS and perform an RFC 8693 exchange.

```bash
export ENTERPRISE_AGW_VERSION=$(helm get metadata enterprise-agentgateway \
  -n agentgateway-system | awk '/^VERSION:/ {print $2}')

helm upgrade enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version $ENTERPRISE_AGW_VERSION -n agentgateway-system --reuse-values -f sts-values.yaml
kubectl -n agentgateway-system rollout status deploy/enterprise-agentgateway --timeout=180s
```

The exchange runs from inside the agent's pod. The mounted ServiceAccount token is the
**actor**; the user JWT, which carries `may_act`, is the **subject**:

```bash
export DELEGATED_TOKEN=$(kubectl exec -n wp-a deploy/sleep -- sh -c \
  "SA=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
   curl -s -X POST http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/token \
   -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
   -d subject_token=$USER_JWT -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
   -d actor_token=\$SA -d actor_token_type=urn:ietf:params:oauth:token-type:jwt" \
  | jq -r .access_token)
```

Inspect both identities:

```bash
echo "$DELEGATED_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{sub, act, iss}'
```

```json
{
  "sub": "<alice's uuid>",
  "act": { "iss": "https://kubernetes.default.svc.cluster.local",
           "sub": "system:serviceaccount:wp-a:default" },
  "iss": "enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777"
}
```

`sub` and `act` are separately inspectable, which is what distinguishes **delegation** from
**impersonation**. A downstream service can tell who the request is
for and which agent is acting.

### Notes

- Both token types must be `urn:ietf:params:oauth:token-type:jwt`. `access_token` is rejected
- **The STS can refuse the first exchange immediately after the rollout**, returning an empty
  body while it finishes loading its validators. Observed in a clean-room run. If the first
  call comes back empty, wait a few seconds and repeat before debugging anything else
- `token uses the unknown key` does **not** always mean a stale JWKS cache. If a second JWT
  policy is attached to the same route (for example a Keycloak-issuer policy left over from
  Part 1), the gateway validates against that provider instead and every STS token fails with
  this error indefinitely. Check for competing policies before waiting on a cache refresh:
  `kubectl -n agent-identity get enterpriseagentgatewaypolicy`. Note that a policy reports
  `Accepted: True` and `Attached: True` even when it is the one being shadowed
- **`groups` does not propagate into the delegated token.** Downstream authorization keys on
  `sub` and `act`. See Part 6, which covers this directly

---

## Part 3 — Exchange at your Okta authorization server (25 min)

The gateway speaks RFC 8693 directly, but it does not authenticate to Okta with a client
secret or add Okta's `audience` and `scope` parameters. A small translator service sits
between them and supplies those. It is roughly sixty lines and we provide it.

> **Prerequisite, see Step 0a in `PRECONFIG.md`.** This part needs the token-exchange grant
> enabled on the service app and in the access policy rule. Do not judge this from the
> authorization server's discovery metadata, which omits the grant even where it works.
>
> **It also needs Okta to have issued the subject token.** Measured with a control on a live
> tenant: an Okta-issued subject token is exchanged successfully, while a Keycloak-issued one
> is refused with `invalid_request: 'subject_token' is invalid`, before policy evaluation.
> Okta exchanges only tokens it issued. If your users authenticate somewhere other than Okta,
> use the appendix instead, where the built-in STS performs the exchange.
>
> **Validation status.** Parts 1, 2, 4, 6 and the appendix were verified end to end clean-room.
> The Okta exchange itself was verified directly against a live tenant. The full Part 3 path
> through the translator was not run.

The translator is `k8s/10-shim.yaml` in the `okta-token-exchange` workshop, roughly sixty
lines of Python that adds Basic client authentication plus the `audience` and `scope`
parameters Okta requires. `WHY-SHIM.md` alongside it documents why the gateway cannot do this
itself.

```bash
kubectl create namespace token-exchange
kubectl create secret generic okta-client -n token-exchange \
  --from-literal=client_id="${OKTA_CLIENT_ID}" \
  --from-literal=client_secret="${OKTA_CLIENT_SECRET}"

# Deploy the translator, then point the gateway's STS_URI at it via
# EnterpriseAgentgatewayParameters (STS_URI / STS_AUTH_TOKEN) and restart the controller.
# See k8s/30-agw.yaml in the okta-token-exchange workshop for the parameter shape.
kubectl apply -n token-exchange -f <okta-token-exchange>/k8s/10-shim.yaml
```

Verify by inspecting the token the MCP backend actually received:

```bash
kubectl exec -n wp-a deploy/sleep -- curl -s http://$GW/mcp -H "Authorization: Bearer $USER_JWT" | jq -r .authorization \
  | cut -d' ' -f2 | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{iss, sub, aud, scp}'
```

What this establishes: `iss` is **your Okta authorization server**, `aud` is
`api://mcp-demo`, and the token reaching the MCP server is **not** the token the user
presented. The user's credential never travels past the gateway.

---

## Part 4 — Multiple identity providers (20 min)

Two Keycloak realms, `idp-a` and `idp-b`, standing in for two providers. Both accepted by
the gateway, each mapping to different entitlements.

```bash
# Both run INSIDE the Keycloak pod. 00-setup-realm.sh is hardcoded to a single realm, so the
# two-provider setup uses the parameterized variant, which is safe to re-run.
kubectl exec -i -n keycloak deploy/keycloak -- \
  env REALM=idp-a GROUP=agent-x-users USERNAME=alice bash < 00-setup-realm-multi.sh
kubectl exec -i -n keycloak deploy/keycloak -- \
  env REALM=idp-b GROUP=customers      USERNAME=carol bash < 00-setup-realm-multi.sh

# Every JWT policy on a route is a competing provider, so remove ALL the single-issuer ones,
# not just the agent route's. Leaving mcp-a-authz or mcp-b-authz attached makes every STS
# token fail with `token uses the unknown key`.
kubectl -n agent-identity delete enterpriseagentgatewaypolicy agent-x-authz mcp-a-authz mcp-b-authz
kubectl apply -f 40-multi-idp-policy.yaml
```

### 1. Issuer-based identification

```bash
export IDPA_JWT=$(mint alice idp-a)
export IDPB_JWT=$(mint carol idp-b)

kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'idp-a alice: %{http_code}\n' \
  -H "Authorization: Bearer $IDPA_JWT" http://$GW/agent-x
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'idp-b carol: %{http_code}\n' \
  -H "Authorization: Bearer $IDPB_JWT" http://$GW/agent-x
```

Expected: both `200`. The rule admits `idp-a` with `agent-x-users` **or** `idp-b` with
`customers`, so each user passes under their own provider's clause.

The security property is what happens when a provider asserts the *other* provider's group:

```bash
kubectl exec -i -n keycloak deploy/keycloak -- \
  env REALM=idp-b GROUP=agent-x-users USERNAME=mallory bash < 00-setup-realm-multi.sh
export SPOOF_JWT=$(mint mallory idp-b)

kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'idp-b + agent-x-users: %{http_code}\n' \
  -H "Authorization: Bearer $SPOOF_JWT" http://$GW/agent-x
```

Expected: `403`. Two IdPs can both mint a group called `agent-x-users`; only one of them is
your workforce directory, and the rule pins the issuer rather than trusting the group name.

### 2. Claim mapping

Claims are normalized across two providers whose tokens are not shaped identically. See Part 6
for which claims survive the exchange.

### 3. Audience binding

The STS honours an `audience` parameter, and the per-server policies require it. The exchange
in Part 2 omits it, so reuse it here with the audience set:

```bash
exchange() {   # exchange <audience>
  kubectl exec -n wp-a deploy/sleep -- sh -c \
    "SA=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
     curl -s -X POST http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/token \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     -d subject_token=$USER_JWT -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
     -d actor_token=\$SA -d actor_token_type=urn:ietf:params:oauth:token-type:jwt \
     -d audience=$1" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"
}

export MCP_A_TOKEN=$(exchange api://mcp-a)

# Confirm the audience landed
echo "$MCP_A_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{sub, aud, act}'

kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'mcp-a: %{http_code}\n' \
  -H "Authorization: Bearer $MCP_A_TOKEN" http://$GW/mcp-a
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'mcp-b: %{http_code}\n' \
  -H "Authorization: Bearer $MCP_A_TOKEN" http://$GW/mcp-b
```

Expected: `mcp-b` returns **401**, refused at the gateway on audience. `mcp-a` passes
authentication and reaches the backend, which answers `400` or `406` to a bare GET because it
wants a JSON-RPC body. The proof that auth succeeded is `jwt.sub` in the gateway log:

```bash
kubectl -n agent-identity logs deploy/e2e-gw --tail=20 | grep 'route=agent-identity/mcp-'
```

A raw user token on `mcp-a` is also refused, since `has(jwt.act)` is false on an unexchanged
token.

---

## Part 5 — Consent across multiple MCP servers (15 min)

The goal is at most one consent step per new capability grant, rather than one per server.

This uses the eager-OAuth and elicitation patterns. Standing these up requires DNS, a TLS
listener, and Postgres for OAuth state, so this part is usually a design walkthrough rather
than a hands-on exercise.

---

## Part 6 — Which claims survive the exchange (5 min)

Worth covering explicitly, because it bears on your claim-mapping criterion and because the
behaviour is deliberate rather than incidental.

The STS does **not** copy IdP-specific claims into the delegated token. `azp`, `realm_access`,
`resource_access`, `session_state`, `nonce`, `auth_time`, `acr` and custom IdP claims are not
carried over, and neither is `groups`. The delegated token is a clean JWT from the STS trust
domain carrying a small, well-defined claim set.

The design reasoning:

- **Security** — internal IdP structure is not leaked to downstream services
- **Trust boundary** — the delegated token is a new assertion from the STS, not a forwarded
  copy of your IdP's token
- **Simplicity** — downstream services trust one issuer and validate a small claim set

Nothing is dropped silently: which claims the STS mints is documented behaviour. The
practical consequence is that **downstream authorization keys on `sub` and `act`**, with group
membership resolved in the service that owns the entitlement.

Measured on v2026.9.0 with a Keycloak subject token. Dropped by the exchange: `acr`, `azp`,
`email`, `email_verified`, `family_name`, `given_name`, `groups`, `jti`, `name`,
`preferred_username`, `realm_access`, `resource_access`, `sid`, `typ`. Added: `act`, `nbf`.
Carried through: `sub`, `aud`, `scope`, `exp`, `iat`, `iss` and **`may_act`**, which is what
allows a further delegation hop.

Worth confirming for any deployment: whether an existing service depends on a group claim
arriving inside the token, and if so what the supported path is.

---

## What the session produces

Evidence, not only a working demo:

- [ ] A decoded delegated token showing `sub` and `act` distinctly
- [ ] The token received by the MCP backend, showing a different issuer and audience than the
      user's token
- [ ] A rejected cross-audience call (token for `mcp-a` refused by `mcp-b`)
- [ ] `bob: 403` and the raw-user-token rejection, as intentional-failure scenarios
- [ ] The claim-propagation behaviour from Part 6, documented

---

## Prerequisites

- **Okta configuration** per `PRECONFIG.md`, for Steps 0 and 3
- **A cluster you can install into.** `00-kind.sh` creates a local KinD cluster if needed
- **A Solo enterprise license key** for `00-platform.sh`
---

## Appendix — running with a real external IdP as the subject issuer

Verified end to end against a live Okta tenant. Use this when Okta cannot perform the
exchange itself, which is the case for any cross-IdP flow, but you still want a real
external IdP in the chain rather than
Keycloak. Okta issues the subject token; agentgateway's built-in STS performs the exchange.

**Okta needs only A1, A2 and A5** from `PRECONFIG.md`: a custom authorization server, a scope,
and a native app with a test user. No exchange client, no client secret, no A3 token-exchange
grant.

Three differences from the Keycloak path, each of which cost real time to find:

**1. The JWKS reference must be in-cluster.** `jwks.remote.backendRef` resolves to a Service,
so an external HTTPS JWKS needs a passthrough. `50-okta-agent-authz.yaml` ships a small nginx
proxy plus the JWT policy.

```bash
set -a; . /path/to/.env; set +a
envsubst < 50-okta-agent-authz.yaml | kubectl apply -f -
kubectl -n agent-identity delete enterpriseagentgatewaypolicy agent-x-authz --ignore-not-found
```

Only one JWT policy may target a route, so the Keycloak one goes.

**2. Okta emits no `groups` claim.** The Keycloak rule `'agent-x-users' in jwt.groups` does not
port. `50-okta-agent-authz.yaml` authorizes on the scope instead: `'mcp.access' in jwt.scp`.

**3. The STS requires `may_act` on the subject token.** Keycloak sets it with a hardcoded-claim
mapper; Okta custom claims do not emit nested JSON, so the exchange fails with
`subject token does not contain may_act claim`. `51-sts-values-okta.yaml` registers the Okta
JWKS as a second subject validator and sets `skipMayActClaimValidation: true` to get past it.

> Read the warning in that file before using it. Skipping the check removes the user's ability
> to constrain which actor may act for them. It is acceptable for a demo against an IdP that
> cannot mint the claim; it is not a production posture. The durable fix is an IdP that emits
> `may_act` as `{"sub": "<actor>"}`.

```bash
envsubst < 51-sts-values-okta.yaml > /tmp/sts-okta.yaml
V=$(helm get metadata enterprise-agentgateway -n agentgateway-system | awk '/^VERSION:/ {print $2}')
helm upgrade enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version $V -n agentgateway-system --reuse-values -f /tmp/sts-okta.yaml
kubectl -n agentgateway-system rollout status deploy/enterprise-agentgateway --timeout=240s
```

Then mint from Okta and run the same chain:

```bash
OKTA_JWT=$(curl -s -X POST "https://${OKTA_DOMAIN}/oauth2/${OKTA_AS_ID}/v1/token" \
  -d grant_type=password -d "client_id=${OKTA_TEST_CLIENT_ID}" \
  -d "username=${OKTA_TEST_USERNAME}" -d "password=${OKTA_TEST_PASSWORD}" \
  -d "scope=openid ${OKTA_SCOPE}" | jq -r .access_token)

kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'okta -> /agent-x: %{http_code}\n' \
  -H "Authorization: Bearer $OKTA_JWT" http://$GW/agent-x
```

Observed on a live tenant: `/agent-x` returns `200` for the Okta token and `401` for a
Keycloak token once the issuer changes. The exchange then yields `sub` = the Okta user,
`act` = `system:serviceaccount:wp-a:default`, and the audience test behaves as in Part 4:
`mcp-b` refuses with `401` while `mcp-a` authenticates, with `jwt.sub=<okta user>` in the
gateway log.
