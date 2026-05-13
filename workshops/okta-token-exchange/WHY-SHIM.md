# Why this workshop needs a shim

> TL;DR: AGW's data plane today **cannot authenticate to Okta's token endpoint** and cannot add the `audience`/`scope` parameters Okta requires. The shim is ~80 lines of Python that fills the gap. It's not architectural choice; it's a hard constraint in the current AGW source.

## What we want

```
client ─── Okta user JWT ──▶ AGW ─── RFC 8693 ──▶ Okta /v1/token ─── decorated JWT ──▶ MCP
```

AGW receives the user's Okta JWT in `Authorization`, sends it to Okta for token exchange (RFC 8693), gets back a token decorated with `aud=api://snowflake-mcp` + `scope=snowflake.access`, forwards that decorated token to MCP.

## What AGW actually sends to `STS_URI`

From `agentgateway-enterprise/crates/agentgateway/src/proxy/token_exchange.rs:383-388` — the literal Rust source:

```rust
let form_pairs = [
    ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
    ("subject_token", incoming_user_jwt),
    ("subject_token_type", TOKEN_TYPE_JWT),
    ("resource", upstream_service_name),
];
```

And the Authorization header, from `crates/agentgateway/src/control/mod.rs:171-177`:

```rust
fn to_bearer(token: &[u8]) -> Vec<u8> {
    const BEARER_PREFIX: &[u8] = b"Bearer ";
    let mut bearer: Vec<u8> = Vec::with_capacity(BEARER_PREFIX.len() + token.len());
    bearer.extend_from_slice(BEARER_PREFIX);
    bearer.extend_from_slice(token);
    bearer
}
```

So the request AGW emits to `STS_URI` is:

```
POST <STS_URI>
Authorization: Bearer <bytes from file at $STS_AUTH_TOKEN>
Content-Type: application/x-www-form-urlencoded
User-Agent: agentgateway
Accept: application/json

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<incoming user JWT>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=<upstream Service name>
```

## What Okta `/v1/token` requires for token-exchange grant

Per [Okta's docs](https://developer.okta.com/docs/guides/set-up-token-exchange/main/):

```
POST https://{yourOktaDomain}/oauth2/{authServerId}/v1/token
Authorization: Basic <base64(client_id:client_secret)>      ← confidential client required
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user JWT>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=<authorization server audience>                    ← required
&scope=<requested scopes>                                    ← required
```

## Three gaps, side-by-side

| Field | AGW sends | Okta needs | Hardcoded? |
|---|---|---|---|
| Authorization header | `Bearer <file-bytes>` | `Basic <base64(id:secret)>` | ✅ `to_bearer()` always prepends `Bearer ` |
| Audience parameter | `resource=<svc-name>` | `audience=<aud value>` | ✅ Field name is literal in `form_pairs` |
| Scope parameter | (not sent) | `scope=<scopes>` | ✅ No code path adds it |

The hardcoding matters: there is **no environment variable, CRD field, Helm value, or annotation** that toggles any of these. Adding them requires modifying Rust source code in `agentgateway-enterprise`.

## Why "just unset STS_AUTH_TOKEN" doesn't help

`AuthSource::None` makes AGW skip the Authorization header entirely. So you'd get:

```
POST <STS_URI>
Content-Type: application/x-www-form-urlencoded

grant_type=...&subject_token=...&subject_token_type=...&resource=...
```

Okta refuses immediately with `invalid_client` — Okta's token-exchange grant requires authenticated clients. Public clients with `token_endpoint_auth_method=none` are not supported for this grant. Even if they were, AGW doesn't send `client_id` in the form body, so Okta has nothing to identify the caller.

## Why "embed credentials in STS_URI" doesn't help

You might try `STS_URI=https://id:secret@yourorg.okta.com/...`. The Rust `http::Uri` parser accepts this, but hyper/reqwest **don't auto-convert userinfo to a Basic auth header** (intentional, for security). The credentials are dropped at connect time. Okta sees no client auth.

## What the shim does

```
AGW sends ────▶ shim:9000 ────▶ Okta /v1/token
```

The shim's only job:

1. **Adds `Authorization: Basic <base64(id:secret)>`** — Okta now accepts the client
2. **Adds `audience=api://snowflake-mcp`** — Okta mints a token with that audience claim
3. **Adds `scope=snowflake.access`** — Okta's access policy can match and grants the scope
4. Forwards the response verbatim — AGW takes the new token and puts it in `Authorization` upstream

Everything else passes through:
- `grant_type` from AGW: `urn:ietf:params:oauth:grant-type:token-exchange` ✓
- `subject_token` from AGW: the user's Okta JWT ✓
- `subject_token_type` from AGW: `urn:ietf:params:oauth:token-type:jwt` — Okta accepts this (close enough to `access_token`)

The Python source is in [`k8s/10-shim.yaml`](./k8s/10-shim.yaml) (about 80 LOC). Worth reading — it's literal RFC 8693 forwarding plus three header/form-field additions.

## What would eliminate the shim

A first-class `OktaExchanger` in the **controller** (Go), mirroring the existing `EntraExchanger`:

- `agentgateway-enterprise/ent-controller/internal/tokenexchange/exchange/okta.go` — implementing the `TokenExchanger` interface defined in `exchanger.go:21`. Same shape as `entra.go` (~150 LOC), different grant type + Basic auth + audience/scope from CRD fields.
- `agentgateway-enterprise/ent-controller/api/v1alpha1/.../tokenexchange_types.go` — add an `Okta *OktaTokenExchangeConfig` peer of `Entra`.
- `agentgateway-enterprise/ent-controller/internal/tokenexchange/exchange/provider_index.go:170` — branch on `te.Okta != nil`.

With that change, the CRD looks like:

```yaml
backend:
  tokenExchange:
    mode: ExchangeOnly
    okta:
      issuer: https://integrator-9380202.okta.com/oauth2/aus<XYZ>
      clientId: <id>
      clientSecretRef: { name: okta-client, key: client_secret }
      audience: api://snowflake-mcp
      scope: snowflake.access
```

No shim, no Rust data-plane changes, no `STS_URI` env vars. The controller does the exchange directly and the data plane fetches the result via the existing wire-stream.

This is upstream work for the Solo team. **This workshop deliberately does not require it** — the shim achieves the same end-state with zero source changes, which is what makes it usable for a prospect proof-of-concept today.

## Historical note: the Snowflake workshop tried this and pivoted

The planning doc at `solo-misc-workshops/Snowflake-Token-Exchange-Workshop/docs/superpowers/plans/2026-04-09-snowflake-token-exchange-workshop.md:494-497` proposed these env vars:

```yaml
- name: STS_TOKEN_EXCHANGE_CLIENT_ID
  value: "agw-exchange"
- name: STS_TOKEN_EXCHANGE_CLIENT_SECRET
  value: "agw-exchange-secret"
```

…which would have been the exact fix for the Basic-auth gap. But:

1. These env vars **don't exist in the AGW Rust source** — `grep STS_` returns only `STS_URI` and `STS_AUTH_TOKEN`.
2. The shipped `k8s/agw.yaml` removed the token-exchange flow entirely. The README states: *"The previous tokenExchange flow is gone; identity is now propagated via the `x-user-id` header set by extauth."*
3. `external-sts/` directory is marked *"Unused in this variant. Left in place from the original token-exchange flow."*

Translation: the workshop tried what this prospect is asking for, hit these exact gaps, and pivoted to introspection + extauth instead. The shim in this workshop is the *other* solution path that wasn't taken.
