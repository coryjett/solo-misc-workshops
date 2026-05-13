# Troubleshooting

Error → cause → fix.

## Okta errors (shim forwards them verbatim, look in `kubectl logs deploy/okta-shim`)

### `{"error":"invalid_client", ...}`

Okta rejected the shim's Basic auth.

- `OKTA_CLIENT_ID` or `OKTA_CLIENT_SECRET` wrong → re-export from the Okta app `agw-token-exchange-client`
- That app not assigned to the access policy rule (Part 1.3) → Okta → Authorization Servers → your AS → Access Policies → your rule → Assign client
- App doesn't have Token Exchange grant enabled → Okta → app → General → Client Credentials section → "Token Exchange" checkbox

### `{"error":"invalid_grant", ...}`

Okta refused to perform the exchange itself.

- Token Exchange grant not in the access policy rule → fix the rule (Part 1.3) to allow `Token Exchange` grant
- The subject token is for a different Authorization Server than the one you're exchanging at → subject token must come from the same AS (the test setup uses Resource Owner Password against your AS, which is correct)
- Subject token expired → re-run `check.sh` (it fetches a fresh one)

### `{"error":"invalid_scope", ...}`

- Scope `snowflake.access` not defined on the AS → Part 1.2
- Scope not granted to the exchange client → Okta → AS → Access Policies → rule → Scopes → include `snowflake.access`

### `{"error":"access_denied", ...}`

- Test user not assigned to the access policy rule (if rule scope was narrowed to specific users) → assign user, or change rule to "Any user"
- Test user not assigned to the subject-token client app → Okta → app → Assignments

### `{"error":"unsupported_grant_type"}`

- The exchange client app doesn't allow `Token Exchange` grant → Okta → app → General → enable grant
- The AS doesn't have Token Exchange enabled in any policy → enable it

## AGW errors

### `401` on every request to AGW

`validate-inbound-okta-jwt` policy is rejecting the subject token.

- Subject token's `aud` claim doesn't match policy audiences → check policy `audiences` in `k8s/30-agw.yaml` (defaults: `${OKTA_AUDIENCE}`, `${OKTA_TEST_CLIENT_ID}`, `api://default`)
- JWKS proxy can't reach Okta → `kubectl logs deploy/okta-jwks-proxy` → check resolver / DNS / network egress
- Token's `iss` claim doesn't match the policy's issuer → make sure `OKTA_DOMAIN` and `OKTA_AS_ID` are right

### `500` / "token exchange failed" in AGW logs

- Shim not reachable → `kubectl get svc okta-shim` and `kubectl logs deploy/okta-shim` → verify pod is Ready
- AGW pod can't resolve shim DNS → cross-namespace `Service` DNS should just work; check `kubectl exec` on the AGW pod and `getent hosts okta-shim.okta-tx.svc.cluster.local`

### MCP backend's `whoami` echoes the **subject token**, not the decorated one

The exchange policy didn't fire.

- The `tokenExchange` policy must target the `AgentgatewayBackend`, not the HTTPRoute — verify `targetRefs` in `exchange-at-okta-via-shim` (k8s/30-agw.yaml)
- `STS_URI` env var not set on the data plane → check `kubectl describe gateway workshop-gateway` then look at the resulting deployment's env

## Local issues

### `OKTA_CLIENT_ID not set` from `setup.sh`

Re-export the env vars listed in `workshop-guide.md` Part 1.7. They must be set in the same shell that runs `setup.sh` (they're not persisted).

### `helm upgrade` fails on AGW chart version

The workshop pins `v2.2.0`. If you have a newer cluster requiring a newer chart, edit `setup.sh` to bump `--version`. The relevant API shapes (`tokenExchange.*` Helm values, `EnterpriseAgentgatewayParameters.spec.env`, `EnterpriseAgentgatewayPolicy.backend.tokenExchange.mode`) have been stable since v2.2.

### Test user password rejected (`invalid_grant` with `error_description="The credentials provided were invalid."`)

- Password is wrong, or
- User account isn't activated, or
- Password policy requires a change at next login (Okta admin → user → "Reset password" with "user must change at next login" UNchecked)

## "Why don't I see audience injection happening?"

Watch the shim's stdout while you call AGW:

```bash
kubectl -n okta-tx logs -f deploy/okta-shim
```

You should see, per request:

```
[shim] inbound from AGW: path=/token grant_type=urn:ietf:params:oauth:grant-type:token-exchange
[shim] -> Okta /token  audience=api://snowflake-mcp scope=snowflake.access
[shim] <- Okta status=200 body[:120]={"token_type":"Bearer","expires_in":3600,"access_token":"eyJ..."}
```

If you only see the first line and not the second, the request body parse failed — likely AGW sent something unexpected. `kubectl exec` into the shim pod and run `python3 -c "import urllib.parse; print(urllib.parse.parse_qs('<paste body>'))"` to debug.

If you see the second line but a 4xx in the third, the error text is Okta's verbatim — match it against the Okta errors section above.
