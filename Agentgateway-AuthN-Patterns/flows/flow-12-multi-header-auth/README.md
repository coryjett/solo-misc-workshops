# Flow 12: Multi-Header Auth (Independent Mechanisms)

Validate two **independent** credentials carried in **different headers** of the same request — each by its own mechanism, with its own success/failure boundary. Two `EnterpriseAgentgatewayPolicy` objects attach to the same HTTPRoute, each pinning the credential location via `traffic.*.location.header.name`.

> **Requires AGW Enterprise `v2026.5.0-beta.1` or later** — the `traffic.jwtAuthentication.location` (and `apiKeyAuthentication.location`, `basicAuthentication.location`) field landed in PR #1555 (commit `08229837e`, 2026-04-20). Older charts (every `v2.x.x` tag including `v2.3.2`) read JWT credentials only from `Authorization: Bearer …` and reject `location` at apply time.
>
> **Docs:** [JWT Auth — token location](https://docs.solo.io/agentgateway/2.2.x/security/jwt/setup/) (covers `Authorization`-only behavior; `location` is documented inline in the API reference)
> **API:** [`AuthorizationLocation`](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#authorizationlocation) · [`JWTAuthentication`](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#jwtauthentication)

### Use cases

- **User token + workload-identity token.** Customer reaches the gateway with a Keycloak/OIDC user token in `Authorization` and an Aembit-style workload JWT in `aembitauth`; both must validate.
- **OIDC user token + service-to-service API key.** Per-user authentication plus a coarse-grained tenant key in `x-tenant-api-key`.
- **Two-issuer JWT validation.** Internal-platform token in `Authorization` plus a partner-issued token in `x-partner-token`, each with their own JWKS / `iss` / `aud`.

### How it works

1. **Client builds a request carrying two credentials in two headers**, e.g.
   ```
   Authorization: Bearer <token-A>
   aembitauth:    <token-B>
   ```
2. **Gateway proxy evaluates each policy independently.** For each `traffic.*Authentication` policy:
   - Pulls the credential from `location.header.name` (default `Authorization` with `Bearer ` prefix when omitted).
   - Validates per its own mechanism — JWKS signature + claims for `jwtAuthentication`, secret comparison for `apiKeyAuthentication`, ext-auth round-trip for `entExtAuth`, htpasswd comparison for `basicAuthentication`.
3. **Both must succeed for the request to reach the backend.** Either failing returns `401` with no information about which check failed.
4. **JWT path strips the validated header.** Successful `jwtAuthentication` calls `location.remove(req)` (`crates/agentgateway/src/http/jwt.rs:467-470`), so the upstream never sees that header. Header-stripping behavior for the other mechanisms varies by mechanism.

![Diagram](../../images/12-multi-header-auth.png)

### Notes

- **`targetRefs` constraint.** All `traffic.*` policies — including `jwtAuthentication`, `entExtAuth`, `apiKeyAuthentication`, `basicAuthentication` — must target one of `Gateway` / `ListenerSet` / `GRPCRoute` / `HTTPRoute` / `Service` / `ServiceEntry`. They **cannot** target an `AgentgatewayBackend`. The CRD validator on `v2026.5.0-beta.1+` rejects that shape with: *"the 'traffic' field can only target a Gateway, ListenerSet, GRPCRoute, HTTPRoute, Service, or ServiceEntry"*.
- **Failure ordering is opaque.** A 401 doesn't tell the client which mechanism rejected the request — useful for security but means client-side debugging needs gateway logs.
- **Combine mechanisms freely.** A mix like `jwtAuthentication` (signature) + `entExtAuth` (introspection) + `apiKeyAuthentication` (tenant key) all on the same route is valid.

> **Working Example:** [example/](example/) — two `jwtAuthentication` policies on `Authorization` and `x-second-token`, each with its own keypair / issuer / JWKS, deployed from scratch on k3d + AGW Enterprise

Back to [Auth Patterns overview](../../README.md)
