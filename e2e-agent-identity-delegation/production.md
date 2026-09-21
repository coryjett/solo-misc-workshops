# Adapting this to production, and what comes next

The workshop README is the runnable path. This is what changes when you take it
off the lab and onto something real, plus the parts the lab deliberately does
not cover.

## Adapting this to production

- Agent: replace the httpbin stand-in with a real agent. Its ServiceAccount becomes the `may_act` subject in the realm and the `act.sub` in Step 13.
- In-agent exchange: agents perform Step 12's token exchange in code (for example with the agentsts-adk package).
- API leg: Step 13's policy applies unchanged on a Solo Enterprise kgateway route in front of a real API.
- Identity provider: Keycloak is the stand-in. Okta, Entra ID, Auth0 and others work the same way; only the issuer and JWKS provider config changes. Multiple identity domains means one JWT provider entry per issuer.
- Users and agents from different providers: the subject token and the actor token are validated independently, so a customer in one IdP and an employee or agent in another is a supported shape rather than a special case. `tokenExchange` takes `subjectValidators` and `actorValidators` as lists, so add an entry per issuer on whichever side it applies to, and list every issuer whose tokens a route must accept as a JWT provider on that route. The one thing that does not move is `may_act`: it has to be stamped by whichever provider issued the user's token, since that is the token the STS reads it from.
- Registry gateway: attach the Step 10 JWT policy to the `agentregistry-delegate` parent route to require a token on every `/registry` path.

## Follow-ups

- Workload identity without a user: the agent hop already uses the pod's Kubernetes ServiceAccount token as the actor token (Step 12). A further step is to let the MCP and API routes accept a projected ServiceAccount token directly, with a JWT provider pointed at the cluster issuer, for workload-to-workload calls that have no user in the chain. The registry to kagent hop stays on OIDC client credentials; the kagent runtime requires it.
- Calling an API in a different trust domain: every exchange in this lab happens at one authorization server, so the STS validates the user token and mints the delegated token itself. When the downstream API trusts a *different* authorization server from the one that authenticated the user, that single-leg exchange does not apply. Enterprise Agentgateway covers it with the `crossAppAccess` backend authentication method, which implements the Identity Assertion JWT Authorization Grant (ID-JAG, also called Cross App Access): the gateway performs an RFC 8693 exchange at the user's IdP to obtain an ID-JAG assertion, then presents it to the resource's authorization server as an RFC 7523 JWT-bearer grant, and attaches the resulting access token upstream. It needs an OIDC ID token inbound rather than an arbitrary access token, and a client registration at each of the two token endpoints. This is the shape to reach for when the caller and the resource live in separate identity domains, for example a customer in one IdP and an employee in another. Docs: [Cross App Access (ID-JAG)](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backend-authn/cross-app-access/).
