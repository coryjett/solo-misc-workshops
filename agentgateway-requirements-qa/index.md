# agentgateway Enterprise: AI gateway requirements Q&A

Answers to a common set of enterprise AI gateway requirements (MCP, A2A, identity, policy, LLM traffic, security, observability, reliability, operations), checked against agentgateway Enterprise v2026.10.1 source and docs in October 2026. Where possible, behavior was also tested on the open-source standalone binary (v1.7.0-alpha.1), which shares the data plane code for these features.

- ✅ = tested
- 📄 = confirmed in source or docs only (enterprise-only, or needs a cluster)
- ⚠️ = gap or caveat

## Contents

**Core requirements**

- [Item 4 · MCP Streamable HTTP transport](#item-4--mcp-streamable-http-transport)
- [Item 6 · MCP feature coverage](#item-6--mcp-feature-coverage)
- [Item 9 · API-to-MCP (MCP Bridge)](#item-9--api-to-mcp-mcp-bridge)
- [Item 12 · A2A discovery and task semantics](#item-12--a2a-discovery-and-task-semantics)
- [Item 16 · Service-to-service authentication](#item-16--service-to-service-authentication)
- [Item 19 · Token validation](#item-19--token-validation)
- [Item 22 · Outbound credentials](#item-22--outbound-credentials)
- [Item 25 · Default-deny, global JWT policy](#item-25--default-deny-global-jwt-policy)
- [Item 47 · Fleet-wide management](#item-47--fleet-wide-management)
- [Items 62 and 65 · Tool input validation, data exfiltration](#items-62-and-65--tool-input-validation-data-exfiltration)
- [Item 69 · End-to-end context propagation](#item-69--end-to-end-context-propagation)
- [Item 74 · Telemetry privacy and governance](#item-74--telemetry-privacy-and-governance)
- [Item 78 · High availability](#item-78--high-availability)
- [Item 83 · Long-running tool execution continuity](#item-83--long-running-tool-execution-continuity)
- [Item 88 · Multi-tenancy and delegated administration](#item-88--multi-tenancy-and-delegated-administration)
- [Items 96, 97, 99 · Catalog, discovery, lifecycle (agentregistry)](#items-96-97-99--catalog-discovery-lifecycle-agentregistry)
- [POC 16 · MCP lifecycle governance](#poc-16--mcp-lifecycle-governance)
- [POC 22 · MCP Apps](#poc-22--mcp-apps)

**[More requirements](#more-requirements)**

- **[MCP protocol support](#mcp-protocol-support)**: [2](#item-2--native-mcp-protocol-awareness) · [3](#item-3--mcp-version-and-compatibility-management) · [5](#item-5--stateful-mcp-session-handling) · [7](#item-7--mcp-app-support) · [8](#item-8--mcp-aggregation-and-virtualization) · [10](#item-10--multiple-mcp-paths-per-configuration) · [11](#item-11--native-a2a-interoperability) · [13](#item-13--multiple-agent-paths)
- **[Identity and access](#identity-and-access)**: [14](#item-14--identity-provider-integration) · [15](#item-15--user-authentication) · [17](#item-17--spiffe-support) · [18](#item-18--legacy-inbound-basic-auth-and-api-keys) · [20](#item-20--delegated-user-access-obo) · [21](#item-21--token-exchange-and-audience-binding) · [23](#item-23--fine-grained-authorization)
- **[Policy and governance](#policy-and-governance)**: [24](#item-24--unified-inline-enforcement-pipeline) · [26](#item-26--policy-as-code) · [27](#item-27--native-and-external-pdp) · [28](#item-28--hierarchy-scope-inheritance) · [29](#item-29--context-aware-per-request-evaluation) · [30](#item-30--deterministic-enforcement-ordering) · [31](#item-31--safe-policy-change-lifecycle) · [32](#item-32--immediate-revocation-and-containment) · [33](#item-33--gateway-governance-metadata) · [34](#item-34--multi-dimensional-rate-limiting)
- **[AI model traffic](#ai-model-traffic)**: [35](#item-35--modelapi-protocol-mediation) · [36](#item-36--provider-neutral-endpoint) · [37](#item-37--governed-model-inventory) · [38](#item-38--deterministic-routing-rules) · [39](#item-39--dynamic-model-selection) · [40](#item-40--model-aware-load-distribution) · [41](#item-41--provider-fallback-and-error-normalization) · [42](#item-42--quota-and-concurrency-controls) · [43](#item-43--ai-traffic-efficiency)
- **[Distributed gateway management](#distributed-gateway-management)**: [44](#item-44--controldata-plane-separation) · [45](#item-45--flexible-control-plane-hosting) · [46](#item-46--portable-data-plane-placement) · [48, 49](#items-48-49--central-desired-state-config-distribution) · [50](#item-50--control-plane-resilience) · [51](#item-51--local-traffic-routing)
- **[Network security](#network-security)**: [52](#item-52--modern-transport-encryption) · [53](#item-53--bidirectional-mtls) · [54](#item-54--certificate-and-trust-lifecycle) · [55, 59](#items-55-59--segmentation-tenant-isolation) · [56](#item-56--egress-destination-control) · [57](#item-57--protocol-and-header-hardening) · [58](#item-58--payload-protection)
- **[AI security](#ai-security)**: [60](#item-60--inbound-and-outbound-ai-inspection) · [61](#item-61--prompt-attack-protection) · [63, 64](#items-63-64--sensitive-data-detection-and-protection) · [66](#item-66--content-and-file-scanning) · [67](#item-67--security-plane-integration-prisma-airs)
- **[Monitoring and audit](#monitoring-and-audit)**: [68](#item-68--native-opentelemetry) · [70](#item-70--ai-protocol-semantic-telemetry) · [71](#item-71--service-and-experience-metrics) · [72](#item-72--security-and-policy-audit-trail) · [73](#item-73--administrative-change-audit) · [75](#item-75--enterprise-monitoring-integration)
- **[Reliability and scalability](#reliability-and-scalability)**: [76](#item-76--performance-testing) · [77](#item-77--automatic-scaling) · [79, 80](#items-79-80--healthy-endpoint-routing-mcp-and-agent-load-balancing) · [81](#item-81--overload-protection) · [82](#item-82--safe-timeouts-and-retries) · [84](#item-84--regional-failover) · [85](#item-85--upgrades-without-disruption)
- **[Platform, tenancy, deployment, cost, catalog](#platform-tenancy-deployment-cost-catalog)**: [86](#item-86--safe-plugins-and-extensions) · [87](#item-87--microsoft-agent-365) · [89, 92](#items-89-92--gitops-automated-deploy-and-maintenance) · [90](#item-90--portable-deployment-options) · [91](#item-91--kubernetes-gateway-api) · [93](#item-93--management-apis) · [94, 95](#items-94-95--budgets-and-chargeback) · [98](#item-98--consumer-access-requests)

**[Proof-of-concept scenarios](#proof-of-concept-scenarios)**

- [2 · Centralized control plane, distributed data plane](#poc-2--centralized-control-plane-distributed-data-plane)
- [3 · MCP S2S (Agent, GW, MCP)](#poc-3--mcp-s2s-agent-gw-mcp)
- [4 · MCP OBO (User, Agent, GW, MCP)](#poc-4--mcp-obo-user-agent-gw-mcp)
- [5 · A2A S2S (Agent1, GW, Agent2, GW, MCP)](#poc-5--a2a-s2s-agent1-gw-agent2-gw-mcp)
- [6 · A2A OBO (User, webapp, GW, Agent, GW, MCP)](#poc-6--a2a-obo-user-webapp-gw-agent-gw-mcp)
- [7 · Long-running executions with progress](#poc-7--long-running-executions-with-progress)
- [8 · Human in the loop](#poc-8--human-in-the-loop)
- [9 · Rate limiting](#poc-9--rate-limiting)
- [10 · Tool access control](#poc-10--tool-access-control)
- [11 · Sensitive content](#poc-11--sensitive-content)
- [12 · MS Agent 365](#poc-12--ms-agent-365)
- [13 · Prisma AIRS](#poc-13--prisma-airs)
- [14 · Management APIs for automation](#poc-14--management-apis-for-automation)
- [15 · MCP stateful session management](#poc-15--mcp-stateful-session-management)
- [17 · MCP disablement (kill switch)](#poc-17--mcp-disablement-kill-switch)
- [18 · MCP routing and load balancing](#poc-18--mcp-routing-and-load-balancing)
- [19 · MCP multiplexing](#poc-19--mcp-multiplexing)
- [20 · MCP catalog](#poc-20--mcp-catalog)
- [21 · Multi-tenancy in a central portal](#poc-21--multi-tenancy-in-a-central-portal)

---

## Item 4 · MCP Streamable HTTP transport
**Topic:** Does the gateway support MCP Streamable HTTP recovery (reconnect, resume) and cancellation?

**Short answer:** yes, they're in the spec, and both are supported. Resume after a dropped stream (`Last-Event-ID`) isn't. Details below.

**Talking point:** "Replicas are stateless for sessions. For long-running work, use MCP tasks (cancellable and pollable), not stream resume."

**Context first:** the 2026-07-28 MCP spec dropped sessions; clients use `server/discover` and send no session ID. The session points below apply to older, session-based clients.

**Recovery**
- ✅ **Any gateway replica can resume a session.**
  - The session ID is encrypted (AES-256-GCM, a per-Gateway key Secret) and holds the upstream session IDs.
  - Test: initialize on replica A, kill A, then a new replica served `tools/list` and `tools/call` with no new initialize.
- 📄 **Pod pinning only for Service (selector) targets.** The session records which pod each upstream session lives on. Static-host targets aren't pinned.
- ⚠️ **If an MCP server pod dies, the client gets HTTP 500** (JSON-RPC `-32603 "failed to send message"`), not a 404. The session stays pinned to the dead IP. ✅
  - If the server process restarts in place and forgets the session, its 404 does reach the client, which re-initializes. ✅
  - Clients don't re-initialize on a 500, so the app must handle it, or use `sessionRouting: Stateless`.
- 📄 **`Stateless` mode:** every request re-initializes upstream. Safe only for stateless MCP servers, and each request pays an extra round trip.
- Changing the session key, or deleting the Gateway, invalidates every session (404, then the client re-initializes).

**Cancellation**
- ✅ **`notifications/cancelled`** is fanned out to every target with the request ID unchanged; the client gets a 202. The gateway doesn't stop the in-flight call itself, so the server must honor the cancel.
- 📄 **`tasks/cancel`** goes only to the server that owns the task, with authorization applied.

**Stream resume**
- ✅ ⚠️ **Not supported.**
  - The gateway strips upstream SSE event IDs, so the client has nothing to resume from.
  - A `Last-Event-ID` header is forwarded blindly to every target.
  - Nothing is buffered or replayed.

**Docs:** [MCP overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/about/) · [Session routing](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/session/)

---

## Item 6 · MCP feature coverage
**Topic:** Does the gateway handle MCP caching (for example caching `tools/list`)?

**Short answer:** the 2026-07-28 MCP spec adds cache hints, and the gateway deliberately sets them to "don't cache", because tool lists are filtered per user. There's no cache for tool results. Change notifications pass through.

**Talking point:** "We deliberately turn off spec cache hints, because tool lists are per user after policy."

- 📄 **The 2026-07-28 spec added cache hints** (`ttlMs`, `cacheScope`) on `server/discover`, list calls and reads.
- 📄 **The gateway sets them to `ttlMs: 0`, `cacheScope: private`** on everything it proxies. Lists are filtered per user by policy, so a shared cache would leak one user's tools to another.
- 📄 **Internal cache:** Enterprise keeps the federated tool list per session for search and code mode. Not configurable.
- 📄 **No tool result cache.** Results depend on the user and the moment, so caching belongs in the MCP server.
- 📄 **LLM semantic cache:** available only through an external integration (vLLM Semantic Router via ExtProc).
- Change notifications (`listChanged`) pass through.

**Docs:** [MCP spec compatibility](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/spec-compatibility/)

---

## Item 9 · API-to-MCP (MCP Bridge)
**Topic:** Can existing REST, GraphQL and gRPC APIs be exposed as MCP tools, keeping their auth and policies?

**Short answer:** yes. REST APIs become MCP tools from an OpenAPI spec, with no new server to run. GraphQL works as a generic POST step, and gRPC through its REST endpoint. The gateway's auth, rate limits and guardrails apply to the generated tools.

**Talking point:** "Existing REST APIs become MCP tools with no new servers. Tool quality depends on the spec, so you need good `operationId`s and descriptions."

- **REST, Enterprise `entMcp` target with `protocol: OpenAPI`** 📄
  - The spec comes from a ConfigMap through `schemaRef` (key `schema`). JSON or YAML.
  - Each operation becomes a tool. ✅ ⚠️ **`operationId` is required on every operation**; one missing ID breaks the whole target.
  - ✅ **The server URL's path becomes the base path** (the host is ignored). Use `/` only if the API is at the root; otherwise set the real base path, or `path` on the target. Only one `servers` entry is allowed.
  - Tool inputs are grouped (for example path parameters under `path`).
- **GraphQL** 📄 ⚠️: works as a generic composable-MCP POST step with a CEL body. There's no GraphQL-specific support, docs or example.
- **gRPC:** through a REST / grpc-gateway endpoint.
- **Policies still apply:** outbound credentials (item 22), plus MCP authentication, tool access, rate limits and guardrails on the generated tools.

**Docs:** [OpenAPI to MCP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/openapi/) · [Composable MCP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/composable/)

---

## Item 12 · A2A discovery and task semantics
**Topic:** How are A2A agent cards governed, and are card signatures, extensions, push notifications and the extended card supported?

**Short answer:** discovery, cancellation, polling and streaming work, and extensions pass through. Push notifications are partial: the config calls go through the gateway, but webhook delivery doesn't. Card signatures aren't verified, and the URL rewrite can break them. The extended card isn't rewritten. That's why the status is Limited.

**Talking point:** "Discovery is governed. Signed cards, the extended card and push egress need design work, so the status is Limited."

| Item | Status | Detail |
|---|---|---|
| Agent card (v1.0) | ✅ | `supportedInterfaces[].url` is rewritten to the gateway, keeping the sub-path. The rest of the card passes through |
| Agent card (v0.3) | ✅ ⚠️ | `url` is rewritten to the **card's base path**, so the agent's own path (`/a2a`) is dropped. **`additionalInterfaces[].url` is not rewritten, so internal URLs leak** |
| Mixed card | ✅ ⚠️ | When a card has both fields, only `supportedInterfaces` is rewritten |
| Signatures | ✅ ⚠️ gap | Passed through unchanged; not verified or re-signed. **The URL rewrite breaks a JWS over the card.** Workaround: the agent signs its public gateway URL (untested) |
| Extensions | ✅ | `capabilities.extensions` and the `X-A2A-Extensions` header pass through. A CEL rule on the header denies with a 403 before the request reaches the agent |
| Push config | ✅ | `tasks/pushNotificationConfig/*` goes through the gateway with auth and logs. The webhook URL in the body is unchanged |
| Push delivery | 📄 ⚠️ | Goes straight from the agent to the webhook. Govern it by routing agent egress through the gateway with a destination allowlist |
| extendedAgentCard | ✅ ⚠️ | **Not rewritten.** Both the v0.3 `agent/getAuthenticatedExtendedCard` and v1.0 `GetExtendedAgentCard` return internal hostnames and ports to authenticated clients. Workaround: the agent puts its public URL in the extended card |
| Cancel / poll / stream | ✅ | `tasks/cancel`, `tasks/get`, `GetTask`, `CancelTask` and SSE pass through. SSE is streamed, not buffered |
| Logs | ✅ ⚠️ | JSON responses log `a2a.method`, `a2a.task.state` and `a2a.context.id`. **SSE (`message/stream`) logs only the method.** A request denied by authorization logs as plain HTTP |

**Docs:** [A2A](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/agent/a2a/)

---

## Item 16 · Service-to-service authentication
**Topic:** Is mTLS supported both inbound (client to gateway) and outbound (gateway to backend), including SPIFFE?

**Short answer:** yes, both directions. Inbound mTLS validates client certs (needs Gateway API 1.5+). Outbound mTLS presents a client cert to backends. SPIFFE/SPIRE certs are supported for both (tested).

**Talking point:** "mTLS proves which workload is calling; the Entra JWT proves who it's for. Use both."

**Inbound (the gateway checks client certs)**
- 📄 ✅ Gateway `spec.tls.frontend.default.validation` (or `perPort`) with `caCertificateRefs`. Default mode `AllowValidOnly`. Test: no cert or an untrusted CA failed the handshake; a valid cert got 200.
- ⚠️ **Needs Gateway API 1.5+ standard, or 1.4 experimental CRDs.** No controller flag is needed. Check your cluster's Gateway API version.
- ✅ ⚠️ **CEL identity:**
  - `source.identity.{namespace,serviceAccount}` is filled only for Istio-format IDs (`spiffe://td/ns/X/sa/Y`).
  - For other certs use `source.spiffeId`, `source.subjectAltNames`, `source.subjectCn` or `source.issuer`.
- Frontend CA validation can't be combined with the SPIFFE certificate source on the same listener.

**Outbound (the gateway presents a cert)**
- 📄 ✅ Backend `tls.mtlsCertificateRef` (a Secret with `tls.crt`/`tls.key`, list of max 1) plus `caCertificateRefs` and `verifySubjectAltNames`. Test: 200 with the cert, 503 `CertificateRequired` without it. Since v2026.5.0.
- ⚠️ Listed in the API reference only; no how-to guide.
- 📄 Standard alternative: `Gateway.spec.tls.backend.clientCertificateRef` with `BackendTLSPolicy`, one cert for the whole Gateway.

**SPIFFE/SPIRE** 📄 (v2026.8.2+; in the changelog and API reference only, no setup guide)
- `spiffe: {}` in the gateway parameters mounts the SPIRE Workload API through the CSI driver `csi.spiffe.io` (`hostPath` also works).
- A listener option `agentgateway.dev/tls-certificate-source: SPIFFE`, and on backends `certificateSource: SPIFFE`.
- A SPIFFE backend can't also set `mtlsCertificateRef`, `caCertificateRefs` or `insecureSkipVerify`.

**Docs:** [Listener mTLS](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/listeners/mtls/) · [Backend TLS](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backendtls/) · [JWT setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/jwt/setup/)

---

## Item 19 · Token validation
**Topic:** Does token validation check algorithms and revocation status?

**Short answer:**
- **Algorithms:** yes; the allowed list is enforced and pinned per key (tested).
- **Revocation status:** not in JWT validation. Introspection is available through ExtAuth for IdPs that support it, and Entra doesn't.

**Talking point:** "Validation is local, with no IdP call per request. Entra doesn't support revoking access tokens or introspection, so the industry answer is short lifetimes plus an emergency deny. If you also use an IdP that supports introspection, our ExtAuth server can check tokens in real time on sensitive routes."

**Algorithms** ✅ (every one tested)
- ✅ Accepted: RS256/384/512, PS256/384/512, ES256/384, EdDSA (Ed25519 only).
- ❌ Rejected: HS256/HS512 (`InvalidAlgorithm`; the RSA-key-as-HMAC confusion attack is blocked), `none`, ES512.
- **Pinning:** a JWK's `alg` pins one algorithm, otherwise the key family decides. An RSA JWK with no `alg` (which is how Entra publishes them) accepts all six RS/PS algorithms.
- ✅ **`kid` is required.** One JWKS key without a `kid`, or one HMAC (`oct`) key, fails the **whole** JWKS. Entra's JWKS is fine.

**Claims** ✅
- `iss` always.
- `aud` when audiences are configured.
- `exp` and `nbf`, with a **60s clock leeway**.
- ⚠️ `requiredClaims` checks only that `exp`, `nbf`, `aud` or `sub` is **present**. To check values (`tid`, `scp`, `roles`, `azp`), use a CEL authorization rule on `jwt.*`.

**JWKS** 📄 ✅
- In Kubernetes, the **controller** fetches the JWKS and pushes the keys to the proxies.
- `cacheDuration` defaults to 5m, the minimum. Where policies share a URL, the shortest TTL wins.
- ✅ **No refetch on an unknown `kid`** (401 `unknown key`). Keys refresh on the TTL. Fine for Entra, which publishes keys before signing with them.

**Revocation** ⚠️ **no revocation check in JWT validation itself**; introspection is available through the bundled ExtAuth server
- **Entra has no token introspection endpoint (RFC 7662) and no revocation endpoint,** so a real-time check isn't possible with Entra on any gateway.
- Options:
  1. Short access-token lifetimes.
  2. An emergency CEL deny on `sub`, `oid`, `jti` or `azp`, pushed through GitOps.
  3. Remove a compromised signing key from the JWKS; takes effect within the cache window.
  4. For an IdP that supports RFC 7662 introspection (Okta, Ping, Keycloak; **not Entra**): the bundled ExtAuth server with an `AuthConfig` using `oauth2.accessTokenValidation.introspection` (`introspectionUrl`, `clientId`, `clientSecretRef`), attached through an `EnterpriseAgentgatewayPolicy`. The field team has used this pattern with agentgateway in a POC (Slack, 04-30). Not tested here, and not on the agentgateway docs pages. It adds an IdP call per request, so put it on sensitive routes only.

**Docs:** [JWT overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/jwt/about/) · [JWT setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/jwt/setup/) · [Authorization (CEL)](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/authorization/)

---

## Item 22 · Outbound credentials
**Topic:** Can clients use OIDC to the gateway while the gateway uses Basic auth to the MCP server?

**Short answer: yes.** Clients authenticate to the gateway with OIDC (an Entra JWT), and the gateway calls the MCP server with Basic auth. Both halves were tested:
1. **Inbound:** `jwtAuthentication` validates the Entra token. ✅ After validation the gateway **strips** the client's token, so the MCP server never sees it.
2. **Outbound:** backend `auth` with `prefix: "Basic "` (below). ✅ The MCP server received exactly `Authorization: Basic ...`, which replaced the client's header.
- **Combine with tool access** (CEL on JWT claims). Per-user authorization then happens at the gateway, while the MCP server sees one shared service credential.
- ⚠️ **What the server loses:** it can't tell which user is calling. If it needs to, add a header from a claim (a transformation on `jwt.sub`), or use token exchange instead (item 21).

**Talking point:** "Clients use OIDC; the MCP server keeps its Basic credential. The gateway validates the user, enforces tool access, strips the user's token and adds the Basic header, so the credential never leaves the gateway."

**API keys** 📄
- Backend `auth.secretRef`, with `location` set to `header` (`name`, optional `prefix`), `queryParameter` or `cookie`.
- No `location` means `Authorization: Bearer <key>`.
- The `credentials` list adds up to 8 extra values, each with its own Secret and location.
- Configured per backend, so the agent never sees the secret.

**Basic auth** ✅ (works; no dedicated option)
- Store `base64(user:pass)` in a Secret under a **custom key** (not `Authorization`, which gets a leading "Bearer " stripped):
  ```yaml
  backend:
    auth:
      secretRef: {name: svc-basic, key: basic}
      location:
        header: {name: Authorization, prefix: "Basic "}
  ```
- ✅ The upstream received exactly `Authorization: Basic dXNlcjpwYXNz`. A client-supplied Authorization header is **replaced**, not duplicated.
- 📄 The Kubernetes Secret translation was checked in code only. Confirm it in your environment.

**Docs:** [Backend API key auth](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backend-authn/key/)

---

## Item 25 · Default-deny, global JWT policy
**Topic:** Can one global policy enforce JWT auth on all MCP servers and routes?

**Short answer:** yes, per Gateway. One policy targeting the Gateway with `inheritance: Override` enforces JWT on every route, and routes can't weaken it. Put authorization in the same policy too, because route-level Allow rules otherwise add up.

**Talking point:** "There's no cluster-wide object by design. A Gateway-level Override policy is the global control, as long as it sets every field you want locked."

**Yes** 📄
- One `EnterpriseAgentgatewayPolicy` targeting the Gateway, with `strategy.inheritance: Override` and `traffic.jwtAuthentication` (`mode: Strict`).
- Gateway-level rules are applied first, and Override locks each field it sets, so routes can't replace the JWT policy.
- ✅ **Why Override matters:** without it, a route-level JWT policy in Permissive mode **did** let a token-less request through (200).

**Rules for Override** 📄
- **The lock is per field.** It locks only the fields set in that Override policy.
- Override is allowed only on traffic-only policies. A policy that also has `frontend` or `backend` is rejected.
- **Enterprise-only fields (`entExtAuth`, `entRateLimit`, `entWAF`, budgets) ignore Override.** A route-level one replaces the Gateway's. The OSS `extAuth` / `rateLimit` fields do lock.

**Authorization adds up** ✅ ⚠️
- Rule sets from each level are combined, and Allow rules are OR'd.
- Test: a Gateway Allow for `alice` plus a route Allow for `bob` (no Override) let **both** in on that route.
- **For a global authorization rule,** put `traffic.authorization` in the Override policy, or use `action: Require` at the Gateway (it must hold across all sets).

**Default deny** ✅
- Once any Allow rule exists, unmatched requests get a **403**.

**Tool visibility** 📄
- Tools a user can't call are hidden from `tools/list`.
- This comes from MCP authorization, a backend policy, so Override doesn't apply to it.

**Scope** 📄
- Policies are namespace-local. One policy can target up to 16 Gateways in its namespace.
- Enforce existence with Kyverno or Gatekeeper, and deliver through GitOps.

**Docs:** [Policy merging](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/about/policies/target-merge/) · [Authorization](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/authorization/) · [Tool access](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

---

## Item 47 · Fleet-wide management
**Topic:** Can the UI manage gateway instances across multiple clusters?

**Short answer:** no, the UI is single-cluster. The fleet view today is GitOps plus central observability. A multi-cluster UI is a roadmap question.

**Talking point:** "The UI is per cluster today. Across clusters, Git is the single source of truth and telemetry goes to a central backend."

- 📄 **No. The UI is single-cluster:** it reads and edits resources in its own cluster only. The source logs "running in single-cluster mode".
  - The UI API still has leftover cluster fields, and there's an undocumented OTLP receiver for remote clusters. **Don't promise a fleet view.**
- **Fleet view today:**
  - **Config:** GitOps, one repo with Argo ApplicationSets across clusters.
  - **Observability:** metrics, logs and traces from every cluster to a central backend.
- **Docs:** [UI install](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/ui/)

---

## Items 62 and 65 · Tool input validation, data exfiltration
**Topic:** How do MCP guardrails validate tool inputs and stop sensitive data leaving?

**Short answer:** three layers. Guardrails inspect tool arguments and results, and reject or mask them with CEL or their own gRPC policy service. Target conditions hide whole MCP servers. Tool access hides or denies tools by identity. Reject and mask were both tested.

**Talking point:** "Simple rules are CEL in config; complex decisions call your own policy service over gRPC. The same call can be allowed for one role and masked for another."

Three layers (also in OSS):
1. **Guardrail processors** (`backend.mcp.guardrails`) 📄 ✅
   - Run per MCP method in the request phase (`mcp.params`, tool arguments), the response phase (`mcp.result`), or both.
   - Up to 16 run in order, and the first reject stops the chain.
   - Two kinds:
     - **A CEL expression** that rejects or transforms.
     - **A remote processor**, a **gRPC ExtMCP service** (not an HTTP webhook). It can pass, mutate or error, and fails closed by default.
   - ✅ **Mask test:** `alice@example.com` came back as `[EMAIL]`.
   - ✅ **Reject test:** a blocked `tools/call` returned `isError: true` "blocked by guardrail", and the server never got the call.
2. **Target conditions** (`spec.mcp.targets[].condition`) 📄
   - Exclude whole MCP servers. Evaluated at session init (stateful) or on every request (stateless).
   - Needs 2+ targets. New in v2026.10.0.
3. **MCP authorization** (`backend.mcp.authorization`) 📄
   - Hides tools, prompts, resources and tasks from lists, and denies calls.
   - Based on JWT claims plus the tool name and target. **It can't see tool arguments.**

**Mapping to the requirements**
- **Item 62** (schemas, arguments, paths, commands, URLs): guardrail CEL on `mcp.params` for simple rules; the gRPC processor for schema or business logic.
- **Item 65** (data, caller, action, target): guardrails see arguments and results; authorization sees the caller, tool and target. Masking responses stops data leaving through tool results.

⚠️ **Version gate:** CEL guardrails and target conditions need **v2026.10.0+**. The v2026.7.1 LTS has remote processors only.

**Docs:** [Guardrails overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/guardrails/about/) · [Guardrails setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/guardrails/setup/) · [Tool access](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

---

## Item 69 · End-to-end context propagation
**Topic:** How are trace IDs propagated end to end across app, agent, gateway, MCP and models?

**Short answer:** standard W3C `traceparent`. The gateway joins the incoming trace and passes it on to MCP servers and models (tested). It needs a tracing policy, and your agents must forward `traceparent` too.

**Talking point:** "Standard OpenTelemetry. Your agents send a trace; we join it and carry it to every MCP server and model."

- ⚠️ **Nothing is traced until a tracing policy points at a collector.**
- ✅ **Incoming traces:** a request with a sampled W3C `traceparent` (`-01`) is joined at 100% (`clientSampling`, default true). Test: every span carried the client's trace ID and parent.
  - An unsampled `-00` parent isn't traced unless `parentNotSampled` is set (v2026.10.0+).
- ✅ **No incoming trace:** nothing is traced by default (`randomSampling` false). With `randomSampling: true`, the gateway starts a new trace.
- ✅ **Spans:**
  - A server span per request, named after the MCP method or `METHOD path`.
  - A client child span per upstream call, labeled LLM or MCP.
  - Attributes follow OTel GenAI semantic conventions v1.40.
- ✅ **Downstream propagation:** the gateway passes `traceparent` to MCP servers both as a header and in `params._meta.traceparent`.
- ✅ **Custom attributes:** CEL `attributes.add` (tested: `my.tool: mcp.tool.name` gave `echo`). The `span.name` key renames a span.
- ⚠️ **Your app and agents must forward `traceparent`,** or the trace breaks at the first hop the gateway doesn't see.

**Docs:** [Tracing setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/traces/setup/) · [Trace attribute reference](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/traces/attribute-reference/)

---

## Item 74 · Telemetry privacy and governance
**Topic:** How are secrets and sensitive payloads kept out of logs and traces?

**Short answer:** metadata only by default. Prompts, tool arguments and bodies aren't logged or traced (tested). You choose which fields to add or drop and which requests to log. Retention and access are set in their own backend.

**Talking point:** "By default we log metadata, never content. You choose what to add, drop or filter."

- ✅ **Prompts, tool arguments and bodies are NOT logged or traced by default.**
  - Test: a prompt containing an SSN and a tool argument containing an email appeared in no log line and no span.
  - Default logs carry metadata only: model, tokens, cost, tool name, `jwt.sub`.
  - Prompt content appears only if you add it with CEL (`llm.prompt` / `llm.completion`).
- ✅ **Access logs:**
  - Key=value lines on stdout by default (`preset: Otel` switches to OTel field names), with `gen_ai.*` and `mcp.*` fields.
  - `attributes.remove` drops fields; `attributes.add` adds only what you choose.
  - The CEL `filter` limits which requests are logged. Tested with `response.code >= 400`: 200s skipped, 4xx logged.
- ✅ **Traces:** `attributes.remove` (tested), sampling, and a trace `filter` that limits which spans are exported.
- **Masking:** guardrails mask data in traffic. Logs are controlled by choosing fields.
- 📄 **Storage:**
  - Traces go to ClickHouse behind the Solo UI.
  - Access logs go there only if you configure OTLP export; otherwise they stay on stdout.
  - Retention and access are set in your own backend.

**Docs:** [Access logs](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/access-logs/view/) · [Log export](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/access-logs/export/)

---

## Item 78 · High availability
**Topic:** How is high availability achieved, and where does leader election come in?

**Short answer:** proxies run as multiple active replicas, with HPA, PDB and zone spreading, and no leader election. Leader election is only inside the controller, where one replica writes status and fetches JWKS, while all replicas serve config. Clients never use it.

**Talking point:** "The data path has no leader: every proxy replica is active, and sessions survive losing one. Leader election only decides which controller replica writes status, and traffic doesn't depend on it."

**Data plane (the proxies, where traffic flows)** 📄
- Run multiple replicas through the gateway parameters on the Gateway's `EnterpriseAgentgatewayParameters`. There are overlays for HPA and PodDisruptionBudget.
  - Zone spreading uses `topologySpreadConstraints` in a Deployment overlay.
- **No leader election on proxies.** They're stateless and all active.
  - ✅ MCP sessions resume on any replica.
  - ✅ A new pod doesn't report ready until it has config.
- **If the controller is down,** running proxies keep serving their last config (item 44).

**Control plane (the controller)** 📄 **This is where leader election lives**
- Run 2+ controller replicas. **All of them serve config (xDS) to proxies**, so proxies can connect to any replica.
- **Leader election picks one replica** to do the singleton jobs:
  - Writing status on Gateways, routes and policies.
  - Fetching remote JWKS keys and storing them.
- If the leader dies, another replica takes over the lease automatically. Traffic isn't affected either way.
- "Clients" (apps, agents, proxies) never take part in leader election; it's internal to the controller.
- ⚠️ With token exchange (STS) on 2+ controller replicas, **Postgres is required** (item 50).

**Why the link was unclear:** the "Advanced install" page covers control-plane options. Proxy HA is on the Customize options page.

**Docs:** [Customize options (proxy)](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/customize/options/) · [Advanced install (controller)](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/advanced/) · [Architecture](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/about/architecture/)

---

## Item 83 · Long-running tool execution continuity
**Topic:** Can a long-running tool call survive a client network drop without running twice?

**Short answer:** yes, through MCP tasks. They've been supported in code since v2026.8.0, but **aren't documented yet**. The tool keeps running on the server, and the client reconnects through any replica and fetches the result by task ID without re-running it. The gateway never retries MCP calls. This needs 2026-07-28 spec clients and servers that support tasks; the gateway removes tasks for older clients. Validate it with your own clients and servers.

**Talking point:** "With MCP tasks, the tool keeps running on the server and the client picks up the result by task ID after reconnecting, through any replica, without running it twice. The docs haven't caught up yet, so validate it with your own client and server."

**How it works, using MCP tasks** (the MCP spec's answer to long-running tools):
1. The client declares the tasks extension (`io.modelcontextprotocol/tasks`) in its capabilities and sends a normal `tools/call`. **The server decides** whether to run it as a task. If it does, it returns a task ID (`resultType: "task"`) right away and keeps working.
2. The client's network drops. **The tool keeps running on the server,** because the task belongs to the server, not to the client connection.
3. The client reconnects, through any gateway replica, and calls `tasks/get` with the task ID for the status or result. The tool **isn't re-run**.
4. `tasks/cancel` stops it if needed.

**What the gateway does** 📄
- It routes `tasks/get` and `tasks/cancel` to the one server that owns the task, with **authorization applied**, so another user can't read the result.
- ✅ The gateway never retries MCP calls, so a tool is never executed twice by the gateway (tested).
- ⚠️ **Not documented anywhere.** The MCP spec-compatibility page never mentions tasks, and no other MCP docs page does either.
- 📄 **Supported in code since v2026.8.0**. In v2026.10.1:
  - The gateway handles `tasks/get`, `tasks/update` and `tasks/cancel` (the 2026-07-28 spec method set). `tasks/list` was removed from the spec and returns 404.
  - **Multiplexing:** task IDs are prefixed `{target}+{id}` in create results, get results and task status notifications, so later calls route back to the owning server.
  - **Authorization** treats tasks as a resource type, so task calls get the same CEL checks as tools. Task IDs are also recorded in the access log.
  - Reported as validated on 2026.9.x across gateway replicas; not re-tested for this page. Validate it with your own clients and servers.

**Limits** ⚠️
- ⚠️ 📄 **Needs 2026-07-28 spec clients.** Tasks are an extension of the 2026-07-28 spec, and the gateway removes the tasks capability from older (2025-xx) clients before forwarding. Older clients never get tasks through the gateway.
- **Needs a tasks-capable client and server SDK.** A plain `tools/call` over a stream that drops is lost; there's no stream resume (item 4).
- MCP sessions expire after 30 minutes idle. Tasks are tracked by task ID, but test the reconnect gap you need.
- A gateway rollout drains only up to `shutdown.max`. Tasks avoid that problem; a long plain `tools/call` doesn't.

**Docs:** [Spec compatibility](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/spec-compatibility/)

---

## Item 88 · Multi-tenancy and delegated administration
**Topic:** Can teams self-manage their own MCPs, agents, routes and policies in isolated tenants, for example through GitOps?

**Short answer:** achievable with Kubernetes plus GitOps: a namespace per team, route delegation, and central Override policies. Gaps: no self-service UI, and enterprise ExtAuth and rate-limit fields aren't locked. Suggest "Yes, with GitOps".

**Talking point:** "Tenancy is namespaces plus route delegation: the platform team owns the Gateway and central guardrails, and each team owns its routes, backends and policies through GitOps, the same model as items 48 and 49."

**The gateway side can be achieved, with Kubernetes plus GitOps** 📄
- **Tenant = namespace (or a set of them).** Kubernetes RBAC limits each team to its own namespace.
- **Route delegation:**
  - The platform team owns the Gateway and parent routes.
  - Each team owns child HTTPRoutes, MCP and A2A backends, policies, Secrets and certificates in its own namespace.
- **Central guardrails** that teams can't weaken: Gateway-level `Override` policies (JWT, authorization, rate limits) plus Kyverno or Gatekeeper rules.
- **GitOps:** a repo or folder per team, with CODEOWNERS for review and Argo projects so each team syncs only its own namespaces.
- **Limits per tenant:** rate limits and budgets keyed on a tenant claim.

**Honest gaps** ⚠️
- **No self-service portal or UI per tenant.** The UI is cluster-wide and single-cluster (item 47); self-service is Git plus Kubernetes RBAC.
- **Override doesn't lock enterprise ExtAuth, rate-limit and WAF fields,** so a team's route-level one replaces the Gateway's (item 25).
- **Authorization rules add up across levels,** so a team's Allow can widen the gateway's allowlist. Use `Require` at the Gateway level.
- **agentregistry tenant RBAC isn't released yet** (it's on main); today it's AccessPolicy.

**Summary:** supported with GitOps, the same model as items 48 and 49.

**Docs:** [Route delegation](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/route-delegation/overview/) · [Delegation inheritance](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/route-delegation/inheritance/) · [Registry access control](https://docs.solo.io/agentregistry/latest/security/access-control/registry/)

---

## Items 96, 97, 99 · Catalog, discovery, lifecycle (agentregistry)
**Topic:** How does agentregistry provide the catalog, authorized discovery and lifecycle approval?

**Short answer:** agentregistry catalogs MCP servers, agents and skills (96). Access policies filter what each consumer sees (97). An approval workflow plus tag versioning covers lifecycle (99).

**Talking point:** "The registry decides what exists, which version, who can see it and who approved it. The gateway enforces it at runtime."

The short version for each item:

- **Item 96 · Inventory:**
  - What it catalogs: MCP servers, agents and skills, each version a tag, with metadata (owner, description, package or remote URL).
  - Sources: their own publishes, plus discovery from runtimes (Microsoft Foundry, Copilot Studio, AgentCore).
- **Item 97 · Authorized discovery:**
  - 📄 **AccessPolicy** filters what each consumer can list and read (released).
  - Tenant RBAC is on main, not released ("next release").
- **Item 99 · Lifecycle and approval** 📄 (see POC 16):
  - **Approval:** since v2026.5.4, off by default. Non-admin create, update and delete wait for approval; the actions are approve, revoke and withdraw.
  - **Versions:** `latest` is an ordinary tag that you promote deliberately.
  - **Retire** = delete the tag. New references are then rejected, and existing ones go to `ReferencePending`.
  - "Deprecated" is a label convention.
  - Audit events need `audit.enabled`.
- **Link to the gateway (Enterprise, Kubernetes):** route delegation into agentgateway, where the registry Deployment's tag decides which version is served at the same URL.

**Docs:** [Catalog quickstart](https://docs.solo.io/agentregistry/latest/quickstart/catalog/) · [Registry access control](https://docs.solo.io/agentregistry/latest/security/access-control/registry/) · [Approval](https://docs.solo.io/agentregistry/latest/security/approval/)

---

## POC 16 · MCP lifecycle governance
**Topic:** How is MCP server lifecycle (review, approval, versions, retirement) governed?

**Short answer:** agentregistry, a separate product. Versions are tags. The approval workflow gates publishes. Retiring means deleting the tag. With Enterprise route delegation, the registry decides which version is live at the same URL.

**Talking point:** "Your CI/CD keeps deploying MCP servers. The registry becomes the version catalog and the approval gate for what enters it (only approved versions can be deployed), and, with Enterprise, the switch for which version is live at the same URL."

**agentregistry** 📄 (a separate product and license)
- **Versions:** each version is a tag, and consumers pin versions. Applying without a tag writes the literal tag `latest`.
- ⚠️ **`latest` is an ordinary tag** with its own copy of the spec. It never moves by itself. You promote by re-applying with tag `latest`, and any apply without a tag overwrites it.
- ⚠️ **Retire means deleting or revoking the tag.**
  - There's no "retired" status, and "deprecated" is a label convention only.
  - New references to a deleted tag are rejected at apply time.
  - Deletion isn't blocked while a tag is in use; a Deployment still using it goes `Ready=False, ReferencePending`.

**Approval** 📄 (Enterprise, since **v2026.5.4**, off by default)
- `requireCreateApproval` gates create, update and delete by non-admins.
- Actions: **approve, revoke, withdraw.** There's no "reject" action; withdrawing someone else's request rejects it. Registry admins skip the queue and are the only approvers.
- ⚠️ Audit events need `audit.enabled` (default false).

**Live version** 📄 (Enterprise, Kubernetes, remote MCP targets)
- Route delegation into agentgateway. The route path comes from the Deployment, so the Deployment's tag decides which version is served at the same URL.
- Two versions side by side need two Deployments on two paths.
- Your CI/CD keeps deploying the servers.

**Validation steps**
1. A non-admin publish of v2 stays pending.
2. An admin approves; flip the Deployment's tag; the same URL serves v2's tools.
3. Delete or revoke v1; a new reference to v1 is rejected (existing ones go `ReferencePending`).


**Ref:** `agentregistry-demo/README.md`

---

## POC 22 · MCP Apps
**Topic:** Are MCP Apps (interactive UI returned with tool results) supported with policies and observability enforced?

**Short answer:** supported with no config (tested). The host fetches the UI (an HTML template) from the MCP server once through the gateway, and renders it locally in a sandbox. Every action in the UI becomes a normal tool call through the gateway, with the same policies and traces. Authorization hides denied UIs, and guardrails can inspect the HTML if configured. The one path outside the gateway is external domains the app declares in its CSP.

**Talking point:** "MCP Apps are MCP servers that also ship a UI. To the gateway it's the same traffic, so policies and observability apply unchanged."

**How an MCP App works** (MCP Apps draft spec, `io.modelcontextprotocol/ui`)
1. **The tool advertises a UI** in `tools/list`: `_meta.ui.resourceUri: "ui://..."`.
2. **The host fetches the UI once** with a normal `resources/read`, through the gateway. It gets back an HTML template (`text/html;profile=mcp-app`) and can prefetch and cache it.
3. **The host renders it locally** in a sandboxed iframe. Nothing UI-related runs on the MCP server.
4. **Data comes from normal tool calls.** The model calls the tool through the gateway, and the host passes the arguments and result into the iframe.
5. **The UI can act:** a button or form asks the host for a `tools/call`, which the host sends to the MCP server through the gateway.
   - The UI talks only to the host (JSON-RPC over `postMessage`), never directly to the MCP server.
   - Tools marked `visibility: ["app"]` are for the UI only, and the host hides them from the model.
- **Typical UI:** a dashboard or chart of results, a sortable table, a map, or a form whose submit calls an app-only tool (for example approve, or refine). It's one self-contained HTML page with inline JS and CSS; the template stays the same, and the data changes per call.
- ⚠️ **What bypasses the gateway:**
  - The iframe-to-host messages, which are local to the host.
  - **Any external domains the app declares in its `csp` metadata** (`connect-src`). The UI can call those directly, without going through agentgateway. With no `csp` declared, the host applies a restrictive default.
  - So review each app's declared `csp` domains, and confirm the host enforces them.

**Hosts that render MCP Apps** (per the official MCP Apps page, October 2026)

| Host | Notes |
|---|---|
| Claude | Web and Claude Desktop |
| VS Code GitHub Copilot | |
| Microsoft 365 Copilot | |
| Goose | |
| Postman | |
| MCPJam | |
| Archestra.AI | |
| ChatGPT | Support announced in January 2026; not on the official list, so confirm before relying on it |

- MCP Inspector does not render apps.
- Many other MCP clients don't support apps yet. The [client matrix](https://modelcontextprotocol.io/extensions/client-matrix) tracks support per client.
- Sources: [MCP Apps overview](https://modelcontextprotocol.io/extensions/apps/overview) · [MCP blog announcement](https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/)

✅ **Supported, no config** (all tested with 2 federated servers)
- `ui://` resources pass through. With 2+ targets they're rewritten to `ui://{target}+{rest}`, and reads route correctly. A single target is unchanged.
- **Authorization:**
  - A denied UI resource is hidden from `resources/list`, and reading it returns "unknown resource".
  - An allowed tool whose UI is denied stays listed, but its UI link is removed.
- **App-only tools:** the `visibility: ["app"]` field is kept but not enforced. The host hides those tools from the model.
- **Guardrails can inspect UI HTML** when a processor lists `resources/read` in the response phase. Tested: a secret in the HTML came back masked. Off by default.
- UI clicks are normal `tools/call` requests, with the same policies, logs and traces.
- ⚠️ **When servers are federated, set `prefixMode: Never` (Kubernetes; `never` in standalone) and keep tool names unique across targets.** Prefixing breaks calls the app makes, and duplicate names emptied the tool list in test.
- The host must render MCP Apps (not tested).

**Validate**
1. Put an Apps server behind `/mcp` and open it in a host that renders apps.
2. A user without access gets no UI.
3. A guardrail masks a field in the UI.
4. The trace shows the `resources/read` and the `tools/call`.
5. Review the app's declared `csp` domains: anything listed there is reachable from the UI without the gateway.

**Docs:** [MCP Apps](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/apps/)

---

---
---

# More requirements


## MCP protocol support

### Item 2 · Native MCP protocol awareness
- The gateway parses JSON-RPC MCP messages: method, tool, resource, prompt and task.
- Those fields drive authorization, rate limits, guardrails, logs (`mcp.method.name`, `gen_ai.tool.name`) and trace spans ✅.
- **Talking point:** "Policy and telemetry work on MCP semantics, not just HTTP paths."
- **Docs:** [MCP overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/about/)

### Item 3 · MCP version and compatibility management
- ✅ **Header check:** an unsupported `MCP-Protocol-Version` header gets HTTP 400 with JSON-RPC `-32022`. On requests after initialize, the error lists the supported versions: `{"supported":["2024-11-05","2025-03-26","2025-06-18","2025-11-25","2026-07-28"],"requested":"..."}`.
- ⚠️ ✅ **Initialize isn't checked:** a version sent only in the initialize body passes through, and the server negotiates it.
- ✅ **Blocking versions with CEL:** deny on `request.headers["mcp-protocol-version"]`, plus `json(request.body).params.protocolVersion` to catch initialize.
  - There's no `mcp.protocolVersion` CEL variable.
  - A blocked request gets a plain HTTP 403, not a JSON-RPC error.
- **Talking point:** "Clients on unsupported versions get a clear error; a gateway-wide rule can block any version you retire."
- **Docs:** [Spec compatibility](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/spec-compatibility/) (doesn't mention -32022)

### Item 5 · Stateful MCP session handling
- See item 4.
- ✅ Sessions resume on any replica, using an encrypted session ID with no shared store.
- 📄 **Authorization:**
  - Tool, prompt and resource authorization runs on every request, from the JWT.
  - **Target selection is different:** `condition` (which servers a session gets) is fixed at session start in Stateful mode, and evaluated per request only in Stateless mode.
- ⚠️ If a pinned MCP server pod dies, the client gets a 500.
- ⚠️ Modern MCP (2026-07-28 spec) has no sessions.
- **Docs:** [Session routing](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/session/) · [Virtual MCP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/virtual/)

### Item 7 · MCP App support
- See POC 22 (tested).
- **Docs:** [MCP Apps](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/apps/)

### Item 8 · MCP aggregation and virtualization
- 📄 **One endpoint fronts many MCP servers.**
  - Names are prefixed per target when a backend has 2+ targets (`prefixMode`: `Conditional` by default, also `Always` and `Never`). Resource URIs aren't prefixed.
  - `ui://{target}+` routes app resources ✅.
- Tool access rules expose only approved tools, prompts and resources.
- Target `condition` CEL can decide which servers each identity gets at all.
- ⚠️ ✅ If one target is down, `tools/list` fails for the whole session by default; calls to healthy targets still work. `spec.mcp.failureMode: FailOpen` serves from the healthy targets instead.
- **Talking point:** "Agents get one governed endpoint; you choose exactly what each identity sees."
- **Docs:** [Virtual MCP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/virtual/) · [Tool access](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

### Item 10 · Multiple MCP paths per configuration
- ✅ One HTTPRoute with several path `matches` to the same MCP backend. Tested with `/p1` and `/p2`: both worked, and a session from `/p1` also worked on `/p2`.
- **Docs:** [Path matching](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/match/path/)

### Item 11 · Native A2A interoperability
- A2A JSON-RPC and SSE pass through with method-aware logs ✅.
- JWT, authorization and rate limits apply like any route.
- v0.3 and v1.0 cards are both handled ✅. Caveats are in item 12.
- **Docs:** [A2A](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/agent/a2a/)

### Item 13 · Multiple agent paths
- Same as item 10: several HTTPRoute path matches to one A2A backend.
- **Docs:** [Path matching](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/match/path/)

## Identity and access

### Item 14 · Identity provider integration
- 📄 JWT validation against Entra, or any OIDC IdP, through JWKS.
- ✅ **Multiple providers on one route** (up to 64). Tested: tokens from two IdPs both accepted, and a token with the right issuer but the wrong key rejected (401).
- 📄 **MCP OAuth** (`jwtAuthentication.mcp`) for clients that discover auth through the MCP authorization spec.
  - ⚠️ With Entra on Kubernetes, only **public PKCE clients** are supported; confidential clients need standalone mode.
- **Docs:** [MCP auth with Entra](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/auth/entra/) · [JWT setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/jwt/setup/)

### Item 15 · User authentication
- 📄 **Browser login:** ExtAuth OIDC auth code flow with a session cookie, stored in the ExtAuth Redis.
  - It's generic OIDC, so Entra works. The docs example uses Keycloak.
- APIs and agents use bearer JWTs (the Entra JWT and OBO page covers JWT validation, not browser login).
- **Docs:** [Authorization code flow](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/extauth/oauth/authorization-code/) · [Entra JWT and OBO](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/extauth/oauth/entra/)

### Item 17 · SPIFFE support
- 📄 SPIFFE SVIDs from SPIRE for listener and backend mTLS (v2026.8.2+). See item 16.
- The agentic mesh (Istio ambient) path uses SPIFFE identities natively.
- ⚠️ CEL `source.identity` fields are parsed only for Istio-format IDs; otherwise use `source.spiffeId`.
- **Docs:** [Agentic mesh](https://docs.solo.io/agentgateway/kubernetes/latest/integrations/agentic-mesh/about/) · [Waypoint policies](https://docs.solo.io/agentgateway/kubernetes/latest/integrations/agentic-mesh/waypoint/policies/)

### Item 18 · Legacy inbound Basic auth and API keys
- 📄 **API keys:** from Secrets, or (recommended) ConfigMaps of SHA-256 hashes. Attach per Gateway or HTTPRoute.
- 📄 **Basic auth is built into the proxy:** `traffic.basicAuthentication`, with htpasswd hashes (MD5, bcrypt, crypt, SHA-1) inline or from a Secret. No ExtAuth needed.
  - Credentials can be read from a custom header, query parameter or cookie (`location`).
- (Item 22 is the outbound side.)
- **Docs:** [API keys](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/apikey/) · [Basic auth](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/extauth/basic/)

### Item 20 · Delegated user access (OBO)
- 📄 **Entra OBO:** the gateway exchanges the user's Entra token for one scoped to the downstream audience, so the backend sees the user's permissions, not the agent's.
- 📄 **Non-Entra option:** Solo STS delegation (RFC 8693, with an `act` claim). There the **agent** does the exchange through the STS ADK.
- ⚠️ 📄 `backend.tokenExchange.entra` is **deprecated** at v2026.10.1. Use `entTokenExchange.entra` (runs in the proxy; client secret or certificate). The Entra docs page and the workshop lab still show the old field.
- ⚠️ 📄 Paired with JWT authentication, set `preserveToken: true`, or the exchange finds no `subject_token`.
- The workshop lab runs the exchange end to end against httpbin, not an MCP server.
- **Talking point:** "The agent never gets more than the user it's acting for."
- **Docs:** [Token exchange with Entra](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backend-authn/token-exchange/idps/entra/) · [STS delegation](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backend-authn/token-exchange/sts/delegation/) · [Entra OBO lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/identity-delegation/msft-entra-obo.md)

### Item 21 · Token exchange and audience binding
- 📄 Exchanged tokens are scoped to each backend's audience.
- **Lifetime:** set by the IdP (Entra), or by `tokenExpiration` for Solo STS (24h in the docs example).
- ✅ **The inbound token isn't passed through:** after JWT validation the gateway strips it by default, and the backend received no `Authorization` header.
- ✅ An outbound auth header replaces any client-supplied one (tested in item 22).
- **Docs:** [Token exchange with Entra](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backend-authn/token-exchange/idps/entra/)

### Item 23 · Fine-grained authorization
- **CEL authorization on:** routes, models, MCP servers, tools, prompts and resources.
  - ✅ Model rules tested: `llm.requestModel` allowed one model and gave a 403 for another, at both route and backend level.
- **Inputs:** JWT claims, workload identity (`source.*`) and headers.
- **Hidden tools** never appear in `tools/list` ✅.
- ⚠️ 📄 **No A2A skill-level authorization.** A2A messages don't name a skill, so the gateway can't key on one; it sees only the method and task. Enforce per agent route, or in the agent.
- **Docs:** [Tool access](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/) · [Authorization](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/authorization/)

## Policy and governance

### Item 24 · Unified inline enforcement pipeline
- One policy model across LLM, MCP, A2A and HTTP. Policies attach at the Gateway, listener, route or backend.
- Enforcement points cover request, response and streaming phases.
- **Docs:** [Policy overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/about/policies/overview/)

### Item 26 · Policy as code
- Every policy is a Kubernetes CRD in Git: reviewed in PRs, promoted by ArgoCD or Flux, rolled back by revert.
- 📄 ⚠️ **Validation before merge is limited.** There's no validating webhook, so `kubectl --dry-run=server` only catches schema errors.
  - Broken references (for example a missing AuthConfig) show up as policy status after apply, and the policy fails closed.
  - Check status in a lower environment. Kyverno or Gatekeeper can enforce conventions.
- **Docs:** [ArgoCD install](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/argocd/)

### Item 27 · Native and external PDP
- **Built-in:** CEL authorization, evaluated in the proxy.
- 📄 **OPA:**
  - Runs inside Solo's ext-auth-service (embedded, with Rego from ConfigMaps), or behind it (your own OPA server).
  - The proxy talks to it over the standard ext_authz gRPC API, and OPA's input is the Envoy CheckRequest.
  - The docs recommend CEL first.
- **Docs:** [OPA](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/extauth/opa/)

### Item 28 · Hierarchy, scope, inheritance
- Levels: Gateway, listener, route, and delegated child routes. `strategy.inheritance: Override` makes parent fields win.
- 📄 ✅ Caveats (from the item 25 verification):
  - The lock is per field.
  - **Authorization rules add up across levels,** so a route Allow can widen a Gateway Allow; use `Require` or an Override.
  - Enterprise `entExtAuth`, `entRateLimit` and `entWAF` ignore Override.
- There's no enterprise, team or application tier above the Gateway; model those with namespaces and Gateways.
- **Talking point:** "Gateway-level guardrails that teams can't weaken, plus team-owned route policies through delegation."
- **Docs:** [Policy merging](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/about/policies/target-merge/) · [Delegation inheritance](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/route-delegation/inheritance/)

### Item 29 · Context-aware per-request evaluation
- CEL evaluates every request using `jwt.*`, `source.*` (workload identity), request and headers, `mcp.*` and `llm.*`.
- ✅ **Time:** use `timestamp(request.startTime)` (for example `.getHours()`). There's no `now()`.
- Risk or classification signals can come from ExtAuth or ExtProc calling your own service.
- **Docs:** [CEL reference](https://docs.solo.io/agentgateway/kubernetes/latest/reference/cel/)

### Item 30 · Deterministic enforcement ordering
- 📄 **Fixed, documented phases:**
  1. Frontend.
  2. Pre-routing: authentication, ExtAuth, ExtProc, transformation.
  3. Route selection.
  4. Post-routing: CORS, authentication, ExtAuth, authorization, local then global rate limits, ExtProc, transformation, CSRF, headers.
  5. Backend: AI and MCP guardrails, backend auth.
- 📄 **Failure behavior:**
  - External calls (ExtAuth, ExtProc, global rate limits, guardrail webhooks, moderation, MCP remote guardrails) **fail closed by default** and can be set to fail open.
  - Enterprise ExtAuth and WAF are always fail-closed.
  - Budget limits fail open.
- **Docs:** [Filter order](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/about/policies/filter-order/)

### Item 31 · Safe policy change lifecycle
- GitOps handles validation, approval, staged rollout and rollback; Argo flags drift.
- The controller writes status conditions (Accepted or Invalid) on each policy.
- 📄 ⚠️ **No dry-run or simulation mode** in the gateway. What to offer instead:
  - Status conditions plus `agctl proxy trace` (shows how policies decide on real requests) in a lower environment.
  - The standalone UI's CEL playground for testing expressions.
- **Docs:** [ArgoCD install](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/argocd/)

### Item 32 · Immediate revocation and containment
- **Kill switches:** pull an MCP target, drop a tool from the allowlist, add a CEL deny on an agent or user, or delete a route.
- 📄 **Speed:** config pushes over xDS are batched (10ms quiet, at most 1s), so changes usually land in well under a second.
- ✅ **Exception:** JWT keys refresh on the JWKS TTL (5m minimum), not instantly.
- **Docs:** [Tool access](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

### Item 33 · Gateway governance metadata
- The gateway has no native risk-level or approval-status input to its policies.
- agentregistry gates what gets published.
- Risk tiers can be modeled as labels or tool lists that CEL keys on.
- **Talking point:** "The registry decides what's approved; the gateway enforces what's deployed."

### Item 34 · Multi-dimensional rate limiting
- 📄 **Redis:** a bundled cache is provided, but it isn't persistent, so counters reset when the pod restarts. For production, bring your own Redis (`sharedExtensions.extCache.redis.url`).
- 📄 **Descriptors are CEL:** `jwt.<claim>`, `request.headers[...]`, `llm.requestModel`, and for MCP tools `body.params.name`. Combine them for multi-dimension limits.
- ✅ ⚠️ **Docs bug:** the global rate-limit docs table shows `claims["sub"]`, which fails ("Undeclared reference to 'claims'"). Use `jwt.sub`.
- Local limits are per proxy.
- **Docs:** [Global rate limit](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/rate-limit-global/) · [MCP rate limit](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/rate-limit/)

## AI model traffic

### Item 35 · Model/API protocol mediation
- ✅ **OpenAI-compatible front door:** translates to Bedrock, Vertex, Azure, Anthropic and others for chat, embeddings (not Anthropic) and streaming, plus native passthrough. Tested: an OpenAI client hitting Bedrock was translated and got an OpenAI-format reply.
- ⚠️ **Batch is passthrough to OpenAI only:** no translation to other providers, and guardrails skip passthrough routes.
- **Docs:** [LLM overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/about/) · [Batches lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/routing/configure-openai-batches.md)

### Item 36 · Provider-neutral endpoint
- Virtual models: the app asks for a stable name, and the gateway maps it to a provider and model. Switching providers is a config change.
- ⚠️ 📄 With native Bedrock paths (`/model/{id}/converse`), virtual models don't rewrite the path in v2026.10.1 (known issue, fix in progress). The OpenAI-format path works ✅.
- **Docs:** [Virtual models](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/models/virtual/)

### Item 37 · Governed model inventory
- 📄 **AgentgatewayModel resources** list the approved models: provider, endpoint and region.
- **Pricing** comes from a model cost catalog (built in, or a ConfigMap) keyed by model name; it isn't a field on the model.
- **Docs:** [Models](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/models/about/) · [Costs](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/cost-controls/costs/)

### Item 38 · Deterministic routing rules
- **Route on:** the requested model and headers, and content (copy a body field into a header, then match on it).
- 📄 **Tenant or tier routing:** virtual model `conditional` routing with CEL on `jwt.*`. Not tested end to end.
- **Docs:** [Content routing](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/content-routing/) · [Virtual models](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/models/virtual/)

### Item 39 · Dynamic model selection
- 📄 **Virtual model routing modes:** weighted, failover by priority, conditional, and callout (an external decision, v2026.10.0+).
  - Callout has a `fallback` model and a CEL-keyed cache, so routing can stick per session.
- 📄 **Health eviction:** by default one 5xx or connection failure evicts a target for 3s, with backoff.
- ⚠️ **Failover isn't a retry:** the request that triggers eviction still fails; only later requests move. Pair it with a retry policy.
- **Docs:** [Virtual models](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/models/virtual/) · [Failover](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/failover/)

### Item 40 · Model-aware load distribution
- 📄 **Gateway API Inference Extension:** the llm-d Router endpoint picker chooses the pod (aware of load, KV cache and LoRA), and agentgateway routes to the pod it picks.
- **Docs:** [Inference routing](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/inference/inference-routing/)

### Item 41 · Provider fallback and error normalization
- 📄 **Retries and failover:** priority-group failover, plus retries on chosen status codes or a CEL condition.
  - Retries buffer the request body to replay it.
  - A `precondition` CEL can skip them (for example on streams).
- ✅ **Error format:** upstream errors keep their status code and come back in the client's API format.
- ⚠️ **What's lost:** the provider's error type isn't preserved; it becomes `invalid_request_error`.
- ⚠️ **Gateway-generated rejections:** guardrail blocks are plain text, unless you set `response.message` and headers.
- **Docs:** [Failover](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/failover/)

### Item 42 · Quota and concurrency controls
- Tokens, requests and tool calls are limited per user, team or tenant (rate limits and budgets).
- 📄 `maxConcurrentRequests` applies per **gateway or port**, not per user. Over the limit gets an immediate 503.
- No per-tenant concurrency or agent fan-out limit.
- **Talking point:** "Per-identity limits on usage; concurrency is a whole-gateway safety valve."

### Item 43 · AI traffic efficiency
- ✅ **Streaming isn't buffered:** chunks arrived in real time in testing. The batch API is supported (passthrough).
- 📄 **Semantic cache** only through vLLM Semantic Router (ExtProc).
- ⚠️ Response guardrails don't run on streams unless `promptGuard.streaming: Enabled`, and masking never applies to streams.
- **Docs:** [vLLM Semantic Router](https://docs.solo.io/agentgateway/kubernetes/latest/integrations/llm/routing/vllm-semantic-router/) · [Streaming](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/streaming/)

## Distributed gateway management

### Item 44 · Control/data-plane separation
- 📄 ✅ **Yes, separated.** The control plane and proxies are separate deployments, and the docs architecture page describes the same outage behavior.
- **During a controller outage:**
  - **Running proxies keep serving** their last config from memory, and reconnect on their own when the controller is back.
  - Config changes wait until it's back.
  - **A proxy pod that starts during the outage stays not-ready** and serves nothing. Config isn't cached on disk. Tested: readiness returned `not ready, pending: state manager`.
- **Mitigation:** run 2+ controller replicas, and avoid proxy rollouts while the controller is down.
- **Docs:** [Architecture](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/about/architecture/) (see the gateway-only subpage's outage table)

### Item 45 · Flexible control-plane hosting
- Self-hosted only (Kubernetes, or standalone on VMs and containers); no Solo-managed control plane.
- Hybrid = a control plane per cluster, managed through GitOps.

### Item 46 · Portable data-plane placement
- Kubernetes (AKS, OpenShift), standalone binary or container on VMs, edge.
- **Docs:** [Standalone install](https://docs.solo.io/agentgateway/standalone/latest/documentation/setup/install/) · [OpenShift](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/openshift/)

### Items 48, 49 · Central desired state, config distribution
- Git is the source of truth, and Argo applies and flags drift.
- The controller validates (status conditions) and pushes over xDS.
- Inspect a proxy's live config to confirm it applied.
- **Docs:** [ArgoCD install](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/argocd/) · [Inspect config](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/operations/inspect-config/)

### Item 50 · Control-plane resilience
- HA controller replicas. The gateway config is CRDs in Git, so it has no database of its own; rollback is Helm or Git revert.
- 📄 **Optional stateful pieces:**
  - **Token exchange (STS):** with 2+ controller replicas it **needs Postgres**, which you must back up. The default is SQLite on an in-memory volume, lost on restart.
  - **UI:** ClickHouse holds telemetry history.
  - **Rate limits:** Redis counters aren't persisted.
- ⚠️ See item 44 for proxy behavior during an outage.
- **Docs:** [Architecture](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/about/architecture/) · [Upgrade](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/operations/upgrade/)

### Item 51 · Local traffic routing
- 📄 **Locality-aware routing:** same zone, then same region, then elsewhere. It's opt-in per Service (`trafficDistribution`).
- ⚠️ It ranks endpoints the gateway can see. Endpoints in other clusters need a mesh or ServiceEntry, and the docs list Istio CRDs as a prerequisite.
- **Docs:** [Locality routing](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/locality-aware-routing/)

## Network security

### Item 52 · Modern transport encryption
- ✅ **Listener TLS:** min and max versions and ciphers are enforced.
  - With min 1.3, a 1.2 handshake was refused.
  - With max 1.2 and one cipher, 1.3 and any other cipher were refused.
- ✅ **Versions:** TLS 1.2 and 1.3 only.
- **Backend TLS:** re-origination to backends.
- **Docs:** [TLS settings](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/listeners/tls-settings/) · [Backend TLS](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backendtls/)

### Item 53 · Bidirectional mTLS
- See item 16 (tested both directions ✅).
- **Docs:** [Listener mTLS](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/listeners/mtls/) · [Backend TLS](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backendtls/)

### Item 54 · Certificate and trust lifecycle
- 📄 **Listener certificates:** standard Kubernetes Secrets, through Gateway API `certificateRefs`. cert-manager works here, and Secret updates are pushed without restarts.
- 📄 **Key Vault:** credentials (API keys, backend mTLS) arrive through the Secrets Store CSI driver as an external secret file store.
  - ⚠️ CSI `enableSecretRotation` must be on to pick up changes.
  - ⚠️ This path doesn't serve listener certificates.
- **Expiry alerts:** from cert-manager's own metrics. The gateway has no certificate-expiry metric.
- **Docs:** [TLS settings](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/listeners/tls-settings/) · [CSI secrets](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/external-secrets/file-csi/)

### Items 55, 59 · Segmentation, tenant isolation
- Separate Gateways or listeners per trust zone or tenant. Route delegation lets each team own its namespace.
- 📄 **Admin interface:** listens on localhost:15000 only, and the proxy Service exposes only the Gateway's listener ports.
  - ⚠️ Metrics (15020) and readiness (15021) can be reached on the pod IP inside the cluster; restrict them with NetworkPolicy.
- **Docs:** [Listeners](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/listeners/overview/) · [Route delegation](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/route-delegation/overview/) · [Gateway setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/gateway/)

### Item 56 · Egress destination control
- 📄 **Mesh egress:** the gateway is the egress point, with ServiceEntry destinations and a default-deny allowlist by service account.
  - ⚠️ Requires a **Solo Enterprise for Istio (ambient)** license.
- 📄 **Dynamic forward proxy:** controlled open egress, with authentication, authorization and rate limits.
- **A2A push webhooks:** this is the pattern for item 12 (design suggestion, untested).
- **Docs:** [Mesh egress](https://docs.solo.io/agentgateway/kubernetes/latest/integrations/agentic-mesh/egress/) · [DFP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/dfp/)

### Item 57 · Protocol and header hardening
- The HTTP stack rejects malformed requests.
- **WAF:** the bundled OWASP CRS v4 includes protocol-enforcement rules (rule groups 920 and 921: request smuggling, header injection, content-type allowlist). The docs page lists only the SQLi, XSS, RCE and scanner groups.
- **Docs:** [WAF OWASP CRS](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/waf/owasp-crs/)

### Item 58 · Payload protection
- ✅ ⚠️ **Size limits only apply where bodies are buffered:**
  - LLM routes: 32MiB default (a 40MiB prompt got 413).
  - Body-reading policies: 2MiB.
  - An explicit `traffic.buffer` limit returns 413 when exceeded.
- ✅ **Plain proxied routes stream with no size cap** unless buffering is set (5MiB passed). Add `traffic.buffer` where you need a cap.
- **Docs:** [Buffering](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/buffer/)

## AI security

### Item 60 · Inbound and outbound AI inspection
- LLM guardrails inspect prompts and responses; MCP guardrails inspect tool arguments and results ✅ (items 62/65).
- 📄 ⚠️ **Gaps:**
  - LLM guardrails skip embeddings, passthrough, models and rerank routes.
  - A2A has no dedicated guardrail; use ExtProc.
- **Docs:** [LLM guardrails](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/guardrails/overview/) · [MCP guardrails](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/guardrails/about/)

### Item 61 · Prompt attack protection
- 📄 ⚠️ **No built-in injection or jailbreak classifier.** Use:
  - **Custom regex rules:** the docs give sample injection and jailbreak patterns. Tested: "IGNORE all previous instructions" got a 403 ✅.
  - **External services:** OpenAI moderation, Bedrock Guardrails, Google Model Armor, or a webhook to your own service.
- **Audit mode:** `action: Audit` on regex, webhook, moderation, Bedrock and Model Armor, so you can measure before enforcing.
- **Docs:** [Regex guardrails](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/guardrails/regex/) · [Multi-layer](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/guardrails/multi-layer/)

### Items 63, 64 · Sensitive data detection and protection
- ✅ **Regex block or mask.** Tested: the upstream received `my ssn is <SSN> and mail <EMAIL_ADDRESS>`.
- 📄 **Built-in patterns cover PII only:** SSN, credit card, phone, email, Canadian SIN. Secrets need custom patterns.
- 📄 **Microsoft Purview DLP:** blocks (no masking), and fails closed with a 503.
- ✅ MCP responses can be masked (item 62/65 test).
- **Docs:** [Regex guardrails](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/guardrails/regex/) · [Purview DLP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/guardrails/purview-dlp/)

### Item 66 · Content and file scanning
- **No built-in malware scanner.**
- **Your own scanner:** content goes to your AV, DLP or sandbox through the guardrail webhook (reject or mask) or ExtProc, and the verdict is enforced inline.
- ⚠️ **WAF limits:** it can restrict URL file extensions and request content types. It can't identify files embedded in LLM JSON payloads, which arrive base64-encoded.

### Item 67 · Security-plane integration, Prisma AIRS
- **Use a small adapter:**
  - LLM prompts and responses go through the guardrail webhook.
  - MCP tool calls go through the MCP remote guardrail (gRPC ExtMCP).
- 📄 **Failure behavior:** both fail closed by default (configurable). AIRS verdicts are enforced.
- ⚠️ **Set a timeout on the adapter Service** (`backend.http.requestTimeout`). The webhook has no timeout of its own, so a hung adapter stalls requests.
- **No native AIRS connector yet** (on the roadmap).
- **Docs:** [Guardrail webhook](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/guardrails/webhook/)

## Monitoring and audit

### Item 68 · Native OpenTelemetry
- ✅ **Traces and logs:** exported over OTLP.
- 📄 **Metrics:** Prometheus format only, with no OTLP metrics push. If you need OTLP, scrape with an OTel Collector, as the docs recommend.
- ⚠️ Tracing needs a tracing policy (item 69).
- **Docs:** [Tracing setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/traces/setup/) · [OTel stack](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/otel-stack/)

### Item 70 · AI-protocol semantic telemetry
- ✅ Logs and spans carry `gen_ai.*` (model, provider, tokens, cost), `mcp.*` (method, target, tool) and `a2a.*` (method, task state, context).
- ⚠️ SSE A2A logs only the method.
- **Docs:** [Trace attributes](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/traces/attribute-reference/)

### Item 71 · Service and experience metrics
- ✅ **Metrics seen live:**
  - `requests_total`, with status and reason labels.
  - `request_duration_seconds`.
  - `gen_ai_server_time_to_first_token` (streaming requests only).
  - `gen_ai_client_token_usage`.
  - `retries_total`.
- **Docs:** [Data plane metrics](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/metrics/dataplane/) · [LLM observability](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/observability/)

### Item 72 · Security and policy audit trail
- ✅ **What's logged by default:** `jwt.sub`, and denials as `http.status=403 error="authorization failed" reason=Authorization`.
- **Adding detail:** claims or the auth method, with `attributes.add`.
- ⚠️ ✅ **Gap:** a denial doesn't say which rule matched.
- **Docs:** [Access logs](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/access-logs/view/)

### Item 73 · Administrative change audit
- **Gateway:** Git history plus the Kubernetes API audit log.
- 📄 **agentregistry audit logging:** needs `audit.enabled` (default false) and an OTLP destination endpoint.
- **Docs:** [ArgoCD install](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/argocd/) · [Registry audit logging](https://docs.solo.io/agentregistry/latest/compliance/audit-logging/)

### Item 75 · Enterprise monitoring integration
- Export over OTLP and Prometheus.
- 📄 **Guides exist for:** Datadog, Grafana Cloud, Honeycomb and Jaeger.
- **Splunk:** through a generic OTel Collector.
- **Docs:** [External metrics](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/metrics/external/) · [Trace configs](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/observability/traces/configs/)

## Reliability and scalability

### Item 76 · Performance testing
- The MCP k6 load-test lab and the sizing guide.
- ⚠️ The sizing guide is on mastertheagent.com, not a Solo domain.
- **Docs:** [k6 lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/load-testing/mcp-load-testing-k6.md) · [Sizing](https://www.mastertheagent.com/solo/agentgateway-deployment-sizing/)

### Item 77 · Automatic scaling
- HPA on proxy Deployments, configured through gateway parameters.
- A new pod gets config over xDS before it reports ready.
- **Docs:** [Customize options](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/customize/options/)

### Items 79, 80 · Healthy endpoint routing, MCP and agent load balancing
- 📄 **Load balancing:** one algorithm, power of two choices, scored on health, latency and pending requests. Plus route weights and optional session affinity (consistent hashing on a CEL key). There's no algorithm setting.
- 📄 ⚠️ **Eviction:** endpoints are evicted after consecutive failures only when `backend.health.eviction` is configured. Without it, failures just lower an endpoint's score. If every endpoint is evicted, traffic goes back to them.
- ⚠️ ✅ A stateful MCP session stays pinned to its pod (item 4).
- **Docs:** [Backend health](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/resiliency/backend-health/) · [Load balancing](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/load-balancing/)

### Item 81 · Overload protection
- **Limits:** local and global rate limits, plus `maxConcurrentRequests` (unlimited by default; over the limit gets an immediate 503).
- **Outlier eviction:** only when configured (items 79 and 80).
- **Docs:** [HTTP rate limit](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/rate-limit-http/)

### Item 82 · Safe timeouts and retries
- **Timeouts and retries:** set per route, with retries only on chosen codes.
- ✅ **The gateway never retries MCP calls, even with a retry policy on the route.** Tested: a failing `tools/call` reached the server once, while the same policy on an HTTP route made 4 attempts. Tool calls with side effects aren't at risk.
- Retry policies apply to HTTP and LLM routes.
- **Docs:** [Retries](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/resiliency/retry/retry/) · [Timeouts](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/resiliency/timeouts/)

### Item 84 · Regional failover
- **Setup:** a gateway per region plus GitOps, and LLM failover across regions.
- ⚠️ 📄 **Locality routing isn't cross-cluster failover.** It ranks endpoints the gateway can see.
- **Recovery time** depends on your DNS or GSLB.
- **Docs:** [Failover](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/failover/) · [Locality routing](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/locality-aware-routing/)

### Item 85 · Upgrades without disruption
- **Rolling upgrades with draining:** the drain window is `shutdown.min` and `shutdown.max` in the gateway parameters. Blue-green by namespace is covered in a workshop lab.
- ✅ MCP sessions resume on the new pods if the session key stays the same.
- ⚠️ A tool call that runs longer than `shutdown.max` is cut off during a rollout. Raise it, or use MCP tasks.
- **Docs:** [Upgrade](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/operations/upgrade/) · [Blue-green lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/upgrades/blue-green-namespaces.md)

## Platform, tenancy, deployment, cost, catalog

### Item 86 · Safe plugins and extensions
- ExtProc, ExtAuth (bring your own), and MCP remote guardrails (gRPC).
- Each runs as a separate service, so they're versioned and deployed like any app, and can't crash the proxy.
- **Docs:** [ExtProc](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/traffic-management/extproc/) · [BYO ExtAuth](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/extauth/byo-ext-auth-service/)

### Item 87 · Microsoft Agent 365
- Not supported. Entra identities and OTel export work with Microsoft tooling today.
- On the roadmap; no committed date.

### Items 89, 92 · GitOps, automated deploy and maintenance
- Helm charts and CRDs, deployed with Argo or Flux; upgrades and rollbacks through Helm.
- **Docs:** [ArgoCD install](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/argocd/) · [Helm install](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/helm/) · [Upgrade](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/operations/upgrade/)

### Item 90 · Portable deployment options
- Helm for Kubernetes, a standalone binary or container, and air-gapped installs; no vendor-hosted dependency.
- **Docs:** [Helm install](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/helm/) · [Standalone install](https://docs.solo.io/agentgateway/standalone/latest/documentation/setup/install/) · [Air-gapped](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/airgap/)

### Item 91 · Kubernetes Gateway API
- 📄 **Supported resources:** Gateway, HTTPRoute, GRPCRoute and BackendTLSPolicy. MCP and A2A are backends behind standard routes.
- 📄 **Conformance tests run in CI,** but the enterprise conformance job isn't required to pass.
- ⚠️ Inbound mTLS needs Gateway API 1.5+.
- **Docs:** [Gateway setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/setup/gateway/)

### Item 93 · Management APIs
- Gateway management is the Kubernetes API (CRDs); agentregistry has a REST API.
- ⚠️ No central multi-cluster management API (POC 14).
- **Docs:** [Gateway API reference](https://docs.solo.io/agentgateway/kubernetes/latest/reference/api/) · [Registry API reference](https://docs.solo.io/agentregistry/latest/reference/api/)

### Items 94, 95 · Budgets and chargeback
- 📄 **Budgets:** per user, team or claim; over budget returns a 429.
- **Attribution:** by JWT claims.
- ✅ **Cost on log lines:** `agw.ai.usage.cost.total` appears only when the cost catalog prices that model.
- **Docs:** [Budget limits](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/cost-controls/budget-limits/) · [Attribution](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/cost-controls/attribution/)

### Item 98 · Consumer access requests
- Not built in. Access is granted by an admin or a GitOps PR (AccessPolicy), and the registry REST API can feed ServiceNow or another ITSM tool.

---

# Proof-of-concept scenarios

### POC 2 · Centralized control plane, distributed data plane
- No federated control plane across clusters or regions; GitOps is the recommended approach.
- Answer: a control plane per cluster, with one Git repo driving all clusters; Argo ApplicationSets target clusters and regions.
- **Validate:** a change in Git lands on the intended clusters only.

### POC 3 · MCP S2S (Agent, GW, MCP)
- **Authentication:** Entra client-credentials JWT validated at the gateway.
- **Authorization:** tool access keyed on `azp`/`appid` or `roles`.
- ⚠️ ✅ **Passing the token through needs a setting:** the gateway strips the JWT after validation by default. Set `backendAuth.passthrough` (or `preserveToken: true`), or exchange the token for the MCP's audience (item 21).
- **Validate:**
  - An allowed app sees its tools; a different app doesn't.
  - OTel data reaches your collector.
  - Failover across 2 MCP replicas works. ✅ Sessions survive losing a gateway replica; ⚠️ losing an MCP pod gives a 500 for stateful sessions.
- **Docs:** [JWT setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/jwt/setup/) · [Tool access](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

### POC 4 · MCP OBO (User, Agent, GW, MCP)
- The user's token goes to the agent. The gateway exchanges it through Entra OBO for the MCP's audience, and the MCP enforces the user's permissions.
- ⚠️ Use `entTokenExchange.entra` (the old field is deprecated) and `preserveToken: true` on the JWT policy (item 20).
- **Docs:** [Token exchange with Entra](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/backend-authn/token-exchange/idps/entra/) · [Entra OBO lab](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/main/labs/identity-delegation/msft-entra-obo.md)

### POC 5 · A2A S2S (Agent1, GW, Agent2, GW, MCP)
- Each hop goes through the gateway with its own JWT check.
- Agent2 calls the MCP with its own credentials, or with an exchanged token if Agent1's identity must carry through.
- ⚠️ 📄 **Agent card rewrite (item 12):**
  - With v0.3 cards, the agent must serve JSON-RPC at the card's base path, and `additionalInterfaces` aren't rewritten.
  - v1.0 `supportedInterfaces` keep their path.
- One trace end to end needs both agents to forward `traceparent` (item 69).

### POC 6 · A2A OBO (User, webapp, GW, Agent, GW, MCP)
- The token is exchanged at each hop (OBO), so the user's permissions reach the MCP.
- ⚠️ With Entra, each hop's exchange must use the app registration that matches the incoming token's `aud`, so each hop needs its own exchange policy and client.
- **Should agents be exposed externally?** Yes, but only behind the gateway, with JWT plus authorization, so the gateway is the single front door.

### POC 7 · Long-running executions with progress
- ✅ **No blocking:** each call holds its own stream, and progress notifications stream back as they happen.
- ✅ **Timeouts:**
  - There's **no request timeout by default; leave it unset**.
  - If one is set, it only bounds the time until response headers arrive, so SSE tools aren't cut off (tested: a 4s SSE tool finished under a 2s timeout). Use `responseIdle` to catch a stalled stream.
  - ⚠️ Don't use `0s` outside an HTTPRoute: a policy rejects it, and standalone treats it as an immediate timeout.
- 📄 **Limits:**
  - `maxConcurrentRequests` is unlimited by default.
  - MCP sessions expire after 30 minutes idle.
  - A rollout drains only up to `shutdown.max`.
- For very long work, use MCP tasks (item 83).
- **Docs:** [Timeouts](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/resiliency/timeouts/)

### POC 8 · Human in the loop
- **No built-in approval workflow;** the prompt lives in the agent or client.
- **What the gateway does:**
  - Restricts risky tools to specific roles.
  - Can call your own policy service on every tool call (remote guardrail).
  - ✅ **Passes MCP elicitation through:** the server's `elicitation/create` reached the client, and the client's answer completed the tool.
- ⚠️ ✅ **Capability catch:** for 2025-xx clients, the gateway removes the client's `elicitation` capability (and `sampling` and `roots`) from the initialize it sends upstream. A server SDK that checks client capabilities may refuse to elicit, so test with their server's SDK.
- ⚠️ **Docs gap:** no docs page covers MCP elicitation passthrough. The `mcp/elicitation` page is a different feature ("STS elicitation" for upstream OAuth credentials), so don't send it as "the elicitation docs".

### POC 9 · Rate limiting
- **Setup:** a per-client or per-agent limit keyed on a JWT claim (`jwt.sub`, not `claims["sub"]` as the docs table shows).
- ✅ **What MCP clients see over the limit (not a 429):**
  - `tools/call`: HTTP 200 with an `isError` tool result that includes the retry time.
  - Other requests: JSON-RPC `-32003` with `{limit, remaining, retryAfterSeconds}`.
  - Notifications only: 429. Plain HTTP routes do return 429 with `retry-after`.
- **Validate:**
  - Requests within the limit succeed.
  - Over the limit you get the responses above.
  - The access log shows `reason=RateLimit`. ✅ That line shows `protocol=http` and no tool name.
- **Docs:** [MCP rate limit](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/rate-limit/)

### POC 10 · Tool access control
- CEL on JWT claims plus `mcp.tool.name`: an allowed tool works, and a denied tool is hidden and its calls are refused ✅.
- ⚠️ ✅ Logs show "authorization failed" but not which rule matched. Add claims with `attributes.add` so the identity appears.
- **Docs:** [Tool access](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

### POC 11 · Sensitive content
- An MCP guardrail with a CEL `expression` on `mcp.params` (`matches()` or `regexReplaceAll`) rejects the call before it reaches the tool. ✅ Reject and mask both tested.
  - There's no separate regex processor; MCP guardrails are CEL `expression` or `remote`.
- ✅ Logs don't contain argument values by default (item 74 test).
- **Docs:** [Guardrails setup](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/guardrails/setup/)

### POC 12 · MS Agent 365
- Not supported (item 87). On the roadmap.

### POC 13 · Prisma AIRS
- Use an adapter (item 67): LLM through the guardrail webhook, MCP tool calls through the remote guardrail. Fails closed if AIRS is down; decisions are logged.
- **Docs:** [Guardrail webhook](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/llm/guardrails/webhook/) · [MCP guardrails](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/guardrails/about/)

### POC 14 · Management APIs for automation
- There's no central management API. Each cluster's Kubernetes API is the management API, plus GitOps; agentregistry has REST.
- An automation layer would drive Git or each cluster's API.

### POC 15 · MCP stateful session management
- ✅ **Tested:** sessions resume on any gateway replica, cancellation fans out, and tasks route to the server that owns them.
- 📄 Sessions expire after 30 minutes idle.
- **Caveats:** see item 4 (losing an MCP pod gives a 500; no SSE resume).

### POC 17 · MCP disablement (kill switch)
- Remove the target, drop the tool from the allowlist, or add a CEL deny on an agent; takes effect in about a second over xDS.
- **Validate:** apply the deny mid-session, and the next call is refused.

### POC 18 · MCP routing and load balancing
- **Setup:** multiple MCP replicas behind a Service, with health- and latency-aware balancing; eviction once it's configured (items 79 and 80).
- **Multi-region:** a gateway per region. Locality routing only ranks endpoints the gateway can see.
- ⚠️ Stateful sessions stay pinned to their pod (item 4).

### POC 19 · MCP multiplexing
- One endpoint, many servers, with tool prefixes and access rules (item 8).
- ⚠️ With MCP Apps, set `prefixMode: Never` (Kubernetes spelling) and keep tool names unique.
- ✅ 📄 **When one target fails:** by default the session's `tools/list` fails. `spec.mcp.failureMode: FailOpen` skips failed targets and serves the healthy ones; it still errors if all of them fail.
- **Docs:** [Virtual MCP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/virtual/)

### POC 20 · MCP catalog
- agentregistry (items 96-97, POC 16).

### POC 21 · Multi-tenancy in a central portal
- The gateway has per-team namespaces and route delegation; agentregistry has AccessPolicy.
- ⚠️ Tenant RBAC (tenant RBACPolicy) is on agentregistry main and **not yet released**. Say "next release."
- No central multi-cluster portal (item 47).
