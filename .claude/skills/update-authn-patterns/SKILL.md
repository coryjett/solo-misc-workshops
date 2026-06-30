---
name: update-authn-patterns
description: >
  Audit and update the Agentgateway-AuthN-Patterns workshop for a new
  Enterprise Agentgateway (AGW) release. TRIGGER when asked to: bump the
  workshop to the latest AGW version, audit the flows for accuracy/completeness
  before sharing, validate the flows, or add/fix flows. Encodes the
  release-comparison + per-flow validation methodology and the non-obvious
  gotchas learned the hard way.
---

# Updating the Agentgateway-AuthN-Patterns workshop

This workshop is **16 self-contained auth flows** (`Agentgateway-AuthN-Patterns/flows/flow-*`),
each `README.md` + `example/setup.sh` (+ `example/README.md`), sharing
`flows/common/{setup-env.sh,setup-base.sh,helpers.sh,deploy-keycloak.sh,cleanup.sh}`.
Plus `diagrams/` (mermaid `.mmd` sources), `images/` (rendered PNGs), a
`decision-flowchart`, `README.md`, and `agentgateway-auth-patterns.md`.

Goal of an update pass: keep it **accurate** (docs match what `setup.sh` actually
deploys, configs valid against the target AGW release) and **complete** (a flow
per meaningful auth capability; decision chart covers every flow) on the **latest
AGW Enterprise release**.

## Prerequisites
- `export AGENTGATEWAY_LICENSE_KEY="<gloo-trial or ent key>"` (required by every flow)
- `docker`, `kubectl`, `helm`, `k3d`, `curl`, `jq`, `openssl`, `python3`, `mmdc` (mermaid-cli)
- A local checkout of `agentgateway-enterprise` for source/CRD verification.

---

## Step 1 — Find the latest AGW release (and confirm it's coordinated)
```bash
# Probe chart versions (helm can't list tags directly; probe candidates):
for v in v2026.6.2 v2026.6.3 v2026.7.0; do
  echo -n "$v: "; helm show chart oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway --version "$v" 2>&1 | grep -E '^version:' || echo "not found"
done
# Confirm BOTH charts the workshop installs exist at that version (coordinated release):
for c in charts/enterprise-agentgateway charts/enterprise-agentgateway-crds; do
  helm show chart "oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/$c" --version <VER> | grep -E '^version:|^appVersion:'
done
```
Note the AGW version scheme is date-based (`v2026.6.2`), NOT the old `2.x.x`.

## Step 2 — Compare against the RELEASE, not a stale checkout (the key lesson)
Field/enum validity must be checked against the **shipped release**, because a local
`agentgateway-enterprise` checkout can be **several releases behind** and miss new
capabilities or deprecations.
```bash
cd <agentgateway-enterprise>
git fetch --tags
git worktree add -q --detach /tmp/agw-<ver> v<ver>   # clean read-only tree at the tag
# CRDs as shipped:
helm pull oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds --version v<ver> --untar --untardir /tmp/agw-crds-<ver>
# Deprecations/removals affecting the flows (diff the policy types between the prior + new tag):
git diff v<prev> v<ver> -- ent-controller/api/v1alpha1/enterpriseagentgateway/enterprise_agentgateway_policy_types.go
```
Enumerate the **auth-relevant policy types** in the new release (traffic + backend)
and map each to a flow; anything with no flow is a **completeness gap** (candidate
new flow). Authoritative source paths:
- Enterprise policy: `ent-controller/api/v1alpha1/enterpriseagentgateway/enterprise_agentgateway_policy_types.go`
- OSS policy/transform/TLS: `controller/api/v1alpha1/agentgateway/agentgateway_policy_types.go`
- CEL context (what `jwt`/claims are available): `crates/agentgateway/src/cel/types.rs`

## Step 3 — Bump the version
- `flows/common/helpers.sh`: `AGW_VERSION="${AGW_VERSION:-v<ver>}"` (single source of truth; all flows inherit it)
- Any flow README that names a specific version (e.g. flow-12) → say it inherits the shared default
- Doc links: standardize to `https://docs.solo.io/agentgateway/latest/...`
  (`find . -name '*.md' -exec sed -i '' 's#agentgateway/2\.2\.x/#agentgateway/latest/#g' {} \;`)

## Step 4 — Audit each flow for accuracy
For every flow check the README's claims against what `example/setup.sh` ACTUALLY
deploys, and validate config field/enum names against the Step-2 CRD/source:
- **"Documents X but does Y"** is the most common bug. Real examples found: a README
  claiming CEL claim-mapping while deploying a static key; a "delegation" flow that
  produces impersonation; a "gRPC ext_authz" flow that deploys the HTTP variant.
- Enum strings: the CRD enum is `ElicitationOnly`/`ExchangeOnly` (the internal source
  name `ElicitOnly` is NOT a valid value).
- Schema shape: traffic JWT is `traffic.jwtAuthentication.providers[].jwks.remote.backendRef`
  (not flat `jwtAuthentication.jwks.backendRef`).
- `backend.mcp.authentication` is deprecated in favor of `traffic.jwtAuthentication.mcp`
  (still works; mutually exclusive).
- Test snippets must use the shared realm `agw-demo` (not `flowNN-realm`).
- No real secrets — only env-var placeholders / obvious demo values. `.workload/` keys
  are generated; keep them gitignored.

## Step 5 — Validate flows (ONE FRESH CLUSTER PER FLOW)
**Flows collide in the `default` namespace** (`echo-backend`, gateway names, etc.), so
running several on one cluster contaminates results — and `cleanup.sh` deletes the
WHOLE cluster (there is no per-flow resource cleanup). So validate each flow on a
fresh cluster:
```bash
cd flows/flow-XX/example
export AGENTGATEWAY_LICENSE_KEY=... CLUSTER_NAME=agwt-fXX
( k3d cluster delete agwt-fXX >/dev/null 2>&1; ./setup.sh ) > /tmp/fXX.log 2>&1 &
# Poll on pgrep — background-task completion notifications fire PREMATURELY here:
for i in $(seq 1 60); do sleep 6; pgrep -f setup.sh >/dev/null || break; done
tail -20 /tmp/fXX.log | cut -c1-160
```
To hit the gateway with a correctly-issued token, the Keycloak `iss` must match the
policy's expected issuer — fetch via the in-cluster host:
```bash
curl ... -H "Host: keycloak.keycloak.svc.cluster.local:8080" .../realms/agw-demo/.../token
```

## Gotchas (each cost real debugging time)
- **Compare against the release tag, not the local checkout** — it lags releases.
- **Cross-flow contamination**: one flow per fresh cluster; `cleanup.sh` nukes the cluster.
- **Premature background notifications**: the `( k3d delete; ./setup.sh ) &` wrapper's
  "completed" fires early; poll `pgrep -f setup.sh` and check cluster resources instead.
- **Experimental Gateway-API channel** (needed for `spec.tls.frontend` client-cert mTLS,
  flow-mtls): (1) install it **from the start** via `GATEWAY_API_CHANNEL=experimental`
  before sourcing setup-env — you canNOT `kubectl apply` experimental over an
  already-installed standard channel (patch rejected); (2) it MUST be `kubectl apply
  --server-side --force-conflicts` (the HTTPRoute CRD exceeds the 256KB client-side
  annotation limit). `setup-base.sh` is parameterized for this.
- **Backticks inside an unquoted heredoc** (`<<EOF`) run as command substitution — never
  put `` `...` `` in YAML comments in setup.sh heredocs (use plain text).
- **`HTTP_CODE=$(curl -w "%{http_code}" ... || echo "000")`** double-counts: curl's `-w`
  already prints `000` on connection failure, so `|| echo "000"` yields `000000`. Use
  `|| true`. (A no-client-cert mTLS rejection legitimately returns `000` / curl exit 56.)
- **Interactive flows can't be fully headless**: elicitation (flow-03), double-OAuth
  (flow-04), and eager-consent (flow-04b) need a browser + real upstream OAuth provider
  to complete consent/upstream-OAuth. Validate the headless part (e.g. 401 +
  protected-resource metadata) and document the interactive completion.
- **Gateway-mediated `tokenExchange` is impersonation, not delegation** — it never sends
  an `actor_token`, so no `act` claim. True delegation (dual `sub`+`act`) requires an
  AGENT-initiated RFC 8693 call with `subject_token`+`actor_token` (+ `may_act` on the
  user JWT). Don't claim delegation for the gateway-mediated path.
- **Claim-based token mapping** = `traffic.transformation.request.set` with a
  `HeaderTransformation.value` CEL expression over `jwt.*` claims (validated). NOT a
  static backend `auth.key`. CEL injects the full header value (`"Bearer " + ...`), so
  no auto-`Bearer ` double-prefix.

## Step 6 — Decision chart
If flows were added/changed, edit `diagrams/decision-flowchart.mmd` and re-render:
```bash
cd diagrams && mmdc -i decision-flowchart.mmd -o ../images/decision-flowchart.png -s 3 -b white
```
Confirm every one of the 16 flows appears in the tree.

## Step 7 — Docs + commit discipline
Update `README.md`, `agentgateway-auth-patterns.md`, per-flow READMEs. Verify all
internal markdown links resolve and `images/*` referenced from at least one doc.
**Commit per flow, only after it validates** — small focused commits with the
validation evidence in the message (this repo allows direct-to-`main`).

## Quick reference — what each AGW capability maps to
- OIDC/JWT validation → `traffic.jwtAuthentication` (flows 01, 12)
- Token exchange / STS → `backend.tokenExchange` (`.oauth` generic, `.elicitation`, `.entra` OBO) (flows 02/03/04/04b/13)
- API key / basic → `traffic.apiKeyAuthentication` / `basicAuthentication` (flows 08, 09)
- ext_authz (Envoy `service.auth.v3`, gRPC or HTTP) → `traffic.extAuth` (flow 10)
- backend credential injection → `AgentgatewayBackend.policies.auth.{secretRef|passthrough}` (flows 05, 06)
- claim→credential mapping → `traffic.transformation` + CEL (flow 07)
- MCP OAuth + DCR → `backend.mcp.authentication` / `traffic.jwtAuthentication.mcp` (flows 11, 13)
- frontend mTLS → Gateway API `spec.tls.frontend.default.validation.caCertificateRefs` (experimental channel) (flow-mtls)
- (newer, not yet flows) `workloadIdentity` (WIMSE), `authorization`, `entExtAuth`, Entra OBO
