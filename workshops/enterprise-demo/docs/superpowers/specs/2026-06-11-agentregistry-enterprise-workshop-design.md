# Switch enterprise-demo workshop to enterprise agentregistry (unified Keycloak SSO + RBAC)

**Date:** 2026-06-11
**Status:** Approved design, pre-implementation
**Scope:** One implementation plan / one PR-sized change.

## Goal

Convert the `enterprise-demo` workshop from **OSS** Agent Registry to **Solo Enterprise for agentregistry**, and use the enterprise edition's mandatory OIDC to introduce a single, shared Keycloak that provides **SSO + RBAC across both agentregistry and kagent**. Result is a "full enterprise showcase" that still fits a **45–50 minute** run.

## Why

- Enterprise agentregistry has **no anonymous-auth mode** — it requires an OIDC issuer. The current workshop runs OSS agentregistry with `enableAnonymousAuth=true`, so the switch forces an IdP into the picture.
- The current workshop installs **kagent Enterprise with OIDC stubbed off** (`oidc.issuer: ""`, `skipOBO: true`, `secret: "dummy-not-used"`). There is no IdP deployed today.
- Rather than two disjoint auth stories, stand up **one Keycloak realm** and wire both products to it — one login everywhere, group-based RBAC. This is the enterprise differentiator the showcase is meant to demonstrate.

## Non-goals

- **kagent OBO / token-exchange** stays disabled (`skipOBO: true`). Wiring real OBO would push past the 50-minute budget. Called out as a future extension only.
- No new MCP servers, agents, or demo content beyond the auth/RBAC beats. The build/publish/deploy flow in Part 1 is preserved.
- No unrelated refactoring of the existing workshop.

## Current state (baseline)

| File | Current behavior |
|------|------------------|
| `setup.sh:90-105` | Installs OSS chart `oci://ghcr.io/agentregistry-dev/agentregistry/charts/agentregistry` into ns `agentregistry`, anonymous auth, bundled pgvector, random JWT key. |
| `setup.sh:127-192` | kagent Enterprise with `oidc.issuer: ""` (mgmt) and `skipOBO: true` (workload) — auth off. |
| `setup.sh:195-203` | arctl installed from OSS `agentregistry-dev/agentregistry` `get-arctl` script. |
| `setup.sh:215-222` | Port-forward `svc/agentregistry 12121`. |
| `README.md`, `architecture.md/.mmd/.png`, `demo-guide.md` | All reference OSS "Agent Registry", ns `agentregistry`, anonymous UX, no IdP. |

## Target architecture

### Auth topology (new)
- **One Keycloak**, realm `solo-ai-demo`, deployed in its own namespace (`keycloak`).
- **Realm-import**: realm + clients + groups + demo users are baked into a JSON imported on pod start (`start --import-realm`). **Zero live Keycloak admin clicking** during the demo.
- Groups: `admins`, `developers`, `viewers`.
- Clients in the realm:
  - `ar-backend` — confidential; agentregistry server token validation.
  - `ar-ui` — public, PKCE; registry UI browser login.
  - `ar-cli-interactive` — public, device-authorization grant; `arctl user login`.
  - `ar-cli-password` — public, password grant; scripted/CI login.
  - `kagent-ui` — public; Solo Enterprise UI SSO login.
- Protocol mappers on each client: a `Groups` claim mapper + audience mappers so `oidc.roleClaim=Groups` resolves.
- Demo users: `admin` (group `admins`), `dev` (group `developers`), `viewer` (group `viewers`).

### Enterprise agentregistry install (replaces OSS block)
```bash
helm upgrade --install agentregistry \
  oci://us-docker.pkg.dev/solo-public/agentregistry-enterprise/helm/agentregistry-enterprise \
  --version 2026.6.0 \
  --namespace agentregistry-system \
  --create-namespace \
  --set oidc.issuer="$KEYCLOAK_ISSUER" \
  --set oidc.clientId=ar-backend \
  --set oidc.clientSecret="$AR_BACKEND_SECRET" \
  --set oidc.publicClientId=ar-ui \
  --set oidc.roleClaim=Groups \
  --set oidc.superuserRole=admins \
  [database/pgvector flags carried over as needed] \
  --wait --timeout 300s
```
- Image source: `us-docker.pkg.dev/agentregistry/enterprise/server`.
- No separate CRDs chart (single chart, confirmed from agentcore quickstart).
- UI: `kubectl -n agentregistry-system port-forward svc/agentregistry-enterprise-server 12121:12121`.

### kagent wired to the same realm
- Flip management values `oidc.issuer: ""` → `oidc.issuer: "$KEYCLOAK_ISSUER"`.
- Add the matching public client (`kagent-ui`) so the Solo Enterprise UI does SSO login against the shared realm.
- **Keep** `skipOBO: true` (workload). OBO is explicitly out of scope.

### arctl (enterprise)
- Replace OSS install with:
  ```bash
  curl -sSL https://storage.googleapis.com/agentregistry-enterprise/install.sh | ARCTL_VERSION=v2026.6.0 sh
  ```
- Add a login step: `arctl user login` (device flow via `ar-cli-interactive`).

### RBAC (new)
- Enterprise agentregistry has **no predefined roles** — RBAC is `AccessPolicy` resources whose `principals` (`kind: Role`, `name: <group>`) match the JWT `Groups` claim.
- Seed three policies, applied in `setup.sh` via `arctl apply -f`:
  - `admins` → `registry:*` + `runtime:*` (all resources).
  - `developers` → `registry:read`, `registry:publish`, `registry:deploy`.
  - `viewers` → `registry:read`.
- Verified in-demo with `arctl user whoami` (shows group → `configured` status) and `forbidden` errors when no policy allows an action.

## New files

```
keycloak/realm-solo-ai-demo.json        # realm import: clients, groups, mappers, demo users
keycloak/keycloak.yaml                   # Keycloak Deployment + Service + realm-import ConfigMap (plain manifest)
rbac/accesspolicy-admins.yaml
rbac/accesspolicy-developers.yaml
rbac/accesspolicy-viewers.yaml
```

Decision: **plain Keycloak manifest** (not bitnami helm) — lighter and more reproducible for a single-cluster workshop.

## File-level change map

| File | Change |
|------|--------|
| `setup.sh` | New Keycloak section before agentregistry; replace OSS agentregistry install with enterprise chart + OIDC; flip kagent `oidc.issuer`; add `kagent-ui` client wiring; switch arctl install + add `arctl user login`; apply RBAC `AccessPolicy` manifests; rename ns `agentregistry` → `agentregistry-system`; update port-forward service name. |
| `demo-guide.md` | Part 1 gains three beats: SSO login to registry UI (`admin`); `arctl user login` device flow; RBAC deny→grant (`viewer` publish → `forbidden` → `arctl user whoami` → admin policy → retry succeeds). Keep build/publish/deploy. Trim filler talk-track elsewhere to hold 45–50 min. Update ports, namespaces, product names. |
| `README.md` | Rename to "Enterprise" throughout; add **license key** prerequisite; update URLs/namespaces; note shared Keycloak SSO. |
| `architecture.md` | Add Keycloak + OIDC/RBAC description; rename namespace; update product/port table. |
| `architecture.mmd` | Add Keycloak node + OIDC arrows to both agentregistry and kagent; rename ns. |
| `architecture.png` | Regenerate from `.mmd` via existing mermaid tooling (`mmdc`). |

## Time budget (45–50 min)

| Part | Before | After | Note |
|------|--------|-------|------|
| Part 1 (Agent Registry) | ~15 min | ~20–22 min | +SSO login, +`arctl user login`, +RBAC deny→grant. Pre-baked realm keeps it tight. |
| Parts 2+ (Gateway, kagent) | unchanged | unchanged | kagent UI now SSO-logs-in (≈30s), no extra narrative. |

Mitigation: trim redundant talk-track in Part 1 build/publish steps so net runtime stays ≤ 50 min. The realm-import (no live Keycloak config) is the primary time-saver.

## Decisions to confirm during planning

These have a chosen default; confirm before/while implementing — do not block design on them.

1. **License gating.** The enterprise agentregistry helm command in the docs shows **no `licensing.licenseKey` flag** (unlike AGW/kagent). License is listed as a prerequisite, so entitlement is likely gated via **image-pull access** to `us-docker.pkg.dev`, not a helm value. **Default:** install with no license flag; add image-pull secret only if the pull fails. Confirm against the quickstart used for the workshop's target environment.
2. **`KEYCLOAK_ISSUER` value.** Realm discovery URL form `http://<keycloak-svc>.<ns>.svc:8080/realms/solo-ai-demo` for in-cluster, vs a port-forwarded/host URL the browser (UI/device flow) can also reach. **Default:** use a single host-reachable issuer (port-forward or NodePort) so browser PKCE + device flow and in-cluster validation share one URL. Confirm Keycloak hostname strategy for kind.
3. **`AR_BACKEND_SECRET`.** Generated at setup time and injected into both the realm import (client secret) and the helm `oidc.clientSecret`. **Default:** `openssl rand -hex 32`, templated into the realm JSON before import.
4. **pgvector/database flags.** Enterprise chart bundles postgres (`database.postgres.bundled`). **Default:** rely on chart defaults; carry over `vectorEnabled`/pgvector image overrides only if semantic search requires them (it did in OSS).

## Success criteria

- `setup.sh` runs clean on a fresh kind cluster: Keycloak up with imported realm; agentregistry-enterprise healthy on OIDC; kagent UI SSO-logs-in against the same realm.
- `arctl user login` succeeds via device flow; `arctl user whoami` shows the user's group as `configured`.
- RBAC demonstrably enforced: `viewer` is denied publish (`forbidden`); `admin`/`developer` can publish/deploy.
- Existing Part 1 build → publish → deploy flow still works end-to-end.
- README/architecture/demo-guide consistently say "Enterprise", correct namespaces/ports, and include the Keycloak/SSO/RBAC story.
- Full walkthrough fits 45–50 minutes.
