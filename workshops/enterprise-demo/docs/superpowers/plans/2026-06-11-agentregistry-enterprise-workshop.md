# Enterprise agentregistry + Unified Keycloak SSO/RBAC — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the `enterprise-demo` workshop from OSS Agent Registry to Solo Enterprise for agentregistry, adding one shared Keycloak realm that provides SSO + RBAC across both agentregistry and kagent.

**Architecture:** A single Keycloak (realm `solo-ai-demo`, pre-baked via realm-import) is deployed first. Enterprise agentregistry installs against it with OIDC required. kagent's Solo Enterprise UI is pointed at the same realm for SSO (OBO stays disabled). RBAC is enforced via `AccessPolicy` (`ar.dev/v1alpha1`) resources mapping Keycloak groups to registry actions.

**Tech Stack:** Helm (OCI charts), Keycloak (realm-import), kind, `arctl` (enterprise), Kubernetes manifests, bash.

**Verification model:** This is an infra/workshop change with no unit-test suite. Each task's "test" is a concrete command + expected output (helm/kubectl/arctl). Commit after each task.

**Important — commits:** The repo owner uses a branch + PR workflow and asked not to push to main. Before Task 1, create a feature branch. Commit locally per task; do NOT push or open a PR unless the user asks.

---

## Pre-flight (do once before Task 1)

- [ ] **Create a feature branch**

```bash
cd /Users/coryjett/Documents/Workspace/Solo/solo-misc-workshops
git checkout -b workshop/agentregistry-enterprise
```

- [ ] **Re-read the spec**

Read `workshops/enterprise-demo/docs/superpowers/specs/2026-06-11-agentregistry-enterprise-workshop-design.md` start to finish so the four "Decisions to confirm" items are fresh.

All paths below are relative to `workshops/enterprise-demo/`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `keycloak/realm-solo-ai-demo.json` (new) | Realm import: 5 clients, 3 groups, 3 users, Groups + audience mappers. |
| `keycloak/keycloak.yaml` (new) | Keycloak Deployment + Service + realm-import ConfigMap. |
| `rbac/accesspolicy-admins.yaml` (new) | `admins` → `registry:*` + `runtime:*`. |
| `rbac/accesspolicy-developers.yaml` (new) | `developers` → read/publish/deploy. |
| `rbac/accesspolicy-viewers.yaml` (new) | `viewers` → read. |
| `setup.sh` (modify) | Deploy Keycloak; install enterprise agentregistry w/ OIDC; wire kagent issuer; enterprise arctl + login; apply RBAC; ns + port-forward updates. |
| `demo-guide.md` (modify) | Part 1 auth/RBAC beats; ns/port/product updates; trim to 45–50 min. |
| `README.md` (modify) | Enterprise rename, license prereq, URLs/ns, SSO note. |
| `architecture.md` / `.mmd` (modify) | Add Keycloak + OIDC/RBAC; regenerate `.png`. |

---

## Task 1: Keycloak realm-import JSON

**Files:**
- Create: `keycloak/realm-solo-ai-demo.json`

Realm `solo-ai-demo`. Clients per docs: `ar-backend` (confidential, service flow only), `ar-ui` (public, auth-code+PKCE, redirect/origins `*`), `ar-cli-interactive` (public, device grant), `ar-cli-password` (public, direct-access grant), `kagent-ui` (public, auth-code+PKCE). Each access-token-bearing client gets a `Groups` group-membership mapper and an audience mapper adding `ar-backend` to `aud`. Groups: `admins`, `developers`, `viewers`. Users: `admin`/`dev`/`viewer` (password `password`, in the matching group).

`${AR_BACKEND_SECRET}` is a literal placeholder token in this file; Task 5 substitutes it at deploy time.

- [ ] **Step 1: Write the realm file**

```json
{
  "realm": "solo-ai-demo",
  "enabled": true,
  "sslRequired": "none",
  "groups": [
    { "name": "admins" },
    { "name": "developers" },
    { "name": "viewers" }
  ],
  "users": [
    {
      "username": "admin", "enabled": true, "email": "admin@solo.io",
      "firstName": "Demo", "lastName": "Admin",
      "credentials": [{ "type": "password", "value": "password", "temporary": false }],
      "groups": ["/admins"]
    },
    {
      "username": "dev", "enabled": true, "email": "dev@solo.io",
      "firstName": "Demo", "lastName": "Dev",
      "credentials": [{ "type": "password", "value": "password", "temporary": false }],
      "groups": ["/developers"]
    },
    {
      "username": "viewer", "enabled": true, "email": "viewer@solo.io",
      "firstName": "Demo", "lastName": "Viewer",
      "credentials": [{ "type": "password", "value": "password", "temporary": false }],
      "groups": ["/viewers"]
    }
  ],
  "clients": [
    {
      "clientId": "ar-backend", "enabled": true, "protocol": "openid-connect",
      "publicClient": false, "secret": "${AR_BACKEND_SECRET}",
      "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "protocolMappers": [
        {
          "name": "groups", "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "claim.name": "Groups", "full.path": "false",
            "access.token.claim": "true", "id.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        }
      ]
    },
    {
      "clientId": "ar-ui", "enabled": true, "protocol": "openid-connect",
      "publicClient": true, "standardFlowEnabled": true,
      "redirectUris": ["*"], "webOrigins": ["*"],
      "attributes": { "pkce.code.challenge.method": "S256" },
      "protocolMappers": [
        {
          "name": "groups", "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "claim.name": "Groups", "full.path": "false",
            "access.token.claim": "true", "id.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        },
        {
          "name": "ar-backend-audience", "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.client.audience": "ar-backend",
            "access.token.claim": "true", "id.token.claim": "false"
          }
        }
      ]
    },
    {
      "clientId": "ar-cli-interactive", "enabled": true, "protocol": "openid-connect",
      "publicClient": true, "standardFlowEnabled": false,
      "attributes": { "oauth2.device.authorization.grant.enabled": "true" },
      "protocolMappers": [
        {
          "name": "groups", "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "claim.name": "Groups", "full.path": "false",
            "access.token.claim": "true", "id.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        },
        {
          "name": "ar-backend-audience", "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.client.audience": "ar-backend",
            "access.token.claim": "true", "id.token.claim": "false"
          }
        }
      ]
    },
    {
      "clientId": "ar-cli-password", "enabled": true, "protocol": "openid-connect",
      "publicClient": true, "standardFlowEnabled": false,
      "directAccessGrantsEnabled": true,
      "protocolMappers": [
        {
          "name": "groups", "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "claim.name": "Groups", "full.path": "false",
            "access.token.claim": "true", "id.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        },
        {
          "name": "ar-backend-audience", "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.client.audience": "ar-backend",
            "access.token.claim": "true", "id.token.claim": "false"
          }
        }
      ]
    },
    {
      "clientId": "kagent-ui", "enabled": true, "protocol": "openid-connect",
      "publicClient": true, "standardFlowEnabled": true,
      "redirectUris": ["*"], "webOrigins": ["*"],
      "attributes": { "pkce.code.challenge.method": "S256" },
      "protocolMappers": [
        {
          "name": "groups", "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "claim.name": "Groups", "full.path": "false",
            "access.token.claim": "true", "id.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        }
      ]
    }
  ]
}
```

- [ ] **Step 2: Validate JSON**

Run: `jq empty keycloak/realm-solo-ai-demo.json && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add keycloak/realm-solo-ai-demo.json
git commit -m "feat(workshop): add Keycloak realm import for unified SSO"
```

---

## Task 2: Keycloak deployment manifest

**Files:**
- Create: `keycloak/keycloak.yaml`

Plain manifest (no helm). Keycloak runs in `start-dev --import-realm`, realm mounted from a ConfigMap. `KC_HOSTNAME_STRICT=false` so tokens use the request host; the issuer string is made identical in-cluster and from the host in Task 5 via a hosts alias to the service DNS name.

The realm ConfigMap is generated from the file in Task 1 at apply time (Task 5) so the secret substitution flows through — this manifest contains only Deployment + Service.

- [ ] **Step 1: Write the manifest**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: keycloak
  labels: { app: keycloak }
spec:
  replicas: 1
  selector: { matchLabels: { app: keycloak } }
  template:
    metadata: { labels: { app: keycloak } }
    spec:
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:26.0
          args: ["start-dev", "--import-realm"]
          env:
            - { name: KC_BOOTSTRAP_ADMIN_USERNAME, value: "admin" }
            - { name: KC_BOOTSTRAP_ADMIN_PASSWORD, value: "admin" }
            - { name: KC_HTTP_ENABLED, value: "true" }
            - { name: KC_HOSTNAME_STRICT, value: "false" }
            - { name: KC_HEALTH_ENABLED, value: "true" }
          ports:
            - { containerPort: 8080, name: http }
          volumeMounts:
            - { name: realm, mountPath: /opt/keycloak/data/import }
          readinessProbe:
            httpGet: { path: /realms/solo-ai-demo, port: 8080 }
            initialDelaySeconds: 20
            periodSeconds: 5
            failureThreshold: 30
      volumes:
        - name: realm
          configMap: { name: keycloak-realm }
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: keycloak
  labels: { app: keycloak }
spec:
  selector: { app: keycloak }
  ports:
    - { name: http, port: 8080, targetPort: 8080 }
```

- [ ] **Step 2: Validate YAML (dry-run, no cluster needed)**

Run: `kubectl create namespace keycloak --dry-run=client -o yaml >/dev/null && python3 -c "import yaml,sys; list(yaml.safe_load_all(open('keycloak/keycloak.yaml'))); print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add keycloak/keycloak.yaml
git commit -m "feat(workshop): add Keycloak deployment manifest"
```

---

## Task 3: RBAC AccessPolicy manifests

**Files:**
- Create: `rbac/accesspolicy-admins.yaml`, `rbac/accesspolicy-developers.yaml`, `rbac/accesspolicy-viewers.yaml`

Schema confirmed from docs: `apiVersion: ar.dev/v1alpha1`, `kind: AccessPolicy`, `spec.principals[].{kind: Role, name}`, `spec.rules[].{actions[], resources[].{kind, name}}`. Applied via `arctl apply -f`.

- [ ] **Step 1: Write `rbac/accesspolicy-admins.yaml`**

```yaml
apiVersion: ar.dev/v1alpha1
kind: AccessPolicy
metadata:
  name: admins
spec:
  description: "Full access for platform admins"
  principals:
    - kind: Role
      name: admins
  rules:
    - actions: ["registry:*", "runtime:*"]
      resources:
        - { kind: server, name: "*" }
        - { kind: agent, name: "*" }
```

- [ ] **Step 2: Write `rbac/accesspolicy-developers.yaml`**

```yaml
apiVersion: ar.dev/v1alpha1
kind: AccessPolicy
metadata:
  name: developers
spec:
  description: "Developers can read, publish, and deploy"
  principals:
    - kind: Role
      name: developers
  rules:
    - actions: ["registry:read", "registry:publish", "registry:deploy"]
      resources:
        - { kind: server, name: "*" }
        - { kind: agent, name: "*" }
```

- [ ] **Step 3: Write `rbac/accesspolicy-viewers.yaml`**

```yaml
apiVersion: ar.dev/v1alpha1
kind: AccessPolicy
metadata:
  name: viewers
spec:
  description: "Read-only access to all artifacts"
  principals:
    - kind: Role
      name: viewers
  rules:
    - actions: ["registry:read"]
      resources:
        - { kind: server, name: "*" }
        - { kind: agent, name: "*" }
```

- [ ] **Step 4: Validate YAML**

Run: `for f in rbac/*.yaml; do python3 -c "import yaml; yaml.safe_load(open('$f')); print('$f OK')"; done`
Expected: three `... OK` lines.

- [ ] **Step 5: Commit**

```bash
git add rbac/accesspolicy-admins.yaml rbac/accesspolicy-developers.yaml rbac/accesspolicy-viewers.yaml
git commit -m "feat(workshop): add RBAC AccessPolicy manifests"
```

---

## Task 4: setup.sh — deploy Keycloak (new section before agentregistry)

**Files:**
- Modify: `setup.sh` (insert a new section between the namespaces/CRDs section ending at line 87 and the `# 3. Agent Registry` header at line 89)

Generates `AR_BACKEND_SECRET`, substitutes it into the realm JSON, creates the realm ConfigMap, applies the manifest, waits for readiness, and exports `KEYCLOAK_ISSUER`. Uses the in-cluster service DNS as the canonical issuer; Task 8 documents the host `/etc/hosts` alias so browser/device flows resolve the same string.

- [ ] **Step 1: Insert the Keycloak section**

Insert after line 87 (`ok "Namespaces and CRDs ready"`):

```bash
# ============================================================================
# 2b. Keycloak (shared IdP for agentregistry + kagent)
# ============================================================================
info "Deploying Keycloak..."
kubectl create namespace keycloak 2>/dev/null || true

export AR_BACKEND_SECRET="$(openssl rand -hex 32)"
export KEYCLOAK_HOST="keycloak.keycloak.svc.cluster.local:8080"
export KEYCLOAK_ISSUER="http://${KEYCLOAK_HOST}/realms/solo-ai-demo"

# Substitute the backend client secret into the realm import, then load as ConfigMap.
sed "s|\${AR_BACKEND_SECRET}|${AR_BACKEND_SECRET}|g" \
  "$(dirname "$0")/keycloak/realm-solo-ai-demo.json" > /tmp/realm-solo-ai-demo.json
kubectl create configmap keycloak-realm -n keycloak \
  --from-file=realm-solo-ai-demo.json=/tmp/realm-solo-ai-demo.json \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f "$(dirname "$0")/keycloak/keycloak.yaml"
kubectl -n keycloak rollout status deployment/keycloak --timeout=180s
rm -f /tmp/realm-solo-ai-demo.json
ok "Keycloak deployed (realm solo-ai-demo)"
```

- [ ] **Step 2: Syntax-check the script**

Run: `bash -n setup.sh && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add setup.sh
git commit -m "feat(workshop): deploy shared Keycloak in setup"
```

---

## Task 5: setup.sh — replace OSS agentregistry with enterprise chart

**Files:**
- Modify: `setup.sh:89-105` (the `# 3. Agent Registry` section)

- [ ] **Step 1: Replace the section**

Replace lines 89-105 (from `# 3. Agent Registry` through `ok "Agent Registry deployed"`) with:

```bash
# ============================================================================
# 3. Agent Registry (Enterprise)
# ============================================================================
info "Deploying Agent Registry Enterprise..."
helm upgrade --install agentregistry \
  oci://us-docker.pkg.dev/solo-public/agentregistry-enterprise/helm/agentregistry-enterprise \
  --version 2026.6.0 \
  --namespace agentregistry-system \
  --create-namespace \
  --set oidc.issuer="${KEYCLOAK_ISSUER}" \
  --set oidc.clientId=ar-backend \
  --set oidc.clientSecret="${AR_BACKEND_SECRET}" \
  --set oidc.publicClientId=ar-ui \
  --set oidc.roleClaim=Groups \
  --set oidc.superuserRole=admins \
  --set database.postgres.vectorEnabled=true \
  --wait --timeout 300s
ok "Agent Registry Enterprise deployed"
```

- [ ] **Step 2: Confirm license gating (Decision #1)**

Run: `helm show values oci://us-docker.pkg.dev/solo-public/agentregistry-enterprise/helm/agentregistry-enterprise --version 2026.6.0 2>/dev/null | grep -iA3 -e licens -e imagePullSecret || echo "no licensing/pull keys in values"`
- If a `licensing.licenseKey` (or similar) key exists: add `--set-string licensing.licenseKey="${AGENTREGISTRY_LICENSE_KEY:-$AGENTGATEWAY_LICENSE_KEY}"` to the helm command and re-commit.
- If only an image-pull secret is needed: the existing cluster's registry access covers it; leave as-is.
Expected: you can state definitively which path applies.

- [ ] **Step 3: Syntax-check**

Run: `bash -n setup.sh && echo OK`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add setup.sh
git commit -m "feat(workshop): install enterprise agentregistry with OIDC"
```

---

## Task 6: setup.sh — wire kagent to the shared realm

**Files:**
- Modify: `setup.sh` management values heredoc (currently `oidc: { issuer: "" }`, lines ~141-143) and keep workload `skipOBO: true`.

- [ ] **Step 1: Set the management issuer**

In the management values heredoc, change:

```yaml
oidc:
  issuer: ""
```

to:

```yaml
oidc:
  issuer: "${KEYCLOAK_ISSUER}"
  clientId: kagent-ui
```

Note: the management heredoc currently uses `<<'EOF'` (quoted, no expansion). Change its opener from `<<'EOF'` to `<<EOF` so `${KEYCLOAK_ISSUER}` expands. Verify no other `$` in that heredoc needs escaping (it contains only static product config — escape any literal `$` as `\$` if present).

- [ ] **Step 2: Leave workload OBO disabled**

Confirm the workload heredoc still contains `oidc:\n  skipOBO: true`. No change. (OBO is out of scope per spec non-goals.)

- [ ] **Step 3: Syntax-check**

Run: `bash -n setup.sh && echo OK`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add setup.sh
git commit -m "feat(workshop): point kagent UI SSO at shared realm"
```

---

## Task 7: setup.sh — enterprise arctl, login, RBAC, port-forward, ns

**Files:**
- Modify: `setup.sh:195-203` (arctl install), `setup.sh:215` (port-forward), `setup.sh:81` (namespace loop), plus a new RBAC apply + arctl login block.

- [ ] **Step 1: Switch arctl to the enterprise installer**

Replace the install line (currently `curl -fsSL https://raw.githubusercontent.com/agentregistry-dev/agentregistry/main/scripts/get-arctl | bash`) with:

```bash
  curl -sSL https://storage.googleapis.com/agentregistry-enterprise/install.sh | ARCTL_VERSION=v2026.6.0 sh
```

- [ ] **Step 2: Update the namespace loop**

In the `for ns in ...` loop (line 81), replace `agentregistry` with `agentregistry-system`. (Keycloak's ns is created in Task 4; the agentregistry-system ns is also `--create-namespace`'d by helm — keeping it in the loop is harmless and explicit.)

- [ ] **Step 3: Update the registry port-forward**

Replace `kubectl port-forward -n agentregistry svc/agentregistry 12121:12121 ...` with:

```bash
kubectl port-forward -n agentregistry-system svc/agentregistry-enterprise-server 12121:12121 &>/dev/null &
```

- [ ] **Step 4: Add Keycloak port-forward (for browser + device flows)**

Next to the other port-forwards, add:

```bash
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &>/dev/null &
```

- [ ] **Step 5: Add arctl login + RBAC seed block**

After arctl is installed and the registry is up, add:

```bash
# ----------------------------------------------------------------------------
# Seed RBAC (admin logs in, applies AccessPolicies)
# ----------------------------------------------------------------------------
info "Seeding RBAC policies..."
arctl user login --client ar-cli-password --username admin --password password
for p in rbac/accesspolicy-admins.yaml rbac/accesspolicy-developers.yaml rbac/accesspolicy-viewers.yaml; do
  arctl apply -f "$(dirname "$0")/$p"
done
ok "RBAC policies applied"
```

Note: confirm the exact `arctl user login` non-interactive flag names against `arctl user login --help` (Decision: password-grant flow via `ar-cli-password`). Adjust `--client/--username/--password` to match actual flags if they differ.

- [ ] **Step 6: Update the printed URLs**

In the final echo block, add `Keycloak: http://localhost:8080 (admin/admin)` and confirm the registry URL line still reads `http://localhost:12121`.

- [ ] **Step 7: Syntax-check + grep for stale references**

Run: `bash -n setup.sh && grep -n "agentregistry-dev\|svc/agentregistry " setup.sh || echo "no stale refs"`
Expected: `OK`-equivalent (exit 0) and `no stale refs`.

- [ ] **Step 8: Commit**

```bash
git add setup.sh
git commit -m "feat(workshop): enterprise arctl, SSO login, RBAC seed, ns/port updates"
```

---

## Task 8: Full setup.sh smoke run on a fresh kind cluster

This is the real integration test for Tasks 1–7. Requires Docker + kind + a valid license/registry access.

- [ ] **Step 1: Add the host alias so the issuer resolves identically**

The canonical issuer is `http://keycloak.keycloak.svc.cluster.local:8080/...`. For browser UI + device-flow logins from the host, that name must resolve to the port-forward. Add (one-time, document in README):

```bash
echo "127.0.0.1 keycloak.keycloak.svc.cluster.local" | sudo tee -a /etc/hosts
```

- [ ] **Step 2: Run setup**

Run: `./setup.sh` (with `OPENAI_API_KEY` and any license env set).
Expected: completes through "RBAC policies applied" with no failed rollout.

- [ ] **Step 3: Verify Keycloak realm + agentregistry health**

Run:
```bash
kubectl -n keycloak get pods
curl -s http://localhost:8080/realms/solo-ai-demo | jq -r .realm
kubectl -n agentregistry-system get pods
```
Expected: keycloak pod `Running`; curl prints `solo-ai-demo`; agentregistry pods `Running`/ready.

- [ ] **Step 4: Verify SSO + RBAC end to end**

Run:
```bash
arctl user login --client ar-cli-interactive   # device flow as 'dev'
arctl user whoami
```
Expected: `whoami` shows group `developers` with `configured` status.
Then attempt a publish as `viewer` and confirm a `forbidden` error; as `dev`/`admin` confirm publish succeeds. (Use the same publish command Part 1 of the demo uses.)

- [ ] **Step 5: Verify kagent UI SSO**

Open the Solo Enterprise UI; confirm it redirects to Keycloak and login as `admin` succeeds.

- [ ] **Step 6: Fix-forward any failures**

If a step fails, fix the relevant task's artifact, re-commit on the branch, and re-run from Step 2. Do not proceed to docs until the smoke run is green.

- [ ] **Step 7: Commit any fixes**

```bash
git add -A
git commit -m "fix(workshop): smoke-run corrections for enterprise setup"
```

---

## Task 9: demo-guide.md — Part 1 auth/RBAC beats + timing

**Files:**
- Modify: `demo-guide.md` (Part 1 section, the products line at top, the URLs/ports table near the end)

- [ ] **Step 1: Update the products + access lines**

Change the products line to name **Agent Registry (Enterprise)**. In the access block add `Keycloak: http://localhost:8080 (admin/admin)` and keep `Agent Registry: http://localhost:12121`.

- [ ] **Step 2: Add the SSO login beat (start of Part 1)**

Insert before "Open the Agent Registry UI": a short beat — open `http://localhost:12121`, get redirected to Keycloak, log in as `admin`. Talk track: "Enterprise registry is locked down — every user authenticates through your IdP. We're using Keycloak here; in your environment it's Okta, Entra, ForgeRock, whatever speaks OIDC."

- [ ] **Step 3: Add the `arctl user login` beat**

Before the first `arctl` publish step, add:
```
arctl user login        # device flow: opens browser, log in as 'dev'
arctl user whoami       # shows group 'developers' → configured
```

- [ ] **Step 4: Add the RBAC deny→grant beat**

After publish is shown, add a contrast: log in as `viewer`, attempt the publish, hit `forbidden`; run `arctl user whoami` (viewer → read-only); switch back to `dev`/`admin`; succeed. Talk track ties group → AccessPolicy.

- [ ] **Step 5: Trim to hold 45–50 min**

Update the timing table at the top of `demo-guide.md` (Part 1 now ~20–22 min). Trim redundant talk-track in the existing build/publish steps so the total stays ≤ 50 min. Confirm the running total in the table sums to ≤ 50.

- [ ] **Step 6: Replace stale ns/URL references**

Run: `grep -n "agentregistry\b\|anonymous\|enableAnonymousAuth" demo-guide.md`
Fix any remaining OSS-isms (namespace `agentregistry` → `agentregistry-system`, drop anonymous-auth language).

- [ ] **Step 7: Commit**

```bash
git add demo-guide.md
git commit -m "docs(workshop): add SSO + RBAC beats to Part 1, retime to <=50min"
```

---

## Task 10: README.md — Enterprise rename, license prereq, URLs

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rename + prereqs**

Rename Agent Registry → **Agent Registry (Enterprise)** in the intro/product lines. Add a Prerequisites bullet: a Solo license / registry access for enterprise charts, plus the one-time `/etc/hosts` alias from Task 8 Step 1. Add a line that all three products share one Keycloak SSO.

- [ ] **Step 2: Update URLs/namespaces**

Ensure any `agentregistry` namespace references become `agentregistry-system`, and add the Keycloak URL.

- [ ] **Step 3: Verify no stale OSS references**

Run: `grep -n "agentregistry-dev\|anonymous\|ghcr.io/agentregistry" README.md || echo "clean"`
Expected: `clean`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(workshop): README enterprise rename + license/SSO prereqs"
```

---

## Task 11: architecture.md / .mmd / .png — add Keycloak + OIDC/RBAC

**Files:**
- Modify: `architecture.md`, `architecture.mmd`; regenerate `architecture.png`

- [ ] **Step 1: Update `architecture.mmd`**

Add a `Keycloak` node in a new `keycloak` namespace box. Add OIDC arrows: `ar-ui`/`arctl`/`Solo Enterprise UI` → Keycloak (login), and agentregistry/kagent → Keycloak (issuer/JWKS). Rename the `agentregistry` namespace box to `agentregistry-system`.

- [ ] **Step 2: Update `architecture.md`**

Update the namespace/port table: add Keycloak (ns `keycloak`, port 8080), rename agentregistry ns, add an "Auth & RBAC" subsection describing the shared realm, groups, and AccessPolicy mapping.

- [ ] **Step 3: Regenerate the PNG**

Run: `npx -y @mermaid-js/mermaid-cli -i architecture.mmd -o architecture.png`
Expected: `architecture.png` regenerated (newer mtime). If `mmdc` is unavailable, note it in the commit and leave the PNG for the maintainer to regen.

- [ ] **Step 4: Commit**

```bash
git add architecture.md architecture.mmd architecture.png
git commit -m "docs(workshop): architecture diagram adds Keycloak SSO/RBAC"
```

---

## Task 12: Final consistency sweep

- [ ] **Step 1: Repo-wide stale-reference grep**

Run:
```bash
grep -rn "agentregistry-dev\|ghcr.io/agentregistry\|enableAnonymousAuth\|svc/agentregistry " . \
  --include="*.md" --include="*.sh" --include="*.yaml" --include="*.mmd" | grep -v docs/superpowers
```
Expected: no output. Fix anything that appears.

- [ ] **Step 2: Confirm time budget**

Re-read `demo-guide.md` timing table; confirm total ≤ 50 min.

- [ ] **Step 3: Commit any cleanups**

```bash
git add -A && git commit -m "docs(workshop): final consistency sweep" || echo "nothing to clean"
```

- [ ] **Step 4: Hand back to user**

Summarize what changed and ask whether to push the branch / open a PR (do not push unprompted).

---

## Self-Review (completed during authoring)

- **Spec coverage:** Keycloak topology → Tasks 1,2,4; enterprise install → Task 5; kagent wiring → Task 6; arctl + RBAC → Tasks 3,7; demo beats → Task 9; README → Task 10; architecture → Task 11; 45–50 min budget → Tasks 9.5, 12.2; smoke validation → Task 8. All spec sections mapped.
- **Decisions-to-confirm** from the spec are concrete verification steps, not placeholders: license gating (Task 5.2), issuer/hostname (Task 4.1 + Task 8.1), AR_BACKEND_SECRET (Task 4.1), pgvector (Task 5.1 sets `vectorEnabled=true`).
- **Type/name consistency:** realm `solo-ai-demo`, groups `admins`/`developers`/`viewers`, clients `ar-backend`/`ar-ui`/`ar-cli-interactive`/`ar-cli-password`/`kagent-ui`, issuer var `KEYCLOAK_ISSUER`, secret var `AR_BACKEND_SECRET`, ns `agentregistry-system`/`keycloak`, service `agentregistry-enterprise-server` — used identically across all tasks.
- **Residual risk (needs live cluster):** exact `arctl user login` flag names (Task 7.5) and the AccessPolicy `resources.kind` enum (`server`/`agent`) — both verified empirically in Task 8.
