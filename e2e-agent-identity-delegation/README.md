# End-to-End Agent Identity, Authorization, and Delegation

Deploy an agent and its MCP servers, register and govern them in Agentregistry Enterprise, then secure every hop (user, agent, MCP server, API) with Enterprise Agentgateway: JWT authentication, CEL authorization, and RFC 8693 token exchange that carries the user's identity through the chain with the agent's identity attached. Solo Enterprise for kagent is an optional last step for teams that want the registry to deploy workloads into the cluster.

Validated from an empty KinD cluster with Enterprise Agentgateway v2026.9.0, Agentregistry Enterprise 2026.9.0, and Keycloak 26. Every `Expected output` block is an observed result.

Running against your own cluster, Keycloak, gateway or Solo UI rather than a fresh
KinD one? Read [bring-your-own.md](bring-your-own.md) first. For what changes in
production and what this lab does not cover, see [production.md](production.md).

## Contents

- [Files in this folder](#files-in-this-folder)
- [Prerequisites](#prerequisites)
- [What you will do](#what-you-will-do)
- [Background](#background)
- [Step 1: Install the platform](#step-1-install-the-platform)
- [Step 2: Deploy Keycloak with the agentregistry realm](#step-2-deploy-keycloak-with-the-agentregistry-realm)
- [Step 3: Install the Solo UI](#step-3-install-the-solo-ui)
- [Step 4: Deploy the agent, MCP servers, and API](#step-4-deploy-the-agent-mcp-servers-and-api)
- [Step 5: Install arctl and Agentregistry Enterprise](#step-5-install-arctl-and-agentregistry-enterprise)
- [Step 6: Register the workloads in the catalog](#step-6-register-the-workloads-in-the-catalog)
- [Step 7: Publish the MCP servers through agentgateway from the registry](#step-7-publish-the-mcp-servers-through-agentgateway-from-the-registry)
- [Step 8: Govern catalog visibility](#step-8-govern-catalog-visibility)
- [Step 9: Mint user tokens and inspect claims](#step-9-mint-user-tokens-and-inspect-claims)
  - [What `may_act` is for](#what-may_act-is-for)
  - [Point the policies at your issuer](#point-the-policies-at-your-issuer)
- [Step 10: Create the gateway and enforce user to agent authorization](#step-10-create-the-gateway-and-enforce-user-to-agent-authorization)
  - [Using a gateway you already have](#using-a-gateway-you-already-have)
- [Step 11: Enforce agent to MCP authorization](#step-11-enforce-agent-to-mcp-authorization)
- [Step 12: Enable the STS and exchange for a delegated token](#step-12-enable-the-sts-and-exchange-for-a-delegated-token)
  - [When the exchange fails](#when-the-exchange-fails)
- [Step 13: Restrict the API to delegated identities](#step-13-restrict-the-api-to-delegated-identities)
- [Step 14: MCP server calls the API through the gateway](#step-14-mcp-server-calls-the-api-through-the-gateway)
- [Step 15: Validate in the Solo UI](#step-15-validate-in-the-solo-ui)
  - [Enable tracing](#enable-tracing)
  - [Read the results](#read-the-results)
- [Step 16 (optional): Deploy from the registry with Solo Enterprise for kagent](#step-16-optional-deploy-from-the-registry-with-solo-enterprise-for-kagent)
- [Validation checklist](#validation-checklist)
- [Cleanup](#cleanup)

## Files in this folder

Files are numbered in the order they are applied: `00` platform and test client, `01` Solo UI,
`02` workloads, `03` Agentregistry, `04` catalog and publishing, `05` gateway and policies, `10`
optional Solo Enterprise for kagent. Each step names the files it uses and explains what they do,
so this is orientation rather than a reference you need to read first.

## Prerequisites

Everything on-cluster is deployed by this lab. Locally you need:

- kubectl, helm, python3
- kind, only if you want a local cluster created by `00-kind.sh`
- A Solo.io enterprise license key

Bringing your own cluster: skip `00-kind.sh`. `00-platform.sh` installs into whatever `kubectl config current-context` points at and never creates a cluster.

## What you will do

1. Install the platform, Keycloak, and the Solo UI (Steps 1 to 3)
2. Deploy the agent, MCP servers, and API (Step 4)
3. Install Agentregistry Enterprise, register the workloads, publish the MCP servers through agentgateway from the registry, and govern who sees what (Steps 5 to 8)
4. Mint user tokens and secure every hop with Enterprise Agentgateway: user to agent, agent to MCP, delegation through the STS, MCP or agent to API, MCP server to API (Steps 9 to 14)
5. Validate in the Solo UI (Step 15)
6. Optional: let the registry deploy workloads into the cluster through Solo Enterprise for kagent (Step 16)

## Background

At every hop the question is the same: who is calling, and are they allowed to call this? alice reaches agent-x with her JWT and bob gets 403 (Step 10). The agent reaches mcp-a and is refused by mcp-b (Step 11). The agent exchanges the user JWT plus its own ServiceAccount token at the built-in STS on port 7777 for a delegated token with `sub: alice` and `act: agent` (Step 12). The API accepts that delegated token and refuses a raw user token (Steps 13 and 14).

Why not forward the user's token: it says nothing about which agent is acting, can be replayed against any route the user could reach, and grants the agent everything the user has. The delegated token is signed by the STS, carries both identities, and is only accepted where STS-issued tokens are trusted.

This is delegation, not impersonation. The agent keeps its own identity the whole way through. The delegated token says alice asked for this and agent-x is the one doing it, and both names stay in the token for every remaining hop. An impersonation token would carry alice alone, and nothing downstream could tell whether alice made the request herself or an agent made it for her. That difference is what makes the chain auditable, and it is what the `act` claim in the expected output below is showing you.

Two gateways do two different jobs. `agentregistry-gateway` (Step 7) is a proxy you hand to Agentregistry so the registry can write routes onto it, which is how teams publish MCP servers without authoring gateway config themselves. `e2e-gw` (Step 10) is a proxy you author yourself, and it is where this workshop hangs the authorization and delegation policies so you can read them in a file. Both are Enterprise Agentgateway. Neither one puts the registry in the request path.

---

## Step 1: Install the platform

Local KinD cluster (skip this if you are bringing your own cluster):

```bash
./00-kind.sh
```

`00-platform.sh` installs the Gateway API CRDs and both Enterprise Agentgateway charts into the current kubeconfig context, and deploys the `sleep` test client:

```bash
export LICENSE_KEY=<solo-enterprise-license-key>
./00-platform.sh
```

Docs: [Install with Helm](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/helm/)

Expected output (truncated):

```
deployment "enterprise-agentgateway" successfully rolled out
NAME                      CONTROLLER                        ACCEPTED   AGE
enterprise-agentgateway   solo.io/enterprise-agentgateway   True       2s
deployment "sleep" successfully rolled out
PLATFORM-READY
```

The `sleep` pod's ServiceAccount (`system:serviceaccount:wp-a:default`) is the agent's workload identity: the actor token in Step 12 and the `jwt.act.sub` Step 13 authorizes on.

---

## Step 2: Deploy Keycloak with the agentregistry realm

```bash
kubectl apply -f 00-keycloak.yaml
kubectl -n keycloak rollout status deploy/keycloak --timeout=300s
```

The realm is imported from a ConfigMap at boot, so a restart re-imports it. It is the `agentregistry` realm from the Agentregistry Enterprise docs (clients `ar-backend`, `ar-cli-interactive`, `ar-cli-password`, `ar-ui`, `ar-mcp-client`; `Groups` claim; `ar-backend` audience; group `admins`; user `admin-user` with password `password`) plus what this lab adds:

- Client `agw-client` (confidential, secret `agw-client-secret`) with the `Groups` mapper and a `may_act` mapper naming the agent's ServiceAccount
- Users `alice` and `bob` (password `pw`); alice is in group `agent-x-users`
- Groups `readers` and `writers` with users `reader` and `writer` (password equals username)
- Clients `kagent-backend` and `kagent-ui` for the Solo UI, and `agentregistry` (service account in group `agentregistry`) for the optional kagent step
- Access token lifespan of one hour, so tokens minted in Step 9 last through the lab

The STS refuses a delegation exchange unless the user's token carries a `may_act` claim naming the actor. The identity provider decides which agent may act on the user's behalf (RFC 8693 section 4.4).

Already running Keycloak with the `agentregistry` realm? Skip the apply and import only the additions:

```bash
kubectl exec -i -n keycloak deploy/keycloak -- bash -c 'cat > /tmp/add.json && /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin && /opt/keycloak/bin/kcadm.sh create partialImport -r agentregistry -s ifResourceExists=SKIP -o -f /tmp/add.json' < realm/workshop-additions.json
```

**A docs-quickstart Keycloak will lose this on restart.** The Agentregistry docs deploy Keycloak with
`args: ["start-dev", "--import-realm"]`, an embedded H2 store, no database and no volume. It re-imports
only its realm ConfigMap at boot, so anything added with `partialImport` is gone after a restart,
eviction or node drain, and every token mint fails afterwards with `invalid_grant`. To make the
additions durable, merge them into that ConfigMap instead:

```bash
./realm/merge-additions.sh <realm-configmap-name> <namespace> > /tmp/realm-cm.yaml
kubectl apply -f /tmp/realm-cm.yaml
kubectl rollout restart deploy/keycloak -n <namespace>
```

The script is idempotent and only adds what is missing. Check first whether yours is ephemeral:

```bash
kubectl get deploy keycloak -n keycloak -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}'
kubectl get pvc -n keycloak
```

`start-dev` with no PVC and no `KC_DB` means in-memory.

`kcadm.sh` ships in the Keycloak image, and `partialImport` with `ifResourceExists=SKIP` adds only what is missing. Nothing already in your realm is changed. Adjust three things in that command for your deployment:

- `-n keycloak deploy/keycloak`: the namespace and workload where your Keycloak runs (`sts/<name>` for a StatefulSet)
- `--user admin --password admin`: your bootstrap admin credentials
- `--server http://localhost:8080`: works when HTTP is enabled inside the pod, which the docs `start-dev` deployment does. A production-mode Keycloak with HTTPS only needs `https://localhost:8443` or your external URL

Then set the issuer in `01-ui.sh`, `03-registry-values.yaml`, `05-agent-authz.yaml`, `05-mcp-authz.yaml`, `05-mcp-api-authz.yaml`, and `05-sts-values.yaml` to your Keycloak URL. Two things the import does not change: your realm keeps its own access token lifespan (Keycloak's default is 5 minutes), so re-run the Step 9 exports if a request returns 401 unexpectedly; and the `agentregistry` client arrives with the lab's fixed secret, so set your own and export it as `AGENTREGISTRY_CLIENT_SECRET` before Step 16.

Confirm the import with the Step 9 decode: alice's token must show both `Groups` and `may_act`.

---

## Step 3: Install the Solo UI

`01-ui.sh` installs the Solo UI (management chart, agentgateway product) into namespace `kagent`, with sign-in through the realm. The optional kagent step upgrades this same release, so there is one UI for the whole lab.

```bash
./01-ui.sh
```

Expected output ends with:

```
deployment "solo-enterprise-ui" successfully rolled out
UI-READY
```

The UI, and later the registry UI, sign you in through Keycloak in the browser. What matters is that
the address your browser lands on is the same string Keycloak stamps as `iss`, because that is what
the servers trust. This lab's Keycloak stamps an in-cluster Service name, which a browser cannot
resolve, so the `/etc/hosts` entry below points that name at a port-forward.

Bringing your own Keycloak? If it is already reachable at the address it stamps as `iss`, browse to
it directly and skip both the hosts entry and the Keycloak port-forward. You still want the
`solo-enterprise-ui` port-forward.

```bash
echo "127.0.0.1 keycloak.keycloak.svc.cluster.local" | sudo tee -a /etc/hosts
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &
kubectl port-forward -n kagent svc/solo-enterprise-ui 4000:80 &
```

Open http://localhost:4000 and sign in as `admin-user` / `password` (group `admins`, mapped to `global.Admin`). The gateway pages fill in from Step 10 on.

Already running the Solo UI? Skip this script. A cluster holds one management release, because its CRDs are cluster-scoped. Set `MGMT_RELEASE` and `MGMT_NAMESPACE` to your release before Step 16 so that step upgrades it in place, and make sure the release has `products.agentgateway.enabled=true` (the agentgateway UI docs set it). Tracing needs that namespace too; Step 15 covers it. Sign in with any user in a group your release maps to `global.Admin` or `global.Reader`.

Docs: [Set up the UI](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/ui/setup/)

---

## Step 4: Deploy the agent, MCP servers, and API

`02-workloads.yaml` creates namespace `e2e-demo` with plain Deployments and Services: `agent-x` (httpbin stands in for the agent), `mcp-a` and `mcp-b` (both `mcp-website-fetcher`, SSE on port 8000), and `api-backend` (httpbin). Nothing here knows about the gateway or the registry yet.

```bash
kubectl apply -f 02-workloads.yaml
kubectl -n e2e-demo rollout status deploy/agent-x deploy/mcp-a deploy/mcp-b deploy/api-backend --timeout=180s
```

`02-mcp-api.yaml` deploys `mcp-api`, an MCP server with one tool, `httpbin_get(path)`. The tool calls the API at `API_BASE` and forwards the bearer token it received. `API_BASE` defaults to the `/api` route on `e2e-gw` (created in Step 10); set it to an existing API gateway to route through that instead. The manifest uses the public image `ghcr.io/coryjett/e2e-mcp-api:v1` (amd64 and arm64), so nothing needs building. Source and Dockerfile are in `mcp-api/`; to change the server, build for your node architecture, push to a registry the cluster can pull from, and set `image:` to that reference:

```bash
docker build --platform linux/amd64 -t <registry>/<repo>/mcp-api:v1 mcp-api/
docker push <registry>/<repo>/mcp-api:v1
```

```bash
kubectl apply -f 02-mcp-api.yaml
kubectl -n e2e-demo rollout status deploy/mcp-api --timeout=120s
```

The MCP `Service` ports carry `appProtocol: agentgateway.dev/mcp`, which the gateway backends in Step 11 require.

---

## Step 5: Install arctl and Agentregistry Enterprise

```bash
curl -sSL https://storage.googleapis.com/agentregistry-enterprise/install.sh | ARCTL_VERSION=v2026.9.0 sh
export PATH=$HOME/.arctl/bin:$PATH
arctl version --json

./03-registry-install.sh
```

The script installs the registry (ClusterIP, bundled PostgreSQL and ClickHouse, OIDC against the realm with `Groups` as the role claim, `admins` as the superuser group, and `ar-ui` as the browser client). Expected output ends with `REGISTRY-READY`.

Load the `arctl` environment in every shell you use for the registry. It port-forwards the API to `localhost:12121`, mints an `admin-user` token, and defines `ar_token`:

```bash
. ./03-registry-env.sh
arctl get runtimes
```

```
NAME              TYPE
virtual-default   Virtual
```

Already running Agentregistry Enterprise? Skip the install. Export `ARCTL_API_BASE_URL` (your registry URL) and `KEYCLOAK_URL` (your Keycloak base URL) before sourcing `03-registry-env.sh`; then no port-forward is opened and tokens are requested directly.

Docs: [Agentregistry Enterprise setup](https://docs.solo.io/agentregistry/latest/setup/), [Build a catalog](https://docs.solo.io/agentregistry/latest/quickstart/catalog/)

---

## Step 6: Register the workloads in the catalog

`04-catalog.yaml` holds the agent (`agent-x`, by image) and the three MCP servers as remote entries pointing at their in-cluster Service URLs. Nothing is redeployed.

```bash
arctl apply -f 04-catalog.yaml
arctl get agents
arctl get mcps
```

Expected output:

```
NAME      TAG     MODE     DESCRIPTION
agent-x   1.0.0   source   Demo agent behind the /agent-x route on e2e-gw. Users in a...
NAME      TAG      DESCRIPTION
mcp-a     latest   MCP server agent-x is authorized to use.
mcp-api   latest   MCP server whose tool calls the httpbin API through the ga...
mcp-b     latest   MCP server agent-x is not authorized to use.
```

Registry UI: port-forward is already open from `03-registry-env.sh`. Open http://localhost:12121/are/catalog and sign in as `admin-user` / `password`. Catalog shows `agent-x` under Agents and the three servers under MCP servers.

Docs: [Register remote MCP servers](https://docs.solo.io/agentregistry/latest/mcp/remote/)

---

## Step 7: Publish the MCP servers through agentgateway from the registry

The registry does not proxy traffic. It writes routes onto an Enterprise Agentgateway proxy you give it, and that proxy serves the MCP traffic. `04-registry-gateway.yaml` creates that proxy: a Gateway named `agentregistry-gateway` (class `enterprise-agentgateway`, port 80, so the controller deploys a proxy and a Service of the same name) and a parent HTTPRoute that delegates `/registry` to child routes the registry will create. Both carry the label `agentregistry.solo.io/runtime: mcp-gateway`, and `04-runtime-virtual.yaml` creates the Virtual runtime of that name. `04-expose.yaml` then publishes each MCP server at `/registry<pathSuffix>`: for each one the registry creates a child HTTPRoute and an agentgateway Backend in `agentregistry-system`, and the agentgateway controller programs the proxy.

The registry acts on the control plane only. It configures the proxy once, and the proxy serves every request after that:

```text
Control plane. Runs once, when you apply 04-expose.yaml.

  arctl expose
  1. the registry finds the Gateway carrying the label
     agentregistry.solo.io/runtime: mcp-gateway
  2. the registry writes a child HTTPRoute and an agentgateway Backend
     into namespace agentregistry-system
  3. the agentgateway controller reads those and programs the proxy

  The registry's work is finished at that point.

Data plane. Runs on every request from then on.

  1. client
  2. agentregistry-gateway Service, namespace agentgateway-system
  3. parent HTTPRoute /registry, namespace agentgateway-system
  4. child HTTPRoute /registry/mcp-a, namespace agentregistry-system
  5. EnterpriseAgentgatewayBackend
  6. mcp-a Service, namespace e2e-demo

  The registry does not appear in that list. Scale it to zero and these
  routes keep serving.
```

Three details of how the pieces bind together:

- The label is the entire binding. Nothing else connects the registry to the proxy. `agentregistry.solo.io/runtime: mcp-gateway` sits on the Gateway and on the parent route, and it has to match a Virtual runtime of the same name. Get the label wrong and the deployments sit at `pending` with reason `NoGatewayBound`.
- The generated child routes land in `agentregistry-system`, not alongside the MCP servers in `e2e-demo`. That namespace is where to look when you want to see what `expose` actually wrote.
- `04-expose.yaml` uses `kind: Deployment`, but that is the registry's own CR and not a Kubernetes Deployment. Nothing is built, deployed, restarted, or moved. It writes routing config for workloads that have been running since Step 4.

```bash
kubectl apply -f 04-registry-gateway.yaml
arctl apply -f 04-runtime-virtual.yaml
arctl apply -f 04-expose.yaml
arctl get deployments
kubectl get httproute -n agentregistry-system
```

Expected: three registry deployments on runtime `mcp-gateway`, and three child HTTPRoutes in `agentregistry-system`. On KinD, where nothing provisions a LoadBalancer, the deployment status reports `NoAcceptedListener` because the Gateway has no external address, and the routes still work in-cluster. On a cluster that does provision one this status is not cosmetic: the Gateway should reach `Programmed` with an address, and a stuck `NoAcceptedListener` or `NoGatewayBound` points at the runtime label, the parent route, or the Gateway binding. Check `kubectl get gateway -A` for an address before assuming the KinD case. Call one from the test client. `RGW` is the proxy's Service, named after the Gateway:

```bash
export RGW=agentregistry-gateway.agentgateway-system.svc.cluster.local:80
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ws","version":"1.0"}}}'
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'mcp-a via registry: %{http_code}\n' -X POST \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT" http://$RGW/registry/mcp-a
```

Expected output:

```
mcp-a via registry: 200
```

Registry UI: Runtimes shows `mcp-gateway` (Virtual) next to `virtual-default`; Instances shows the three deployments.

Using an existing agentgateway Gateway instead: label it `agentregistry.solo.io/runtime=mcp-gateway`, drop the Gateway document from `04-registry-gateway.yaml`, and point the HTTPRoute's `parentRefs` at your Gateway's name. `RGW` becomes `<gateway-name>.<namespace>.svc.cluster.local:80`, or the Gateway's load balancer address from outside the cluster. If the deployments were created before the label landed they stay `pending` with reason `NoGatewayBound`; `arctl delete -f 04-expose.yaml && arctl apply -f 04-expose.yaml` binds them.

Docs: [Virtual runtime](https://docs.solo.io/agentregistry/latest/setup/runtime/virtual/), [Expose MCP servers with agentgateway](https://docs.solo.io/agentregistry/latest/quickstart/mcp-gateway/)

---

## Step 8: Govern catalog visibility

If `ar_token` fails, `ARCTL_API_TOKEN` ends up empty and `arctl` silently falls back to your stored
admin session, so the commands below return the full catalog and look like they worked. Check the
token is real first:

```bash
ar_token reader | wc -c        # a few thousand, not 0
```

A plain `401 Unauthorized` from any `arctl` command usually means that stored session expired rather
than a misconfiguration. `arctl user login` fixes it.

Before any policy, `reader` sees nothing:

```bash
ARCTL_API_TOKEN=$(ar_token reader) arctl get mcps
ARCTL_API_TOKEN=$(ar_token reader) arctl get agents
```

```
No mcps found.
No agents found.
```

Grant readers `agent-x` and `mcp-a` only:

```bash
arctl apply -f 04-access-policy.yaml
ARCTL_API_TOKEN=$(ar_token reader) arctl get mcps
ARCTL_API_TOKEN=$(ar_token reader) arctl get agents
```

Expected: `mcp-a` and `agent-x` listed, `mcp-b` and `mcp-api` absent. The principal is the Keycloak group name from the `Groups` claim.

Registry UI: Access Policies shows `readers-see-agent-x-stack`. Sign out and sign in as `reader` / `reader`: the catalog shows only `agent-x` and `mcp-a`.

This policy governs discovery, not calls. It decides what `arctl` and the registry UI will show a given user, and it is never consulted when a request reaches a gateway. A user who cannot see `mcp-b` in the catalog can still call `/mcp-b` through a gateway right up until a gateway policy says otherwise, which is what Steps 10 and 11 add. Two policies, two planes, and you want both: registry access control decides who finds out a server exists, gateway authorization decides whose code gets to use it.

Docs: [Access control](https://docs.solo.io/agentregistry/latest/security/access-control/)

---

## Step 9: Mint user tokens and inspect claims

Gateway requests are sent from the in-cluster `sleep` pod, so the lab does not require a LoadBalancer. If your cluster provisions them, an internal one is a reasonable choice and gives you a private address to reach the gateway from your own network. Define a token helper and mint both users:

```bash
: "${KEYCLOAK_URL:=http://keycloak.keycloak.svc.cluster.local:8080}"

TOK() { kubectl exec -n wp-a deploy/sleep -- curl -s -X POST \
  "${KEYCLOAK_URL}/realms/agentregistry/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=agw-client -d client_secret=agw-client-secret \
  -d username=$1 -d password=pw | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"; }

export USER_JWT=$(TOK alice)
export BOB_JWT=$(TOK bob)
```

Both are ordinary OIDC access tokens. From here on they travel as an `Authorization: Bearer <token>` header on each request, and the gateway policies read their claims straight off that header. Nothing else about the caller is passed anywhere.

Bringing your own Keycloak: set `KEYCLOAK_URL` to an address the `sleep` pod can reach before running
this. If it is not reachable in-cluster, drop the `kubectl exec` and run the `curl` from your shell.

Decode alice's payload:

```bash
_seg=$(echo "$USER_JWT" | cut -d. -f2 | tr '_-' '/+')
while [ $(( ${#_seg} % 4 )) -ne 0 ]; do _seg="${_seg}="; done
echo "$_seg" | base64 -d 2>/dev/null | python3 -m json.tool | grep -A3 -E 'Groups|may_act'
```

Expected output:

```
    "Groups": [
        "agent-x-users"
    ],
    "may_act": {
        "sub": "system:serviceaccount:wp-a:default"
    }
```

bob's token (`$BOB_JWT`) has `may_act` and no `Groups`, because bob is in no group. That missing group is what Step 10 checks.

Check how long these tokens last before going further, because the rest of the lab reuses them:

```bash
python3 -c "
import os,json,base64
t=os.environ['USER_JWT']; p=t.split('.')[1]; p+='='*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p))
print('lifetime:', c['exp']-c['iat'], 'seconds')"
```

The lab's Keycloak issues one-hour tokens. A Keycloak you brought yourself may be much shorter, and
five minutes is a common default. That is short enough to expire between minting a token and running
the next step, which surfaces as `invalid subject token` at Step 12 and as an unexplained 401 at
Steps 10, 13 and 14. It also quietly weakens Steps 13 and 14, where a 401 is the expected result: an
expired token returns the same 401 whether the policy works or not, so the test passes without
proving anything.

If the lifetime is short, raise it for the session in the Keycloak admin console under Realm
settings, Tokens, Access Token Lifespan. Otherwise re-mint immediately before each step that uses
`$USER_JWT`, in the same command where possible. The delegated token from Step 12 is unaffected,
since `tokenExpiration` in `05-sts-values.yaml` governs it.

### What `may_act` is for

`may_act` is the claim the delegation in Step 12 depends on.

Keycloak stamps it into alice's token, and it names exactly one actor: `system:serviceaccount:wp-a:default`, the ServiceAccount of the pod that is allowed to act on her behalf. In Step 12 the STS reads the claim and refuses the exchange unless the actor token's subject matches what it names. So the identity provider decides which agent may act for which user. Not the gateway, not the agent, and not anything in this repo.

Two consequences follow. If the mapper is missing from the realm, Step 12 fails even when every gateway policy is correct, and the error names the grant rather than the realm. And carrying `may_act` only makes a user delegatable: it says nothing about what that user is allowed to reach, which is why bob has the claim and still gets a 403 in Step 10.

Docs: [Token exchange overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/token-exchange/overview/)

### Point the policies at your issuer

The gateway compares the token's `iss` claim to the `issuer` string in each policy, character for
character. A mismatch is a 401 for every caller, including ones who should pass, so do this before
Step 10. Read what your Keycloak actually stamps:

```bash
ISS=$(python3 -c "
import os,json,base64
t=os.environ['USER_JWT']; p=t.split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p))['iss'])")
echo "$ISS"
```

If that is not `http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry`, set it in the
three policy files:

```bash
sed -i '' "s|issuer: http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry|issuer: $ISS|g" \
  05-agent-authz.yaml 05-mcp-authz.yaml 05-mcp-api-authz.yaml
```

Keycloak stamps whatever hostname it is configured with, not the address you called, so re-minting
against a different URL does not change `iss`. The policies have to match the token.

There is also nothing to pass on the client side. The issuer is not a parameter on the token request,
so a caller cannot ask for one and cannot override it. The realm's configured frontend URL decides it.
That leaves two real fixes: point the policies at the string Keycloak is already stamping, as above, or
change Keycloak's frontend URL and re-mint. Trying different token endpoints is not one of them.

Leave `jwks.remote.backendRef` alone unless your Keycloak Service is named something other than
`keycloak` in namespace `keycloak`. That field only says how the gateway fetches the signing keys and
is independent of the issuer string.

---

## Step 10: Create the gateway and enforce user to agent authorization

`05-gateway.yaml` creates Gateway `e2e-gw` (class `enterprise-agentgateway`, port 8080) and a tracing policy that sends its traces to the Solo UI. `05-agent-authz.yaml` adds an `HTTPRoute` on `/agent-x` to the Step 4 agent and an `EnterpriseAgentgatewayPolicy` combining JWT authentication with CEL authorization:

```yaml
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
        - issuer: http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry
          jwks:
            remote:
              backendRef: {name: keycloak, ...}
              jwksPath: /realms/agentregistry/protocol/openid-connect/certs
    authorization:
      action: Require
      policy:
        matchExpressions:
          - "'agent-x-users' in jwt.Groups"
```

`jwksPath` is required whenever `jwks.remote.backendRef` is set.

Docs: [JWT authentication](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/jwt/), [Authorization policies (CEL)](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/authorization/)

```bash
kubectl apply -f 05-gateway.yaml -f 05-agent-authz.yaml
kubectl -n e2e-demo rollout status deploy/e2e-gw --timeout=180s
```

Send a request as each identity:

```bash
export GW=e2e-gw.e2e-demo.svc.cluster.local:8080

kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'anonymous: %{http_code}\n' http://$GW/agent-x/get
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'alice: %{http_code}\n' -H "Authorization: Bearer $USER_JWT" http://$GW/agent-x/get
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'bob: %{http_code}\n' -H "Authorization: Bearer $BOB_JWT" http://$GW/agent-x/get
```

Expected output:

```
anonymous: 401
alice: 200
bob: 403
```

401 means no or invalid token (authentication). 403 means a valid token with insufficient claims (authorization).

---

### Using a gateway you already have

Skip `05-gateway.yaml` entirely and attach the routes to your existing agentgateway Gateway. The
listener has to accept routes from `e2e-demo`, which `allowedRoutes.namespaces.from: All` satisfies.
On a shared gateway prefer a selector, since `All` lets any namespace in the cluster publish a route
on that listener and that is a fair question from a security reviewer:

```yaml
  allowedRoutes:
    namespaces:
      from: Selector
      selector:
        matchLabels: { kubernetes.io/metadata.name: e2e-demo }
```

```bash
sed -i '' 's/parentRefs: \[ { name: e2e-gw } \]/parentRefs: [ { name: YOUR-GATEWAY, namespace: YOUR-NAMESPACE } ]/' \
  05-agent-authz.yaml 05-mcp-authz.yaml 05-api-authz.yaml 05-mcp-api-authz.yaml

export GW=YOUR-GATEWAY.YOUR-NAMESPACE.svc.cluster.local:YOUR-PORT
```

Three things to know. The authorization policies target our HTTPRoutes by name, so they only affect
`/agent-x`, `/mcp-a`, `/mcp-b`, `/api` and `/mcp-api`, and other traffic on that gateway is untouched.
The tracing policy in `05-gateway.yaml` is different: it targets the Gateway itself, so it would turn
on sampling for everything on that proxy rather than just these routes. Leave it out here, and see
Step 15 for the version that names your own Gateway and telemetry collector. And Step 12 still
upgrades the agentgateway release, which restarts the shared controller.

## Step 11: Enforce agent to MCP authorization

Step 7 published the MCP servers onto `agentregistry-gateway`, and only those: it did not touch the agent and it wrote none of the policies. Steps 10 and 11 are the hand-authored side, on `e2e-gw`, so the policy sits in a file you can read and change. That leaves `mcp-a` reachable two ways on purpose. Step 14 calls it through both proxies and gets the same answer, because the policy decides, not the path.

`05-mcp-authz.yaml` puts the Step 4 MCP servers behind `EnterpriseAgentgatewayBackend` MCP static targets, routed at `/mcp-a` and `/mcp-b` with opposing authorization policies. `mcp-a` requires alice's group. `mcp-b` requires a group nobody has.

- The backend uses `spec.mcp.targets[].static: {host, port, protocol: SSE}`. The `HTTPRoute` backendRef carries `group: enterpriseagentgateway.solo.io` and `kind: EnterpriseAgentgatewayBackend`.

Docs: [About MCP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/about/), [Static MCP backends](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/static-mcp/), [Control access to tools](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

```bash
kubectl apply -f 05-mcp-authz.yaml
```

Send an MCP `initialize` through the gateway as alice:

```bash
kubectl exec -n wp-a deploy/sleep -- curl -s -X POST -H "Authorization: Bearer $USER_JWT" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d "$INIT" http://$GW/mcp-a

kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'mcp-b: %{http_code}\n' -X POST -H "Authorization: Bearer $USER_JWT" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d "$INIT" http://$GW/mcp-b
```

Expected output:

```
event: message
data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"experimental":{},"tools":{"listChanged":false}},"serverInfo":{"name":"mcp-website-fetcher","version":"1.14.1"}}}

mcp-b: 403
```

In production this policy's CEL matches the delegated token's `jwt.act.sub` (the agent identity) instead of the user's group. Same policy shape, one expression change.

The other production change is where the policy hangs. Attach it to the route the registry generated instead of hand-writing a parallel one. A policy targets a route by name, and it is a separate object that the registry does not own, so it survives reconciliation. Editing a registry-generated child HTTPRoute directly does not: the registry owns those objects in `agentregistry-system` and reconciles them back to whatever the Deployment CR says, so a hand-edit there lasts only until the next reconcile. One gateway, routes published by the registry, policies attached by you, is the shape you want.

---

## Step 12: Enable the STS and exchange for a delegated token

Upgrade the controller with the `tokenExchange` block from `05-sts-values.yaml`. `subjectValidators` points at the Keycloak JWKS, and `actorValidators` and `apiValidators` are `k8s`. All three are lists, and all three have to be present: the chart renders the validators ConfigMap only when they are, and the controller exits with `at least one validator is required` without it.

```bash
export ENTERPRISE_AGW_VERSION=$(helm get metadata enterprise-agentgateway -n agentgateway-system | awk '/^VERSION:/ {print $2}')

helm upgrade enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version $ENTERPRISE_AGW_VERSION -n agentgateway-system --reuse-values -f 05-sts-values.yaml
kubectl -n agentgateway-system rollout status deploy/enterprise-agentgateway --timeout=180s
```

The STS listens on the controller Service, port 7777. Token endpoint `/token`, JWKS at `/.well-known/jwks.json`.

Docs: [Token exchange overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/token-exchange/overview/), [On-behalf-of (OBO) tokens](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/token-exchange/obo/), [OAuth token exchange](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/token-exchange/)

Exchange from inside the agent's pod: the mounted SA token is the `actor_token`, the user JWT is the `subject_token`. In production the agent does this in code.

```bash
export DELEGATED_TOKEN=$(kubectl exec -n wp-a deploy/sleep -- sh -c "SA=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
  curl -s -X POST http://enterprise-agentgateway.${AGW_NAMESPACE:-agentgateway-system}.svc.cluster.local:7777/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=$USER_JWT -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  -d actor_token=\$SA -d actor_token_type=urn:ietf:params:oauth:token-type:jwt" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
```

Decode it to verify both identities are present:

```bash
_seg=$(echo "$DELEGATED_TOKEN" | cut -d. -f2 | tr '_-' '/+')
while [ $(( ${#_seg} % 4 )) -ne 0 ]; do _seg="${_seg}="; done
echo "$_seg" | base64 -d 2>/dev/null | python3 -c "import json,sys; c=json.load(sys.stdin); print('sub:',c['sub']); print('act:',json.dumps(c.get('act'))); print('iss:',c['iss'])"
```

Expected output:

```
sub: <alice's Keycloak user uuid>
act: {"iss": "https://kubernetes.default.svc.cluster.local", "sub": "system:serviceaccount:wp-a:default"}
iss: enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777
```

Both token types must be `urn:ietf:params:oauth:token-type:jwt`. Claims such as `Groups` do not propagate into the delegated token; downstream authorization keys on `sub` and `act`.

The STS is not a separate workload. It is port 7777 on the existing controller container, alongside
xDS on 9978, so the chart ships one Deployment in total. Two things follow. Enabling it restarts the
control plane, which is why the bring-your-own-gateway note warns that Step 12 touches a shared
controller. And a bad validators file does not merely break token exchange, it stops the controller
from starting at all.

### When the exchange fails

The command above pipes the response through `python3` to pull out `access_token`, which means a
failure surfaces as `KeyError: 'access_token'` and hides what the STS actually said. Re-run it
without that pipe to read the real body:

```bash
kubectl exec -n wp-a deploy/sleep -- sh -c "SA=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
  curl -s -X POST http://enterprise-agentgateway.${AGW_NAMESPACE:-agentgateway-system}.svc.cluster.local:7777/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=$USER_JWT -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  -d actor_token=\$SA -d actor_token_type=urn:ietf:params:oauth:token-type:jwt"
```

`{"error":"invalid_grant","error_description":"invalid subject token"}` means the STS could not
validate the user JWT. In order of likelihood: `$USER_JWT` is empty because the shell lost the
export, the token has expired (see the lifetime note in Step 9), or the JWKS the subject validator
fetches does not hold the key that signed it. Decode the token and compare its `kid` against the
JWKS to tell the last case from the others:

```bash
echo "len=${#USER_JWT}"

# the key that signed the token
python3 -c "
import os,json,base64
t=os.environ['USER_JWT']; h=t.split('.')[0]; h+='='*(-len(h)%4)
print('kid:', json.loads(base64.urlsafe_b64decode(h)).get('kid'))"

# the keys the subject validator will check against, from the url in 05-sts-values.yaml
kubectl exec -n wp-a deploy/sleep -- curl -s \
  "${KEYCLOAK_URL:-http://keycloak.keycloak.svc.cluster.local:8080}/realms/agentregistry/protocol/openid-connect/certs" \
  | python3 -c "import json,sys; print('kids:', [k['kid'] for k in json.load(sys.stdin)['keys']])"
```

A `kid` missing from that list means the validator is pointed at a different Keycloak from the one
that minted the token, and the fix is the `subjectValidators` url rather than anything about the
token.

Three different things in this lab are called an issuer, and only one of them is compared against an
incoming token:

- `tokenExchange.issuer` in `05-sts-values.yaml` is what the STS **stamps** on tokens it mints. It is
  the `iss` you see on the delegated token, and it is never matched against the user's token.
- `subjectValidators` has no issuer field at all, only a JWKS URL. It verifies the signature, so it
  cannot produce an issuer mismatch.
- The `issuer` in the `05-*` policy files is the one the gateway compares character for character
  against the token's `iss`, which is the check described in Step 9.

So `invalid subject token` is never an issuer mismatch. It is an empty, expired, or unverifiable
token.

---

## Step 13: Restrict the API to delegated identities

`05-api-authz.yaml` routes `/api` to the Step 4 API with a policy whose JWT provider trusts only the STS issuer (JWKS fetched from the controller's port 7777) and authorizes on the agent's identity:

```yaml
    authorization:
      action: Require
      policy:
        matchExpressions:
          - "jwt.act.sub == 'system:serviceaccount:wp-a:default'"
```

```bash
kubectl apply -f 05-api-authz.yaml
sleep 30

kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'delegated token: %{http_code}\n' -H "Authorization: Bearer $DELEGATED_TOKEN" http://$GW/api/get
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'raw user token: %{http_code}\n' -H "Authorization: Bearer $USER_JWT" http://$GW/api/get
kubectl exec -n wp-a deploy/sleep -- curl -s -o /dev/null -w 'anonymous: %{http_code}\n' http://$GW/api/get
```

Expected output:

```
delegated token: 200
raw user token: 401
anonymous: 401
```

The raw user token is signed by Keycloak rather than the STS, so it fails authentication (401) at this route. Users cannot bypass the agent chain to reach the API. The same policy applies unchanged on a Solo Enterprise kgateway route in front of a real API.

---

## Step 14: MCP server calls the API through the gateway

`05-mcp-api-authz.yaml` routes `/mcp-api` to the Step 4 `mcp-api` server. The route accepts a Keycloak user token or an STS delegated token and forwards it to the server (`preserveToken: true`). Call the tool with each:

```bash
kubectl apply -f 05-mcp-api-authz.yaml
sleep 8
mcp-api/mcpcall.sh "$DELEGATED_TOKEN"
mcp-api/mcpcall.sh "$USER_JWT"
```

Expected output:

```
HTTP 200
HTTP 401
```

With the delegated token every hop (agent, gateway, MCP server, gateway, API) sees the same `sub` and `act`. With the raw user token the MCP hop admits the call but the API route rejects it.

The 401 only proves something if `$USER_JWT` was still valid when it was sent. An expired token
returns 401 from the gateway's authentication check, before authorization is ever consulted, so the
step looks like it passed whether or not the policy is doing its job. Re-mint immediately before
this comparison, and treat a 401 on a token minted a second earlier as the real result.

The same server is published through the second agentgateway proxy (Step 7). It answers the same there, because the API route is what enforces delegation:

```bash
mcp-api/mcpcall.sh "$DELEGATED_TOKEN" $RGW /registry/mcp-api
mcp-api/mcpcall.sh "$USER_JWT" $RGW /registry/mcp-api
```

---

## Step 15: Validate in the Solo UI

### Enable tracing

Spans reach the UI only when a tracing policy points the proxy at the management release's telemetry
collector. `05-gateway.yaml` applied one in Step 10, targeting `e2e-gw` and shipping to a collector in
namespace `kagent`, which is where this lab's own management release lives.

Both of those are wrong if you brought your own gateway or your own Solo UI, and the symptom is an
empty Tracing view rather than an error. Find what your cluster actually has:

```bash
kubectl get httproute -n e2e-demo -o jsonpath='{range .items[*]}{.metadata.name}{" parent="}{.spec.parentRefs[*].name}{" ns="}{.spec.parentRefs[*].namespace}{"\n"}{end}'
kubectl get svc -A | grep -i telemetry-collector
```

Then apply a policy naming your Gateway and your collector. The policy has to live in the same
namespace as the Gateway it targets, so this moves out of `e2e-demo` when your gateway is elsewhere:

```yaml
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata: { name: tracing, namespace: YOUR-GATEWAY-NAMESPACE }
spec:
  targetRefs: [ { group: gateway.networking.k8s.io, kind: Gateway, name: YOUR-GATEWAY } ]
  frontend:
    tracing:
      backendRef: { name: solo-enterprise-telemetry-collector, namespace: YOUR-MGMT-NAMESPACE, kind: Service, port: 4317 }
      randomSampling: "true"
```

The management chart names its Services `solo-enterprise-*` whatever you called the release, so the
collector name is stable and only the namespace changes. Installing the management chart into
`agentgateway-system` alongside the controller is a common layout and a common reason `kagent` is not
the right namespace here.

Two things about the result. This policy targets the Gateway rather than a route, so
`randomSampling: "true"` samples every request on that proxy, not only this lab's routes. On a shared
gateway that is worth deciding on deliberately. And a span is recorded when a request is served, not
retrospectively, so re-run a Step 10 or Step 14 request after applying the policy and look at a short
time window rather than a long one.

### Read the results

Open http://localhost:4000 (port-forward from Step 3) as `admin-user`.

- Gateways: `e2e-gw` in `e2e-demo` and `agentregistry-gateway` in `agentgateway-system`, with request count, duration, and error rate. Re-run the Step 10 requests and watch the counts move.
- Routes: `agent-x`, `mcp-a`, `mcp-b`, `api-backend`, `mcp-api`, and the registry's child routes under `/registry`. Open a route to see its attached policy and destinations.
- Policies: the `EnterpriseAgentgatewayPolicy` objects from Steps 10 to 14. Open one and view the applied JSON to confirm the JWT provider issuer and the CEL expression.
- Tracing: one trace per request. Alice's `/agent-x` call shows 200, bob's shows 403, the anonymous call shows 401, and the Step 13 raw-token call to `/api` shows 401 at the gateway with no upstream span.
- Playground: select the `agent-x` route, paste `$USER_JWT` as the bearer token, and send a request to `/get`.

Docs: [Explore the UI](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/ui/explore/)

---

## Step 16 (optional): Deploy from the registry with Solo Enterprise for kagent

Solo Enterprise for kagent is the registry runtime that creates workloads in a Kubernetes cluster from catalog entries. This step installs it, registers it as a runtime, deploys a second copy of the agent and MCP servers from the catalog, and re-points the `e2e-gw` routes at them. The policies do not change.

The script upgrades the Step 3 management release (or the one named by `MGMT_RELEASE` and `MGMT_NAMESPACE`) with the kagent and agentregistry products, then installs the kagent CRDs and kagent-enterprise with OIDC against the realm. The `agentregistry` group maps to `global.Writer`, which is how the registry may create workloads. No LLM key is configured.

```bash
./10-kagent-install.sh
./10-register-kagent-runtime.sh
arctl get runtimes
```

Expected output ends with `KAGENT-READY`, then `RUNTIME-READY`, and the runtime list gains `kagent` (type Kagent).

The kagent controller marks a bring-your-own agent Ready only once `/.well-known/agent-card.json` answers on port 8080, so `agent-x-kagent` uses `traefik/whoami`, which answers every path and echoes the request it received. Each MCP server entry names its image under `origin.oci` and its listen port and path under `transport`. `mcp-api-kagent` uses the same image as `02-mcp-api.yaml`.

```bash
arctl apply -f 10-catalog-kagent.yaml
arctl apply -f 10-deploy-kagent.yaml
arctl get deployments
kubectl get pods -n kagent
kubectl get agents,mcpservers -n kagent
```

Expected: one pod each for `agent-x-kagent`, `mcp-a-kagent`, `mcp-b-kagent`, and `mcp-api-kagent` in namespace `kagent`, created by the kagent controller from the registry deployments, with matching kagent `Agent` and `MCPServer` resources.

`10-gateway-kagent.yaml` replaces the backends of the Step 10, 11, and 14 routes with the kagent Services (a `ReferenceGrant` lets routes in `e2e-demo` reference Services in `kagent`). Route names and policies stay the same.

```bash
kubectl apply -f 10-gateway-kagent.yaml
sleep 15
```

Re-run the Step 10, 11, and 14 requests. Results are identical: alice 200 and bob 403 on `/agent-x`, mcp-a 200 and mcp-b 403, `mcp-api/mcpcall.sh` returns HTTP 200 with the delegated token and HTTP 401 with the raw user token. Alice's `/agent-x` response is now the whoami echo, and its `Authorization` line shows the token the gateway forwarded to the pod in namespace `kagent`.

Solo UI: the kagent product pages list `agent-x-kagent` (type BYO) and the three MCP servers in namespace `kagent`, all Ready. Registry UI: Runtimes shows `kagent`, Instances shows the four kagent deployments.

Docs: [Solo Enterprise for kagent install](https://docs.solo.io/kagent/latest/install/install-kagent/), [kagent runtime](https://docs.solo.io/agentregistry/latest/setup/runtime/kagent/)

---

## Validation checklist

1. `arctl get agents` and `arctl get mcps` list the four Step 4 workloads (Step 6)
2. `mcp-a via registry: 200` through `agentregistry-gateway` (Step 7)
3. `reader` sees nothing, then exactly `agent-x` and `mcp-a` (Step 8)
4. `anonymous: 401`, `alice: 200`, `bob: 403` on `/agent-x` (Step 10)
5. MCP `initialize` result from `mcp-a`, `403` from `mcp-b` (Step 11)
6. Delegated token decodes with `sub` = alice and `act.sub` = `system:serviceaccount:wp-a:default` (Step 12)
7. `delegated: 200`, `raw user: 401`, `anonymous: 401` on `/api` (Step 13)
8. `HTTP 200` then `HTTP 401` from `mcp-api/mcpcall.sh` with the delegated and raw tokens, on both gateways (Step 14)
9. Traces for those requests appear in the Solo UI's Tracing view (Step 15)
10. Optional: the Step 10, 11, and 14 results repeat against the kagent-deployed workloads (Step 16)

## Cleanup

```bash
# 1. Registry objects, then the proxy the registry published to
arctl delete -f 04-access-policy.yaml
arctl delete -f 04-expose.yaml
arctl delete -f 04-runtime-virtual.yaml
arctl delete -f 04-catalog.yaml
kubectl delete -f 04-registry-gateway.yaml --ignore-not-found

# 2. Gateway routes, policies, and workloads
kubectl delete -f 05-mcp-api-authz.yaml -f 05-api-authz.yaml -f 05-mcp-authz.yaml -f 05-agent-authz.yaml -f 05-gateway.yaml --ignore-not-found
kubectl delete -f 02-mcp-api.yaml -f 02-workloads.yaml --ignore-not-found

# 3. Restore the controller to its pre-STS configuration
helm upgrade enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version $ENTERPRISE_AGW_VERSION -n agentgateway-system \
  --set licensing.licenseKey="$LICENSE_KEY"

# 4. Registry, UI (and kagent if Step 16 ran), Keycloak, test client
helm uninstall agentregistry-enterprise -n agentregistry-system
helm uninstall kagent kagent-crds -n kagent 2>/dev/null
helm uninstall kagent-mgmt -n kagent
kubectl delete ns agentregistry-system kagent --ignore-not-found
kubectl delete -f 00-keycloak.yaml -f 00-client.yaml --ignore-not-found

# Or, if 00-kind.sh created the KinD cluster, delete it all at once:
kind delete cluster --name agw-e2e
```
