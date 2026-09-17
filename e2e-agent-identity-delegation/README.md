# End-to-End Agent Identity, Authorization, and Delegation

One workshop, in the order the products are used: deploy an agent and its MCP servers, register and govern them in Agentregistry Enterprise, then secure every hop (user, agent, MCP server, API) with Enterprise Agentgateway. Each hop gets JWT authentication and CEL-based authorization, and RFC 8693 token exchange carries the user's identity through the chain with the agent's identity attached. Solo Enterprise for kagent is an optional last step for teams that want the registry to deploy workloads into the cluster.

Validated end to end on a local KinD cluster with Enterprise Agentgateway v2026.9.0, Agentregistry Enterprise 2026.9.0, and Keycloak 26, including a clean-room run from an empty cluster using only the files in this folder. Every `Expected output` block is an observed result.

## Files in this folder

| File | Purpose |
|---|---|
| `00-kind.sh` | Optional. Creates a local KinD cluster named `agw-e2e` |
| `00-platform.sh` | Gateway API CRDs, Enterprise Agentgateway charts, test client, into the current kubeconfig context |
| `00-client.yaml` | `sleep` test client in ns `wp-a`. Its ServiceAccount is the agent's workload identity |
| `00-keycloak.yaml` | Keycloak 26.1.3 in ns `keycloak` with the `agentregistry` realm imported at boot. Issuer pinned to the in-cluster Service name so browser and pod tokens match |
| `realm/` | The realm JSON, the workshop-only additions for an existing Keycloak, and the import helper |
| `01-ui.sh` | Solo UI (management chart, agentgateway product) |
| `02-workloads.yaml` | The agent stand-in, two MCP servers, and the API. Plain Deployments and Services |
| `02-mcp-api.yaml`, `mcp-api/` | MCP server whose tool calls the API and forwards the caller's token |
| `03-registry-install.sh`, `03-registry-values.yaml` | Agentregistry Enterprise |
| `03-registry-env.sh` | Port-forward, `arctl` environment, token helper |
| `04-catalog.yaml` | Catalog entries for the running workloads |
| `04-registry-gateway.yaml`, `04-runtime-virtual.yaml`, `04-expose.yaml` | Registry gateway, Virtual runtime, and the deployments that publish the MCP servers through it |
| `04-access-policy.yaml` | Catalog visibility for readers |
| `05-gateway.yaml` | Gateway `e2e-gw` and its tracing policy |
| `05-agent-authz.yaml` | Route `/agent-x`, JWT plus group-based authorization |
| `05-mcp-authz.yaml` | MCP backends and routes for `mcp-a` and `mcp-b`, opposing authorization policies |
| `05-sts-values.yaml` | Helm values enabling the STS (`tokenExchange` block) |
| `05-api-authz.yaml` | Route `/api` that trusts only STS-issued delegated tokens |
| `05-mcp-api-authz.yaml` | Route `/mcp-api` for the MCP server that calls the API |
| `10-*` | Optional. Solo Enterprise for kagent as a registry runtime that deploys into the cluster |

## Prerequisites

Everything on-cluster is deployed by this lab. Locally you need:

- kubectl, helm, docker, python3
- kind, only if you want a local cluster created by `00-kind.sh`
- A Solo.io enterprise license key

Bringing your own cluster: skip `00-kind.sh`. `00-platform.sh` installs into whatever `kubectl config current-context` points at and never creates a cluster.

## What you will do

1. Install the platform, Keycloak, and the Solo UI (Steps 1 to 3)
2. Deploy the agent, MCP servers, and API (Step 4)
3. Install Agentregistry Enterprise, register the workloads, publish the MCP servers through the registry gateway, and govern who sees what (Steps 5 to 8)
4. Mint user tokens and secure every hop with Enterprise Agentgateway: user to agent, agent to MCP, delegation through the STS, MCP or agent to API, MCP server to API (Steps 9 to 14)
5. Validate in the Solo UI (Step 15)
6. Optional: let the registry deploy workloads into the cluster through Solo Enterprise for kagent (Step 16)

## Background

At every hop the question is the same: who is calling, and are they allowed to call this? The identity answering it changes at each hop.

1. alice calls the gateway with her user JWT and reaches agent-x. bob is denied with 403. (Step 10)
2. The agent calls the gateway with a JWT and reaches mcp-a. mcp-b is denied with 403. (Step 11)
3. The agent sends the user JWT plus its own SA token to the STS on port 7777 and receives a delegated token with `sub: alice` and `act: agent`. (Step 12)
4. An MCP tool calls the gateway with the delegated token and reaches the API. A raw user token is denied with 401. (Steps 13 and 14)

Enterprise Agentgateway includes a built-in STS on port 7777 (RFC 8693 token exchange). The delegated token it issues preserves the user's `sub` and embeds the agent's identity in `act`, so downstream services see who asked and through which agent.

Why not forward the user's token: a raw user token says nothing about which agent is acting, can be replayed against any route the user could reach, and grants the agent everything the user has. The delegated token is signed by the STS, carries both identities, and is only accepted where STS-issued tokens are trusted.

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

The controller upgrade uses `--reuse-values`, so re-running this script after Step 12 does not wipe the STS configuration.

Docs: [Install with Helm](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/helm/)

Expected output (truncated):

```
deployment "enterprise-agentgateway" successfully rolled out
NAME                      CONTROLLER                        ACCEPTED   AGE
enterprise-agentgateway   solo.io/enterprise-agentgateway   True       2s
deployment "sleep" successfully rolled out
PLATFORM-READY
```

The `sleep` pod's ServiceAccount (`system:serviceaccount:wp-a:default`) stands in for the agent's workload identity. Its mounted SA token is the actor token in Step 12, and Step 13's policy authorizes on this identity via `jwt.act.sub`.

---

## Step 2: Deploy Keycloak with the agentregistry realm

```bash
kubectl apply -f 00-keycloak.yaml
kubectl -n keycloak rollout status deploy/keycloak --timeout=300s
```

The realm is imported from a ConfigMap at boot (`start-dev --import-realm`), so there is nothing to run inside the pod and a restart re-imports it. It is the `agentregistry` realm from the Agentregistry Enterprise docs (clients `ar-backend`, `ar-cli-interactive`, `ar-cli-password`, `ar-ui`, `ar-mcp-client`; `Groups` claim; `ar-backend` audience; group `admins`; user `admin-user` with password `password`) plus what this lab adds:

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

`kcadm.sh` ships in the Keycloak image, and `partialImport` with `ifResourceExists=SKIP` adds only what is missing. Nothing already in your realm is changed. Adjust three things in that command for your deployment:

- `-n keycloak deploy/keycloak`: the namespace and workload where your Keycloak runs (`sts/<name>` for a StatefulSet)
- `--user admin --password admin`: your bootstrap admin credentials
- `--server http://localhost:8080`: works when HTTP is enabled inside the pod, which the docs `start-dev` deployment does. A production-mode Keycloak with HTTPS only needs `https://localhost:8443` or your external URL

Then set the issuer in `01-ui.sh`, `03-registry-values.yaml`, `05-agent-authz.yaml`, `05-mcp-authz.yaml`, `05-mcp-api-authz.yaml`, and `05-sts-values.yaml` to your Keycloak URL. Two things the import does not change: your realm keeps its own access token lifespan (Keycloak's default is 5 minutes), so re-run the Step 9 exports if a request returns 401 unexpectedly; and the `agentregistry` client arrives with the lab's fixed secret, so set your own and export it as `AGENTREGISTRY_CLIENT_SECRET` before Step 16.

Confirm the import with the Step 9 decode: mint a token for `alice` through `agw-client` and check the payload shows both `Groups` and `may_act`. If both are present, everything downstream works against your realm.

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

The UI, and later the registry UI, sign you in through Keycloak in the browser. The browser is sent to the issuer the servers trust, `http://keycloak.keycloak.svc.cluster.local:8080`, so make that name resolve to your machine and port-forward Keycloak once for the rest of the lab:

```bash
echo "127.0.0.1 keycloak.keycloak.svc.cluster.local" | sudo tee -a /etc/hosts
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &
kubectl port-forward -n kagent svc/solo-enterprise-ui 4000:80 &
```

Open http://localhost:4000 and sign in as `admin-user` / `password` (group `admins`, mapped to `global.Admin`). The gateway pages fill in from Step 10 on.

Docs: [Set up the UI](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/ui/setup/)

---

## Step 4: Deploy the agent, MCP servers, and API

`02-workloads.yaml` creates namespace `e2e-demo` with plain Deployments and Services: `agent-x` (httpbin stands in for the agent), `mcp-a` and `mcp-b` (both `mcp-website-fetcher`, SSE on port 8000), and `api-backend` (httpbin). Nothing here knows about the gateway or the registry yet.

```bash
kubectl apply -f 02-workloads.yaml
kubectl -n e2e-demo rollout status deploy/agent-x deploy/mcp-a deploy/mcp-b deploy/api-backend --timeout=180s
```

`02-mcp-api.yaml` deploys `mcp-api`, an MCP server with one tool, `httpbin_get(path)`. The tool calls the API at `API_BASE` and forwards the bearer token it received. `API_BASE` defaults to the `/api` route on `e2e-gw` (created in Step 10); set it to an existing API gateway to route through that instead. Source and Dockerfile are in `mcp-api/`. Build the image and make it available to the cluster (KinD shown; push to a registry for any other cluster and set `image:` in the manifest):

```bash
docker build -t mcp-api:local mcp-api/
kind load docker-image mcp-api:local --name agw-e2e
kubectl apply -f 02-mcp-api.yaml
kubectl -n e2e-demo rollout status deploy/mcp-api --timeout=120s
```

The MCP `Service` ports carry `appProtocol: agentgateway.dev/mcp`. Without it the gateway backends in Step 11 never pick the servers up.

---

## Step 5: Install arctl and Agentregistry Enterprise

```bash
curl -sSL https://storage.googleapis.com/agentregistry-enterprise/install.sh | ARCTL_VERSION=v2026.9.0 sh
export PATH=$HOME/.arctl/bin:$PATH
arctl version --json

./03-registry-install.sh
```

The script installs the registry (ClusterIP, bundled PostgreSQL and ClickHouse, OIDC against the realm with `Groups` as the role claim, `admins` as the superuser group, and `ar-ui` as the browser client). Expected output ends with `REGISTRY-READY`.

Load the `arctl` environment in every shell you use for the registry. It port-forwards the API to `localhost:12121`, mints an `admin-user` token in-cluster so the issuer matches, and defines `ar_token`:

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

The registry records what runs and where. `04-catalog.yaml` holds the agent (`agent-x`, by image) and the three MCP servers as remote entries pointing at their in-cluster Service URLs. Nothing is redeployed.

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

## Step 7: Publish the MCP servers through the registry gateway

The registry can expose registered MCP servers through agentgateway itself. `04-registry-gateway.yaml` creates a Gateway (`agentregistry-gateway`, port 80) and a parent HTTPRoute that delegates `/registry` to child routes the registry creates. Both carry the label `agentregistry.solo.io/runtime: mcp-gateway`, and `04-runtime-virtual.yaml` creates the Virtual runtime of that name. `04-expose.yaml` then publishes each MCP server at `/registry<pathSuffix>`.

```bash
kubectl apply -f 04-registry-gateway.yaml
arctl apply -f 04-runtime-virtual.yaml
arctl apply -f 04-expose.yaml
arctl get deployments
kubectl get httproute -n agentregistry-system
```

Expected: three registry deployments on runtime `mcp-gateway`, and three child HTTPRoutes in `agentregistry-system`. On KinD without a LoadBalancer the deployment status reports `NoAcceptedListener` because the Gateway has no external address. The routes still work in-cluster. Call one from the test client:

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

Docs: [Virtual runtime](https://docs.solo.io/agentregistry/latest/setup/runtime/virtual/), [Expose MCP servers with agentgateway](https://docs.solo.io/agentregistry/latest/quickstart/mcp-gateway/)

---

## Step 8: Govern catalog visibility

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

Docs: [Access control](https://docs.solo.io/agentregistry/latest/security/access-control/)

---

## Step 9: Mint user tokens and inspect claims

All gateway requests in this lab are sent from the in-cluster `sleep` pod, so the gateway is reached by its Service DNS name and no LoadBalancer is needed. Define a token helper and mint both users:

```bash
TOK() { kubectl exec -n wp-a deploy/sleep -- curl -s -X POST \
  http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry/protocol/openid-connect/token \
  -d grant_type=password -d client_id=agw-client -d client_secret=agw-client-secret \
  -d username=$1 -d password=pw | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"; }

export USER_JWT=$(TOK alice)
export BOB_JWT=$(TOK bob)
```

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

Decode bob's token the same way (`$BOB_JWT`): `may_act` is present and there is no `Groups` block, because bob is in no group. That missing group is what Step 10 checks. Tokens last one hour; re-run the two exports if a request later returns 401 unexpectedly.

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

## Step 11: Enforce agent to MCP authorization

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

In the full production flow this policy's CEL matches the delegated token's `jwt.act.sub` (the agent identity) instead of the user's group. Same policy shape, one expression change.

---

## Step 12: Enable the STS and exchange for a delegated token

Upgrade the controller with the `tokenExchange` block from `05-sts-values.yaml`. The subject validator points at the Keycloak JWKS and the actor validator is `k8s`.

```bash
export ENTERPRISE_AGW_VERSION=$(helm get metadata enterprise-agentgateway -n agentgateway-system | awk '/^VERSION:/ {print $2}')

helm upgrade enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version $ENTERPRISE_AGW_VERSION -n agentgateway-system --reuse-values -f 05-sts-values.yaml
kubectl -n agentgateway-system rollout status deploy/enterprise-agentgateway --timeout=180s
```

The STS listens on the controller Service, port 7777. Token endpoint `/token`, JWKS at `/.well-known/jwks.json`.

If the controller was already running with an older STS config, the gateway may reject fresh STS tokens with `token uses the unknown key` for up to about 30 seconds while its JWKS cache refreshes.

Docs: [Token exchange overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/token-exchange/overview/), [On-behalf-of (OBO) tokens](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/token-exchange/obo/), [OAuth token exchange](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/token-exchange/)

Perform the exchange from inside the agent's pod. The mounted SA token is the `actor_token` and the user JWT (with `may_act`) is the `subject_token`. In production the agent does this in code.

```bash
export DELEGATED_TOKEN=$(kubectl exec -n wp-a deploy/sleep -- sh -c "SA=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
  curl -s -X POST http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/token \
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

Both token types must be `urn:ietf:params:oauth:token-type:jwt`. The `access_token` type is rejected. Claims such as `Groups` do not propagate into the delegated token; downstream authorization keys on `sub` and `act`.

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

The raw user token is a valid Keycloak JWT for the right user, but it is signed by Keycloak rather than the STS, so it fails authentication (401) at this route. Users cannot bypass the agent chain to reach the API directly. The same JWT plus CEL policy applies unchanged on a Solo Enterprise kgateway route in front of a real API. Only the gateway hosting the policy changes.

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

With the delegated token the chain is agent, gateway, MCP server, gateway, httpbin, and every hop sees the same `sub` and `act`. With the raw user token the MCP hop admits the call but the API route rejects it, so the MCP server cannot reach the API with an identity it was not delegated.

The same server is also published through the registry gateway (Step 7). Calling it there gives the same answers, because the API route, not the MCP route, is what enforces delegation:

```bash
mcp-api/mcpcall.sh "$DELEGATED_TOKEN" $RGW /registry/mcp-api
mcp-api/mcpcall.sh "$USER_JWT" $RGW /registry/mcp-api
```

---

## Step 15: Validate in the Solo UI

Open http://localhost:4000 (port-forward from Step 3) as `admin-user`.

- Gateways: `e2e-gw` in `e2e-demo` and `agentregistry-gateway` in `agentgateway-system`, with request count, duration, and error rate. Re-run the Step 10 requests and watch the counts move.
- Routes: `agent-x`, `mcp-a`, `mcp-b`, `api-backend`, `mcp-api`, and the registry's child routes under `/registry`. Open a route to see its attached policy and destinations.
- Policies: the `EnterpriseAgentgatewayPolicy` objects from Steps 10 to 14. Open one and view the applied JSON to confirm the JWT provider issuer and the CEL expression.
- Tracing: one trace per request. Alice's `/agent-x` call shows 200, bob's shows 403, the anonymous call shows 401, and the Step 13 raw-token call to `/api` shows 401 at the gateway with no upstream span.
- Playground: select the `agent-x` route, paste `$USER_JWT` as the bearer token, and send a request to `/get`.

Docs: [Explore the UI](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/ui/explore/)

---

## Step 16 (optional): Deploy from the registry with Solo Enterprise for kagent

So far the workloads were deployed with `kubectl` and registered afterwards. Solo Enterprise for kagent is the registry runtime that creates workloads in a Kubernetes cluster from catalog entries. This step installs it, registers it as a runtime, deploys a second copy of the agent and MCP servers from the catalog, and re-points the `e2e-gw` routes at them. The JWT and CEL policies do not change.

Install kagent. The script upgrades the Step 3 management release with the kagent and agentregistry products, installs the kagent CRDs, the controller signing key, and kagent-enterprise with OIDC pointed at the realm. The `agentregistry` group is mapped to `global.Writer`, which is how the registry is allowed to create workloads. No LLM key is configured; the agent is a bring-your-own image.

```bash
./10-kagent-install.sh
./10-register-kagent-runtime.sh
arctl get runtimes
```

Expected output ends with `KAGENT-READY`, then `RUNTIME-READY`, and the runtime list gains `kagent` (type Kagent).

Catalog and deploy. The kagent controller marks a bring-your-own agent Ready only once `/.well-known/agent-card.json` answers on port 8080, so `agent-x-kagent` uses `traefik/whoami`, which answers every path and echoes the request it received. Each MCP server entry names its image under `origin.oci` and its listen port and path under `transport`.

```bash
arctl apply -f 10-catalog-kagent.yaml
arctl apply -f 10-deploy-kagent.yaml
arctl get deployments
kubectl get pods -n kagent
kubectl get agents,mcpservers -n kagent
```

Expected: one pod each for `agent-x-kagent`, `mcp-a-kagent`, `mcp-b-kagent`, and `mcp-api-kagent` in namespace `kagent`, created by the kagent controller from the registry deployments, with matching kagent `Agent` and `MCPServer` resources.

Re-point the gateway. `10-gateway-kagent.yaml` replaces the backends of the Step 10, 11, and 14 routes with the kagent Services (a `ReferenceGrant` lets routes in `e2e-demo` reference Services in `kagent`). Route names and policies stay the same.

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
9. Optional: the Step 10, 11, and 14 results repeat against the kagent-deployed workloads (Step 16)

## Adapting this to production

- Agent: replace the httpbin stand-in with a real agent. Its ServiceAccount becomes the `may_act` subject in the realm and the `act.sub` in Step 13.
- In-agent exchange: agents perform Step 12's token exchange in code (for example with the agentsts-adk package).
- API leg: Step 13's policy applies unchanged on a Solo Enterprise kgateway route in front of a real API.
- Identity provider: Keycloak is the stand-in. Okta, Entra ID, Auth0 and others work the same way; only the issuer and JWKS provider config changes. Multiple identity domains means one JWT provider entry per issuer.
- Registry gateway: attach the Step 10 JWT policy to the `agentregistry-delegate` parent route to require a token on every `/registry` path.

## Follow-ups

- Workload identity without a user: the agent hop already uses the pod's Kubernetes ServiceAccount token as the actor token (Step 12). A further step is to let the MCP and API routes accept a projected ServiceAccount token directly, with a JWT provider pointed at the cluster issuer, for workload-to-workload calls that have no user in the chain. The registry to kagent hop stays on OIDC client credentials; the kagent runtime requires it.

## Bring your own components

Each piece is optional if you already run it. Everything the lab creates is confined to its own namespaces (`e2e-demo`, `keycloak`, `wp-a`, `kagent`, `agentregistry-system`) and its own Gateways `e2e-gw` and `agentregistry-gateway`. Existing gateways, routes, and policies are not touched.

| You already have | Skip | Adjust |
|---|---|---|
| Kubernetes cluster | `00-kind.sh` | Point `kubectl` at your cluster and run `00-platform.sh`. The lab needs no StorageClass and no LoadBalancer; the gateways are reached by Service DNS. |
| Enterprise Agentgateway | Step 1, but still `kubectl apply -f 00-client.yaml` (the client's SA is the actor identity) | The chart names the controller Service `enterprise-agentgateway` regardless of release name, so only a different namespace changes the STS address. Update it in `05-sts-values.yaml` (`issuer`), `05-api-authz.yaml` and `05-mcp-api-authz.yaml` (provider `issuer` and JWKS `backendRef` namespace), and Step 12's exchange URL. Step 12's `helm upgrade` must target your release name and namespace. |
| Keycloak | `00-keycloak.yaml` | Import `realm/workshop-additions.json` into your `agentregistry` realm (Step 2 shows the partial import). Then set the issuer in `01-ui.sh`, `03-registry-values.yaml`, the `05-*` policies, and `05-sts-values.yaml` to your Keycloak URL. A realm built from the Agentregistry Enterprise docs already carries the `Groups` claim these policies use. |
| Agentregistry Enterprise | `03-registry-install.sh` | Export `ARCTL_API_BASE_URL` and `KEYCLOAK_URL` before sourcing `03-registry-env.sh`. Steps 6 to 8 then run against your registry. For Step 7 the label on `04-registry-gateway.yaml` must match a Virtual runtime in your registry. |
| A real agent workload | The httpbin stand-in in `02-workloads.yaml` | Route to it and use its ServiceAccount as the `may_act` subject and in Step 13's `jwt.act.sub`. |
| Solo Enterprise for kagent | `10-kagent-install.sh` | Run `10-register-kagent-runtime.sh` with `KAGENT_URL` pointing at your controller and `AGENTREGISTRY_CLIENT_SECRET` set to your client secret. |
| Istio or ambient mesh | Nothing | The lab's namespaces are not mesh-enrolled and do not need to be. |

The STS `tokenExchange` values ride on the controller's Helm release. Enabling it on an existing install is Step 12's `--reuse-values` upgrade, and the Cleanup command removes it again.

## Cleanup

```bash
# 1. Registry objects, then the registry gateway
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
