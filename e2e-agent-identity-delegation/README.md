# Configure End-to-End Agent Identity, Authorization, and Delegation

Part 1 (Steps 1 to 8) secures every hop with Enterprise Agentgateway. Part 2 (Steps 9 to 14) adds Agentregistry Enterprise and Solo Enterprise for kagent so the agent and MCP servers are cataloged, deployed into the cluster from the registry, and governed by access policy.

This lab secures every hop of an agentic call chain (user, agent, MCP server, API) with Enterprise Agentgateway. Each hop gets JWT authentication and CEL-based authorization, and RFC 8693 token exchange carries the user's identity through the whole chain with the agent's identity attached.

Validated end to end against controller v2026.9.0 on a local KinD cluster with Keycloak 26, including a clean-room run from an empty cluster using only the files in this folder. Every `Expected output` block is an observed result.

## Files in this folder

| File | Purpose |
|---|---|
| `00-kind.sh` | Optional. Creates a local KinD cluster named `agw-e2e` |
| `00-platform.sh` | Platform bootstrap into the current kubeconfig context: Gateway API CRDs, Enterprise Agentgateway charts, test client |
| `00-client.yaml` | `sleep` test client in ns `wp-a`. Its ServiceAccount is the actor identity for delegation |
| `00-keycloak.yaml` | Keycloak 26.1.3 in ns `keycloak` with the `agentregistry` realm imported at boot |
| `realm/` | The realm JSON, and the workshop-only additions for an existing Keycloak |
| `01-agent-authz.yaml` | Gateway `e2e-gw`, agent stand-in, JWT plus group-based authz (`EnterpriseAgentgatewayPolicy`) |
| `02-mcp-authz.yaml` | Two MCP servers, `EnterpriseAgentgatewayBackend` MCP targets, opposing authz policies |
| `sts-values.yaml` | Helm values enabling the STS (`tokenExchange` block) |
| `03-api-authz.yaml` | API route that trusts only STS-issued delegated tokens |
| `04-mcp-api.yaml`, `mcp-api/` | MCP server whose tool calls the API through the gateway with the caller's token |

## Prerequisites

Everything on-cluster is deployed by this lab. Locally you need:

- kubectl, helm, python3
- kind, only if you want a local cluster created by `00-kind.sh`
- A Solo.io enterprise license key

Bringing your own cluster: skip `00-kind.sh`. `00-platform.sh` installs into whatever `kubectl config current-context` points at and never creates a cluster.

## Lab objectives

- Install Enterprise Agentgateway and deploy Keycloak as the identity provider
- Demo 1, user to agent: require a Keycloak JWT and authorize on `groups` with a CEL `matchExpression`
- Demo 2, agent to MCP: route MCP traffic through the gateway with `EnterpriseAgentgatewayBackend` MCP targets and authorize which MCP servers a caller may reach
- Demo 3, delegation: enable the built-in STS and exchange the user JWT plus the agent's Kubernetes SA token for a delegated token carrying both `sub` (user) and `act` (agent)
- Demo 4, MCP or agent to API: restrict an API route to STS-issued delegated tokens so raw user tokens cannot bypass the agent chain
- Step 8, MCP server to API: an MCP tool calls the API through the gateway carrying the delegated token, and is refused with a raw user token
- Validate every allow and deny path (200, 401, 403)

## Background

At every hop the question is the same: who is calling, and are they allowed to call this? The identity answering it changes at each hop.

1. alice calls the gateway with her user JWT and reaches agent-x. bob is denied with 403. (Demo 1)
2. The agent sends the user JWT plus its own SA token to the STS on port 7777 and receives a delegated token with `sub: alice` and `act: agent`. (Demo 3)
3. The agent calls the gateway with a JWT and reaches mcp-a. mcp-b is denied with 403. (Demo 2)
4. An MCP tool calls the gateway with the delegated token and reaches the API. A raw user token is denied with 401. (Demo 4)

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

The controller upgrade uses `--reuse-values`, so re-running this script after Step 6 does not wipe the STS configuration.

Docs: [Install with Helm](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/helm/)

Expected output (truncated):

```
deployment "enterprise-agentgateway" successfully rolled out
NAME                      CONTROLLER                        ACCEPTED   AGE
enterprise-agentgateway   solo.io/enterprise-agentgateway   True       2s
deployment "sleep" successfully rolled out
PLATFORM-READY
```

The `sleep` pod's ServiceAccount (`system:serviceaccount:wp-a:default`) stands in for the agent's workload identity. Its mounted SA token is the actor token in Step 6, and Step 7's policy authorizes on this identity via `jwt.act.sub`.

---

## Step 2: Deploy Keycloak with the agentregistry realm

```bash
kubectl apply -f 00-keycloak.yaml
kubectl -n keycloak rollout status deploy/keycloak --timeout=300s
```

The realm is imported from a ConfigMap at boot (`start-dev --import-realm`), so there is nothing to run inside the pod and a restart re-imports it. It is the `agentregistry` realm from the Agentregistry Enterprise docs (clients `ar-backend`, `ar-cli-interactive`, `ar-cli-password`, `ar-ui`, `ar-mcp-client`; `Groups` claim; `ar-backend` audience; group `admins`; user `admin-user` with password `password`) plus what this lab adds:

- Client `agw-client` (confidential, secret `agw-client-secret`) with the `Groups` mapper and a `may_act` mapper naming the agent's ServiceAccount
- Users `alice` and `bob` (password `pw`); alice is in group `agent-x-users`
- Groups `readers` and `writers` with users `reader` and `writer` (password equals username), used in Part 2
- Clients `kagent-backend`, `kagent-ui`, and `agentregistry` (service account in group `agentregistry`), used in Part 2

The STS refuses a delegation exchange unless the user's token carries a `may_act` claim naming the actor. The identity provider decides which agent may act on the user's behalf (RFC 8693 section 4.4).

Already running Keycloak with the `agentregistry` realm? Skip the apply and import only the additions:

```bash
kubectl exec -i -n keycloak deploy/keycloak -- bash -c 'cat > /tmp/add.json && /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin && /opt/keycloak/bin/kcadm.sh create partialImport -r agentregistry -s ifResourceExists=SKIP -o -f /tmp/add.json' < realm/workshop-additions.json
```

Then set the issuer in `01-agent-authz.yaml`, `02-mcp-authz.yaml`, `04-mcp-api.yaml`, `sts-values.yaml`, `05-kagent-install.sh`, `06-registry-values.yaml`, and `06-registry-install.sh` to your Keycloak URL.

---

## Step 3: Mint user tokens and inspect claims

All requests in this lab are sent from the in-cluster `sleep` pod, so the gateway is reached by its Service DNS name and no LoadBalancer is needed. Define a token helper and mint both users:

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

Decode bob's token the same way (`$BOB_JWT`): `may_act` is present and there is no `Groups` block, because bob is in no group. That missing group is what Demo 1 checks.

---

## Step 4: Enforce user to agent authorization (Demo 1)

`01-agent-authz.yaml` creates ns `e2e-demo` with the agent stand-in (`agent-x`, httpbin), Gateway `e2e-gw` (class `enterprise-agentgateway`, port 8080), an `HTTPRoute` on `/agent-x`, and an `EnterpriseAgentgatewayPolicy` combining JWT authentication with CEL authorization:

```yaml
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
        - issuer: http://keycloak.keycloak.svc.cluster.local:8080/realms/agentregistry
          jwks:
            remote:
              backendRef: {name: keycloak-jwks, ...}
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
kubectl apply -f 01-agent-authz.yaml
kubectl -n e2e-demo rollout status deploy/e2e-gw --timeout=180s
kubectl -n e2e-demo rollout status deploy/agent-x --timeout=180s
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

## Step 5: Enforce agent to MCP authorization (Demo 2)

`02-mcp-authz.yaml` deploys two MCP servers (`mcp-a` and `mcp-b`, both `mcp-website-fetcher`), each behind an `EnterpriseAgentgatewayBackend` with an MCP static target, routed at `/mcp-a` and `/mcp-b` with opposing authz policies. `mcp-a` requires alice's group. `mcp-b` requires a group nobody has.

Manifest details that matter:

- The MCP `Service` port carries `appProtocol: agentgateway.dev/mcp`. Without it the backend never picks the server up.
- The backend uses `spec.mcp.targets[].static: {host, port, protocol: SSE}`. The `HTTPRoute` backendRef carries `group: enterpriseagentgateway.solo.io` and `kind: EnterpriseAgentgatewayBackend`.

Docs: [About MCP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/about/), [Static MCP backends](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/static-mcp/), [Control access to tools](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

```bash
kubectl apply -f 02-mcp-authz.yaml
kubectl -n e2e-demo rollout status deploy/mcp-a deploy/mcp-b --timeout=180s
```

Send an MCP `initialize` through the gateway as alice:

```bash
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ws","version":"1.0"}}}'

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

## Step 6: Enable the STS and exchange for a delegated token (Demo 3)

Upgrade the controller with the `tokenExchange` block from `sts-values.yaml`. The subject validator points at the Keycloak JWKS and the actor validator is `k8s`.

```bash
export ENTERPRISE_AGW_VERSION=$(helm get metadata enterprise-agentgateway -n agentgateway-system | awk '/^VERSION:/ {print $2}')

helm upgrade enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version $ENTERPRISE_AGW_VERSION -n agentgateway-system --reuse-values -f sts-values.yaml
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

Both token types must be `urn:ietf:params:oauth:token-type:jwt`. The `access_token` type is rejected. Claims such as `groups` do not propagate into the delegated token; downstream authorization keys on `sub` and `act`.

---

## Step 7: Restrict the API to delegated identities (Demo 4)

`03-api-authz.yaml` deploys `api-backend` on route `/api` with a policy whose JWT provider trusts only the STS issuer (JWKS fetched from the controller's port 7777) and authorizes on the agent's identity:

```yaml
    authorization:
      action: Require
      policy:
        matchExpressions:
          - "jwt.act.sub == 'system:serviceaccount:wp-a:default'"
```

```bash
kubectl apply -f 03-api-authz.yaml
kubectl -n e2e-demo rollout status deploy/api-backend --timeout=120s

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

## Step 8: MCP server calls the API through the gateway

`04-mcp-api.yaml` deploys `mcp-api`, an MCP server with one tool, `httpbin_get(path)`. The tool calls the API at `API_BASE` and forwards the bearer token it received. `API_BASE` defaults to the `/api` route on `e2e-gw`; set it to an existing API gateway to route through that instead. Source and Dockerfile are in `mcp-api/`.

Build the image and make it available to the cluster (KinD shown; push to a registry for any other cluster and set `image:` in the manifest):

```bash
docker build -t mcp-api:local mcp-api/
kind load docker-image mcp-api:local --name agw-e2e
kubectl apply -f 04-mcp-api.yaml
kubectl -n e2e-demo rollout status deploy/mcp-api --timeout=120s
```

The route `/mcp-api` accepts a Keycloak user token or an STS delegated token and forwards it to the server (`preserveToken: true`). Call the tool with each:

```bash
mcp-api/mcpcall.sh "$DELEGATED_TOKEN"
mcp-api/mcpcall.sh "$USER_JWT"
```

Expected output:

```
HTTP 200
HTTP 401
```

With the delegated token the chain is agent, gateway, MCP server, gateway, httpbin, and every hop sees the same `sub` and `act`. With the raw user token the MCP hop admits the call but the API route rejects it, so the MCP server cannot reach the API with an identity it was not delegated.

---

## Validation checklist

1. `anonymous: 401`, `alice: 200`, `bob: 403` on `/agent-x` (Demo 1)
2. MCP `initialize` result from `mcp-a`, `403` from `mcp-b` (Demo 2)
3. Delegated token decodes with `sub` = alice and `act.sub` = `system:serviceaccount:wp-a:default` (Demo 3)
4. `delegated: 200`, `raw user: 401`, `anonymous: 401` on `/api` (Demo 4)
5. `HTTP 200` then `HTTP 401` from `mcp-api/mcpcall.sh` with the delegated and raw tokens (Step 8)

## Adapting this to production

- Agent: replace the httpbin stand-in with a real agent, for example a kagent agent. Its ServiceAccount becomes `AGENT_SA` in Step 2 and the `act.sub` in Step 7.
- In-agent exchange: agents perform Step 6's token exchange in code (for example with the agentsts-adk package).
- API leg: Step 7's policy applies unchanged on a Solo Enterprise kgateway route in front of a real API.
- Identity provider: Keycloak is the stand-in. Okta, Entra ID, Auth0 and others work the same way; only the issuer and JWKS provider config changes. Multiple identity domains means one JWT provider entry per issuer.

## Follow-ups

- Workload identity without a user: the agent hop already uses the pod's Kubernetes ServiceAccount token as the actor token (Step 6). A further step is to let the MCP and API routes accept a projected ServiceAccount token directly, with a JWT provider pointed at the cluster issuer, for workload-to-workload calls that have no user in the chain. The registry to kagent hop stays on OIDC client credentials; the kagent runtime requires it.

## Bring your own components

Each piece is optional if you already run it. Everything the lab creates is confined to its own namespaces (`e2e-demo`, `keycloak`, `wp-a`) and its own Gateway `e2e-gw`. Existing gateways, routes, and policies are not touched.

| You already have | Skip | Adjust |
|---|---|---|
| Kubernetes cluster | `00-kind.sh` | Point `kubectl` at your cluster and run `00-platform.sh`. The lab needs no StorageClass and no LoadBalancer; the gateway is reached by Service DNS. |
| Enterprise Agentgateway | Step 1, but still `kubectl apply -f 00-client.yaml` (the client's SA is the actor identity) | The chart names the controller Service `enterprise-agentgateway` regardless of release name, so only a different namespace changes the STS address. Update it in three places: `sts-values.yaml` (`issuer`), `03-api-authz.yaml` (provider `issuer` and JWKS `backendRef` namespace), and Step 6's exchange URL. Step 6's `helm upgrade` must target your release name and namespace. Validated with release `my-agw` in ns `gw-system`. |
| Keycloak | `00-keycloak.yaml` | Import `realm/workshop-additions.json` into your `agentregistry` realm (Step 2 shows the partial import). Then set the issuer in `01-agent-authz.yaml`, `02-mcp-authz.yaml`, `04-mcp-api.yaml`, `sts-values.yaml`, `05-kagent-install.sh`, `06-registry-values.yaml`, and `06-registry-install.sh` to your Keycloak URL. A realm built from the Agentregistry Enterprise docs already carries the `Groups` claim these policies use. |
| agentregistry | Nothing, the lab never touches it | Deploy your real agent through the registry, point the `/agent-x` HTTPRoute's backendRef at its Service, and use its ServiceAccount as `AGENT_SA` (Step 2) and in Step 7's `jwt.act.sub` expression. |
| A real agent workload | The httpbin stand-in in `01-agent-authz.yaml` | Route to it and use its ServiceAccount as `AGENT_SA` everywhere. |
| Istio or ambient mesh | Nothing | The lab's namespaces are not mesh-enrolled and do not need to be. |

The STS `tokenExchange` values ride on the controller's Helm release. Enabling it on an existing install is Step 6's `--reuse-values` upgrade, and the final Cleanup command removes it again.

## Cleanup

```bash
# 1. Remove demo routes, policies, and workloads
kubectl delete -f 04-mcp-api.yaml --ignore-not-found
kubectl delete -f 03-api-authz.yaml --ignore-not-found
kubectl delete -f 02-mcp-authz.yaml --ignore-not-found
kubectl delete -f 01-agent-authz.yaml --ignore-not-found

# 2. Restore the controller to its pre-STS configuration
helm upgrade enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version $ENTERPRISE_AGW_VERSION -n agentgateway-system \
  --set licensing.licenseKey="$LICENSE_KEY"

# 3. Remove Keycloak and the test client
kubectl delete -f 00-keycloak.yaml --ignore-not-found
kubectl delete -f 00-client.yaml --ignore-not-found

# Or, if 00-kind.sh created the KinD cluster, delete it all at once:
kind delete cluster --name agw-e2e
```

---

# Part 2: Agentregistry Enterprise and Solo Enterprise for kagent

Part 1 deployed the agent and MCP servers with `kubectl`. Part 2 makes the registry the source of truth: the agent and MCP servers are cataloged in Agentregistry Enterprise, deployed into the cluster from the catalog through the kagent runtime, and visibility is governed by registry access policies. The gateway policies from Part 1 then apply to the registry-deployed workloads.

Everything runs against the same cluster and Keycloak realm. Access is CLI-first: the registry API is port-forwarded and tokens are minted in-cluster. Browser login to the registry or kagent UI needs a Keycloak issuer the browser can reach, which a cluster with a LoadBalancer provides and a local KinD cluster does not.

## Using an existing Keycloak and Agentregistry Enterprise

If Keycloak and Agentregistry Enterprise are already running and configured as the Agentregistry Enterprise docs describe (realm `agentregistry`, `Groups` claim, `admins` superuser group), use them instead of the lab copies:

1. Import the workshop additions into your realm (Step 2 shows the partial import with `realm/workshop-additions.json`). This adds `agw-client`, alice and bob, the `readers` and `writers` groups, and the `kagent-backend`, `kagent-ui`, and `agentregistry` clients. Set the `agentregistry` client secret to a value of your choice and export it as `AGENTREGISTRY_CLIENT_SECRET`.
2. Point the Part 1 policies and `sts-values.yaml` at your issuer, then run Steps 3 to 8 against it.
3. Install kagent with your issuer: `KEYCLOAK_ISSUER=<your issuer> ./05-kagent-install.sh`.
4. Skip `06-registry-install.sh`. Export `ARCTL_API_BASE_URL` (your registry URL), `KEYCLOAK_URL` (your Keycloak base URL), and `KEYCLOAK_ISSUER`, then run `./06-register-kagent-runtime.sh`. The kagent controller must be reachable from the registry at `KAGENT_URL` (default `http://kagent-controller.kagent:8083`, same cluster).
5. Continue with Steps 12 to 14. `. ./06-registry-env.sh` honors the same variables, so `arctl` and `ar_token` work against your installation.

## Files for Part 2

| File | Purpose |
|---|---|
| `05-kagent-install.sh` | Solo Enterprise management chart, kagent CRDs, kagent-enterprise |
| `06-registry-install.sh`, `06-registry-values.yaml` | Agentregistry Enterprise |
| `06-register-kagent-runtime.sh` | Registers the kagent runtime in the registry (lab or existing) |
| `06-registry-env.sh` | Port-forward, `arctl` environment, token helper |
| `07-catalog.yaml` | Agent and MCP server catalog entries |
| `07-deploy.yaml` | Registry deployments to the kagent runtime |
| `08-access-policy.yaml` | Catalog visibility for readers |
| `09-gateway-registry.yaml` | Gateway routes and backends for the registry-deployed workloads |

## Step 9: Install arctl

```bash
curl -sSL https://storage.googleapis.com/agentregistry-enterprise/install.sh | ARCTL_VERSION=v2026.8.0 sh
export PATH=$HOME/.arctl/bin:$PATH
arctl version --json
```

The realm already holds everything Part 2 needs (Step 2): `admin-user` in `admins`, `reader` and `writer`, and the `kagent-backend`, `kagent-ui`, and `agentregistry` clients. The `agentregistry` client's service account is in group `agentregistry`; kagent maps that group to `global.Writer`, which is how the registry is allowed to create workloads.

## Step 10: Install Solo Enterprise for kagent

```bash
export LICENSE_KEY=<solo-enterprise-license-key>
./05-kagent-install.sh
```

The script installs the management chart with the kagent and agentregistry products enabled, the kagent CRDs, the controller signing key, and kagent-enterprise with OIDC pointed at the realm. The `agentregistry` group is mapped to `global.Writer`. No LLM key is configured; the agent deployed in Step 12 is a bring-your-own image.

Expected output ends with:

```
deployment "kagent-controller" successfully rolled out
KAGENT-READY
```

Docs: [Solo Enterprise for kagent install](https://docs.solo.io/kagent/latest/install/install-kagent/), [Keycloak identity provider](https://docs.solo.io/kagent/latest/security/idp/keycloak/)

## Step 11: Install Agentregistry Enterprise and register the kagent runtime

```bash
./06-registry-install.sh
```

The script installs the registry (ClusterIP, bundled PostgreSQL and ClickHouse, OIDC against the realm with `Groups` as the role claim and `admins` as the superuser group), then calls `06-register-kagent-runtime.sh`, which port-forwards the API, logs in as `admin-user`, stores the `agentregistry` client secret as a registry Secret, and registers the kagent runtime pointing at `kagent-controller.kagent:8083`.

Expected output ends with:

```
NAME              TYPE
kagent            Kagent
virtual-default   Virtual
RUNTIME-READY
REGISTRY-READY
```

In a new shell, load the environment before running `arctl`:

```bash
. ./06-registry-env.sh
```

Docs: [Agentregistry Enterprise setup](https://docs.solo.io/agentregistry/latest/setup/), [kagent runtime](https://docs.solo.io/agentregistry/latest/setup/runtime/kagent/)

## Step 12: Catalog the agent and MCP servers, deploy them from the registry

The catalog holds `agent-x` (bring-your-own image, A2A on port 8080), `mcp-a` and `mcp-b` (website fetcher, SSE on port 8000), and `mcp-api` (the Step 8 server, streamable HTTP on port 8000). The kagent controller marks a bring-your-own agent Ready only once `/.well-known/agent-card.json` answers on port 8080, so the registry copy of `agent-x` uses `traefik/whoami`, which answers every path and echoes the request it received. Each MCP server entry names its image under `origin.oci` and its listen port and path under `transport`. On KinD, load the local image first:

```bash
kind load docker-image mcp-api:local --name agw-e2e
arctl apply -f 07-catalog.yaml
arctl get agents
arctl get mcps
```

Deploy all four to the cluster through the kagent runtime:

```bash
arctl apply -f 07-deploy.yaml
arctl get deployments
kubectl get pods -n kagent
```

Expected: one pod each for `agent-x`, `mcp-a`, `mcp-b`, and `mcp-api` in namespace `kagent`, created by the kagent controller from the registry deployments, and `kubectl get agents,mcpservers -n kagent` lists the matching kagent resources.

## Step 13: Point the gateway at the registry-deployed workloads

Remove the Part 1 workloads and re-point the routes. The JWT and CEL policies are unchanged.

```bash
kubectl -n e2e-demo delete deploy agent-x mcp-a mcp-b mcp-api --ignore-not-found
kubectl -n e2e-demo delete svc agent-x mcp-a mcp-b mcp-api --ignore-not-found
kubectl apply -f 09-gateway-registry.yaml
```

Re-run the Step 4, 5, and 8 requests. Expected results are identical: alice 200 and bob 403 on `/agent-x`, mcp-a 200 and mcp-b 403, `mcp-api/mcpcall.sh` returns HTTP 200 with the delegated token and HTTP 401 with the raw user token. The workloads answering now came from the registry. Alice's `/agent-x` response is the whoami echo, and its `Authorization` line shows the token the gateway forwarded to the pod in namespace `kagent`.

The `ReferenceGrant` in `09-gateway-registry.yaml` lets routes in `e2e-demo` reference Services in `kagent`.

## Step 14: Govern catalog visibility

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
arctl apply -f 08-access-policy.yaml
ARCTL_API_TOKEN=$(ar_token reader) arctl get mcps
ARCTL_API_TOKEN=$(ar_token reader) arctl get agents
```

Expected: `mcp-a` and `agent-x` listed, `mcp-b` and `mcp-api` absent. The principal is the Keycloak group name from the `Groups` claim.

## Validation checklist, Part 2

1. `arctl get runtimes` lists `kagent` and `virtual-default`
2. Four pods in namespace `kagent`, one per registry deployment
3. Part 1 results repeat against the registry-deployed workloads (Step 13)
4. `reader` sees nothing, then exactly `agent-x` and `mcp-a` (Step 14)

## Cleanup, Part 2

```bash
arctl delete accesspolicy readers-see-agent-x-stack
arctl delete deployment agent-x mcp-a mcp-b mcp-api
arctl delete runtime kagent
helm uninstall agentregistry-enterprise -n agentregistry-system
helm uninstall kagent kagent-crds kagent-mgmt -n kagent
kubectl delete ns agentregistry-system kagent --ignore-not-found
```
