# Configure End-to-End Agent Identity, Authorization, and Delegation

In this lab, you'll secure every hop of an agentic call chain — user → agent → MCP server → API — with Enterprise Agentgateway: JWT authentication and CEL-based authorization at each hop, and RFC 8693 token exchange so the user's identity travels the whole chain with the agent's identity attached.

This runbook was validated end to end against controller **v2026.9.0** on a local KinD cluster (Keycloak 26), including a clean-room run from an empty cluster using only the files in this folder. All `Expected output:` blocks show actual observed results.

## Files in this folder

| File | Purpose |
|---|---|
| `00-platform.sh` | Platform bootstrap: KinD cluster, Gateway API CRDs, Enterprise Agentgateway charts, test client |
| `00-client.yaml` | `sleep` test client in ns `wp-a` — its ServiceAccount is the **actor identity** for delegation |
| `00-keycloak.yaml` | Keycloak 26 (start-dev) in ns `keycloak` |
| `00-setup-realm.sh` | Realm `agent-demo`: users, group, client, `groups` + `may_act` mappers |
| `01-agent-authz.yaml` | Gateway `e2e-gw`, agent stand-in, JWT + group-based authz (`EnterpriseAgentgatewayPolicy`) |
| `02-mcp-authz.yaml` | Two MCP servers, `EnterpriseAgentgatewayBackend` MCP targets, opposing authz policies |
| `sts-values.yaml` | Helm values enabling the STS (`tokenExchange` block) |
| `03-api-authz.yaml` | API route that trusts only STS-issued delegated tokens |

## Pre-requisites

Everything on-cluster is deployed by this lab. Locally you need:
- kubectl, helm, kind (skippable if you bring a cluster), python3
- **Solo.io Trial License Key**: Enterprise Agentgateway requires a valid license key.

## Lab Objectives

- Install Enterprise Agentgateway and deploy Keycloak as the identity provider
- **Demo 1 — User → Agent:** Require a Keycloak JWT and authorize on `groups` with a CEL `matchExpression` in an `EnterpriseAgentgatewayPolicy`
- **Demo 2 — Agent → MCP:** Route MCP traffic through the gateway via `EnterpriseAgentgatewayBackend` MCP targets and authorize which MCP servers a caller may reach
- **Demo 3 — Delegation:** Enable the built-in STS and exchange the user JWT + the agent's Kubernetes SA token for a delegated token carrying both `sub` (user) and `act` (agent)
- **Demo 4 — MCP/Agent → API:** Restrict an API route to STS-issued delegated tokens only, so raw user tokens cannot bypass the agent chain
- Validate every allow AND deny path (200 / 401 / 403)

## Background

At every hop, the question is the same — *who is calling, and are they allowed to call this?* — but the identity answering it changes:

```
alice ──[user JWT]──► AGW ──► agent-x                 (Demo 1: bob denied, 403)
                        │
        agent ──[user JWT + SA token]──► STS :7777 ──► delegated token {sub: alice, act: agent}
                        │                              (Demo 3)
        agent ──[JWT]──► AGW ──► mcp-a                 (Demo 2: mcp-b denied, 403)
                        │
        MCP tool ──[delegated token]──► AGW ──► API    (Demo 4: raw user token denied, 401)
```

Enterprise Agentgateway includes a built-in STS on port 7777 (RFC 8693 token exchange). The delegated token it issues preserves the user's `sub` and embeds the agent's identity in `act` — downstream services see who asked and through what, natively.

> **Why not just forward the user's token?** A raw user token says nothing about *which agent* is acting, can be replayed against any route the user could reach, and grants the agent everything the user has. The delegated token is scoped: signed by the STS, carrying both identities, and only accepted where STS-issued tokens are trusted.

---

## Step 1 — Install the Platform

`00-platform.sh` creates a KinD cluster (skip with `SKIP_KIND=1` to use your current context), installs the Gateway API CRDs and both Enterprise Agentgateway charts, and deploys the `sleep` test client:

```bash
export LICENSE_KEY=<solo-enterprise-license-key>
./00-platform.sh
```

> **Note:** The controller upgrade uses `--reuse-values`, so re-running this script after Step 5 will not wipe the STS configuration.

Docs: [Install with Helm](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/install/helm/)

Expected output (truncated):

```
deployment "enterprise-agentgateway" successfully rolled out
NAME                      CONTROLLER                        ACCEPTED   AGE
enterprise-agentgateway   solo.io/enterprise-agentgateway   True       2s
deployment "sleep" successfully rolled out
PLATFORM-READY
```

> **Note — the client pod is also an identity:** the `sleep` pod's ServiceAccount (`system:serviceaccount:wp-a:default`) stands in for the agent's workload identity. Its mounted SA token is the **actor token** in Step 6, and Step 7's policy authorizes on exactly this identity via `jwt.act.sub`.

---

## Step 2 — Deploy Keycloak and Configure the Realm

```bash
kubectl apply -f 00-keycloak.yaml
kubectl -n keycloak rollout status deploy/keycloak --timeout=300s
```

`00-setup-realm.sh` creates realm `agent-demo` with users `alice` and `bob` (password `pw`), group `agent-x-users` (alice only), confidential client `agw-client`/`agw-client-secret`, a `groups` protocol mapper, and a hardcoded `may_act` mapper naming the agent's ServiceAccount. Run it inside the Keycloak pod:

```bash
kubectl exec -i -n keycloak deploy/keycloak -- bash -c "AGENT_SA=system:serviceaccount:wp-a:default bash -s" < 00-setup-realm.sh
```

> **Note:** the `-i` flag on `kubectl exec` is required — without it the script is silently not delivered to the pod (exit 0, nothing created).

Expected output (truncated):

```
Created new realm with id 'agent-demo'
...
REALM-READY
```

> **Why the `may_act` mapper?** The STS refuses a delegation exchange unless the **user's** token carries a `may_act` claim naming the actor. That is Keycloak — the identity authority — explicitly authorizing which agent may act on the user's behalf (RFC 8693 §4.4). Governance, not friction.

---

## Step 3 — Mint User Tokens and Inspect Claims

All requests in this lab are sent from the in-cluster `sleep` pod (KinD has no LoadBalancer, so the gateway is reached by its in-cluster Service DNS). Define a token helper and mint both users:

```bash
TOK() { kubectl exec -n wp-a deploy/sleep -- curl -s -X POST \
  http://keycloak.keycloak.svc.cluster.local:8080/realms/agent-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=agw-client -d client_secret=agw-client-secret \
  -d username=$1 -d password=pw | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"; }

export USER_JWT=$(TOK alice)
export BOB_JWT=$(TOK bob)
```

Decode alice's payload to inspect the claims:

```bash
_seg=$(echo "$USER_JWT" | cut -d. -f2 | tr '_-' '/+')
while [ $(( ${#_seg} % 4 )) -ne 0 ]; do _seg="${_seg}="; done
echo "$_seg" | base64 -d 2>/dev/null | python3 -m json.tool | grep -A3 -E 'groups|may_act'
```

Expected output:

```
    "groups": [
        "agent-x-users"
    ],
    "may_act": {
        "sub": "system:serviceaccount:wp-a:default"
    }
```

Bob's token carries `may_act` but **no** `agent-x-users` group — the group is what Demo 1 checks.

---

## Step 4 — Enforce User → Agent Authorization (Demo 1)

`01-agent-authz.yaml` creates ns `e2e-demo` with the agent stand-in (`agent-x`, httpbin), Gateway `e2e-gw` (class `enterprise-agentgateway`, port 8080), an `HTTPRoute` on `/agent-x`, and an `EnterpriseAgentgatewayPolicy` combining JWT authentication with CEL authorization:

```yaml
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
        - issuer: http://keycloak.keycloak.svc.cluster.local:8080/realms/agent-demo
          jwks:
            remote:
              backendRef: {name: keycloak-jwks, ...}
              jwksPath: /realms/agent-demo/protocol/openid-connect/certs
    authorization:
      action: Require
      policy:
        matchExpressions:
          - "'agent-x-users' in jwt.groups"
```

> **Note:** `jwksPath` is required whenever `jwks.remote.backendRef` is set — omitting it is a validation error.

Docs: [JWT authentication](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/jwt/) · [Authorization policies (CEL)](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/authorization/)

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

The 401/403 split matters: 401 = no/invalid token (authentication), 403 = valid token, insufficient claims (authorization).

---

## Step 5 — Enforce Agent → MCP Authorization (Demo 2)

`02-mcp-authz.yaml` deploys two MCP servers (`mcp-a`, `mcp-b` — `mcp-website-fetcher`), each behind an `EnterpriseAgentgatewayBackend` with an MCP static target, routed at `/mcp-a` and `/mcp-b` with opposing authz policies: `mcp-a` requires alice's group; `mcp-b` requires a group nobody has.

Key manifest details:
- The MCP `Service` port carries `appProtocol: agentgateway.dev/mcp` — omit it and the backend never picks the server up.
- `spec.mcp.targets[].static: {host, port, protocol: SSE}` on the backend; the `HTTPRoute` backendRef carries `group: enterpriseagentgateway.solo.io`, `kind: EnterpriseAgentgatewayBackend`.

Docs: [About MCP](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/about/) · [Static MCP backends](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/static-mcp/) · [Control access to tools](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/tool-access/)

```bash
kubectl apply -f 02-mcp-authz.yaml
kubectl -n e2e-demo rollout status deploy/mcp-a deploy/mcp-b --timeout=180s
```

Send a real MCP `initialize` through the gateway as alice:

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

> **Note:** in the full production flow this policy's CEL matches the DELEGATED token's `jwt.act.sub` (the agent identity) rather than the user's group — same policy shape, one expression change.

---

## Step 6 — Enable the STS and Exchange for a Delegated Token (Demo 3)

Upgrade the controller with the `tokenExchange` block (`sts-values.yaml` — subject validator points at the Keycloak JWKS, actor validator is `k8s`):

```bash
export ENTERPRISE_AGW_VERSION=$(helm get metadata enterprise-agentgateway -n agentgateway-system | awk '/^VERSION:/ {print $2}')

helm upgrade enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version $ENTERPRISE_AGW_VERSION -n agentgateway-system --reuse-values -f sts-values.yaml
kubectl -n agentgateway-system rollout status deploy/enterprise-agentgateway --timeout=180s
```

The STS listens on the controller Service, port 7777: token endpoint `/token`, JWKS at `/.well-known/jwks.json`.

> **Note:** if the controller was already running with an older STS config, the gateway may briefly reject fresh STS tokens with `token uses the unknown key` until its JWKS cache refreshes (~30s). See Troubleshooting.

Docs: [Token exchange overview](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/token-exchange/overview/) · [On-behalf-of (OBO) tokens](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/mcp/token-exchange/obo/) · [OAuth token exchange](https://docs.solo.io/agentgateway/kubernetes/latest/documentation/security/token-exchange/)

Perform the exchange from inside the agent's pod — the mounted SA token is the `actor_token`, the user JWT (with `may_act`) is the `subject_token`. In production the agent does this in code; here by hand:

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

> **Note:** both token types must be `urn:ietf:params:oauth:token-type:jwt` — `...token-type:access_token` is rejected. And claims like `groups` do **not** propagate into the delegated token: downstream authorization keys on `sub`/`act`, which is the point.

---

## Step 7 — Restrict the API to Delegated Identities (Demo 4)

`03-api-authz.yaml` deploys `api-backend` on route `/api` with a policy whose JWT provider trusts **only the STS issuer** (JWKS via a backend to the controller's port 7777) and authorizes on the agent's identity:

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

The raw user token is a valid Keycloak JWT with the right user — but it is signed by Keycloak, not the STS, so it fails **authentication** (401) at this route. Users cannot bypass the agent chain to reach the API directly. The same JWT+CEL policy shape applies unchanged on a Solo Enterprise kgateway route in front of a real API — the gateway hosting the policy changes, the policy doesn't.

---

## Validation checklist

1. `anonymous: 401 / alice: 200 / bob: 403` on `/agent-x` (Demo 1)
2. MCP `initialize` result from `mcp-a`, `403` from `mcp-b` (Demo 2)
3. Delegated token decodes with `sub` = alice and `act.sub` = `system:serviceaccount:wp-a:default` (Demo 3)
4. `delegated: 200 / raw user: 401 / anonymous: 401` on `/api` (Demo 4)

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Realm script exits 0 but creates nothing | `kubectl exec` without `-i` — stdin never reached the pod | Use `kubectl exec -i` |
| Policy rejected: `jwksPath is required` | `jwks.remote.backendRef` set without `jwksPath` | Add the explicit JWKS path |
| Keycloak: `Account is not fully set up` | User missing profile fields / pending required actions | Set `firstName`/`lastName`/`email`, `requiredActions: []` |
| Keycloak mints no tokens, `unknown_error` | An empty protocol mapper (inline `kcadm -s config...` quoting silently produced blank config) | Create mappers from a JSON file with `kcadm -f` |
| STS: `subject token does not contain may_act claim` | `may_act` mapper missing, or its `sub` doesn't match the actor token's `sub` | Re-check the mapper against the agent's SA identity |
| STS 400: unsupported token type | `subject_token_type`/`actor_token_type` set to `...access_token` | Use `urn:ietf:params:oauth:token-type:jwt` for both |
| `mcp: no backends configured` / resets on MCP route | Service port missing MCP `appProtocol` | Set `appProtocol: agentgateway.dev/mcp` |
| 401 `token uses the unknown key "..."` on the API route right after enabling the STS | The gateway cached the STS JWKS from before the controller restart (the STS signing key changes on restart) | Self-heals on the next JWKS refresh — wait ~30s and retry |

## Adapting This to Production

- **Agent:** swap the httpbin stand-in for a real agent (e.g. a kagent agent). The agent's ServiceAccount becomes `AGENT_SA` in Step 2 and the `act.sub` in Step 7.
- **In-agent exchange:** agents perform Step 6's token exchange in code (e.g. via the agentsts-adk package) rather than by hand.
- **API leg:** Step 7's policy shape applies unchanged on a Solo Enterprise kgateway route in front of a real API.
- **Identity provider:** Keycloak is the stand-in — the same shape carries over to Okta, Entra ID, Auth0, etc.; only the issuer/JWKS provider config changes. Multiple identity domains means one JWT provider entry per issuer.

## Bring Your Own Components

Each piece is optional if you already run it. Everything the lab creates is confined to its own namespaces (`e2e-demo`, `keycloak`, `wp-a`) and its own Gateway `e2e-gw` — existing gateways, routes, and policies are never touched.

| You already have | Skip | Adjust |
|---|---|---|
| **Enterprise Agentgateway** | Step 1 (still `kubectl apply -f 00-client.yaml` — the client's SA is the actor identity) | The chart names the controller Service `enterprise-agentgateway` regardless of release name, so only a different **namespace** changes the STS address — update it in three places: `sts-values.yaml` (`issuer`), `03-api-authz.yaml` (provider `issuer` + JWKS `backendRef` namespace), and Step 6's exchange URL. Step 6's `helm upgrade` must target **your** release name and namespace. (Validated: custom release `my-agw` in ns `gw-system` — all four demos pass.) |
| **Keycloak** | `00-keycloak.yaml` | Run `00-setup-realm.sh` against your instance (it only needs kcadm admin credentials; the realm it creates is additive). Then update the Keycloak host/realm in **three** files: `01-agent-authz.yaml` AND `02-mcp-authz.yaml` (provider `issuer` + JWKS `backendRef` in each policy) and `sts-values.yaml` (`subjectValidator.remoteConfig.url`). (Validated: Keycloak as `sso.idp.svc` — all four demos pass.) Reusing an existing realm instead also works — it needs a groups claim matching the CEL expression and a `may_act` mapper naming the actor SA. |
| **agentregistry** | Nothing — the lab never touches it | Deploy your real agent through the registry, point the `/agent-x` HTTPRoute's backendRef at its Service, and use its ServiceAccount as `AGENT_SA` (Step 2) and in Step 7's `jwt.act.sub` expression. |
| **A real agent workload** | The httpbin stand-in in `01-agent-authz.yaml` | Same as above: route to it, and swap `AGENT_SA` to its ServiceAccount everywhere. |
| **Istio / ambient mesh** | Nothing | Coexists — the lab's namespaces aren't mesh-enrolled and don't need to be. |

> **Note:** the STS `tokenExchange` values ride on the controller's helm release — enabling it on an existing install is Step 6's `--reuse-values` upgrade, and Cleanup's final helm command removes it again.

## Cleanup

```bash
# 1. Remove demo routes, policies, and workloads
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

# Or, if 00-platform.sh created the KinD cluster, delete it all at once:
kind delete cluster --name agw-e2e
```
