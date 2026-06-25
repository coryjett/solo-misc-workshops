# Cedar ext_authz for agentgateway

Authorize **LLM** and **MCP** traffic through agentgateway with a bring-your-own
[Cedar](https://www.cedarpolicy.com/) policy engine, wired in over the standard
external-authorization (ext_authz) gRPC contract.

A tiny Go service ([cedar-go](https://github.com/cedar-policy/cedar-go)) receives each
request from the gateway, turns it into a Cedar authorization query, and answers
allow/deny. agentgateway forwards the request body, so Cedar can decide on the actual
content — the **LLM model** in an OpenAI request, or the **tool name and arguments** in
an MCP `tools/call`. Cedar is **default-deny**, and a `forbid` always beats a `permit`.

## What it demonstrates

- **ext_authz delegation** — `EnterpriseAgentgatewayPolicy.traffic.extAuth` pointing at a
  custom gRPC authorizer (distinct from the Solo `entExtAuth` AuthConfig path).
- **LLM model allowlist** — permit a team/tier to call only approved chat models; org-wide
  `forbid` of an expensive model.
- **Per-MCP-tool authorization** — allow `tools/list` and a specific tool, deny a
  destructive one for everyone.
- **Per-argument constraints** — same tool, but a `tools/call` whose `path` argument escapes
  `/docs` is denied (Cedar reads `params.arguments`, not just the tool name).
- **Identity from a JWT** — the gateway-validated token's claims (`team`, `tier`, `org`,
  `scp`, `sub`) become the Cedar principal + entity attributes.

## Architecture

```
                          ext_authz (gRPC, h2c)
  MCP / LLM client  ──►  agentgateway  ◄────────────►  cedar-authz-server (cedar-go)
   (Bearer JWT)            │   ▲                          evaluates authz.cedar
                           │   │ allow / deny             (policies via ConfigMap)
                           ▼   │
                  upstream OpenAI  /  remote MCP server
```

The gateway calls the Cedar service **before** forwarding upstream. `failureMode: FailClosed`
means an unreachable authorizer denies the request.

## Prerequisites

- `docker`, `k3d`, `kubectl`, `helm`, `go` (1.23+), `jq`
- An agentgateway Enterprise license: `export AGENTGATEWAY_LICENSE_KEY=...`
- An OpenAI API key for the LLM route: `export OPENAI_API_KEY=...`

The **IdP is Keycloak**, deployed by this workshop (`make keycloak`). Its `cedar-demo`
realm has a client-credentials client whose hardcoded protocol mappers stamp the claims
Cedar authorizes on — `team=GTM`, `tier=premium`, `org=acme`, `scp=["api.read"]` (plus
`sub`). `test/get-token.sh` fetches a token from it.

## Setup

```bash
# 1. k3d cluster + agentgateway Enterprise
./k3d-setup.sh

# 2. deploy Keycloak (the IdP) + import the cedar-demo realm
make keycloak

# 3. build the Cedar image, import it into k3d, apply svc + routes + both extAuth policies
make load deploy        # `deploy` needs OPENAI_API_KEY (creates the openai-secret)

# 4. watch Cedar decisions
make logs
```

> The Cedar image is built locally and `k3d image import`ed — never pushed to a registry
> (`imagePullPolicy: Never`).

> **JWT trust:** the Cedar service reads the (gateway-forwarded) token's claims; it does
> not re-verify the signature. To make the gateway enforce Keycloak as the trust anchor,
> add a JWT authentication policy on the routes pointing at the realm's JWKS
> (`http://keycloak.keycloak.svc.cluster.local:8080/realms/cedar-demo/protocol/openid-connect/certs`)
> so invalid tokens are rejected before ext_authz.

## The policies

Live in [`cedar-authz-server/policies/authz.cedar`](cedar-authz-server/policies/authz.cedar)
(schema in [`schema.cedarschema`](cedar-authz-server/policies/schema.cedarschema)). They're
also delivered to the cluster via the `cedar-policies` ConfigMap in
[`k8s/10-cedar-authz-deploy.yaml`](k8s/10-cedar-authz-deploy.yaml), so you can edit them live:

```bash
kubectl edit configmap cedar-policies -n agentgateway-system
kubectl rollout restart deploy/cedar-authz-server -n agentgateway-system
```

| Rule | Effect |
|---|---|
| `permit` LLM chat | `GTM` team **and** `premium` tier may call `gpt-4o` / `gpt-4o-mini` |
| `forbid` `gpt-4-turbo` | org-wide deny — beats any permit |
| `permit` MCP `listTools` | `GTM` may list tools on the `solo-docs` server |
| `permit` MCP `callTool` | `GTM` may call `search_solo_docs` |
| `forbid` unless `path like "/docs*"` | per-argument: deny if the call escapes `/docs` |
| `forbid` `delete_page` | destructive tool denied for everyone |

## Testing

Grab a token and exercise the allow/deny pairs in
[`test/requests.http`](test/requests.http) (VS Code REST Client / IntelliJ HTTP client, or
translate to `curl`). Port-forward the gateway and Keycloak in two terminals:
`make gw-forward` (→ `localhost:8080`) and `make kc-forward` (→ `localhost:8081`).

```bash
JWT=$(./test/get-token.sh --raw)        # from Keycloak (defaults to localhost:8081)

# ALLOWED — GTM + premium + allowlisted model
curl -sS localhost:8080/v1/chat/completions -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'

# DENIED — model not on the allowlist (Cedar default-deny)
curl -sS localhost:8080/v1/chat/completions -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"hello"}]}'

# DENIED — MCP tool argument escapes /docs (per-argument forbid)
curl -sS localhost:8080/mcp -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_solo_docs","arguments":{"path":"/etc/secrets","query":"x"}}}'
```

`make logs` shows the matching `ALLOW` / `DENY` line with the reason for each.

## How the wiring works

- [`k8s/30-policy-openai-extauth.yaml`](k8s/30-policy-openai-extauth.yaml) and
  [`k8s/50-policy-mcp-extauth.yaml`](k8s/50-policy-mcp-extauth.yaml) attach
  `traffic.extAuth` to the OpenAI and MCP routes, with `forwardBody` so Cedar sees the
  request content and `grpc.contextExtensions.route_type` (`llm` / `mcp`) so the service
  knows how to parse it.
- The Cedar service ([`cedar.go`](cedar-authz-server/cedar.go)) decodes the JWT payload
  (already validated by the gateway), builds the Cedar entities, and evaluates. It does
  **not** re-verify the signature — in production, forward claims as trusted headers or via
  metadata instead of re-parsing the bearer token.

## Cleanup

```bash
make undeploy
kubectl delete namespace keycloak --ignore-not-found
k3d cluster delete agw-demo
```
