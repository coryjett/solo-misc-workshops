# P1 · What it looks like on Kubernetes (containers, control plane, data plane)

**Area:** Platform · **Time:** 5 min

**Proves:** agentgateway is just Kubernetes: a controller, a proxy Deployment, and Gateway API objects you manage like any other config.

**Needs:** S0.

## Steps

```bash
kubectl --context kind-agentic-demo -n agentgateway-system get pods          # controller, mcp-gateway proxy, UI, ext-auth, rate limiter
kubectl --context kind-agentic-demo get gateway,httproute -A                  # standard Gateway API objects
kubectl --context kind-agentic-demo -n agentgateway-system get enterpriseagentgatewaybackends,enterpriseagentgatewaypolicies
```
Open in the editor: `gateway/00-gateway.yaml` (the Gateway), `gateway/50-frontdoor-mcp.yaml` (backend, route, policies).

## In the UI

Solo UI (http://localhost:8082): **Gateways** (`mcp-gateway`, its routes and destinations), **Routes** (every path you just listed with kubectl), **Policies** (the same policy objects, all Active). Same objects, two views: CLI for automation, UI for operators.

## Expect

Pods Running; routes for `/mcp`, `/frontdoor/mcp`, `/a2a/agent-*`, `/registry`; backends and policies listed.

## Say

- Control plane (controller) turns YAML into proxy config; the data plane (the `mcp-gateway` pod) carries traffic. Scale them separately.
- Everything on screen is YAML in a folder, applied by a script: the same files go through any CI/CD or GitOps pipeline.
- Same Helm chart on any conformant Kubernetes. A standalone binary covers VMs and bare metal.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.
