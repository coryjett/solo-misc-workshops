# P1 · What it looks like on Kubernetes (containers, control plane, data plane)

<!-- nav:start -->
[All modules](README.md) · [Platform](README.md#platform) · Previous: [S0](S0-preflight.md) · Next: [P2](P2-observability.md)
<!-- nav:end -->

**Area:** Platform · **Time:** 5 min

## Framing

- Teams worry that new infrastructure components complicate existing Kubernetes operations.
- Integrating new gateways often requires learning proprietary management tools and workflows.
- Next: the gateway as ordinary Kubernetes objects, in kubectl and in the UI.

**Proves:** agentgateway is just Kubernetes: a controller, a proxy Deployment, and Gateway API objects you manage like any other config.

**Needs:** [S0](S0-preflight.md).

## Steps

**1. List the platform pods**

```bash
kubectl --context kind-agentic-demo -n agentgateway-system get pods
```
- Controller, the `mcp-gateway` proxy, UI, ext-auth, rate limiter.

**2. List Gateways and routes**

```bash
kubectl --context kind-agentic-demo get gateway,httproute -A
```
- Standard Gateway API objects, one route per path.

**3. List backends and policies**

```bash
kubectl --context kind-agentic-demo -n agentgateway-system get \
  enterpriseagentgatewaybackends,enterpriseagentgatewaypolicies
```
- The gateway's own resources: what it routes to, and the rules.

Editor:
- `gateway/00-gateway.yaml`: the Gateway.
- `gateway/50-frontdoor-mcp.yaml`: a backend, its route and policies.

## In the UI

- Solo UI http://localhost:8082 **Gateways**: `mcp-gateway`, its routes and destinations.
- **Routes**: every path you just listed with kubectl.
- **Policies**: the same objects, all Active.
- Say: same objects, two views. CLI for automation, UI for operators.

## Expect

Pods Running; routes for `/mcp`, `/frontdoor/mcp`, `/a2a/agent-*`, `/registry`; backends and policies listed.

## Say

- Control plane (controller) turns YAML into proxy config; the data plane (the `mcp-gateway` pod) carries traffic. Scale them separately.
- Everything on screen is YAML in a folder, applied by a script: the same files go through any CI/CD or GitOps pipeline.
- Same Helm chart on any conformant Kubernetes. A standalone binary covers VMs and bare metal.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [Platform](README.md#platform) · Previous: [S0](S0-preflight.md) · Next: [P2](P2-observability.md)
<!-- nav:end -->
