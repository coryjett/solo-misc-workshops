# D2 · agentshield: who can reach what, beside the gateway

<!-- nav:start -->
[All modules](README.md) · [Ecosystem](README.md#ecosystem) · Previous: [D1](D1-agentdesktop.md) · Next: [D3](D3-agentevals.md)
<!-- nav:end -->

**Area:** Ecosystem · **Time:** 6 min

**Status:** draft, not rehearsed on this lab. Run it once end to end before using it in a demo, then remove this line.

**Proves:** An open-source tool (agentshield, Apache 2.0, pre-1.0) can sit beside the platform and read the same cluster: it builds one graph of workloads, identities, Services, Gateways and HTTPRoutes, and (with a model) flags changes that open a new lateral path and proposes a fix a person must approve. The gateway enforces on the request path; agentshield audits the paths from outside it.

**Needs:** [S0](S0-preflight.md). Runs on the Mac against the lab, nothing is installed in the cluster. Docker (PostgreSQL 16 on `127.0.0.1:5432`), free host ports 5432, 8088 and 5173, `gh`, and for the playground Node.js 24 or `>=26.12.1` with pnpm 11 (`corepack enable`). No API key for this card: without a model there are no findings and no remediation proposals on the lab, so the finding and approval flow is shown in the playground with synthetic data. The in-cluster Helm path is not used (chart is not published to a repo, the chart default image tag `latest` does not exist on ghcr, and it needs a PostgreSQL the Pods can reach). Pre-run steps 1 and 2 before the call: the first `make demo` spends minutes in `pnpm install`. Not yet run end to end on this lab: unverified.

## Steps

```bash
# 1. Get the project and its one tagged build (v0.0.1-rc.0, a pre-release; the binary embeds the web UI)
git clone https://github.com/agentshield-dev/agentshield.git ~/agentshield
cd ~/agentshield
gh release download v0.0.1-rc.0 --repo agentshield-dev/agentshield --pattern 'agentshield_0.0.1-rc.0_darwin_arm64.tar.gz' --dir .agentshield
tar -xzf .agentshield/agentshield_0.0.1-rc.0_darwin_arm64.tar.gz -C .agentshield

# 2. Playground: the real UI against a fake in-browser backend (second terminal, leave running)
make demo                                  # http://127.0.0.1:5173

# 3. Live graph of the lab, read-only discovery (third terminal, leave running)
export POSTGRES_PASSWORD='development-only-password'
make postgres-up
export AGENTSHIELD_DATABASE_URL="postgres://agentshield:${POSTGRES_PASSWORD}@127.0.0.1:5432/agentshield?sslmode=disable"
kubectl --context kind-agentic-demo config view --minify --flatten > .agentshield/kind-agentic-demo.kubeconfig
.agentshield/agentshield --listen 127.0.0.1:8088 --kubernetes-kubeconfig .agentshield/kind-agentic-demo.kubeconfig

# 4. Health and a resource count
curl -s http://127.0.0.1:8088/readyz -o /dev/null -w '%{http_code}\n'
curl -s http://127.0.0.1:8088/api/v1/overview

# 5. The objects it will draw for the MCP front door (same view, straight from the cluster)
kubectl --context kind-agentic-demo -n agentgateway-system get gateway,httproute
```

## In the UI

Playground (`http://127.0.0.1:5173`): choose a scenario, trigger its observation, open the finding (evidence and cited graph facts), then prepare and approve the proposed NetworkPolicy and show the approval dialog with the exact change. **Reset** restores the clean environment.

Live (`http://127.0.0.1:8088`): the environment graph. Select the `mcp-gateway` Gateway in `agentgateway-system` and show its HTTPRoutes and neighbours, then a kagent agent Pod and its ServiceAccount. Exact page names in the live UI: unverified.

## Expect

- `readyz` returns `200`; graph routes return `503` until discovery's first publication.
- The graph shows the lab namespaces (`agentgateway-system`, `agentregistry-system`, `kagent`, `keycloak`, `demo-tools`) with workloads, Pods, Services, ServiceAccounts, RBAC and Gateway API objects. Count: unverified (the project says about 250 resources for an empty kind cluster; the lab will be more).
- No findings and no proposals on the live graph: detection only runs when a model feature is enabled.
- The lab's Gateways use GatewayClass `enterprise-agentgateway`. The agentshield agentgateway plugin selects Gateways by controller `agentgateway.dev/gatewayclass-controller` and exposes no flag to change it, so the agentgateway-specific facets may not appear; the Gateways and HTTPRoutes still appear as plain Gateway API objects. Unverified on this lab.
- HTTPRoutes whose backend is an `EnterpriseAgentgatewayBackend` (front door, governed MCP) are not modelled as Services; expect a diagnostic or no edge there. Unverified.

## Say

- Two different questions. The gateway answers "may this caller use this tool right now". agentshield answers "did this change open a path that was not there before, and what evidence says so".
- It reads the same Kubernetes objects the platform writes (Gateway API, Services, RBAC, NetworkPolicies) with a read-only ClusterRole; it is not in the request path.
- Every fact in its graph records which plugin and observation produced it, and a model finding is accepted only if it cites facts the graph returned.
- Fixes are proposals: a person prepares (dry-run) and approves each one, the same human-in-the-loop idea as the registry approval in [R3](R3-registry-approval.md).
- Its own evaluation harness puts open-source agentgateway in front of the model it calls, so the two meet on the LLM path too.

## Don't claim

- That it is a supported product or on a roadmap. It is pre-1.0 open source in its own org (`agentshield-dev`); Solo engineers are among its contributors, support status unverified.
- Production readiness: pre-1.0, one pre-release tag (v0.0.1-rc.0, 2026-11-06), no authentication on the API or UI, one process per database, no HA.
- Detection quality: the project publishes no results; its evaluation is a six-campaign smoke test.
- That it sees MCP, A2A or LLM traffic through agentgateway: an agentgateway access-log normalizer exists but nothing feeds it yet. Today's telemetry is Istio waypoint access logs and AWS VPC Flow Logs, and the lab runs neither.
- That it understands Enterprise agentgateway policies or CRDs (tool authz, guardrails, backends). It does not watch them.
- Findings on the lab: those need `--agentic-investigation` and an OpenAI Responses API endpoint (or `--resource-rule-authoring`). Routing that through the lab's own gateway on `localhost:8081` is untested.

## Cleanup

```bash
# Ctrl-C the agentshield process and make demo first, then:
cd ~/agentshield
docker compose -f deploy/postgres/compose.yaml down -v   # stops PostgreSQL and removes its data volume
cd ~ && rm -rf ~/agentshield                             # clone, binary, kubeconfig copy, telemetry JSONL
```
Nothing was created in the cluster: discovery only reads, and no remediation was approved on the live graph.

<!-- nav:start -->
[All modules](README.md) · [Ecosystem](README.md#ecosystem) · Previous: [D1](D1-agentdesktop.md) · Next: [D3](D3-agentevals.md)
<!-- nav:end -->
