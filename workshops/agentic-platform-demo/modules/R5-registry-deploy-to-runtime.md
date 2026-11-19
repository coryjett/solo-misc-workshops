# R5 · Deploy to an agent runtime (kagent)

**Area:** Registry · **Time:** 5 min

**Proves:** The approved artifact is the unit; where it runs is a choice.

**Needs:** S0. kagent UI: `kubectl --context kind-agentic-demo -n kagent port-forward svc/kagent-ui 8083:8080 >/dev/null 2>&1 &` then http://localhost:8083

**Changes state:** deploys everything-reference-mcp to kagent. Once per reset.

## Steps

Registry UI (admin): **Runtimes** (`mcp-gateway` virtual, `onprem-k8s-kagent`). **Catalog** > **everything-reference-mcp** > **Deploy** (Kubernetes / `onprem-k8s-kagent`).
kagent UI: reload > **MCP & tools**, filter `everything`: 8 tools discovered.

## Expect

Deployed on kagent; tools discovered.

## Say

- kagent here; cloud runtimes (AgentCore, Foundry) are registry runtimes too. Agents reach tools through the gateway, so they inherit the rules.

## Cleanup

```bash
as_user admin; arctl delete deployment default/everything-reference-mcp   # kagent removes the server and its pods
```
