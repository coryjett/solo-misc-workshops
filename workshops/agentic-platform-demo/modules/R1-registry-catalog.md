# R1 · What exists: catalog and shadow-IT discovery

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [X1](X1-extension-points.md) · Next: [R2](R2-registry-team-scoping.md)
<!-- nav:end -->

**Area:** Registry · **Time:** 6 min

**Proves:** One place knows every agent, MCP server and model, who owns it and what data it touches, including ones nobody registered.

**Needs:** [S0](S0-preflight.md). Registry tab as admin.

## Steps

Registry UI (admin):
1. **Catalog**: search `team:engineering`, then `data:restricted`.
2. Open **incident-triage** > **Agent Composition**: prompt, skill pinned to a commit, MCP servers.
3. Open **data-masking-mcp** > **Used by Agents**: the blast radius.
4. **Instances** > clear the "Managed Resources" filter: agents and servers nobody registered.

## Expect

Engineering and restricted-data items; dependency view; unregistered (discovered) items.

## Say

- Discovery finds agents already running in the cluster: shadow IT, found for you.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [X1](X1-extension-points.md) · Next: [R2](R2-registry-team-scoping.md)
<!-- nav:end -->
