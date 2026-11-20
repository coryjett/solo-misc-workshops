# D1 · agentdesktop: the AI tools on the developer's laptop, governed

<!-- nav:start -->
[All modules](README.md) · [Ecosystem](README.md#ecosystem) · Previous: [R6](R6-audit-trail.md) · Next: [D2](D2-agentshield.md)
<!-- nav:end -->

**Area:** Ecosystem · **Time:** 8 min

**Status:** draft, not rehearsed on this lab. Run it once end to end before using it in a demo, then remove this line.

**Proves:** The gateway governs traffic once it arrives; agentdesktop covers the laptop it comes from. A fleet controller runs on the same cluster as the gateway, and a workstation daemon shows exactly what it would write into a developer tool (Claude Code here) to send its model traffic through agentgateway with a short-lived credential, without the provider key ever reaching the laptop.

**Needs:** [S0](S0-preflight.md). Internet access from the kind node (pulls `ghcr.io/agentdesktop-dev/agentdesktop-controller:v0.6.0`, `ghcr.io/dexidp/dex:v2.45.1`, `docker.io/library/postgres:17-alpine`), `git`, `openssl`, and an arm64 Mac for the workstation binary (use `agentdesktop-darwin-amd64` on Intel). Uses the project's own Dex (user `admin@example.com` / `password`), not the lab's Keycloak personas. Everything lands in a new `agentdesktop` namespace; nothing in `agentgateway-system` is touched.
Partial on this lab: the controller and the workstation preview run; enrollment of the laptop and a model call through the gateway do **not** (they need `/etc/hosts` entries for in-cluster names, an Anthropic API key, and a Strict JWT policy on a Gateway the example names `agentgateway-proxy`, which this lab does not have). Never run the project's own Kubernetes example top to bottom on this lab: it installs open-source agentgateway into `agentgateway-system` and its cleanup deletes that namespace.
Whole card unverified: not yet run on this lab.

## Steps

```bash
# Project example files at the release tag (main has moved ahead of v0.6.0)
git clone --branch v0.6.0 --depth 1 https://github.com/agentdesktop-dev/agentdesktop.git /tmp/agentdesktop
cd /tmp/agentdesktop

# Dev dependencies: namespace agentdesktop, Dex, disposable PostgreSQL
kubectl --context kind-agentic-demo apply -f examples/kubernetes/infrastructure.yaml
kubectl --context kind-agentic-demo -n agentdesktop rollout status deployment/postgres
kubectl --context kind-agentic-demo -n agentdesktop rollout status deployment/dex

# Dev CAs, controller TLS Secret, gateway JWT signing key. The script calls plain kubectl,
# so give it a kubeconfig that holds only the lab context.
kubectl config view --minify --flatten --context kind-agentic-demo > /tmp/agentdesktop-kubeconfig
KUBECONFIG=/tmp/agentdesktop-kubeconfig examples/kubernetes/create-tls.sh

# Controller from the repo chart. The chart defaults the image tag to its appVersion (0.1.0),
# which is not a published tag, so pin the release image.
helm --kube-context kind-agentic-demo upgrade --install agentdesktop deploy/helm/agentdesktop-controller \
  --namespace agentdesktop --values examples/kubernetes/values.yaml --set image.tag=v0.6.0
kubectl --context kind-agentic-demo -n agentdesktop rollout status deployment/agentdesktop

# Management UI/API listens on loopback inside the pod. Forward it to 18080, clear of the lab's host ports.
kubectl --context kind-agentic-demo -n agentdesktop port-forward deployment/agentdesktop 18080:8080 >/dev/null 2>&1 &
curl --fail http://127.0.0.1:18080/api/v1/settings

# Workstation side, preview only: what the daemon would write into Claude Code. No files change.
curl -fL -o /tmp/agentdesktop-bin https://github.com/agentdesktop-dev/agentdesktop/releases/download/v0.6.0/agentdesktop-darwin-arm64
chmod +x /tmp/agentdesktop-bin
(umask 077 && mkdir -p /tmp/agentdesktop-standalone && openssl rand -hex 32 > /tmp/agentdesktop-standalone/usage-token)
/tmp/agentdesktop-bin daemon --config examples/standalone/config.yaml --user --dry-run
```
Editor: `examples/kubernetes/values.yaml` (`daemonConfig`: the gateway URL, `controllerJwt` with audience `agentgateway`, allowed client `claude-code`, a Claude Code company announcement) and `examples/kubernetes/agentgateway.yaml` (the gateway side: `jwtAuthentication` with issuer `agentdesktop-controller`, plus access-log attributes `llm.client` and `user`). Show the second file, do not apply it here. Compare it with this lab's `gateway/41-llm-identity.yaml`: same `jwtAuthentication` block, different issuer.

## In the UI

Agentdesktop controller UI: http://127.0.0.1:18080 (device inventory and configuration; empty fleet, since no laptop enrolls on this lab). Solo UI: nothing new; agentdesktop does not register with it. Only the editor view connects the two.

## Expect

- Three rollouts finish. `kubectl --context kind-agentic-demo -n agentdesktop get svc` shows `agentdesktop` and `dex` as LoadBalancer with EXTERNAL-IP `<pending>` (no load-balancer provider in kind); harmless for this card.
- `/api/v1/settings` returns JSON with `admin_listen` `127.0.0.1:8080` and `oidc_enabled`, `tls_enabled`, `gateway_jwt_enabled` true (shape taken from the project's managed quickstart; values on this chart unverified).
- The dry run prints a "Dry run" banner saying no files will be changed, then an `UPDATE Claude Code settings` diff for `~/.claude/settings.json` adding `apiKeyHelper` (the agentdesktop `credential --client-id claude-code` helper), the company announcement, and `env.ANTHROPIC_BASE_URL` `http://127.0.0.1:4001/`, then a one-line summary.
- The diff shows the presenter's real Claude Code settings. Check it before sharing the screen.

## Say

- Three layers: MDM manages the device, agentdesktop manages the AI tools on it, agentgateway enforces model policy and holds the provider keys.
- Agentdesktop finds the tools (Claude Code, Codex, Cursor, OpenCode, VS Code, Grok Build, Copilot CLI, Pi), lists their MCP servers and skills without collecting secrets or skill bodies, and writes managed settings and sandbox policy in each tool's own format.
- Each tool request gets a short-lived JWT from the controller carrying user, device and client label. The gateway validates it like any other issuer, and access logs and usage can be broken down by user, device, tool and model.
- Open source, Apache 2.0, started by Solo.io; agentgateway is its reference gateway.

## Don't claim

- That this lab ran enrollment or a model call through the gateway. It ran the controller and a dry-run preview only.
- MCP traffic through the gateway: agentdesktop inventories MCP connections; the project's announcement says they are not automatically proxied through agentgateway.
- Any integration with agentregistry or kagent. Neither appears in the repository; do not imply the catalog drives what the laptop may use.
- That the client label proves which program called. The README says it is asserted by the local helper and is not cryptographic proof; SPIFFE identities are listed as future work.
- Replacing MDM. The project positions itself on top of MDM.
- Production readiness or a supported product. v0.6.0 (2026-11-06), chart version 0.x, the Kubernetes example is labeled "local development cluster, not production", and the stock controller only serves its management UI on loopback (remote admin needs a build with a compiled-in auth provider). Commercial support status: unverified.
- That the Kubernetes example's `AgentgatewayPolicy` (open-source `agentgateway.dev` API) works unchanged on agentgateway Enterprise, which uses `EnterpriseAgentgatewayPolicy` in this lab: unverified.

## Cleanup

```bash
kill %1   # the port-forward, from the same shell
helm --kube-context kind-agentic-demo uninstall agentdesktop --namespace agentdesktop
kubectl --context kind-agentic-demo delete namespace agentdesktop
rm -rf /tmp/agentdesktop /tmp/agentdesktop-kubeconfig /tmp/agentdesktop-bin /tmp/agentdesktop-standalone
```
Do not use the project's own clean-up block: it uninstalls agentgateway and deletes `agentgateway-system`. Whether the dry run leaves local daemon state (for example under `~/.config/agentdesktop` or a socket) is unverified; check after the first run.

<!-- nav:start -->
[All modules](README.md) · [Ecosystem](README.md#ecosystem) · Previous: [R6](R6-audit-trail.md) · Next: [D2](D2-agentshield.md)
<!-- nav:end -->
