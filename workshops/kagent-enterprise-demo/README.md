# Solo Enterprise for kagent: UI demo kit

A standalone kind cluster for showing Solo Enterprise for kagent (kagent 1.x on Agent Substrate) entirely in the kagent UI: build an agent, approve a change, tracing, roles, the gateway deciding each role's tools, sandbox and egress, and the Substrate runtime. About 30 minutes.

Use this kit for a kagent-first conversation. For agentgateway-first demos, or kagent wired to the full gateway and Keycloak, use [../agentic-platform-demo](../agentic-platform-demo) (modules K1-K9).

## Run it

```bash
./install.sh        # once: kind cluster kagent-ent (k8s 1.36), Enterprise kagent, agentgateway, tool servers (about 8 min)
demo/start.sh       # before each demo: health check, reset, UI on http://localhost:8001
```

Then follow [DEMO.md](DEMO.md).

- `demo/start.sh stop` stops the UI port-forward. `./teardown.sh` deletes the cluster and keeps the kit.
- Browser rehearsal of every beat: `cd demo/rehearse && npm i && node rehearse.mjs` (20 checks).
- Uses only this folder's `kubeconfig`; your default kube context is never touched.

## Needs

- Docker, `kind`, `kubectl`, `helm`, `node`, Google Chrome (for the rehearsal).
- [../agentic-platform-demo/local.env](../agentic-platform-demo/local.env.example) set up, with `OPENAI_ENV_FILE` pointing at a file that holds `OPENAI_API_KEY` and `SOLO_LICENSE_KEY`.
- The tool servers are built from that demo's `tools/`.

## What's lab-only

- Sign-in uses kagent's bundled identity provider (Admin, Writer, Reader, No Role), not a real IdP.
- The Substrate egress proxy is patched to trust this kit's CA (`gateway/egress-trust.sh`); in production the gateway's certificate comes from a CA the proxy already trusts.
