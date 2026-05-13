# Workshop: AGW Token Exchange against Okta (RFC 8693)

Demonstrates **gateway-mediated OAuth 2.0 Token Exchange** where a user's Okta-issued JWT is exchanged at Okta's custom Authorization Server for a token decorated with a specific audience and scope (e.g. for Snowflake) before being forwarded to an MCP backend.

```
┌────────┐  Okta user JWT       ┌─────┐  RFC 8693      ┌──────┐  RFC 8693+Basic+aud  ┌──────┐
│ client │ ───────────────────▶ │ AGW │ ─────────────▶ │ shim │ ────────────────────▶│ Okta │
└────────┘  in Authorization    └──┬──┘  to STS_URI    └──┬───┘                       └──┬───┘
                                   │                     │                              │
                                   │                     │◀─────────────────────────────┘
                                   │                     │  decorated Okta token
                                   │◀────────────────────┘
                                   │
                                   ▼
                            ┌─────────────┐
                            │ MCP backend │  echoes Authorization → proves the swap
                            └─────────────┘
```

> **The whole point of this workshop is the shim.** AGW's data plane today cannot speak Okta's token endpoint directly — three hardcoded behaviors in the Rust source conflict with Okta's requirements. The shim is a ~80-line Python pod that bridges them. **Read [`WHY-SHIM.md`](./WHY-SHIM.md) first** if you want to understand the architecture; everything else here is plumbing.

## What you'll build

- **Okta** — custom Authorization Server, scope, access policy with Token Exchange grant, confidential client app, test user
- **Shim** — Python pod that receives AGW's RFC 8693 request, adds `Authorization: Basic <client>`, `audience`, `scope`, forwards to Okta, returns the decorated token
- **MCP backend** — echoes the inbound Authorization so you can see the swap
- **AGW** — Gateway + HTTPRoute + AgentgatewayBackend + EnterpriseAgentgatewayPolicy with `tokenExchange.mode: ExchangeOnly` and `STS_URI` pointing at the shim

## Prerequisites

- Kubernetes cluster (k3d / kind / GKE), `kubectl`, `helm` v3+, `jq`, `curl`
- An Okta tenant (the workshop assumes `integrator-9380202.okta.com` but is configurable)
- `export AGENTGATEWAY_LICENSE_KEY="<your license>"`

## Run it

```bash
# 1. Configure Okta (admin console clicks) — see workshop-guide.md Part 1
# 2. Export the values you collected:
export OKTA_DOMAIN="integrator-9380202.okta.com"
export OKTA_AS_ID="aus<XYZ>"
export OKTA_CLIENT_ID="<from Okta>"
export OKTA_CLIENT_SECRET="<from Okta>"
export OKTA_TEST_CLIENT_ID="<from Okta>"
export OKTA_TEST_USERNAME="<test user>"
export OKTA_TEST_PASSWORD="<test password>"
export OKTA_AUDIENCE="api://snowflake-mcp"
export OKTA_SCOPE="snowflake.access"
export AGENTGATEWAY_LICENSE_KEY="<license>"

# 3. Install
./setup.sh

# 4. Test
./check.sh

# 5. Clean up
./cleanup.sh
```

## Files

| Path | Purpose |
|---|---|
| [`README.md`](./README.md) | This file — overview + run instructions |
| [`WHY-SHIM.md`](./WHY-SHIM.md) | **The explanation.** Why AGW needs the shim. Cites AGW Rust source line numbers and matches them against Okta's documented requirements. |
| [`workshop-guide.md`](./workshop-guide.md) | Step-by-step walkthrough including Okta admin clicks |
| [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) | Common Okta error responses and what they mean |
| [`setup.sh`](./setup.sh) | Automated installer (assumes Okta is already configured) |
| [`cleanup.sh`](./cleanup.sh) | Tears down everything from this workshop |
| [`check.sh`](./check.sh) | Sanity test — gets a subject token, calls AGW, validates the decorated token reaches MCP |
| [`k8s/00-namespace.yaml`](./k8s/00-namespace.yaml) | `okta-tx` namespace |
| [`k8s/10-shim.yaml`](./k8s/10-shim.yaml) | The Python translator — Deployment, Service, ConfigMap with the Python source |
| [`k8s/20-mcp-echo.yaml`](./k8s/20-mcp-echo.yaml) | Mock MCP server that echoes the inbound `Authorization` so you can verify the swap |
| [`k8s/30-agw.yaml`](./k8s/30-agw.yaml) | Gateway, Backend, HTTPRoute, EnterpriseAgentgatewayPolicy (`tokenExchange.ExchangeOnly`) |
| [`k8s/secret.yaml.tpl`](./k8s/secret.yaml.tpl) | Template for the Okta client secret |
| [`docs/architecture.mmd`](./docs/architecture.mmd) | Mermaid architecture diagram source |

## After the workshop

Three takeaways you should be able to recite:

1. **AGW can perform RFC 8693 token exchange against any IdP** as long as you bridge the data-plane request shape to what the IdP requires. The shim is that bridge.

2. **The bridge is small and well-defined** — it adds Basic client auth, an `audience` parameter, and a `scope` parameter. Everything else (grant type, subject_token, response parsing) works without changes.

3. **Native provider support is a clean upstream addition** — the controller-side Go interface (`TokenExchanger`) already supports multiple providers; Entra is the only implementation today. Adding an Okta provider eliminates the shim. Not done in this workshop because it requires modifying the AGW source; the shim achieves the same outcome with zero source changes.
