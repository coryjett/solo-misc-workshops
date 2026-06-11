# Solo.io AI Platform — End-to-End Demo

A 45-minute guided demo of the Solo.io AI platform: **Agent Registry (Enterprise)**, **Agent Gateway**, and **kagent** — three products that work independently but are most powerful together. All three products share a single Keycloak SSO (realm `solo-ai-demo`) providing group-based RBAC across Agent Registry and kagent.

## The Story

You're a platform engineer building an AI-powered developer experience. You need to:

1. **Catalog and discover** MCP servers your teams have built (Agent Registry (Enterprise))
2. **Route, secure, and observe** all agent-to-tool traffic (Agent Gateway)
3. **Create and run** an AI agent that uses those tools (kagent)

This demo builds each layer progressively — by the end, you'll have a working agent calling MCP tools through a secured gateway, with full observability.

## Quick Start

```bash
export OPENAI_API_KEY=sk-...
export AGENTGATEWAY_LICENSE_KEY=eyJ...

./setup.sh
```

The setup script provisions a k3d cluster and installs the three products. Then follow the [Demo Guide](demo-guide.md) to build, publish, and deploy hands-on.

## Prerequisites

- `docker`, `kubectl`, `helm` installed
- An OpenAI API key
- An Agent Gateway Enterprise license key
- A Solo license / image-pull access to the enterprise chart registry (`us-docker.pkg.dev`) — the Enterprise Agent Registry chart is entitled via image-pull access (no `licenseKey` value is required for it)
- ~8 GB RAM available (for local k3d/kind cluster)
- ~45 minutes (manual) or ~10 minutes (automated via `setup.sh`)

### One-time host setup

Add a `/etc/hosts` alias so the host can resolve the in-cluster OIDC issuer (`keycloak.keycloak.svc.cluster.local`). This is used by both `arctl` and the browser-based OIDC login flows, and must be run **before** `./setup.sh`:

```bash
echo '127.0.0.1 keycloak.keycloak.svc.cluster.local' | sudo tee -a /etc/hosts
```

> **No cloud cluster required.** The demo guide includes provisioning a local k3d or kind cluster. Cloud clusters (GKE, EKS, AKS) also work.

## Demo Flow

| Time | Section | Product | What You'll See |
|------|---------|---------|-----------------|
| 0:00 | [Part 1: Agent Registry](demo-guide.md#part-1-agent-registry-15-min) | Agent Registry (Enterprise) | Build, publish, and deploy an MCP server + prompt + skill + agent |
| 0:15 | [Part 2: Agent Gateway](demo-guide.md#part-2-agent-gateway-15-min) | Agent Gateway | Configure routing, add API key auth + RBAC, see traces in Solo Enterprise UI |
| 0:30 | [Part 3: kagent](demo-guide.md#part-3-kagent-15-min) | kagent | Create an agent as YAML, connect to tools via AGW, chat in Solo Enterprise UI |

## Service URLs & Namespaces

| Service | URL | Namespace |
|---------|-----|-----------|
| Agent Registry (Enterprise) | http://localhost:12121 | `agentregistry-system` |
| Keycloak (SSO, realm `solo-ai-demo`) | http://localhost:8080 (admin/admin) | `keycloak` |
| Solo Enterprise UI (kagent) | http://localhost:8082 | `kagent` |
| Agent Gateway | — | `agentgateway-system` |

> **Port note:** the Solo Enterprise UI (kagent) is served at `localhost:8082` — it was moved off `8080` to avoid a collision with Keycloak, which keeps `8080`.

Demo users (all with password `password`), provisioned in the `solo-ai-demo` realm:

| User | Group |
|------|-------|
| `admin` | `admins` |
| `dev` | `developers` |
| `viewer` | `viewers` |
| 0:40 | [Putting It All Together](demo-guide.md#putting-it-all-together-5-min) | All three | End-to-end flow, three UIs, each product's contribution |

## Architecture

![Solo.io AI Platform](platform-overview.png)

Three products, each answering a different question:

- **Agent Registry (Enterprise)** — *"What tools exist?"* — Catalog, discover, version, and deploy MCP servers
- **Agent Gateway** — *"How do I get there safely?"* — Route, authenticate, authorize, rate-limit, and observe agent traffic
- **kagent** — *"Run the agent"* — Kubernetes-native agent lifecycle with declarative YAML and GitOps

![Architecture](architecture-overview.png)

See [architecture.md](architecture.md) for detailed data flows and component descriptions.

## Files

| File | Description |
|------|-------------|
| [demo-guide.md](demo-guide.md) | Hands-on workshop walkthrough |
| [setup.sh](setup.sh) | Infrastructure setup (cluster + product installs) |
| [architecture.md](architecture.md) | Detailed architecture, data flows, and component table |

---

Continue to the **[Demo Guide](demo-guide.md)** for the full walkthrough.
