# Solo.io AI Platform — End-to-End Demo

A 45-minute guided demo of the Solo.io AI platform: **Agent Registry**, **Agent Gateway**, and **kagent** — three products that work independently but are most powerful together.

## The Story

You're a platform engineer building an AI-powered developer experience. You need to:

1. **Catalog and discover** MCP servers your teams have built (Agent Registry)
2. **Route, secure, and observe** all agent-to-tool traffic (Agent Gateway)
3. **Create and run** an AI agent that uses those tools (kagent)

This demo builds each layer progressively — by the end, you'll have a working agent calling MCP tools through a secured gateway, with full observability.

## Prerequisites

- `docker`, `kubectl`, `helm` installed
- An OpenAI API key
- An Agent Gateway Enterprise license key
- Access to kagent Enterprise Helm charts (provided by Solo.io)
- ~8 GB RAM available (for local k3d/kind cluster)
- ~45 minutes

> **No cloud cluster required.** The demo guide includes provisioning a local k3d or kind cluster. Cloud clusters (GKE, EKS, AKS) also work.

## Demo Flow

| Time | Section | Product | What You'll See |
|------|---------|---------|-----------------|
| 0:00 | [Part 1: Agent Registry](demo-guide.md#part-1-agent-registry-15-min) | Agent Registry | Scaffold, publish, and deploy MCP servers from the catalog |
| 0:15 | [Part 2: Agent Gateway](demo-guide.md#part-2-agent-gateway-15-min) | Agent Gateway | Route MCP traffic, add JWT auth + tool-level RBAC, see traces in Solo Enterprise UI |
| 0:30 | [Part 3: kagent](demo-guide.md#part-3-kagent-15-min) | kagent | Create an agent as YAML, connect to tools via AGW, chat in Solo Enterprise UI |
| 0:40 | [Putting It All Together](demo-guide.md#putting-it-all-together-5-min) | All three | End-to-end flow, three UIs, each product's contribution |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                         Solo.io AI Platform                                      │
│                                                                                 │
│  ┌───────────────────┐    ┌───────────────────────┐    ┌──────────────────────┐ │
│  │                   │    │                       │    │                      │ │
│  │  Agent Registry   │    │   Agent Gateway       │    │   kagent             │ │
│  │                   │    │                       │    │                      │ │
│  │  "What tools      │    │  "How do I get there  │    │  "Run the agent"     │ │
│  │   exist?"         │───►│   safely?"            │───►│                      │ │
│  │                   │    │                       │    │  ┌──────────────┐    │ │
│  │  ┌─────────────┐  │    │  ┌─────────────────┐  │    │  │   Agent      │    │ │
│  │  │ MCP Servers │  │    │  │ Routing         │  │    │  │   "weather   │    │ │
│  │  │ Agents      │  │    │  │ Authentication  │  │    │  │    assistant"│    │ │
│  │  │ Skills      │  │    │  │ RBAC            │  │    │  │              │    │ │
│  │  │ Prompts     │  │    │  │ Rate Limiting   │  │    │  │  Uses tools  │    │ │
│  │  └─────────────┘  │    │  │ Guardrails      │  │    │  │  via AGW     │    │ │
│  │                   │    │  │ Observability   │  │    │  └──────────────┘    │ │
│  │  Catalog +        │    │  └─────────────────┘  │    │                      │ │
│  │  Discovery +      │    │                       │    │  K8s-native          │ │
│  │  Versioning       │    │  AI-native proxy      │    │  agent lifecycle     │ │
│  │                   │    │  for all agent traffic │    │                      │ │
│  └───────────────────┘    └───────────────────────┘    └──────────────────────┘ │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

Continue to the **[Demo Guide](demo-guide.md)** for the full walkthrough.
