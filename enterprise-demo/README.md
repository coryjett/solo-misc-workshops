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
- ~8 GB RAM available (for local k3d/kind cluster)
- ~45 minutes

> **No cloud cluster required.** The demo guide includes provisioning a local k3d or kind cluster. Cloud clusters (GKE, EKS, AKS) also work.

## Demo Flow

| Time | Section | Product | What You'll See |
|------|---------|---------|-----------------|
| 0:00 | [Part 1: Agent Registry](#part-1-agent-registry) | Agent Registry | Catalog MCP servers, search, publish artifacts |
| 0:15 | [Part 2: Agent Gateway](#part-2-agent-gateway) | Agent Gateway | Route MCP traffic, add auth + RBAC, see traces |
| 0:30 | [Part 3: kagent](#part-3-kagent) | kagent | Create an agent, connect to tools via AGW, chat |
| 0:40 | [Putting It All Together](#putting-it-all-together) | All three | End-to-end flow from registry → gateway → agent |

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
