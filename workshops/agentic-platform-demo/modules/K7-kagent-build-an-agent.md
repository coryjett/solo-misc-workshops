# K7 · Build an agent in the UI

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K6](K6-kagent-sandbox-and-egress.md) · Next: [K8](K8-kagent-tracing.md)
<!-- nav:end -->

**Area:** Agents · **Time:** 5 min

## Framing

- Teams want to try agents without writing code or waiting on a platform ticket.
- Agents built ad hoc usually bring their own keys and their own access.
- Next: build one in the UI from shared parts the platform team already governs.

**Proves:** An agent is a template (model, prompt, tools) plus a harness (where it runs). Both pick from shared, governed parts: the gateway model and the gateway tools.

**Needs:** [S0](S0-preflight.md). Sign in to http://localhost:8084 as `admin` / `admin`.

## Steps

**1. The model**

- **Agents**: the Overview diagram. A template plus a harness make an agent; each chat is a sandboxed session.

**2. Create the template**

- **Create**, **AgentTemplate**. Enter:
  - **Name:** `my-assistant`
  - **Model configuration:** `kagent/via-gateway`
  - **System prompt:** `Answer questions about company systems briefly, using your tools. Never guess.`
  - **Add an MCP server:** `kagent/governed-tools`, leave **All tools**
  - **Create template**
- The tool list is empty on purpose: the gateway decides each user's tools at chat time ([K2](K2-kagent-same-agent-different-user.md)).

**3. Create the agent**

- **Create**, **Agent**. **Name:** `my-assistant`, **Shared harness:** `kagent-default`, **Template:** Reference, `my-assistant`. **Create agent**.
- **Expect:** status **Ready** in a few seconds.

**4. Use it**

- Open `my-assistant`, **New chat:** `Look up customer C-1001 and check stock of SKU-4471 at site-112.`
- **Expect:** a records call and an inventory call in one turn (admin may use every system).

## Say

- Nothing in this agent holds a key. Model and tools are the platform's shared, governed endpoints.
- The template is a Kubernetes resource, so the same agent can live in Git and roll out by GitOps.

## Notes

- Keep this exact prompt. The gateway's AI guard can read role-play wording such as "You are a helpful assistant" as an injection attempt and refuse the model call with 403.

## Cleanup

`./reset.sh` deletes agents and templates made during a demo.

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K6](K6-kagent-sandbox-and-egress.md) · Next: [K8](K8-kagent-tracing.md)
<!-- nav:end -->
