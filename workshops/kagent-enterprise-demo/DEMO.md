# Solo Enterprise for kagent: demo runbook

**Length:** about 30 min, 8 beats, all in the kagent UI. **Product:** Solo Enterprise for kagent v2026.11.2 (kagent 1.0.1 on Agent Substrate). **Cluster:** local kind `kagent-ent` (k8s 1.36). **Model:** OpenAI `gpt-5-mini`.
Every command uses only `./kubeconfig`; your default kube context is never touched.

## Setup (once)

- `./install.sh`: creates the cluster from `kind-config.yaml` if missing, installs Enterprise with the lab license (`SOLO_LICENSE_KEY`), then turns on the Kubernetes tools server, the example agent and trace content capture. About 6 min.
- `kubectl apply -f demo/sample-app.yaml`: the `shop/web` app the agent inspects and scales (`demo/reset.sh` also does this).

## T-10

```bash
demo/start.sh   # from this folder
```
- Checks pods, resets the demo, starts the UI port-forward (detached, reconnects on its own) and confirms http://localhost:8001 answers.
- Ends with `== ready`. Safe to rerun any time, including mid-demo if the UI drops.
- `demo/start.sh stop` ends the port-forward after the call.
- Open http://localhost:8001. It signs you in as **admin** with no password (bundled identity provider).
- Account menu, bottom left, shows `admin`. If not: **Change role**, then **Admin**.
- Optional full check (about 4 min, 10 model turns): `cd demo/rehearse && node rehearse.mjs`, then `demo/reset.sh` again.

## Beat 0 · Dashboard (2 min)

- **Click:** Dashboard, time range **30d**.
- **Point:** agent runs, tokens per model, invocations per agent, workers assigned vs idle.
- **Say:** "This is what the platform team sees: who runs which agents, on which models, at what token cost."

## Beat 1 · Build an agent in the UI (5 min)

- **Click:** Agents. Walk the Overview diagram: **AgentTemplate** (what it does) plus **Harness** (where it runs) make an **Agent**; each chat is a **Session** on Agent Substrate.
- **Click:** Create, then **AgentTemplate**. Enter:
  - **Name:** `ops-assistant`
  - **Model configuration:** `kagent/default-model-config`
  - **Description:** `Kubernetes operations assistant for the platform team`
  - **System prompt:** `You are a Kubernetes operations assistant. Answer briefly. Use your tools to look things up; never guess.`
  - **Add an MCP server:** `kagent/kagent-tool-server`, tools `k8s_get_resources`, `k8s_describe_resource`, `k8s_get_pod_logs`, `k8s_get_events`
  - **Add an MCP server** again: `kagent/kagent-tool-server`, tool `k8s_scale`, tick **Require approval**
  - **Create template**
- **Click:** Create, then **Agent**. Enter:
  - **Name:** `ops-assistant`
  - **Shared harness:** `kagent-default` (already selected)
  - **Template:** Reference, `ops-assistant`
  - **Create agent**. Status turns **Ready** in a few seconds.
- **Say:** "Read-only tools run freely. The one tool that changes things needs a human. That is enforced by the platform, not by asking the model nicely."

## Beat 2 · Chat, and approve a change (4 min)

- **Click:** the `ops-assistant` row, then type:
  - `List the pods in the shop namespace with their status.`
  - **Expect:** a `k8s_get_resources` call card, then `web-...` pods Running.
- **Click:** New chat, then type:
  - `Scale the web deployment in the shop namespace to 1 replica.`
  - **Expect:** a yellow box, "The agent is asking permission to run a tool", `k8s_scale`, with **Approve** and **Reject**.
  - **Click:** Approve. **Expect:** `deployment.apps/web scaled`.
- **Say:** "Every change an agent makes can require a person. The approval is part of the session record."

## Beat 3 · Tracing and analytics (3 min)

- **Click:** Tracing. Each turn is a row: agent, model, duration, tokens.
- **Click:** the newest `ops-assistant` row.
  - **Point:** Execution Flow (agent, LLM, tool), Trace Tree with `execute_tool k8s_scale` and each `generate_content gpt-5-mini` call, tokens top right.
- **Click:** Agents, `ops-assistant`, **Analytics**.
- **Say:** "Every tool call and model call is traced per agent and per user, stored in your cluster. Cost questions get answered from this."

## Beat 4 · Access control by role (4 min)

- **Show:** `demo/rbac.yaml` in your editor. Three `EnterpriseKagentRBACPolicy` objects, already applied:
  - `admins`: everything.
  - `writers`: view agents, templates and tools; chat; view traces.
  - `readers`: view agents, templates and traces only.
- **Click:** account menu, **Change role**, **Reader**. Open `ops-assistant`.
  - **Expect:** "Could not start this conversation · Not authorized".
- **Click:** Change role, **Writer**. New chat: `How many pods are in the shop namespace? Just the number.`
  - **Expect:** a normal answer.
- **Click:** Create, AgentTemplate, name `writer-test`, **Create template**.
  - **Expect:** "Could not create the agent template · Not authorized".
- **Click:** Change role, **Admin**.
- **Say:** "Roles come from your identity provider's groups: Entra ID, Okta, Keycloak or any OIDC. Here the bundled provider fakes three groups so we can switch live."

## Beat 4b · Same agent, the gateway decides the tools (4 min)

- **Setup (already done by reset):** `company-assistant` gets its tools only through agentgateway (`/mcp` over HTTPS), with the signed-in user's token. The token never enters the sandbox; the Substrate egress proxy swaps it in.
- **Show:** `demo/company-assistant.yaml` (`tokenPassthrough: true`) and the gateway rule in `gateway/gateway.yaml`:
  - `'admins' in jwt.Groups` gets everything.
  - `'writers' in jwt.Groups && mcp.tool.target == 'inventory'` gets inventory only.
- **Click:** Change role, **Admin**. Agents, `company-assistant`, New chat: `Which company system tools do you have? List their names only.`
  - **Expect:** `records_lookup_customer`, `records_account_status`, `inventory_check_stock`, `inventory_low_stock`.
- **Click:** New chat: `Look up customer C-1001.`
  - **Expect:** `Jordan Rivera`, with `DOB: [DOB REDACTED]` and `Phone: [PHONE REDACTED]` in the tool result. The gateway masked them.
- **Click:** Change role, **Writer**. New chat, the same tools question.
  - **Expect:** only `inventory_check_stock`, `inventory_low_stock`.
- **Click:** New chat: `Look up customer C-1001.`
  - **Expect:** the agent says it cannot reach the records system.
- **Click:** Change role, **Admin**.
- **Say:** "Same agent, same template. The gateway decides what each person's agent can touch, with the same policy engine you are already testing for your apps. Agents don't get a shared service account with everyone's access."

## Beat 5 · Sandbox and egress (5 min)

- **Click:** `ops-assistant`, New chat:
  - `Using bash, run exactly: uname -r; wget -q -T 8 -O - https://example.com | head -c 60; echo . Show the output verbatim.`
  - **Expect:** `4.19.0-gvisor`, then `wget: bad address 'example.com'`.
- **Point:** the agent can run code, but inside a gVisor sandbox with no outbound access by default. Models and MCP tools still work because the platform routes them.
- **Click:** Policies, **Create egress policy**:
  - **Name:** `allow-example-com`, **Origin:** `https://example.com`, Authentication **None**, **Create policy**.
- **Click:** Agents, `ops-assistant` row menu, edit (or go to `/agents/kagent/ops-assistant/edit`). **Egress policies:** `allow-example-com`. Save.
- **Click:** New chat:
  - `Using bash, run exactly: wget -q -T 8 -O - https://example.com | head -c 60; echo; echo ---; wget -q -T 8 -O - https://www.google.com | head -c 60; echo . Show the output verbatim.`
  - **Expect:** `<!doctype html>...` for example.com, `bad address 'www.google.com'` for Google.
- **Say:** "Egress is allow-listed per agent. An egress policy can also inject a credential header at the proxy, so the secret never enters the sandbox."

## Beat 6 · Substrate (2 min)

- **Click:** Substrate.
  - **Point:** **Actors running 0/N**, **Workers busy 0/1**: every chat is suspended between turns and costs storage, not a pod.
  - **Point:** Actor templates: one per agent revision. Editing a template made a new revision; running chats keep theirs.
- **Say:** "This is why many mostly idle agents fit on a small pool, and why a change never alters a conversation already in progress."

## Close

- **Ask:**
  - What will agents do first: ops, research, coding?
  - Which IdP groups map to who may build agents vs use them?
  - What must the sandbox stop: untrusted code, egress, data access?
  - Should model and tool calls go through agentgateway, for budgets and per-user policy?

## Reset and recovery

- **Between runs:** `demo/start.sh` (about 30 s).
- **UI not loading:** rerun `demo/start.sh`.
- **Account stuck on another role:** account menu, Change role, Admin.
- **Cluster broken:** `./teardown.sh -y && ./install.sh && demo/start.sh` (about 8 min).
- **After the engagement:** `./teardown.sh` stops the port-forward, deletes the cluster and local state, and keeps the kit.

## Don't claim

- **Production install:** kind, bundled Postgres and ClickHouse, in-cluster object storage, bundled identity provider with no real login.
- **Dashboard latency numbers:** cold-start rate and activation p95 come from one laptop node with one worker.
- **microVM:** not shown; gVisor only here.
- **agentgateway in this lab:** tool calls from `company-assistant` go through it as the user (beat 4b). Model calls and budgets do not; describe those.
- **Kit CA on the egress proxy:** lab-only. In production the gateway certificate comes from a CA the proxy already trusts.
