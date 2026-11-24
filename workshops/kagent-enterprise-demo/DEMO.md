# Solo Enterprise for kagent: demo runbook

**Length:** about 30 min · 8 beats · all in the kagent UI
**Product:** Solo Enterprise for kagent v2026.11.2 (kagent 1.0.1 on Agent Substrate)
**Model:** OpenAI `gpt-5-mini`
**UI:** http://localhost:8001

## Before the call

**T-10**
```bash
demo/start.sh   # from this folder
```
- Wait for `== ready`.
- Open http://localhost:8001.
- Account menu (bottom left) shows `admin`. If not: **Change role**, **Admin**.

**Optional full check** (about 4 min)
```bash
cd demo/rehearse && node rehearse.mjs && cd ../.. && demo/start.sh
```

**Setup, once:** `./install.sh` (about 8 min).

---

## Beat 0 · Dashboard

**Time:** 2 min

### Framing
- Agents are spreading across teams.
- Nobody can say who runs what, on which model, at what cost.
- Next: one view of the whole agent fleet.

### Steps
**1. Open the dashboard**
- **Click:** Dashboard, range **30d**.

### Point out
- Agent runs.
- Tokens per model.
- Invocations per agent.
- Workers assigned vs idle.

### Say
- "This is what the platform team sees: who runs which agents, on which models, at what token cost."

---

## Beat 1 · Build an agent in the UI

**Time:** 5 min

### Framing
- Teams want agents without waiting on a platform ticket.
- Ad hoc agents bring their own keys and their own access.
- Next: build one from shared, governed parts.

### Steps
**1. The model**
- **Click:** Agents. Walk the Overview diagram.

**2. Create the template**
- **Click:** Create, **AgentTemplate**.
- **Name:** `ops-assistant`
- **Model configuration:** `kagent/default-model-config`
- **Description:** `Kubernetes operations assistant for the platform team`
- **System prompt:** `You are a Kubernetes operations assistant. Answer briefly. Use your tools to look things up; never guess.`
- **Add an MCP server:** `kagent/kagent-tool-server`, tools `k8s_get_resources`, `k8s_describe_resource`, `k8s_get_pod_logs`, `k8s_get_events`
- **Add an MCP server** again: `kagent/kagent-tool-server`, tool `k8s_scale`, tick **Require approval**
- **Click:** Create template.

**3. Create the agent**
- **Click:** Create, **Agent**.
- **Name:** `ops-assistant`
- **Shared harness:** `kagent-default` (preselected)
- **Template:** Reference, `ops-assistant`
- **Click:** Create agent.
- **Expect:** status **Ready** in a few seconds.

### Point out
- Template = what it does. Harness = where it runs.
- Each chat is a session on Agent Substrate.
- Only `k8s_scale` needs approval.

### Say
- "Read-only tools run freely. The one tool that changes things needs a person."
- "The platform enforces that, not the prompt."

---

## Beat 2 · Chat, and approve a change

**Time:** 4 min

### Framing
- Read-only agents are easy to trust.
- Agents that change things are where the risk is.
- Next: the agent stops and asks before a change.

### Steps
**1. Read**
- **Click:** the `ops-assistant` row.
- **Type:** `List the pods in the shop namespace with their status.`
- **Expect:** a `k8s_get_resources` card, then `web-...` pods Running.

**2. Change**
- **Click:** New chat.
- **Type:** `Scale the web deployment in the shop namespace to 1 replica.`
- **Expect:** yellow box, "The agent is asking permission to run a tool", `k8s_scale`.

**3. Approve**
- **Click:** Approve.
- **Expect:** `deployment.apps/web scaled`.

### Point out
- The tool call and its arguments are visible before approval.
- The approval stays in the session record.

### Say
- "Every change an agent makes can require a person."

---

## Beat 3 · Tracing and analytics

**Time:** 3 min

### Framing
- A bad agent answer is hard to debug from the chat alone.
- Audit needs a record of every call.
- Next: every turn traced.

### Steps
**1. Trace list**
- **Click:** Tracing.

**2. One turn**
- **Click:** the newest `ops-assistant` row.

**3. Per agent**
- **Click:** Agents, `ops-assistant`, **Analytics**.

### Point out
- Execution Flow: agent, LLM, tool.
- Trace Tree: `execute_tool k8s_scale`, each `generate_content gpt-5-mini`.
- Tokens, top right.

### Say
- "Every tool and model call, per agent and per user, stored in your cluster."

---

## Beat 4 · Access control by role

**Time:** 4 min

### Framing
- Not everyone who uses an agent should be able to change it.
- Agent platforms often have one admin role, or none.
- Next: three groups, three levels of access.

### Steps
**1. Show the policies**
- **Open:** `demo/rbac.yaml` in your editor (already applied).

**2. Reader**
- **Click:** account menu, **Change role**, **Reader**. Open `ops-assistant`.
- **Expect:** "Could not start this conversation · Not authorized".

**3. Writer chats**
- **Click:** Change role, **Writer**. New chat.
- **Type:** `How many pods are in the shop namespace? Just the number.`
- **Expect:** a normal answer.

**4. Writer cannot build**
- **Click:** Create, AgentTemplate, name `writer-test`, Create template.
- **Expect:** "Could not create the agent template · Not authorized".

**5. Back to admin**
- **Click:** Change role, **Admin**.

### Point out
- `admins`: everything.
- `writers`: view and chat.
- `readers`: view and traces only.

### Say
- "Roles come from your IdP's groups: Entra ID, Okta or any OIDC."
- "Here the bundled provider fakes three groups so we can switch live."

---

## Beat 4b · Same agent, the gateway decides the tools

**Time:** 4 min

### Framing
- A shared agent usually means one service account with everyone's access.
- That makes the agent the easiest way around access control.
- Next: the gateway decides each person's tools.

### Steps
**1. Show the wiring**
- **Open:** `demo/company-assistant.yaml`: `tokenPassthrough: true`.
- **Open:** `gateway/gateway.yaml`: the two `matchExpressions` rules.

**2. Admin's tools**
- **Check:** role is **Admin**.
- **Click:** Agents, `company-assistant`, New chat.
- **Type:** `Which company system tools do you have? List their names only.`
- **Expect:** `records_...` and `inventory_...` tools.

**3. Admin looks up a customer**
- **Click:** New chat.
- **Type:** `Look up customer C-1001.`
- **Expect:** `Jordan Rivera`, with `[DOB REDACTED]` and `[PHONE REDACTED]`.

**4. Writer's tools**
- **Click:** Change role, **Writer**. New chat, the same tools question.
- **Expect:** only `inventory_check_stock`, `inventory_low_stock`.

**5. Writer looks up a customer**
- **Click:** New chat.
- **Type:** `Look up customer C-1001.`
- **Expect:** the agent cannot reach the records system.

**6. Back to admin**
- **Click:** Change role, **Admin**.

### Point out
- Same agent, same template.
- The user's token reaches the gateway; the sandbox never holds it.
- The gateway masked the personal data.

### Say
- "The gateway decides what each person's agent can touch."
- "Same policy engine you use for apps."

---

## Beat 5 · Sandbox and egress

**Time:** 5 min

### Framing
- Agents run code: shell commands, scripts, downloads.
- An agent with internet access can leak what it reads.
- Next: a sandbox with no egress until a policy allows a host.

### Steps
**1. Run code**
- **Click:** `ops-assistant`, New chat.
- **Type:** `Using bash, run exactly: uname -r; wget -q -T 8 -O - https://example.com | head -c 60; echo . Show the output verbatim.`
- **Expect:** `4.19.0-gvisor`, then `wget: bad address 'example.com'`.

**2. Allow one host**
- **Click:** Policies, **Create egress policy**.
- **Name:** `allow-example-com`
- **Origin:** `https://example.com`
- **Authentication:** None
- **Click:** Create policy.

**3. Attach it**
- **Go to:** `/agents/kagent/ops-assistant/edit`
- **Egress policies:** `allow-example-com`. Save.

**4. Try again**
- **Click:** New chat.
- **Type:** `Using bash, run exactly: wget -q -T 8 -O - https://example.com | head -c 60; echo; echo ---; wget -q -T 8 -O - https://www.google.com | head -c 60; echo . Show the output verbatim.`
- **Expect:** `<!doctype html>...` for example.com, `bad address 'www.google.com'` for Google.

### Point out
- gVisor kernel: the code never touches the node's kernel.
- Models and tools need no rule; everything else is denied.

### Say
- "Egress is allow-listed per agent."
- "A policy can inject a credential at the proxy, so the secret never enters the sandbox."

---

## Beat 6 · Substrate

**Time:** 2 min

### Framing
- Most agents sit idle most of the time.
- One pod per agent wastes capacity.
- Next: chats suspended between turns.

### Steps
**1. Open Substrate**
- **Click:** Substrate.

### Point out
- **Actors running 0/N**, **Workers busy 0/1**.
- Actor templates: one per agent revision.

### Say
- "Idle chats cost storage, not compute."
- "A change never alters a conversation already in progress."

---

## Close

- What will agents do first?
- Which IdP groups build agents, which only use them?
- What must the sandbox stop?
- Should model and tool calls go through agentgateway?

## Reset and recovery

- **Between runs:** `demo/start.sh` (30 s).
- **UI not loading:** `demo/start.sh`.
- **Stuck on another role:** Change role, Admin.
- **Cluster broken:** `./teardown.sh -y && ./install.sh && demo/start.sh` (8 min).
- **After the engagement:** `./teardown.sh`.

## Don't claim

- **Production install:** this is kind with a test identity provider.
- **Dashboard latency cards:** laptop numbers.
- **microVM:** not shown.
- **Model calls through the gateway:** not wired here; only tools (beat 4b).
- **Kit CA on the egress proxy:** lab-only.
