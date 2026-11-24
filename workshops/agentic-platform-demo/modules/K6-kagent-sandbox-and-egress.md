# K6 · Sandboxed agents: no outbound access until a policy allows it

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K5](K5-kagent-who-may-build-and-use.md) · Next: [L1](L1-llm-routing-failover.md)
<!-- nav:end -->

**Area:** Agents · **Time:** 5 min

## Framing

- Agents run code: shell commands, scripts, downloads.
- An agent that can reach the internet can leak whatever it can read.
- Next: a gVisor sandbox with no egress, then one host allowed by policy.

**Proves:** Each session runs in a gVisor sandbox on Agent Substrate; outbound traffic goes through an egress proxy that only allows the model, the tools and hosts an EgressPolicy names.

**Needs:** [S0](S0-preflight.md), [K1](K1-kagent-agents-on-the-platform.md). Sign in as `admin` / `admin`.

## Steps

**1. Which sandbox is this?**

- **platform-assistant**, **New chat:** `What Linux kernel release is this sandbox running? Use bash to run uname -r.`
- **Expect:** `4.19.0-gvisor`. The agent's code runs in a gVisor sandbox, not on the node's kernel.

**2. Try the internet**

- **New chat:**
  `Check connectivity from your sandbox with bash: for h in example.com www.google.com; do wget -q --spider https://$h && echo "$h reachable" || echo "$h unreachable"; done`
- **Expect:** `example.com unreachable`, `www.google.com unreachable`. No egress by default.

**3. Allow one host**

- **Policies**, **Create egress policy**: name `allow-example-com`, origin `https://example.com`, **Create policy**.
- **Agents**, platform-assistant, edit (`/agents/kagent/platform-assistant/edit`): **Egress policies** `allow-example-com`, save.

**4. Try again**

- **New chat**, the same connectivity message.
- **Expect:** `example.com reachable`, `www.google.com unreachable`.

## Say

- Models and tools need no rule: kagent derives them from the template. Everything else is denied until named.
- The same proxy carries the user's token to the gateway, so the sandbox never holds a credential.
- A prompt like "download this URL" never even reaches the model: the gateway's AI guard ([L3](L3-llm-prompt-guard.md)) refuses it as possible exfiltration. Two layers, model side and network side.

## Cleanup

`./reset.sh` removes the egress policy.

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K5](K5-kagent-who-may-build-and-use.md) · Next: [L1](L1-llm-routing-failover.md)
<!-- nav:end -->
