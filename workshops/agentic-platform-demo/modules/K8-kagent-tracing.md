# K8 · Follow an agent's work: tracing and analytics

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K7](K7-kagent-build-an-agent.md) · Next: [K9](K9-kagent-fleet-view.md)
<!-- nav:end -->

**Area:** Agents · **Time:** 3 min

## Framing

- When an agent gives a bad answer, teams need to see what it did, not guess.
- Agent frameworks often log nothing a platform or audit team can use.
- Next: every turn traced, with each model call, tool call, token count and duration.

**Proves:** kagent traces every turn (agent, model and tool spans, tokens, timing) into your cluster, and shows per-agent analytics.

**Needs:** [S0](S0-preflight.md), one chat from [K2](K2-kagent-same-agent-different-user.md), [K3](K3-kagent-gateway-policy-follows-the-agent.md) or [K7](K7-kagent-build-an-agent.md). Signed in as `admin`.

## Steps

**1. The trace list**

- **Tracing**, range **1h**. Each row is one turn: agent, model, duration, tokens.

**2. One turn**

- Open the newest `platform-assistant` row.
- **Point:** Execution Flow (agent, LLM, tool), the Trace Tree with `execute_tool records_...` and each `generate_content` call, tokens top right.

**3. Per agent**

- **Agents**, `platform-assistant`, **Analytics**.

## Say

- The agent's trace sits beside the gateway's own log of the same calls ([P2](P2-observability.md)): what the agent decided, and what the gateway allowed.
- Traces stay in your cluster (ClickHouse) and can also export over OpenTelemetry.

## Cleanup

None.

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K7](K7-kagent-build-an-agent.md) · Next: [K9](K9-kagent-fleet-view.md)
<!-- nav:end -->
