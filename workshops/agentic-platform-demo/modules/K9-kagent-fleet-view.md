# K9 · The agent fleet: dashboard and Substrate

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K8](K8-kagent-tracing.md) · Next: [L1](L1-llm-routing-failover.md)
<!-- nav:end -->

**Area:** Agents · **Time:** 3 min

## Framing

- Many agents sit idle most of the time, but each one usually holds a pod.
- Platform teams need one view of usage, tokens and capacity.
- Next: the fleet dashboard, and the runtime that suspends idle chats.

**Proves:** The dashboard shows runs, tokens per model and invocations per agent; Agent Substrate suspends each chat between turns, so idle agents use storage, not compute.

**Needs:** [S0](S0-preflight.md), a few chats from earlier modules. Signed in as `admin`.

## Steps

**1. Dashboard**

- **Dashboard**, range **24h**.
- **Point:** Total Agent Runs, Total Tokens per Model, Agent Invocations Over Time, workers assigned vs idle.

**2. Substrate**

- **Substrate**.
- **Point:** **Actors running 0/N** and **Workers busy 0/1**: every chat is suspended between turns.
- **Point:** Actor templates: one per agent revision. A running chat keeps the revision it started on.

## Say

- Capacity tracks use: many mostly idle agents fit on a small worker pool.
- Each chat resumes on the next message with its memory intact.

## Don't claim

- The cold-start and latency cards: laptop numbers from one node.

## Cleanup

None.

<!-- nav:start -->
[All modules](README.md) · [Agents](README.md#agents) · Previous: [K8](K8-kagent-tracing.md) · Next: [L1](L1-llm-routing-failover.md)
<!-- nav:end -->
