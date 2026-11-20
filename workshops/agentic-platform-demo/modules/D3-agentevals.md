# D3 · agentevals: score agents from their OpenTelemetry traces

<!-- nav:start -->
[All modules](README.md) · [Ecosystem](README.md#ecosystem) · Previous: [D2](D2-agentshield.md)
<!-- nav:end -->

**Area:** Ecosystem · **Time:** 5 min

**Status:** draft, not rehearsed on this lab. Run it once end to end before using it in a demo, then remove this line.

**Proves:** An agent's behavior can be scored from the telemetry it already emits: did it call the expected tools, and is the answer close to a known-good one. No rerun of the agent, no SDK, and results go back out as OpenTelemetry events.

**Needs:** The Mac only, not the lab. Python 3.11 or later in a virtualenv (agentevals-cli 0.14.1 on PyPI requires `>=3.11`), `git`, network to PyPI and GitHub. No cluster, no CRDs, no API keys for the deterministic metrics shown here. The lab cannot run the upstream Kubernetes walkthrough as is: it needs kagent `v1.0.0-alpha12` or later with a real Anthropic model config and a `helm upgrade` of kagent's telemetry settings, and the lab runs OSS kagent 0.10.1 with a placeholder model key. Not rehearsed on this lab yet (unverified).

## Steps

```bash
python3.12 -m venv /tmp/agentevals-venv && . /tmp/agentevals-venv/bin/activate   # any Python 3.11+; the Mac's default may be too new for the dependency wheels (unverified)
pip install agentevals-cli==0.14.1                                                # CLI, REST API, OTLP receivers, embedded web UI
git clone --depth 1 https://github.com/agentevals-dev/agentevals /tmp/agentevals  # only for samples/ (recorded traces and eval sets)
cd /tmp/agentevals
agentevals run samples/helm.json --eval-set samples/eval_set_helm.json -m tool_trajectory_avg_score   # PASS: the trace calls helm_list_releases
agentevals run samples/k8s.json  --eval-set samples/eval_set_helm.json -m tool_trajectory_avg_score   # FAIL: expected helm_list_releases, actual (none)
agentevals run samples/helm.json --eval-set samples/eval_set_helm.json -m tool_trajectory_avg_score --output json   # same result, machine readable for CI
agentevals serve                                                                 # web UI on http://localhost:8001 (Ctrl-C to stop)
```

Editor: `samples/eval_set_helm.json` is the golden run: the expected tool call per turn. The trace files are recorded OTLP JSON from a Kubernetes Helm agent.

## In the UI

agentevals UI http://localhost:8001: upload `samples/helm.json` and `samples/eval_set_helm.json`, pick `tool_trajectory_avg_score`, run, then open the span tree to show the `execute_tool` span that matched. Exact button labels unverified; the upstream README says the UI lets you "upload traces and eval sets, pick evaluators, inspect span trees, watch live sessions". API docs at http://localhost:8001/docs.

## Expect

- First run: `[PASS]  tool_trajectory_avg_score  1  PASSED`.
- Second run: `[FAIL] ... 0  FAILED` with `Expected: - helm_list_releases({})` and `Actual: (none)`.
- The CLI exit code differs between the two (the README says the exit code can gate a deployment; exact codes unverified).

## Say

- agentevals is an OTLP destination like any tracing backend. Point an exporter or a Collector at it (4318 HTTP, 4317 gRPC) and it turns GenAI spans into turns, tool calls, tokens and answers, then scores them.
- Deterministic gates (tool trajectory, response match) plus LLM judges and rubrics, and custom evaluators in any language (a program that reads JSON on stdin and writes a score).
- Scores go back out as `gen_ai.evaluation.result` log events parented to the evaluated span, so they land next to the agent's traces in the customer's own backend.
- Upstream has a Kubernetes walkthrough with kagent and an OpenTelemetry Collector: two agents on different runtimes, same prompt, one chosen as the golden run, the other scored against it.
- Different job from the upstream workshop's evaluations lab ([evaluate-openai-model-performance](https://github.com/solo-io/fe-enterprise-agentgateway-workshop/blob/c87f684c35ea1fdaa292868f0e58ba00629c3b56/labs/evaluations/evaluate-openai-model-performance.md), Promptfoo): that lab runs Promptfoo prompts through agentgateway to compare model answers. agentevals scores what an agent already did, from its traces, including which tools it called.
- Apache 2.0, open source, under active development (v0.14.1, 2026-11-17).

## Don't claim

- That agentevals integrates with agentgateway or agentregistry. Neither appears in its repo; the only Solo-ecosystem integration documented is kagent (a Kubernetes example and a daily telemetry contract check against kagent's span registry).
- That it is a supported product. It is open source in its own org (`agentevals-dev`); Solo engineers are among its main contributors, support status unverified, and its README warns "Expect breaking changes".
- That it scores this lab's traffic. The lab's gateway traces go to the Solo UI collector; whether agentgateway's LLM and MCP spans carry the `invoke_agent` and `execute_tool` spans agentevals needs is unverified.
- LLM-judge metrics live: they need a judge model and key (unverified whether one can point at the lab gateway's `auto` model).
- Claude Code or other coding-agent scoring end to end: upstream calls that partial.

## Cleanup

```bash
deactivate
rm -rf /tmp/agentevals /tmp/agentevals-venv
```
Stop `agentevals serve` with Ctrl-C first. Nothing in the cluster was touched.

<!-- nav:start -->
[All modules](README.md) · [Ecosystem](README.md#ecosystem) · Previous: [D2](D2-agentshield.md)
<!-- nav:end -->
