# kagent OTEL Tracing — Hub/Spoke Troubleshooting

For diagnosing OTLP trace export failures on kagent-enterprise hub/spoke deployments. Covers the common case where the management cluster is fixed but the spoke continues to fail, plus several other independent symptoms with the same surface error.

---

## TL;DR

If you see this error in a kagent-controller pod:

```
2026/04/15 15:11:34 traces export: exporter export timeout:
  rpc error: code = Unavailable desc =
  delegating_resolver: invalid target address "": missing address
```

**The target string the OTEL exporter handed to gRPC is empty.** Despite the `delegating_resolver` phrasing, this is **not** necessarily a proxy issue — recent gRPC-Go (post-v1.65) wraps the resolver chain with `delegatingresolver` by default whether or not `HTTP_PROXY` env vars exist. So the error simply means "empty target arrived at the resolver layer."

### Root cause #1 — Schemeless OTLP endpoint (most common)

**This is verified against the OSS source** (`kagent/go/core/internal/telemetry/tracing.go:36`). The controller's tracing init calls `autoexport.NewSpanExporter(ctx)`, which constructs an OTLP gRPC exporter that parses the endpoint string with Go's `url.Parse`. A schemeless value like:

```
solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
```

…is parsed by `url.Parse` as **`scheme:opaque`** — the segment before `:` becomes the URL scheme, the segment after becomes the opaque path, and `Host` ends up **empty**. The exporter dials `u.Host` → gRPC sees `""` → resolver emits the error.

**Fix:** prepend `http://` (or `https://` if your collector terminates TLS):

```yaml
otel:
  tracing:
    enabled: true
    exporter:
      otlp:
        endpoint: http://solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
        insecure: true
```

Or live-patch the deployment to test quickly:

```bash
kubectl -n kagent set env deploy/kagent-controller \
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
kubectl -n kagent rollout status deploy/kagent-controller
sleep 30
kubectl -n kagent logs --tail=200 deploy/kagent-controller | grep "traces export" | wc -l
# Expect 0
```

If the count is 0: confirmed. Update the Helm value durably (next chart upgrade clobbers `kubectl set env`).

> **Common confusion:** the OTEL spec used to allow bare `host:port` for OTLP gRPC. Newer versions tightened this to require a scheme. Some example YAML in older docs and chart `values.yaml` defaults still show schemeless format — those defaults are out of date.

### Other root causes (rank below schemeless)

2. **Pod hasn't restarted since ConfigMap update** — `envFrom` is snapshotted at pod creation. Fix: `kubectl rollout restart deploy/kagent-controller -n kagent`.

3. **Corporate HTTP/HTTPS proxy is intercepting the in-cluster OTLP call** — only applies if proxy env vars actually exist on the pod. Check:
   ```bash
   kubectl -n kagent exec deploy/kagent-controller -- env | grep -iE "PROXY"
   ```
   If `HTTP_PROXY`/`HTTPS_PROXY` are set and `NO_PROXY` doesn't include `.svc.cluster.local`, add cluster suffixes.

4. **A second OTEL initialization path** with empty default endpoint exists inside the binary, independent of the SDK env vars — rare, but possible in pre-release builds (controller reports `version: "dev"` in its config dump).

5. **Helm template took the "separate endpoints" path** (writes `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` instead of the generic `OTEL_EXPORTER_OTLP_ENDPOINT`) AND the binary version pinned in your chart only reads the generic. The current OSS kagent (`go/core/internal/telemetry/tracing.go:36`) uses `autoexport` and respects both via the OTEL SDK, so this shouldn't bite — but if you're on an older snapshot build it can. Verify by setting both names side by side.

---

## Two distinct error patterns

The customer's logs surfaced **two separate problems** that both manifest as "tracing isn't working." They have different root causes and different fixes. Diagnose them independently.

### Pattern A — Go controller emits empty target

**Where:** kagent-controller pod (Go binary)
**Log format:** stdlib log (`2026/04/15 15:11:34 ...`)
**Symptom:**
```
traces export: exporter export timeout: rpc error: code = Unavailable
desc = delegating_resolver: invalid target address "": missing address
```

**Root cause:** gRPC proxy delegation. The controller has `HTTP_PROXY`/`HTTPS_PROXY` set (often from EKS node config, EC2 metadata, or chart values). gRPC sees the proxy, instantiates `delegating_resolver`, and the resolver delegates to a target that ends up empty.

**Fix:** Add cluster-internal patterns to `NO_PROXY` so gRPC bypasses the proxy when dialing the in-cluster collector.

### Pattern B — Python agent pod points at wrong service

**Where:** Spawned agent runtime pod (Python kagent-adk)
**Log format:** Python logging (`2026-04-15 14:43:39,279 - opentelemetry.exporter.otlp...`)
**Symptom:**
```
INFO - Trace endpoint: solo-enterprise-ui.kagent.svc.cluster.local:4317
ERROR - Failed to export traces to solo-enterprise-ui.kagent.svc.cluster.local:4317
```

**Root cause:** Chart-templating bug. The kagent-enterprise Helm chart has a stale default trace endpoint pointing at `solo-enterprise-ui` (the UI service, port 4317), which is wrong. Should point at `solo-enterprise-telemetry-collector`. This default predates the controller/collector split.

**Fix:** Find the Helm value controlling agent-pod templating (usually `agent.tracing.endpoint`, `agentRuntime.otel.endpoint`, or similar) and set it to `solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317`. Or patch the agent Deployment directly:

```bash
kubectl -n kagent set env deploy/<agent-name> \
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
```

Note: agent pods are templated by the controller when reconciling `Agent` CRs. Patching the Deployment directly works until the controller re-reconciles. Fix the chart value for durability.

---

## Diagnostic flow

Work top-down. Each step has a 1-line check.

### 1. What's actually in the controller pod's env?

```bash
kubectl -n kagent exec deploy/kagent-controller -- env | grep -iE "OTEL|PROXY"
```

Expect:
```
OTEL_TRACING_ENABLED=true
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc
OTEL_EXPORTER_OTLP_TRACES_INSECURE=true
OTEL_EXPORTER_OTLP_TRACES_TIMEOUT=15
OTEL_LOGGING_ENABLED=false
```

- **No `OTEL_*` lines at all** → ConfigMap not loaded as `envFrom`. Check `kubectl get deploy kagent-controller -o jsonpath='{.spec.template.spec.containers[*].envFrom}'`. Should reference `kagent-controller` ConfigMap.
- **`OTEL_*` shows old/different values than ConfigMap** → pod hasn't restarted since ConfigMap was updated. `kubectl rollout restart deploy/kagent-controller`.
- **`OTEL_*` correct AND `PROXY` vars present** → Pattern A, jump to step 2.
- **`OTEL_*` correct AND `PROXY` vars absent** → endpoint really is empty downstream. Rare. Check chart version; potential SDK bug. Try adding `http://` scheme as a workaround.

### 2. Proxy check (if Pattern A suspected)

```bash
kubectl -n kagent exec deploy/kagent-controller -- env | grep -iE "PROXY|http_proxy|https_proxy|no_proxy"
```

If you see something like:
```
HTTPS_PROXY=http://corp-proxy.example.com:3128
HTTP_PROXY=http://corp-proxy.example.com:3128
NO_PROXY=localhost,127.0.0.1,169.254.169.254,10.0.0.0/8
```

…note whether `NO_PROXY` includes `.svc.cluster.local` (or your cluster's internal suffix). If it doesn't, the OTLP traffic for `solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317` is being sent through the corporate proxy, which doesn't accept it.

Fix:
```bash
CURRENT_NO_PROXY=$(kubectl -n kagent exec deploy/kagent-controller -- printenv NO_PROXY)
kubectl -n kagent set env deploy/kagent-controller \
  NO_PROXY="${CURRENT_NO_PROXY},.svc,.svc.cluster.local,.cluster.local,kagent.svc.cluster.local"
```

The cluster suffixes that matter:
- `.svc.cluster.local` — full FQDN
- `.svc` — short suffix some libraries match against
- `.cluster.local` — bare cluster domain
- Your pod/service CIDRs if proxy is also intercepting by IP

### 3. Collector reachable from controller pod?

Even with NO_PROXY fixed, verify connectivity:
```bash
kubectl -n kagent exec deploy/kagent-controller -- \
  timeout 5 bash -c 'echo > /dev/tcp/solo-enterprise-telemetry-collector.kagent.svc.cluster.local/4317' \
  && echo CONNECTED || echo FAILED
```

If FAILED:
- Verify the Service exists: `kubectl -n kagent get svc solo-enterprise-telemetry-collector`
- Verify the collector pod is running: `kubectl -n kagent get pods | grep telemetry`
- Check NetworkPolicy: `kubectl -n kagent get networkpolicy`

### 4. Agent pod (Pattern B)

Find an agent pod, check its env:
```bash
kubectl -n kagent get pods | grep -v controller | grep -v collector
kubectl -n kagent exec deploy/<agent-pod-name> -- env | grep -i OTEL
```

If `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` references anything other than `solo-enterprise-telemetry-collector...:4317` — most commonly `solo-enterprise-ui...:4317` — that's the chart-templating bug. Patch the Deployment as a quick fix; fix the Helm value for durability.

---

## Hub/spoke config checklist

Use this as the standard inventory after any chart upgrade or fresh install. "The hub is fixed" doesn't mean "the spoke is fixed" — the two have independent config chains and need to be verified separately.

### Management (hub) cluster

| # | Layer | Check | Expected |
|---|---|---|---|
| 1 | Helm value | `helm get values kagent -n kagent \| grep -A5 otel` | `solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317` |
| 2 | ConfigMap | `kubectl get cm kagent-controller -n kagent -o yaml \| grep OTEL` | matches Helm value |
| 3 | Env reaches pod | `kubectl exec deploy/kagent-controller -n kagent -- env \| grep OTEL` | matches ConfigMap |
| 4 | Proxy bypass | `kubectl exec deploy/kagent-controller -n kagent -- env \| grep PROXY` | `NO_PROXY` includes `.svc.cluster.local` if any PROXY is set |
| 5 | Service exists | `kubectl get svc -n kagent solo-enterprise-telemetry-collector` | port 4317 |
| 6 | Collector exporters | `kubectl get cm solo-enterprise-telemetry-collector-config -n kagent -o yaml \| grep "endpoint:"` | `tcp://<clickhouse>:9000` only |
| 7 | Collector receivers | `kubectl get cm solo-enterprise-telemetry-collector-config -n kagent -o yaml \| grep "0.0.0.0:"` | `0.0.0.0:4317` (local) + `0.0.0.0:4316` (remote) |
| 8 | Agent template | `kubectl exec deploy/<agent> -n kagent -- env \| grep OTEL` | endpoint points at collector, NOT `solo-enterprise-ui` |

### Relay (spoke) cluster

| # | Layer | Check | Expected |
|---|---|---|---|
| 1 | Helm value | `helm get values kagent -n kagent \| grep -A5 otel` | `solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317` (local collector) |
| 2 | ConfigMap | `kubectl get cm kagent-controller -n kagent -o yaml \| grep OTEL` | matches |
| 3 | Env reaches pod | `kubectl exec deploy/kagent-controller -n kagent -- env \| grep OTEL` | matches |
| 4 | Proxy bypass | `kubectl exec deploy/kagent-controller -n kagent -- env \| grep PROXY` | `NO_PROXY` includes `.svc.cluster.local` |
| 5 | Service exists | `kubectl get svc -n kagent solo-enterprise-telemetry-collector` | port 4317 |
| 6 | Relay Helm value | `helm get values kagent-relay -n kagent \| grep -A3 telemetry` | `telemetry.fqdn` = hub LB address, not empty |
| 7 | Relay collector exporter | `kubectl get cm solo-enterprise-telemetry-collector-config -n kagent -o yaml \| grep "endpoint:"` | `<hub-LB>:4316`, not empty, not just `:4316` |
| 8 | Agent template | `kubectl exec deploy/<agent> -n kagent -- env \| grep OTEL` | endpoint points at LOCAL spoke collector |

---

## Why the error mentions `delegating_resolver`

In **gRPC-Go v1.65+**, `delegatingresolver` is the default wrapper around the resolver chain regardless of whether proxy env vars are set. So the error name is not by itself proof of proxy involvement.

The empty target it emits about (`""`) is whatever string the OTEL exporter handed to gRPC. The most common path: the OTEL OTLP gRPC exporter ran `url.Parse(endpoint)` on a schemeless `host:port` string and ended up with `Host = ""`.

So: don't chase proxies just because of the error name. Verify with `kubectl exec ... env | grep PROXY` whether proxy is actually set on the pod. If not, focus on root cause #1 (schemeless endpoint).

---

## Verification against known-good clusters

A useful sanity check: confirm a known-working hub/spoke pair has none of the proxy env vars set, and the same schemeless OTEL endpoint format that the broken cluster has. This rules out "endpoint format" as a root cause and proves the issue is environment-specific.

```bash
# On a working cluster:
kubectl -n kagent get cm kagent-controller -o yaml | grep OTEL
# Expect: schemeless host:port

kubectl -n kagent exec solo-enterprise-telemetry-collector-0 -- env | grep -iE "PROXY|OTEL"
# Expect: no PROXY vars
```

If your working cluster uses schemeless endpoints and lacks proxy vars, but the broken cluster uses schemeless endpoints AND has proxy vars, the difference is the proxy — not the endpoint format.

---

## Fix recipes

### Quick fix (test that it works)

```bash
# Get current NO_PROXY value
CURRENT=$(kubectl -n kagent exec deploy/kagent-controller -- printenv NO_PROXY 2>/dev/null || echo "")

# Patch in cluster-internal suffixes
kubectl -n kagent set env deploy/kagent-controller \
  NO_PROXY="${CURRENT},.svc,.svc.cluster.local,.cluster.local"

# Watch logs to confirm the error stops
kubectl -n kagent logs -f deploy/kagent-controller | grep -i "traces export"
```

### Durable fix (chart value)

For kagent-enterprise chart, the value name varies by chart version. Common patterns:

```yaml
# Option 1: global extraEnv
global:
  extraEnv:
    - name: NO_PROXY
      value: ".svc,.svc.cluster.local,.cluster.local,10.0.0.0/8,localhost"

# Option 2: nested under proxy
global:
  proxy:
    noProxy: ".svc,.svc.cluster.local,.cluster.local,10.0.0.0/8,localhost"

# Option 3: kagent-enterprise controller env
kagentEnterprise:
  controller:
    env:
      - name: NO_PROXY
        value: ".svc,.svc.cluster.local,.cluster.local"
```

Check your installed chart's `values.yaml` or `helm show values` output for the right path.

### Agent-template fix

For Pattern B (Python agent pointing at `solo-enterprise-ui:4317`), the chart value is usually under the agent runtime section:

```yaml
agent:
  tracing:
    endpoint: solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
# or
agentRuntime:
  otel:
    exporterOtlpEndpoint: solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317
```

Again, `helm show values kagent-enterprise/kagent` will reveal the exact path.

---

## What this isn't

These errors look similar to but are **not**:

- **DNS resolution failures** — those show `lookup ... no such host` and include the hostname
- **TLS errors** — those mention `x509`, `certificate`, or `handshake`
- **Timeouts to a real address** — those show `context deadline exceeded` with the actual host:port
- **Service not found** — those show `connection refused` with a real address

If the address in the error is **anything other than `""`**, it's a different problem. The empty-string target is uniquely a proxy/delegating-resolver issue or a true config-not-loaded issue.

---

## Case history

| Date | Pattern | Resolution |
|---|---|---|
| _example_ | A + B | Hub previously fixed (chart value). Spoke still failing → root cause was schemeless OTLP endpoint (root cause #1). Fix: prepend `http://` on `otel.tracing.exporter.otlp.endpoint`. Separate agent-template fix for Pattern B (wrong service hostname). |

(Append new entries as cases come in.)
