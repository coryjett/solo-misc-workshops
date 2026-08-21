# Solo Enterprise for Istio — ambient mesh build & test runbook

Runbook for the ambient mesh in `istio-ns-a`: an ingress gateway (Gateway API, gatewayclass `istio`), a waypoint (`testapp-waypoint`, gatewayclass `istio-waypoint`), and the `testapp` app with `testapp-blue` / `testapp-green` backends.

Everything routes through Gateway API. Use `HTTPRoute`, not `VirtualService`. Circuit breaking and mTLS identity still come from Istio APIs (`DestinationRule`, `AuthorizationPolicy`).

## Contents

- [0. Overview, prerequisites & build order](#0-overview-prerequisites--build-order)

*Part A — single cluster*
- [1. Single-cluster build: enroll workloads + waypoint](#1-single-cluster-build-enroll-workloads--waypoint)
- [2. Weighted routing (blue/green and canary)](#2-weighted-routing-bluegreen-and-canary)
- [3. Circuit breaking](#3-circuit-breaking)
- [4. Authorization policies (which services can talk to which)](#4-authorization-policies-which-services-can-talk-to-which)
- [5. Egress gateway (force external traffic through an egress gateway)](#5-egress-gateway-force-external-traffic-through-an-egress-gateway)
- [6. Verify policy is applied at the waypoint](#6-verify-policy-is-applied-at-the-waypoint)

*Part B — multicluster*
- [7. Multicluster build: east-west gateways + global services](#7-multicluster-build-east-west-gateways--global-services)
- [8. Multicluster testing (failover, blue/green, weighted routing)](#8-multicluster-testing-failover-bluegreen-weighted-routing)
    - [What to test (demo scenarios)](#what-to-test-demo-scenarios)
    - [Traffic management: failover, blue/green, weighted routing](#multicluster-traffic-management-failover-bluegreen-weighted-routing)

*Reference & troubleshooting*
- [9. Reference: rules of thumb + certificates](#9-reference)
    - [Shared root of trust across clusters — CURRENT setup (one root → per-cluster intermediate)](#shared-root-of-trust-across-clusters-one-root--per-cluster-intermediate--current-setup)
- [10. Troubleshooting (appendix)](#10-troubleshooting-appendix)
    - [Mesh graph nodes not appearing](#mesh-graph-nodes-not-appearing)
    - [Egress not routing through the gateway](#egress-not-routing-through-the-gateway)
    - [Multicluster check (split namespaces and NodePort)](#multicluster-check-split-namespaces-and-nodeport)
    - [Multicluster troubleshooting table](#multicluster-troubleshooting-table)
    - [Next session: restore PeerAuthentication + fix ingress path](#next-session-restore-peerauthentication--fix-ingress-path)

## 0. Overview, prerequisites & build order

This runbook builds an ambient mesh in `istio-ns-a` and takes it through testing, then extends it to multicluster. Work top to bottom:

**build single cluster (§1–5) → test single cluster (§6) → build multicluster (§7) → test multicluster (§8)**

Reference material and troubleshooting are at the back (§9–10).

**Prerequisites (assumed in place before §1):**
- Ambient mesh installed (istiod, istio-cni, ztunnel) — Solo Enterprise for Istio.
- `istio-ns-a` exists and is ambient-enrolled; Gateway API CRDs installed (use `HTTPRoute`, not `VirtualService`). Circuit breaking and mTLS identity still come from Istio APIs (`DestinationRule`, `AuthorizationPolicy`).
- A waypoint (`testapp-waypoint`, gatewayClass `istio-waypoint`) and the `testapp` app with `testapp-blue` / `testapp-green` backends.
- For multicluster (§7+): a second cluster, a shared root of trust (one OpenSSL-generated root CA + a per-cluster intermediate in each cluster's `istio-system/cacerts` — see §9 "Shared root of trust"), and network reachability between the east-west gateways.

```bash
NS=istio-ns-a
```

### Environment profile (this engagement)

Characteristics of the target environment that shape the choices in this runbook (kept generic — no customer identifiers):

- **Platform:** OpenShift on bare metal, **OVN-Kubernetes** CNI (enforces `NetworkPolicy`; `EgressFirewall` / `AdminNetworkPolicy` available). No cloud LoadBalancer by default — confirm whether **MetalLB** is available before choosing LoadBalancer vs NodePort.
- **Ambient install topology: SPLIT** — **istiod in `istio-system`**, **istio-cni + ztunnel in `kube-system`** (⚠️ the ztunnel namespace **differs per cluster** in this engagement — one cluster runs it in `istio-system`; check with `oc get ds -A | grep ztunnel`). istiod must be told where via **`trustedZtunnelNamespace`** or ztunnel cert requests fail with "impersonation failed" (§10). The split is also why `istioctl multicluster check -i <ns>` can't pass every check in one run (see §10, multicluster check).
- **Trust domain: COMMON `cluster.local` on both clusters** (decided 2026-08-20; no aliases). Distinct per-cluster domains were tried first and failed peering with `no cert pool found for trust domain <peer>` — see the §7 trust-domain note for the options and trade-offs.
- **Certificates:** currently the Istio **plug-in CA** — an **OpenSSL-generated root** + a **per-cluster intermediate** loaded via `istio-system/cacerts`; istiod signs workload SVIDs from the intermediate. Multicluster requires both clusters to chain to the **same root** (see §9 "Shared root of trust"). **Venafi via cert-manager `istio-csr` is planned, not yet in use** (§9 keeps that design for later).
- **Multicluster peering: NodePort** (not LoadBalancer). E-W gateway ports `15008` (HBONE) / `15012` (xDS) are remapped to nodePorts; nodes carry an **InternalIP only** (no ExternalIP). Consequences captured in §7: set `preferred-data-plane-service-type: NodePort` on each local gateway; `remote.items` uses the peer node IP + the peer's **xDS nodePort**; HA via multi-replica anti-affinity + a VIP or Hostname multi-A record.
- **Network naming:** one network name per cluster — keep **local** and **peer** names distinct. A local object wearing the peer's name breaks cross-cluster routing (see §7 build + §10 troubleshooting).
- **UI / graph:** the Solo Enterprise UI graph is **ClickHouse + OpenTelemetry** backed; infrastructure nodes (waypoints, gateways, ztunnel) are hidden until **"Show Infrastructure"** is enabled (see §10).

## 1. Single-cluster build: enroll workloads + waypoint

Get the workloads into the mesh and the waypoint fronting `testapp` before applying any traffic policy. `testapp` is a Service with no pods of its own; the real workloads are the `testapp-blue` / `testapp-green` Deployments.

### Before you start

These label and selector rules are what usually break weighted routing.

1. Per-version Services select only their own pods.
   ```bash
   kubectl get endpoints testapp-blue testapp-green -n $NS -o wide
   ```
2. No app Service selects the waypoint pod. If one does, the waypoint becomes its own backend and you get a loop (`immediate_connect_error: Invalid argument | remote_address: envoy://main_internal/`).
   ```bash
   kubectl get svc testapp -n $NS -o json | jq .spec.selector
   ```
3. Only `testapp` is waypoint-fronted. `testapp-blue` / `testapp-green` are backends only. This cluster enrolls with a custom label, so check the effect, not the label. Only `testapp` should show a waypoint.
   ```bash
   istioctl ztunnel-config services -n $NS | grep -i testapp
   ```
4. All version pods run the same dataplane. Under ambient they show as `HBONE`.
   ```bash
   istioctl ztunnel-config workloads -n $NS | grep -i testapp
   ```

### Enroll the workloads and the waypoint

`testapp` is only a Service. There is no `testapp` Deployment or `testapp` pod. The real workloads are the `testapp-blue` and `testapp-green` Deployments; the `testapp` Service selects their pods (both labeled `app: testapp`) and is the VIP the waypoint fronts.

Two separate things, set in two places, both label-driven in this cluster:

- Mesh capture is a label on each real Deployment's pod template (`testapp-blue`, `testapp-green`). Puts their pods in ambient, shows as `HBONE`. Goes on the Deployment or namespace, never a Service.
- Waypoint is a label on the `testapp` Service only. Fronts its VIP with `testapp-waypoint`. The Service has no pods of its own to capture.

End state:

- `testapp-blue` and `testapp-green` pods are `HBONE`.
- Only the `testapp` Service is fronted by the waypoint.

If the waypoint isn't provisioned: `istioctl waypoint apply -n $NS --name testapp-waypoint`, or keep it as a plain Gateway in Git.

## 2. Weighted routing (blue/green and canary)


Send a weighted percentage of traffic to two versions of an app, `testapp-blue` and `testapp-green`.

Each version has its own Service whose selector matches only that version's pods. An `HTTPRoute` parented to the `testapp` Service lists both as `backendRefs` with weights, and the waypoint fronting `testapp` enforces the split. No subsets, no `DestinationRule` needed for the split.

```
                    -> testapp-blue  svc (weight 100) -> blue pods
testapp waypoint -> HTTPRoute (weighted)
                    -> testapp-green svc (weight 0)   -> green pods
```

### Split at the waypoint

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: testapp-canary
  namespace: istio-ns-a
spec:
  parentRefs:
    - group: ""
      kind: Service        # attach to the Service, not a Gateway
      name: testapp
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - group: ""
          kind: Service
          name: testapp-blue
          port: 8080
          weight: 100
        - group: ""
          kind: Service
          name: testapp-green
          port: 8080
          weight: 0
```

Shift traffic by editing the weights and re-applying. Weights are relative and don't have to sum to 100.

```bash
# 90/10 canary
kubectl patch httproute testapp-canary -n $NS --type=json -p='[
  {"op":"replace","path":"/spec/rules/0/backendRefs/0/weight","value":90},
  {"op":"replace","path":"/spec/rules/0/backendRefs/1/weight","value":10}
]'
```

### Make ingress honor the split (mesh vs ingress path)

The split lives in the HTTPRoute, and the HTTPRoute only runs where traffic passes through the waypoint. That is not automatic for every source.

- Mesh (east-west, pod-to-Service) traffic goes through the waypoint as soon as the Service is bound to one. Every in-mesh source behaves the same: a curl loop from the `client`, `testapp-blue`, or `testapp-green` pod to `testapp` all honor the split.
- Ingress (north-south) traffic does not go through the waypoint by default. An ingress gateway sends straight to the `testapp` Service endpoints, skips the HTTPRoute, and L4 load-balances across the blue and green pods. Symptom: in-mesh honors the split but the same route hit through the ingress host gets ~even blue/green regardless of the weights.

Two labels on the Service, two jobs. You need both for the split to apply to ingress traffic:

- `istio.io/use-waypoint: testapp-waypoint` binds the waypoint to the Service. This is the foundational label; it enables the waypoint for mesh traffic and produces the `WaypointBound: True` status condition. Without it nothing is bound and the next label does nothing.
- `istio.io/ingress-use-waypoint: "true"` extends that binding to ingress traffic. It is a boolean. It must be the string `"true"`. Setting it to the waypoint name (`testapp-waypoint`) looks right but is not truthy, so ingress silently bypasses the waypoint and you get the load-balanced behavior above.

```bash
kubectl label svc testapp -n $NS istio.io/use-waypoint=testapp-waypoint --overwrite
kubectl label svc testapp -n $NS istio.io/ingress-use-waypoint=true --overwrite
kubectl get svc testapp -n $NS -o json \
  | jq '.metadata.labels | {use_waypoint: ."istio.io/use-waypoint", ingress_use_waypoint: ."istio.io/ingress-use-waypoint"}'
# want use_waypoint = "testapp-waypoint" and ingress_use_waypoint = "true"
```

Verified with a blue-only route the whole time (`istioctl proxy-config` unchanged), only the label value changing:

| Service labels | in-mesh | via ingress |
| --- | --- | --- |
| `use-waypoint` only | blue only | load-balanced |
| `use-waypoint` + `ingress-use-waypoint: testapp-waypoint` (wrong value) | blue only | load-balanced |
| `use-waypoint` + `ingress-use-waypoint: "true"` | blue only | blue only |
| `ingress-use-waypoint: "true"` only (no `use-waypoint`) | load-balanced | load-balanced |

Once ingress goes through the waypoint, the waypoint's `AuthorizationPolicy` rules apply to the ingress gateway's identity too. If ingress starts returning `403 RBAC: access denied` right after you flip the label, add the ingress gateway's service account to the allow rule.

If the Service is managed by a Helm chart, fix `ingress-use-waypoint` in the chart values so it is not reverted to the wrong value on the next release.

### Verify (Accepted doesn't mean enforced)

`Accepted=True` only means the parent accepted the attachment. What runs lives in the proxy.

First check the route's status conditions. `ResolvedWaypoints=True` is the signal that istiod bound the route to the Service's waypoint and programmed it there:

```bash
kubectl get httproute testapp-canary -n $NS -o json \
  | jq -r '.status.parents[0].conditions[] | "\(.type)=\(.status)  (\(.reason)) \(.message)"'
# want all three True:
#   Accepted=True           (Accepted)          Route was valid
#   ResolvedRefs=True       (ResolvedRefs)      All references resolved
#   ResolvedWaypoints=True  (ResolvedWaypoints) All waypoints resolved
# ResolvedWaypoints missing or False means the Service isn't waypoint-fronted (the
# istio.io/use-waypoint label), so the split has nowhere to be enforced.
```

Then confirm the split is actually in the waypoint's proxy:

```bash
PROXY=$(kubectl get pod -n $NS -l gateway.networking.k8s.io/gateway-name=testapp-waypoint -o name | head -1)
istioctl proxy-config routes ${PROXY#pod/} -n $NS -o json \
  | jq '.. | objects | select(has("weightedClusters")) | .weightedClusters'
# Expect testapp-blue (100) and testapp-green (0). A single default cluster means the split isn't applied.
```

### Watch traffic shift

Each backend returns its version in the JSON response body, so a curl loop through the waypoint shows the split. Adjust the `jq` filter to whatever field your app returns the version in (e.g. `.version`, `.podName`).

One-shot tally (50 requests):

```bash
HOST=functional-test-sidecar-istio-ns-a.apps.example.com
for i in $(seq 1 50); do
  curl -s http://$HOST/ | jq -r '.version'
done | sort | uniq -c
# 100/0 -> all blue, 50/50 -> ~even, 0/100 -> all green
```

Live view. Leave this running in one terminal; it prints a fresh tally every 20 requests. Patch the weights in another terminal and watch the numbers move with no restart:

```bash
while true; do
  for i in $(seq 1 20); do curl -s http://$HOST/ | jq -r '.version'; done \
    | sort | uniq -c | tr '\n' ' '; echo
done
# e.g.  20 blue            (at 100/0)
#       11 blue   9 green  (after patching to 50/50)
#       2 blue  18 green   (after patching to 10/90)
```

In the other terminal, shift the weights and watch the live view react:

```bash
kubectl patch httproute testapp-canary -n $NS --type=json -p='[
  {"op":"replace","path":"/spec/rules/0/backendRefs/0/weight","value":10},
  {"op":"replace","path":"/spec/rules/0/backendRefs/1/weight","value":90}
]'
```

From inside the mesh instead of the external host, run the loop from a pod against the Service: `kubectl exec -n $NS deploy/<client> -- sh -c 'for i in $(seq 1 20); do curl -s http://testapp:8080/ | jq -r ".version"; done' | sort | uniq -c` (needs `jq` in the client image).

**Solo docs:** [request routing overview](https://docs.solo.io/istio/1.30.x/ambient/traffic-management/overview/) · [traffic splitting](https://docs.solo.io/istio/1.30.x/ambient/traffic-management/traffic-splitting/) · [canary with Argo Rollouts](https://docs.solo.io/istio/1.30.x/ambient/traffic-management/argo-rollouts/)

## 3. Circuit breaking

Circuit breaking comes from a `DestinationRule` `trafficPolicy`. In ambient, **all of it is enforced at the waypoint** — the connection-pool limits (including tcp `maxConnections`), the http limits, and outlier detection. ztunnel does not read `DestinationRule`, so a Service with no waypoint gets no circuit-breaking enforcement at all.

Target the backend Services (`testapp-blue`, `testapp-green`), not the fronted `testapp` Service. At the waypoint the weighted split resolves to per-version upstream clusters, and the connection-pool and outlier settings attach to those clusters. A DestinationRule on `testapp` alone does not land on the blue/green clusters.

```yaml
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: testapp-blue-cb
  namespace: istio-ns-a
spec:
  host: testapp-blue.istio-ns-a.svc.cluster.local   # repeat for testapp-green
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100          # tcp connection-pool limit — waypoint
      http:
        http1MaxPendingRequests: 50  # L7, waypoint
        http2MaxRequests: 100
        maxRequestsPerConnection: 10
    outlierDetection:                # eject bad endpoints, L7, waypoint
      consecutive5xxErrors: 5
      interval: 10s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
```

Verify the limits and outlier config landed on the backend cluster in the waypoint:

```bash
istioctl proxy-config clusters ${PROXY#pod/} -n $NS --fqdn testapp-blue.istio-ns-a.svc.cluster.local -o json \
  | jq '.[0] | {circuitBreakers: .circuitBreakers.thresholds, outlierDetection}'
# thresholds show maxConnections / maxPendingRequests; outlierDetection shows consecutive5xx etc.
```

Note: circuit breaking is a waypoint feature — connection-pool limits, http limits, and outlier detection all require a waypoint. A Service with no waypoint gets **no** circuit-breaking or connection-pool enforcement at all. (ztunnel still does L4 identity/port authorization, but it doesn't read `DestinationRule`.)

You need one DestinationRule per backend Service here (`testapp-blue`, `testapp-green`), not one. A single DestinationRule on `host: testapp` with `subsets` for blue and green does not work with this setup, and it fails silently. The HTTPRoute routes to the `testapp-blue` / `testapp-green` Services, so the waypoint's upstream clusters are keyed by those service FQDNs with no subset. A subset DestinationRule instead programs `testapp|blue` / `testapp|green` subset clusters, which nothing routes to (Gateway API HTTPRoute cannot target a subset). Verified on a waypoint: with a subset DR applied, the `testapp-blue` and `testapp-green` service clusters showed no `outlierDetection` at all, while the config sat on orphaned subset clusters. A wildcard host (`*.istio-ns-a.svc.cluster.local`) does not work either; it draws an `IST0174` warning and applies inconsistently.

A single subset DestinationRule is only valid in the other routing model, where a `VirtualService` does the split by routing to `subset: blue` / `subset: green` (and the per-version Services go away). That trades this section's two DestinationRules for one, at the cost of moving the split back to `VirtualService`. Do not run that `VirtualService` alongside the HTTPRoute on the same Service.

### Outlier detection is not failover for the weighted split

The weight and outlier detection work at two different levels and do not rescue each other. Know this before you rely on circuit breaking to protect a canary.

- The HTTPRoute weight decides, per request, which cluster to use: the blue cluster or the green cluster. That is a routing decision made before any endpoint is picked.
- Outlier detection works inside a cluster. It ejects bad endpoints from that version's own pool. It does not remove the version from the weighted split or hand its share to the other version.

So if green is weighted at 50 and every green pod is failing, outlier detection ejects all of green (with `maxEjectionPercent: 100` that is the whole pool), the green cluster is left with no healthy endpoint, and the route still sends 50% of requests to it. Those requests return `503 no healthy upstream`. Envoy does not fall back to blue; the weight already committed them to green. Retries do not help either, since a retry picks another host in the same (empty) green cluster.

Reproduced on a waypoint: green returning 500, `consecutive5xxErrors: 1`, `maxEjectionPercent: 100`, split 50/50. 60 requests came back as roughly 29 `{"version":"blue"} 200` and 31 `no healthy upstream 503` — exactly the green half failing.

What to do:

- To stop routing to a broken version, set its HTTPRoute weight to 0. That is the mechanism. Do not expect outlier detection to do it.
- Use outlier detection for its real job: a version that has several pods where some go bad. It ejects the bad pods so the version's healthy pods keep serving. If the entire version is bad, no outlier setting helps and the weight is what is still feeding it.
- Mental model: weight selects the version, outlier detection selects the pods within a version. They are orthogonal.

### Failing over when a whole version is down

There is no native Envoy or Istio feature that redistributes a weighted backend's share when it has no healthy endpoints. The weight is static. So anything that keeps traffic off a fully-unhealthy version has to change the weight. Three ways, in order of how much you keep the canary:

1. One pool instead of a split. Put both versions behind a single Service and add outlier detection on that one host. The load balancer plus ejection skip the unhealthy pods on their own, so a dead version just stops receiving traffic and everything lands on the healthy pods. Verified: with both versions in one pool and green returning 500, traffic went to blue with no `no healthy upstream`. The cost is that you lose weighted control; this is load-balancing across all healthy pods, not a 90/10 canary. Good for pure resilience, not controlled rollouts.

   ```yaml
   apiVersion: v1
   kind: Service
   metadata: {name: testapp-all, namespace: istio-ns-a}
   spec:
     selector: {app: testapp}          # selects blue AND green pods
     ports: [{name: http, port: 8080, targetPort: 80}]
   ---
   apiVersion: networking.istio.io/v1
   kind: DestinationRule
   metadata: {name: testapp-all, namespace: istio-ns-a}
   spec:
     host: testapp-all
     trafficPolicy:
       outlierDetection: {consecutive5xxErrors: 5, interval: 10s, baseEjectionTime: 30s, maxEjectionPercent: 100}
   ```

2. Keep the split, automate the weight. Run a progressive-delivery controller (Flagger or Argo Rollouts). It watches the canary's success rate from the mesh metrics and sets the failing version's HTTPRoute weight to 0 automatically, then ramps it back as the version recovers. This is the real answer for a canary that aborts on failure: deterministic weights in steady state, automatic reaction on trouble. The cost is running the controller and wiring a metrics source.

3. Manual. Alert on the 503s or the success rate and patch the weight to 0 by hand (see progressive delivery above). Simplest, human in the loop.

Whichever you pick, the lever is always the weight. Outlier detection cannot do it because it operates below the weight.

**Solo docs:** [resiliency / failover overview](https://docs.solo.io/istio/1.30.x/ambient/resiliency/failover/overview/) · [L7 failover at the waypoint](https://docs.solo.io/istio/1.30.x/ambient/resiliency/failover/l7-waypoint/) · [waypoints (L7)](https://docs.solo.io/istio/1.30.x/ambient/waypoints/overview/)

## 4. Authorization policies (which services can talk to which)

`AuthorizationPolicy` decides who may call whom, keyed on SPIFFE identity. In ambient, L4 rules (source identity, ports) are enforced at ztunnel, and L7 rules (methods, paths, headers) at the waypoint. Default is allow; the first `ALLOW` policy that selects a workload flips it to deny-by-default for that workload.

Lock `testapp` down to callers from the ingress gateway only (L7, on the waypoint):

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: testapp-allow-ingress
  namespace: istio-ns-a
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: testapp-waypoint       # enforced at the waypoint
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/istio-ns-a/sa/testapp-ingress"
      to:
        - operation:
            methods: ["GET", "POST"]
```

Restrict the blue/green backends to only accept from `testapp` (L4, at ztunnel, use a selector not a Gateway targetRef):

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: backends-allow-testapp
  namespace: istio-ns-a
spec:
  selector:
    matchLabels:
      app: testapp                 # matches blue+green pods sharing app=testapp
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/istio-ns-a/sa/testapp"
```

Confirm what the workload actually enforces:

```bash
istioctl x describe pod -n $NS <testapp-blue-pod>            # lists applied AuthorizationPolicies
istioctl proxy-config rbac ${PROXY#pod/} -n $NS         # L7 rules on the waypoint
```

Get the exact principal strings from the workload identities: `istioctl ztunnel-config workloads -n $NS` (the identity/SA column gives the SPIFFE path). A typo'd principal silently denies everything.

**Solo docs:** [security overview](https://docs.solo.io/istio/1.30.x/ambient/security/overview/) · [waypoints (L7)](https://docs.solo.io/istio/1.30.x/ambient/waypoints/overview/)

## 5. Egress gateway (force external traffic through an egress gateway)

Egress uses the same `istio-waypoint` type as the rest of this runbook. A dedicated egress waypoint is the sanctioned way out: external `ServiceEntry` hosts are pinned to it with `istio.io/use-waypoint`, so their traffic flows through one choke point where you get L7 policy, TLS origination, and logging. An `AuthorizationPolicy` on that waypoint restricts which identities may use it. This runs the egress gateway in `istio-ns-a` alongside the app (not a separate namespace); the one wrinkle that creates is in the NetworkPolicy step below. Built and tested on a k3d ambient cluster.

### Create the gateway

`istio-ns-a` already exists and is ambient-enrolled, so there's no new namespace to create. The egress gateway is an `istio-waypoint` Gateway named `egress-gw` in `istio-ns-a`. Two ways to create it — `istioctl` for a quick start, or a hand-written `Gateway` resource for GitOps (both produce the same thing: the Gateway and its Envoy deployment).

`istioctl` (quick):

```bash
istioctl waypoint apply -n istio-ns-a --name egress-gw --for all
# preview instead of apply: istioctl waypoint generate -n istio-ns-a --name egress-gw --for all
```

Declarative `Gateway` (GitOps — equivalent to the command above):

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: egress-gw
  namespace: istio-ns-a
  labels:
    # What this waypoint captures. `all` is REQUIRED for ServiceEntry-fronted
    # egress — egress targets are ServiceEntries, not Kubernetes Services, so
    # the default `service` traffic type won't pick them up.
    istio.io/waypoint-for: all
spec:
  gatewayClassName: istio-waypoint
  listeners:
    - name: mesh
      port: 15008
      protocol: HBONE
```

This is a second waypoint in `istio-ns-a` (the app already has `testapp-waypoint`). That's fine — each is bound to different targets via `use-waypoint`, so they don't collide: `testapp-waypoint` fronts the `testapp` Service, `egress-gw` fronts the external `ServiceEntry` hosts.

### Configure the gateway

The Gateway resource above is the whole gateway config — `gatewayClassName: istio-waypoint` selects the ambient waypoint dataplane, the `mesh`/`15008`/`HBONE` listener is the fixed ambient inbound tunnel, and `istio.io/waypoint-for` sets what it captures. You don't hand-write listeners for app hosts; a waypoint takes its routing from the `ServiceEntry` + `use-waypoint` bindings below, its access rules from the `AuthorizationPolicy`, and its logging from a `Telemetry`. Confirm it's up before wiring hosts to it:

```bash
kubectl get gateway egress-gw -n istio-ns-a                 # PROGRAMMED=True
kubectl get pods -n istio-ns-a -l gateway.networking.k8s.io/gateway-name=egress-gw   # 1/1 Running
```

### Pin external hosts to it

```yaml
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: testapp-egress
  namespace: istio-ns-a
  labels:
    istio.io/use-waypoint: egress-gw     # route this host through the egress waypoint
spec:
  hosts:
    - testapp-egress.apps.example.com
  ports:
    - number: 443
      name: tls
      protocol: TLS
  resolution: DNS
  location: MESH_EXTERNAL
```

### Restrict who can egress

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: egress-allow
  namespace: istio-ns-a
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: egress-gw
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/istio-ns-a/sa/testapp"]
```

### Force traffic through it (stop the bypass)

Steps so far route registered hosts through the waypoint, but they do not force it. Two things confirmed in testing:

- `outboundTrafficPolicy: REGISTRY_ONLY` does not work in ambient — this is architectural, not a version bug. Tested directly: an HBONE-captured pod with `REGISTRY_ONLY` set, no `ServiceEntry`, and no NetworkPolicy still reached `example.org`, `bing.com`, and `example.com` (all `200`). There is no per-pod Envoy in ambient; ztunnel is an L4 passthrough that forwards any non-waypointed destination to its original IP, so `REGISTRY_ONLY` has nothing to enforce against and a waypoint never sees the unregistered traffic. Blocking unregistered egress is therefore a CNI concern, not a mesh one (see the mesh-wide section). This is confirmed upstream: ambient does not implement `REGISTRY_ONLY` (istio/istio discussion #53021, https://github.com/istio/istio/discussions/53021). Making ztunnel honor it was floated as one option in ztunnel #369 (https://github.com/istio/ztunnel/issues/369, now closed) but not adopted — ztunnel's passthrough for unknown destinations is deliberate, and the upstream direction for ambient egress is waypoint-based (the `DYNAMIC_DNS` work), not ztunnel strictness. So don't expect a registry-only switch in ambient; treat egress blocking as a CNI responsibility. How `REGISTRY_ONLY` actually behaves (tested on a sidecar pod): it does not touch DNS. The name still resolves to the real IP, the request reaches the sidecar's Envoy, and Envoy — having no cluster for an unregistered host — routes it to the BlackHoleCluster, so the connection is accepted then reset (`TLS connect error: unexpected eof`, `000`). So in sidecar mode it is a soft, client-side block (the pod's own Envoy refuses to forward), not a network firewall — a pod that bypasses its sidecar or reaches a host by IP isn't stopped. In ambient there is no per-pod Envoy to blackhole and ztunnel passes the connection straight through, so unregistered egress simply succeeds. Either way, the CNI is the right enforcement point for a real block.
- A pod can still open a direct connection to an unregistered IP, skipping the waypoint entirely.

The actual lock is a Kubernetes `NetworkPolicy` that denies direct pod egress except in-cluster and DNS, so the egress waypoint becomes the only way out. This cluster runs **OVN-Kubernetes**, which enforces `NetworkPolicy`, so the lock is real.

Because the egress gateway runs **in `istio-ns-a` alongside the app**, a single `podSelector: {}` deny would also cut off the gateway's own internet access — the one pod that must reach out. So use two policies: a namespace-wide deny, plus an allow that gives the `egress-gw` pod full egress. NetworkPolicies are additive (union of allows), so the gateway ends up permitted everywhere while every other pod is confined.

```yaml
# 1) Deny direct egress for every pod in the namespace, except in-cluster + DNS.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-deny-direct-egress
  namespace: istio-ns-a
spec:
  podSelector: {}                # every pod in istio-ns-a (incl. egress-gw — relaxed by policy #2)
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock: {cidr: 10.128.0.0/14}  # OVN-K pod CIDR — confirm from the cluster network config
        - ipBlock: {cidr: 172.30.0.0/16}  # OVN-K service CIDR — confirm from the cluster network config
    - to: []
      ports:
        - {protocol: UDP, port: 53}
        - {protocol: TCP, port: 53}
---
# 2) Let ONLY the egress gateway pod reach the internet. Additive with #1,
#    so egress-gw = (in-cluster+DNS) ∪ (everywhere) = everywhere; app pods stay confined.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-gw-allow-internet
  namespace: istio-ns-a
spec:
  podSelector:
    matchLabels:
      gateway.networking.k8s.io/gateway-name: egress-gw
  policyTypes: [Egress]
  egress:
    - {}                          # allow all egress from the egress-gw pod
```

Get the CIDRs from the cluster (don't trust the defaults above):

```bash
# OpenShift / OVN-Kubernetes
oc get network.config/cluster -o jsonpath='{.spec.clusterNetwork[*].cidr}{"\n"}{.spec.serviceNetwork[*]}{"\n"}'
```

### Verify traffic goes through the egress gateway

Work top to bottom — config binding first, then a live traversal proof, then behavior.

**1. The ServiceEntry is bound to the egress waypoint (config level).**

```bash
istioctl ztunnel-config services -n istio-ns-a | grep -i testapp-egress
# the host row should list WAYPOINT = egress-gw. If it shows None, the binding
# didn't take — check the use-waypoint label and waypoint-for: all on the gateway.
```

**2. Turn on an access log for the egress gateway** (no restart needed — pushed live over xDS):

```yaml
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: egress-gw-logs
  namespace: istio-ns-a
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: egress-gw
  accessLogging:
    - providers:
        - name: envoy
```

**3. Send traffic, then read the gateway log — the definitive traversal proof.**

```bash
CLIENT=$(kubectl get pod -n istio-ns-a -l app=<yourapp> -o name | head -1)
kubectl exec -n istio-ns-a ${CLIENT#pod/} -- curl -sS -o /dev/null -w '%{http_code}\n' --max-time 8 \
  https://testapp-egress.apps.example.com/

kubectl logs -n istio-ns-a deploy/egress-gw --tail=30 | grep testapp-egress
# A line on the egress-gw naming the host + the real upstream IP means it went through.
# TLS passthrough logs L4, so expect a form like:
#   [...] "- - -" ... "<upstream-ip>:443" ...|443|tcp|testapp-egress.apps.example.com ...
# If the curl succeeds but NOTHING shows here, it bypassed the gateway (recheck step 1 + the NetworkPolicy).
```

**4. Gateway metrics corroborate it** (counters climb as you send traffic):

```bash
EGW=$(kubectl get pod -n istio-ns-a -l gateway.networking.k8s.io/gateway-name=egress-gw -o name | head -1)
kubectl exec -n istio-ns-a ${EGW#pod/} -c istio-proxy -- \
  pilot-agent request GET 'stats/prometheus' | grep -iE 'testapp-egress|tcp_connections_opened'
```

**5. Behavior checks — the force actually holds.**

```bash
# in-mesh unaffected
kubectl exec -n istio-ns-a ${CLIENT#pod/} -- curl -s -o /dev/null -w '%{http_code}\n' --max-time 8 http://testapp:8080/   # 200
# registered host reaches out (via the gateway)
kubectl exec -n istio-ns-a ${CLIENT#pod/} -- curl -s -o /dev/null -w '%{http_code}\n' --max-time 8 https://testapp-egress.apps.example.com   # 200
# an UNREGISTERED host is blocked by the NetworkPolicy (not by REGISTRY_ONLY)
kubectl exec -n istio-ns-a ${CLIENT#pod/} -- curl -s -o /dev/null -w '%{http_code}\n' --max-time 8 https://www.bing.com   # 000 blocked
# a workload whose identity isn't in egress-allow is denied at the waypoint (test from a pod with a different service account)
```

Registered host works + unregistered host blocked = the gateway is the only way out.

**If it's not working:** a `503 UF`/`UH` or a hang on the registered host usually means the gateway can't resolve/reach the external upstream host (DNS or network), not a mesh misconfig. Isolate by curling the host from the gateway pod itself:

```bash
kubectl exec -n istio-ns-a ${EGW#pod/} -c istio-proxy -- \
  curl -sS -o /dev/null -w '%{http_code} %{remote_ip}\n' --max-time 8 \
  https://testapp-egress.apps.example.com/
# NXDOMAIN / hang here = network/DNS problem outside the mesh; no ServiceEntry can fix that.
```

### Notes

- One `ServiceEntry` per host, in `istio-ns-a`, with the `use-waypoint` label. A second `ServiceEntry` for the same host without the label shadows the routing and the traffic skips the waypoint. This was the single biggest trap in testing.
- The egress gateway runs in `istio-ns-a` alongside the app, so the NetworkPolicy needs the two-policy pattern above (namespace deny + an allow for the `egress-gw` pod). Skip the second policy and the gateway itself can't reach the internet, so all egress dies. Confirm the allow works: `kubectl get networkpolicy -n istio-ns-a`.
- Get the pod and service CIDRs from the cluster network config (command above); wrong CIDRs either block the mesh or leave a hole. OVN-Kubernetes enforces `NetworkPolicy`, so the lock holds on this cluster.
- TLS passthrough (`protocol: TLS`) means the egress access log shows L4 lines (SNI, upstream IP, bytes), not HTTP status codes. That's expected. For HTTP-level logs you'd terminate/re-originate TLS at the waypoint (`protocol: HTTP` + a `DestinationRule` with `tls.mode: SIMPLE`).
- Solo's egress guide covers the routing + authz but not the NetworkPolicy bypass-lock; that piece is what makes it a true force-through.

### Mesh-wide: force all external traffic through the gateway

The single-host setup above scales to "everything in the mesh, all egress through one gateway" — but the routing piece changes and there's a real version caveat.

Design:

- One central egress gateway in its own namespace. App namespaces bind to it cross-namespace with `istio.io/use-waypoint: egress-gw` plus `istio.io/use-waypoint-namespace: <egress-ns>`.
- Every app namespace ambient-enrolled (`istio.io/dataplane-mode=ambient`).
- The force is a cluster-wide deny. NetworkPolicy is namespaced (one per app namespace); on OpenShift/OVN-Kubernetes prefer a cluster-scoped `AdminNetworkPolicy`, or a per-namespace `EgressFirewall`, to deny direct egress to `0.0.0.0/0` except in-cluster + DNS + the egress gateway. Same "only the gateway leaves" logic, one object.

Routing every external host to the gateway is where it gets hard, and this was tested:

- Exact-host `ServiceEntry`s route and forward correctly (verified: `200`, gateway log shows the real upstream).
- There is no true catch-all. `*` and TLD wildcards like `*.com` are rejected by Istio validation. Wildcards must be prefix wildcards on a real domain (`*.example.com`, `*.amazonaws.com`).
- Wildcard egress needs `resolution: DYNAMIC_DNS` (not `DNS` or `NONE`) plus the `use-waypoint` label:
  ```yaml
  apiVersion: networking.istio.io/v1
  kind: ServiceEntry
  metadata:
    name: external-wildcard
    namespace: istio-egress
    labels:
      istio.io/use-waypoint: egress-gw
  spec:
    hosts: ["*.example.com"]
    location: MESH_EXTERNAL
    ports: [{number: 443, name: tls, protocol: TLS}]
    resolution: DYNAMIC_DNS
  ```
- Version caveat, tested on Istio 1.29.4: a `DYNAMIC_DNS` wildcard was accepted and traffic did reach the waypoint, but the waypoint returned `NR filter_chain_not_found` and dropped it — wildcard egress did not forward end to end on that build, while an exact-host `ServiceEntry` for the same host forwarded fine. `DYNAMIC_DNS` is a newer feature; confirm it forwards on the cluster's actual version before relying on wildcards for the POC.

Practical recommendation for the POC: apply the cluster-wide deny (that's the real force, and it works), and register external destinations as exact-host `ServiceEntry`s, which are proven. Treat wildcard `DYNAMIC_DNS` as "verify on our version first" — if it still returns `filter_chain_not_found`, enumerate the specific hosts/subdomains instead of relying on `*.domain`.

### Blocking unregistered egress — the mesh can't, the CNI can

The natural instinct is "make the mesh reject anything not in the registry" (the sidecar `REGISTRY_ONLY` behavior). Ambient does not do this (tested — see the force-section note above), and there is no waypoint setting that will, because unregistered traffic never reaches a waypoint. So block-by-default is enforced **below the mesh**, at the CNI.

On OVN-Kubernetes the right tool is `EgressFirewall`, which allowlists by **DNS name** and denies the rest — the closest thing to "only registered domains may leave":

```yaml
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default            # must be "default"; one per namespace
  namespace: istio-ns-a
spec:
  egress:
    - type: Allow
      to:
        dnsName: "*.example.com"              # approved external domains (wildcard dnsName)
    - type: Allow
      to:
        dnsName: "api.partner.example.com"
    - type: Allow
      to:
        cidrSelector: 172.30.0.0/16        # in-cluster service CIDR (adjust) so DNS + mesh work
    - type: Deny
      to:
        cidrSelector: 0.0.0.0/0            # everything else denied
```

This is independent of the mesh — it covers every pod (meshed or not), enforces by domain, and needs no `ServiceEntry`. Two things to confirm on the cluster's OpenShift version: wildcard `dnsName` support (older OVN-K was exact-name only) and that DNS-name rules are re-resolved often enough for your destinations (fine for stable infra like `*.example.com`; risky for fast-rotating IPs).

The clean division of labor for the POC:

- CNI (`EgressFirewall` / `AdminNetworkPolicy`) = the hard block: deny all egress except approved domains/CIDRs. This is what stops unregistered traffic. Cluster-wide, mesh-independent.
- Egress waypoint (`ServiceEntry` + `use-waypoint`) = the optional L7 layer on the specific external services that need identity authz, access logs, or TLS origination. Not the enforcement mechanism.

Do not try to make the waypoint the universal choke point — it can only act on traffic that a `ServiceEntry` routes to it.

**Solo docs:** [egress overview](https://docs.solo.io/istio/1.30.x/ambient/traffic-management/egress/overview/) · [egress gateway (waypoint)](https://docs.solo.io/istio/1.30.x/ambient/traffic-management/egress/egress/) · [mTLS egress](https://docs.solo.io/istio/1.30.x/ambient/traffic-management/egress/egress-mtls/)

## 6. Verify policy is applied at the waypoint

`Accepted=True` on an HTTPRoute or an applied DestinationRule only means the config was accepted, not that it is running. What actually runs lives in the waypoint's Envoy config. Read it directly and confirm both the weights and the circuit-breaker knobs are programmed.

```bash
NS=istio-ns-a
WP=$(kubectl get pod -n $NS -l gateway.networking.k8s.io/gateway-name=testapp-waypoint -o name | head -1)
WP=${WP#pod/}
```

### Weighting

Pull the route's weighted clusters out of the waypoint:

```bash
istioctl proxy-config routes $WP -n $NS -o json \
  | jq -c '[.. | objects | select(has("weightedClusters")) | .weightedClusters.clusters[]
           | {backend:(.name|split("|")[3]), weight}]'
```

Output matches the HTTPRoute weights:

```json
[{"backend":"testapp-blue.istio-ns-a.svc.cluster.local","weight":90},
 {"backend":"testapp-green.istio-ns-a.svc.cluster.local","weight":10}]
```

If you see a single default cluster instead of `weightedClusters`, the split is not applied at the waypoint. One weight at 0 also collapses to a single cluster, which is expected. Set both weights non-zero if you want to see both here.

### Circuit breaking

Circuit-breaker and outlier settings attach to the backend clusters. Read the cluster the DestinationRule targets:

```bash
istioctl proxy-config clusters $WP -n $NS \
  --fqdn testapp-blue.istio-ns-a.svc.cluster.local -o json \
  | jq -c '.[0] | {circuitBreakers: .circuitBreakers.thresholds, outlierDetection}'
```

Output matches the DestinationRule:

```json
{"circuitBreakers":[{"maxConnections":2,"maxPendingRequests":1,"maxRequests":4294967295,"maxRetries":4294967295}],
 "outlierDetection":{"consecutive5xx":3,"interval":"5s","baseEjectionTime":"30s","maxEjectionPercent":50}}
```

`maxConnections` and `maxPendingRequests` reflect your `connectionPool` values; `maxRequests`/`maxRetries` at the uint32 max mean unset. `outlierDetection` mirrors your DestinationRule. If this block is empty or the FQDN returns no cluster, the DestinationRule did not land on the backend cluster, usually because it targets the `testapp` Service instead of `testapp-blue` / `testapp-green` (see §3, circuit breaking).

**Solo docs:** [L7 observability](https://docs.solo.io/istio/1.30.x/ambient/observability/layer7/) · [waypoints (L7)](https://docs.solo.io/istio/1.30.x/ambient/waypoints/overview/)

## 7. Multicluster build: east-west gateways + global services

Extends the single-cluster mesh to span two clusters (here: `cluster1` + a second,
call the kube contexts `$C1` and `$C2`). Cross-cluster traffic stays mTLS end-to-end via
**"double HBONE"**: source ztunnel → the *target* cluster's **east-west (E-W) gateway** →
target ztunnel → pod.

**Model (Solo Enterprise for Istio):**
- **One E-W gateway per cluster**, GatewayClass **`istio-eastwest`**, in namespace
  **`istio-eastwest`**, listening on **`:15008`** (HBONE cross-network) and **`:15012`**
  (xDS TLS). The E-W gateway is implemented as a ztunnel. (The **`istio-remote`** class is used
  only for the *remote-peer* Gateway object that represents the other cluster — see the remote
  block under Set up.)
- **Shared root of trust** — both clusters must chain to the **same root CA**. Current setup:
  one OpenSSL-generated root + a per-cluster intermediate, loaded via each cluster's
  `istio-system/cacerts` secret (the plug-in CA model — full setup + verification in §9
  "Shared root of trust"). The trust bundle every workload receives (the `istio-ca-root-cert`
  ConfigMap) must be identical across clusters, or cross-cluster mTLS fails the TLS handshake.
  (When Venafi/istio-csr lands later, the same rule holds — both issuers chain to one root.)
- **Cluster + network identity** — each cluster sets `global.multiCluster.clusterName` +
  `global.network` (istiod) and the matching `multiCluster.clusterName` / `network` on
  ztunnel; the `istio-system` ns carries `topology.istio.io/network=<net>`.
- **Global service** — label a Service (or its namespace) `solo.io/service-scope=global` →
  it gets the hostname **`<svc>.<ns>.mesh.internal`** whose endpoints are **aggregated across
  clusters**. Requires **namespace sameness** (same `namespace`+`service` name in each
  cluster).
- **Locality default is `PreferNetwork`** — a global service resolves to the **local** cluster's
  endpoints, and only fails over to a remote cluster when no local endpoint is healthy. Tune
  with the Service annotation `networking.istio.io/traffic-distribution`
  (`PreferNetwork` | `PreferClose` | `PreferRegion` | `Any`).

### Set up

```bash
C1=admin@cluster1        # existing cluster
C2=<second-cluster-context>

# 0) Prereq: both clusters ambient-installed with a clusterName + network, and the SAME
#    root of trust. GENERATE the root + per-cluster intermediates and load cacerts FIRST —
#    the OpenSSL commands are in §9 "Shared root of trust across clusters" (root, intermediates,
#    cert-chain, kubectl create secret cacerts). Then verify BOTH the CA source and the
#    distributed trust bundle match across clusters:
for c in $C1 $C2; do kubectl --context $c -n istio-system get secret cacerts \
  -o jsonpath='{.data.root-cert\.pem}' | base64 -d | openssl x509 -noout -fingerprint -sha256; done
for c in $C1 $C2; do kubectl --context $c -n istio-ns-a get configmap istio-ca-root-cert \
  -o jsonpath='{.data.root-cert\.pem}' | openssl x509 -noout -fingerprint -sha256; done
# ALL four fingerprints MUST be identical.

# 1) Create the E-W gateway in each cluster (GatewayClass istio-eastwest, ns istio-eastwest).
#    DECLARATIVE (this engagement applies YAML directly — GitOps), per cluster:
cat <<'EOF' | kubectl --context=$C1 apply -f -    # repeat on $C2 with network: cluster2
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: istio-eastwest
  namespace: istio-eastwest
  labels:
    topology.istio.io/network: cluster1                              # LOCAL network name
  annotations:
    peering.solo.io/preferred-data-plane-service-type: NodePort     # NodePort peering (drop for LB)
spec:
  gatewayClassName: istio-eastwest
  listeners:
  - name: cross-network
    port: 15008
    protocol: HBONE
  - name: xds-tls
    port: 15012
    protocol: TLS
    tls:
      mode: Passthrough
EOF
#    (istioctl equivalent, useful to GENERATE the YAML once for Git: 
#     istioctl multicluster expose -n istio-eastwest --generate > eastwest-gateway.yaml)

# 2) Link the clusters — apply the REMOTE-PEER Gateway (GatewayClass istio-remote) on each side.
#    Full YAML + the remote.items Helm form are in "Network names in the values files" below —
#    peer's network label, address (IP only), and xDS nodePort.
#    (istioctl equivalent/generator: istioctl multicluster link --contexts=$C1,$C2 -n istio-eastwest)

# 3) Verify the link
istioctl multicluster check --contexts=$C1,$C2
kubectl --context $C1 get gateway -n istio-eastwest          # Programmed=True
istioctl --context $C1 proxy-status                          # remote proxies SYNCED
```

#### Network names in the values files (the #1 cross-cluster footgun)

Each cluster has ONE network name. It must be **identical** across istiod, the injecting
namespaces, all proxies, and that cluster's **own** E-W gateway — and **distinct** from the peer's.
The peer's name appears **only** on the `istio-remote` peer Gateway. Mixing them up produces
`Network Configuration Check: eastwest gateway has network X but cluster network is Y` (see the §10 troubleshooting table). Example with **local `cluster1`**, **remote `cluster2`**:

**Local cluster `cluster1` — istiod + own E-W gateway (Helm):**
```yaml
# istiod values — identity of THIS cluster
global:
  multiCluster:
    clusterName: cluster1
  network: cluster1            # ← THIS cluster's network
  trustDomain: cluster.local   # ← COMMON across BOTH clusters (see trust-domain note below)
platforms:
  peering:
    enabled: true
env:
  PILOT_ENABLE_IP_AUTOALLOCATE: "true"
  DISABLE_LEGACY_MULTICLUSTER: "true"
---
# peering chart — this cluster's OWN east-west gateway
eastwest:
  create: true
  cluster: cluster1
  network: cluster1            # ← MUST be the local network, NOT cluster2
```
The install also labels `istio-system` with `topology.istio.io/network=cluster1`.

**Local cluster `cluster1` — the REMOTE peer object (represents `cluster2`):**
```yaml
# peering chart — the remote peer link (this is the ONLY place cluster2 appears locally)
remote:
  create: true
  items:
    - name: istio-remote-peer-cluster2
      cluster: cluster2
      network: cluster2                         # ← the REMOTE network name (plain, no .local)
      address: <cluster2-NODE-IP>               # IP ONLY — no port
      addressType: IPAddress                    # or Hostname (multi-A DNS) for HA
      preferredDataplaneServiceType: nodeport   # NodePort peering; resolves HBONE (15008) port automatically
      nodeport: <cluster2-xds-nodePort>         # the peer's 15012 (xDS) nodePort — HBONE is auto-resolved
      trustDomain: cluster.local                # must equal the PEER'S ACTUAL meshConfig trustDomain
```
> **NodePort port handling (verified):** the `address` is an **IP only** — you cannot append a
> port. `preferredDataplaneServiceType: nodeport` resolves the HBONE (15008) data-plane port
> automatically; you supply only the **xDS (15012) nodeport** manually (xDS is the bootstrap
> channel, so its port can't be auto-discovered). To clear the check's *"NodePort service
> reporting ClusterIP"* warning, also set `peering.solo.io/preferred-data-plane-service-type:
> NodePort` on each cluster's **own** E-W gateway — that annotation, not `remote.items`, is what
> makes istiod advertise a NodeIP instead of the ClusterIP. (RBAC to list nodes is necessary but
> not sufficient — with no ExternalIP, discovery needs the NodePort preference to fall through.)
Equivalent declarative form:
```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: istio-remote-peer-cluster2
  namespace: istio-eastwest
  labels:
    topology.istio.io/network: cluster2     # remote network — correct here
spec:
  gatewayClassName: istio-remote
```

**Remote cluster `cluster2` — mirror image (swap the names):** istiod `clusterName/network:
cluster2`; its own `eastwest.network: cluster2`; and its `remote` peer item `cluster/network:
cluster1`, `address: <cluster1-NODE-IP>` (IP only), `nodeport: <cluster1-xds-nodePort>`.

> Gloo Operator equivalent: set `spec.cluster` + `spec.network` on the `ServiceMeshController`
> (`operator.gloo.solo.io/v1`) to the **local** name; the `remote.items[].network` to the peer's.

The bug we hit: the local E-W gateway had `network: cluster2` (the remote's name). Set
`eastwest.network: cluster1` and re-apply — if only the label is patched, the operator
reverts it; the **values file** is the source of truth.

#### Trust domain: decide COMMON vs DISTINCT before peering

istiod only auto-builds trust anchors for its **own** trust domain. With **distinct** per-cluster
domains (`cluster1.local` / `cluster2.local`), peering fails at the xDS TLS handshake even when
the root CA matches perfectly — istiod logs `Could not verify certificate: no cert pool found
for trust domain <peer>` plus `deltaadsc ... remote error: tls: bad certificate` on a 1-minute
retry loop. Options:

| Option | Config | Trade-off |
|---|---|---|
| **COMMON domain (chosen here)** — `trustDomain: cluster.local` on both | Same value in both istiod values + both peer objects' `trustDomain`; then FULL restart (istiod → ztunnel → E-W gw → waypoints/ingress) on both clusters, since every identity is re-issued | Simplest; existing `cluster.local/...` authz principals keep working. Identities no longer encode origin cluster — "allow only from cluster X" can't be expressed by principal |
| **DISTINCT domains** + `meshConfig.caCertificates` | Keep per-cluster domains; on each cluster add `caCertificates: [{pem: <common root>, trustDomains: [<peer-domain>]}]` + istiod restart only | Keeps per-cluster identity for authz/audit; a little more config; no workload re-issuance |
| `trustDomainAliases` | Alias the peer's domain | Quick, but merges the domains for validation — POC-only |
| `PILOT_SKIP_VALIDATE_TRUST_DOMAIN=true` | istiod env | Disables validation entirely — avoid |

**Common-domain cutover (no aliases):** flip `trustDomain` in both istiod values + both peer
objects → `grep -rn "<old-domain>"` across all values/YAML (authz principals too!) → restart
istiod, then ztunnel, then E-W gateway, then `oc rollout restart deploy -n <app-ns>` for
waypoints/ingress/egress — **both clusters in the same window**. Roll **every meshed
namespace** — including the Solo Enterprise UI/telemetry namespace — or expect transient
crashloops there until ztunnel re-issues identities. Mid-roll, `no cert pool` /
`bad certificate` errors are expected until everything on both sides is re-issued.

#### `trustedZtunnelNamespace` — required when ztunnel isn't where istiod expects

If ztunnel runs in a nonstandard namespace (split installs; can **differ per cluster**), istiod
rejects its cert requests: `serverca ... impersonation failed for identity spiffe://... caller
(Pod{Name: ztunnel-..., ServiceAccount: ztunnel}) is not allowed to impersonate`. Fix — in each
cluster's **istiod values**, set it to wherever THAT cluster's ztunnel actually runs:
```yaml
trustedZtunnelNamespace: "istio-system"    # check first: oc get ds -A | grep ztunnel
```
Then restart istiod, then ztunnel.

#### East-west gateway high availability (surviving a node failure)

Two INDEPENDENT layers — you need both. Don't try to solve node-failure with the peer address
alone, and don't front the peer nodes with a ServiceEntry (the `istio-remote` Gateway has no
ServiceEntry reference; its input is `address` = IPAddress or Hostname, and registry-based
hostname resolution for E-W gateways was historically buggy — fixed only in Istio 1.18. Not a
supported HA path).

**Layer 1 — data-plane HA: run the E-W gateway multi-replica with pod anti-affinity + a PDB.**
This is the documented mechanism and the one that actually survives a node loss. NodePort is
**cluster-wide** (every node accepts `:<hbone-nodePort>`/`:<xds-nodePort>` and kube-proxy forwards to a live gateway
pod), so with replicas spread across nodes, a dead node just means traffic routes to a replica
elsewhere — regardless of which node IP the peer dialed.
```yaml
# east-west gateway values (each cluster's OWN gateway)
eastwest:
  create: true
  cluster: cluster1
  network: cluster1
  deployment:
    replicas: 3                       # ≥3
    # spread replicas across nodes so no two share a node
    affinity:
      podAntiAffinity:
        requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchLabels:
              gateway.networking.k8s.io/gateway-name: istio-eastwest
          topologyKey: kubernetes.io/hostname
---
# protect against draining too many during upgrade/maintenance
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: istio-eastwest-pdb
  namespace: istio-eastwest
spec:
  minAvailable: 2                     # keep ≥2 of the 3 Ready
  selector:
    matchLabels:
      gateway.networking.k8s.io/gateway-name: istio-eastwest
```

**Layer 2 — address reachability: the peer must be able to dial a *live* node, not only a dead
one.** Pick one:
- **LoadBalancer VIP (best)** — MetalLB (L2/BGP) on bare-metal OpenShift gives one stable VIP over
  all nodes; ports preserved (no nodePort remap). `preferredDataplaneServiceType: loadbalancer`,
  peer `address: <VIP>`.
- **Hostname multi-A (no-LB fallback)** — `addressType: Hostname`, `address:` a DNS name whose
  A-records list **all** worker node IPs; istiod spreads across the resolved nodes. Same nodePort
  on every node (NodePort is cluster-wide), so one `nodeport:` value covers all.

**`externalTrafficPolicy` caveat (Hostname route):** if the E-W Service is `Local`, only nodes
running a gateway pod answer the nodePort — point DNS **only** at those nodes (or the multi-replica
anti-affinity spread + `Cluster` policy makes all nodes safe to list). Check:
`oc -n istio-eastwest get svc istio-eastwest -o jsonpath='{.spec.externalTrafficPolicy}'`.

| Concern | Fix |
|---|---|
| Gateway pod survives node loss | **Layer 1**: 3 replicas + pod anti-affinity + PDB (minAvailable 2) |
| Peer can still reach a live node | **Layer 2**: LB VIP (best) or Hostname multi-A DNS |
| "Reference a ServiceEntry fronting the nodes" | Not supported — no such field; use VIP or Hostname |

Docs: [multicluster peering best practices / recommendations](https://docs.solo.io/istio/1.30.x/ambient/multicluster/best-practices/peering-recs/) (multi-replica + pod anti-affinity + PDB).

### Expose `testapp` across clusters

```bash
# label the Service global in BOTH clusters (namespace sameness: istio-ns-a in each)
for c in $C1 $C2; do
  kubectl --context $c -n istio-ns-a label svc testapp solo.io/service-scope=global --overwrite
done
# → global hostname: testapp.istio-ns-a.mesh.internal  (endpoints aggregated across clusters)
```
Route to it (ingress or in-mesh) by referencing the global hostname in an HTTPRoute
`backendRefs` (`name: testapp.istio-ns-a.mesh.internal`). The waypoint/weighted-routing
rules from §2 (weighted routing) still apply on the local side; the E-W gateway only carries the cross-cluster hop.

## 8. Multicluster testing (failover, blue/green, weighted routing)

With the mesh spanning both clusters (§7), run these scenarios to prove cross-cluster behavior.

### What to test (demo scenarios)

| Scenario | How | Expected |
|---|---|---|
| **Cross-cluster reachability** | Scale `testapp` to 0 in `$C1`, keep it in `$C2`; curl the global host from a client pod in `$C1` | Request routes `$C1` ztunnel → `$C2` E-W gateway → `$C2` pod (double HBONE); succeeds |
| **Locality preference** | Both clusters have endpoints; curl the global host repeatedly from `$C1` | Stays on `$C1` endpoints (default `PreferNetwork`) — no cross-cluster hop |
| **Locality failover** | With traffic flowing local, scale `$C1` `testapp` to 0 (or make it unhealthy) | Traffic **fails over** to `$C2` via the E-W gateway; scale back → returns local |
| **Traffic distribution** | Set `networking.istio.io/traffic-distribution: PreferClose` on the Service | Routing follows the new policy (e.g. spreads/prefers-closest) |
| **Ingress → remote backend** | Hit the `$C1` ingress host for a global service whose backend lives only in `$C2` | Ingress → local E-W path → `$C2` pod |
| **Cross-cluster identity (mTLS)** | Apply an `AuthorizationPolicy` (L4 at ztunnel) allowing only a specific SA; call cross-cluster from an allowed vs denied identity | Allowed SPIFFE identity passes; others get denied — identity is preserved across the E-W hop |
| **Graph** | Generate cross-cluster traffic, open the Solo UI graph | The E-W gateway renders as an explicit cross-cluster intermediate node (see §10 appendix, mesh graph) |

### Multicluster traffic management: failover, blue/green, weighted routing

Two DISTINCT mechanisms — don't conflate:
- **Failover / locality** = *automatic*, endpoint-health driven. One global service, endpoints in
  both clusters. Controlled by the `traffic-distribution` annotation (L4) + a DestinationRule
  `localityLbSetting` on a waypoint (L7 zone/region).
- **Blue/green & weighted** = *explicit* split by version. **Cross-cluster DestinationRule
  `subset:` routing is NOT supported** — instead expose one **global "subset" Service per version**
  and split with an HTTPRoute's weighted `backendRefs`.

#### A. Multicluster failover (locality + L7 health)

**Prerequisite — the service must be aggregated across clusters (namespace sameness):**
- **Same service name, same namespace** in both clusters → identically-named services in the
  identically-named namespace are treated as ONE global service; their endpoints aggregate under
  `<svc>.<ns>.mesh.internal`. (Name + namespace is the join key; selectors/ports need not be
  byte-identical.)
- **Labeled `solo.io/service-scope: global` in BOTH clusters** (on the Service or the namespace).
  Labeling only one side does not aggregate.
- Baseline already in place: shared root CA + E-W gateways peered/linked.

If the service exists in only one cluster you get cross-cluster *reachability*, not *failover* —
there is no remote target to fail over to. (Contrast B/C below: blue/green & weighted deliberately
use **different** service names so you can split between versions.)

1) Traffic-distribution on the global Service (L4, ztunnel):
```yaml
apiVersion: v1
kind: Service
metadata:
  name: testapp
  namespace: istio-ns-a
  labels:
    solo.io/service-scope: global                              # → testapp.istio-ns-a.mesh.internal
  annotations:
    networking.istio.io/traffic-distribution: PreferNetwork    # default: local-first, fail over to remote
    # swap to test: PreferClose | PreferRegion | Any
```

2) L7 zone/region-aware failover + health ejection (needs a waypoint on the path):
```yaml
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: testapp-failover
  namespace: istio-ns-a
spec:
  host: testapp.istio-ns-a.mesh.internal                       # the GLOBAL hostname
  trafficPolicy:
    loadBalancer:
      simple: ROUND_ROBIN
      localityLbSetting:
        enabled: true
        failoverPriority:
        - topology.kubernetes.io/zone                          # same zone first,
        - topology.kubernetes.io/region                        # then same region, then remote
    outlierDetection:                                          # eject unhealthy → triggers failover
      consecutive5xxErrors: 5
      interval: 10s
      baseEjectionTime: 3m
      maxEjectionPercent: 50
```
Attach the waypoint: `kubectl label ns istio-ns-a istio.io/use-waypoint=testapp-waypoint`

**Test:** steady traffic from `$C1`; make `$C1` endpoints unhealthy (scale to 0 or return 5xx) →
traffic ejects local and flows to `$C2` via the E-W gateway. Restore → returns local.

#### B. Multicluster blue/green

**Prerequisite — the opposite of failover's naming rule:**
- Each version is a **separate Service with a DIFFERENT name** (`testapp-blue`, `testapp-green`) —
  distinct names are what let you address and split between versions. Do NOT rely on namespace
  sameness to merge them.
- **Each subset Service is labeled `solo.io/service-scope: global`** so it gets its own
  `<name>.<ns>.mesh.internal` hostname; the HTTPRoute weights reference those global hostnames.
- Namespace sameness still applies *within* a subset: if `testapp-blue` exists in **both** clusters
  (same name+namespace, both labeled global), its endpoints aggregate — so a single weighted slice
  can itself failover across clusters. Put a version in only one cluster to pin that slice there.
- Same baseline: shared root CA + peered E-W gateways.

Expose blue and green as **separate global Services**; flip the HTTPRoute weight 100/0 → 0/100:
```yaml
apiVersion: v1
kind: Service
metadata: {name: testapp-blue,  namespace: istio-ns-a, labels: {solo.io/service-scope: global}}
spec: {selector: {app: testapp, version: blue},  ports: [{port: 8080}]}
---
apiVersion: v1
kind: Service
metadata: {name: testapp-green, namespace: istio-ns-a, labels: {solo.io/service-scope: global}}
spec: {selector: {app: testapp, version: green}, ports: [{port: 8080}]}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: testapp-bluegreen, namespace: istio-ns-a}
spec:
  parentRefs:
  - group: ""
    kind: Service
    name: testapp                                    # stable global front door
    port: 8080
  rules:
  - backendRefs:
    - name: testapp-blue.istio-ns-a.mesh.internal    # global hostname, NOT the local Service
      port: 8080
      weight: 100                                    # blue live
    - name: testapp-green.istio-ns-a.mesh.internal
      port: 8080
      weight: 0                                      # green dark → flip to 0/100 to cut over
```
Put blue in `$C1` and green in `$C2` (or both in each) → the weight flip is a **cross-cluster** cutover.

#### C. Multicluster weighted / canary

Same shape as B with non-100/0 weights (90/10 → 50/50). Because each backend is a global subset
host, a 10% slice can live **entirely in the other cluster**:
```yaml
  rules:
  - backendRefs:
    - name: testapp-v1.istio-ns-a.mesh.internal
      port: 8080
      weight: 90
    - name: testapp-v2.istio-ns-a.mesh.internal      # v2 endpoints only in $C2
      port: 8080
      weight: 10
```
For automated canary, **Argo Rollouts** drives these weights across the `.mesh.internal` hostnames.

**Gotchas:**
- Cross-cluster **DestinationRule `subset:` is unsupported** — use per-version global Services +
  HTTPRoute weights, never subsets.
- Weighted `backendRefs` MUST reference the **`.mesh.internal` global** hostname, not the local
  Service — otherwise the split stays single-cluster.
- Failover (A) and weighting (B/C) compose: within each weighted subset service, locality/health
  failover still applies.
- `solo.io/service-takeover=true` forces all callers onto the global hostname (use when local
  callers would otherwise bypass the split).

**Docs — verified against Solo Enterprise for Istio 1.30.x (2026-08-19):**

| What | Doc | Confirms |
|---|---|---|
| Expose global service (`solo.io/service-scope: global` → `<name>.<ns>.mesh.internal`) | [multi-apps overview #scope](https://docs.solo.io/istio/1.30.x/ambient/multicluster/multi-apps/overview/#scope) | label value + hostname format |
| **A** — traffic-distribution (`PreferNetwork`/`PreferClose`/`PreferRegion`/`Any`) | [overview #endpoint-traffic-control](https://docs.solo.io/istio/1.30.x/ambient/multicluster/multi-apps/overview/#endpoint-traffic-control) | annotation name + all 4 values (default `PreferNetwork`) |
| **A** — L7 zone/region failover DestinationRule (`localityLbSetting.failoverPriority` + `outlierDetection` on the `.mesh.internal` host) | [multicluster zone & region failover](https://docs.solo.io/istio/1.30.x/ambient/resiliency/failover/multicluster-failover/) | exact DR fields; `host` = global hostname |
| **A** — L7 failover via waypoint (single-cluster base) | [L7 waypoint failover](https://docs.solo.io/istio/1.30.x/ambient/resiliency/failover/l7-waypoint/) | `outlierDetection` + `istio.io/use-waypoint` attach |
| **B/C** — weighted / blue-green via per-version global Services + HTTPRoute `backendRefs` weights | [overview #subset-routing](https://docs.solo.io/istio/1.30.x/ambient/multicluster/multi-apps/overview/#subset-routing) | HTTPRoute weights to `.mesh.internal` subset hosts; **DR `subset:` unsupported cross-cluster** |
| **C** — automated canary driving the weights | [Argo Rollouts canary](https://docs.solo.io/istio/1.30.x/ambient/traffic-management/argo-rollouts/) | Gateway API plugin splits via HTTPRoute `backendRef` weights |
| Force callers onto global host (`solo.io/service-takeover: true`) | [overview (takeover section)](https://docs.solo.io/istio/1.30.x/ambient/multicluster/multi-apps/overview/) | takeover label |

#### Ingress → global service: the working pattern + gotchas (validated live)

Point the ingress gateway's HTTPRoute at the global hostname:
```yaml
backendRefs:
- group: networking.istio.io    # REQUIRED — empty group ⇒ ResolvedRefs=False, reason
  kind: Hostname                # InvalidKind: 'unsupported backendRef: group "" kind "Hostname"'
  name: testapp.istio-ns-a.mesh.internal
  port: 8080
```
- **Endpoint accounting is N+1, not N+M:** on each cluster, `ztunnel-config services` shows the
  global service (`autogen.<ns>.<svc>`) with **local pods + ONE endpoint per remote network**
  (the peer's E-W gateway). You never see the peer's individual pods — its ztunnel fans out
  after the HBONE hop. e.g. 6 local + 1 remote = `7/7` is the fully-aggregated healthy state.
- **"Only local responses" is NORMAL:** default `PreferNetwork` sends 100% of traffic to local
  endpoints while any are healthy. Cross-cluster only on local exhaustion (failover) — or set
  `networking.istio.io/traffic-distribution: Any` on the Service for active-active spread.
- Layering that works: keep each cluster's **local** blue/green split (Service-parented weighted
  HTTPRoute at its waypoint) and make only the **front** Service global — global layer does
  cross-cluster availability, local layer does version weighting.

### Verify peering is working (layered — cheapest to definitive)

Run top-down; the first layer that fails is your break. Don't trust the `check` exit code alone
(it's unreliable for split-namespace / NodePort — see §10); read the individual signals.

**1. Control plane / link health**
```bash
istioctl multicluster check --contexts=$C1,$C2 -i istio-system   # runs Peers/Stale/SA (precheck skips these)
istioctl --context $C1 proxy-status                              # remote-cluster proxies appear + SYNCED
kubectl --context $C1 -n istio-eastwest get gateway -o wide      # Programmed=True, address = NodeIP (not ClusterIP)
```

**2. Peer reachability (NodePort path actually open)** — both ports, from the peer side:
```bash
nc -vz <peer-node-ip> <hbone-nodePort>    # 15008
nc -vz <peer-node-ip> <xds-nodePort>      # 15012
```

**3. Remote endpoints aggregated** (ambient — check ztunnel, not Endpoints):
```bash
istioctl --context $C1 ztunnel-config services  -n istio-ns-a | grep testapp   # endpoints span BOTH clusters
istioctl --context $C1 ztunnel-config workloads | grep -Ei "testapp|eastwest|<peer-net>"
```
**Healthy NodePort-peering output looks like** (in `ztunnel-config workloads`):
- `NetworkGateway/<peer-net>/node.istio-eastwest.<peer>.mesh.internal/15008` — the peer network registered with its node-hostname gateway
- `autogen.node.<peer>.<node-name>...` rows with **peer node IPs** — node discovery auto-registers ALL the peer's nodes as gateway endpoints (more than the single configured address → built-in node-level HA)

**4. Global DNS resolves** (proves DNS capture on the peered name):
```bash
kubectl --context $C1 exec deploy/<client> -- getent hosts testapp.istio-ns-a.mesh.internal
```

**5. THE definitive proof — remote-only cross-cluster call.** Endpoints only in `$C2`, call from `$C1`:
```bash
kubectl --context $C1 scale deploy/testapp --replicas=0
kubectl --context $C1 exec deploy/<client> -- curl -s testapp.istio-ns-a.mesh.internal:8080/hostname
# response from a $C2 pod = DNS capture + E-W gateway + double-HBONE + endpoint aggregation all working.
# best if the app echoes cluster/pod so you SEE it came from the remote cluster. Drive HTTP (not raw TCP)
# so you can confirm the origin and see the hop in the graph.
```

**6. Cross-cluster identity (mTLS across the E-W hop)** — apply an `AuthorizationPolicy` allowing
only a specific SA; the allowed SPIFFE identity passes cross-cluster, others are denied.

> **Cert compatibility gotcha:** a single-context `multicluster check` only prints the **local**
> root SHA — it does **not** compare clusters. Run it with `--contexts=$C1,$C2`, or diff the roots
> yourself: `for c in $C1 $C2; do kubectl --context $c -n istio-system get secret cacerts -o
> jsonpath='{.data.root-cert\.pem}' | base64 -d | openssl x509 -noout -fingerprint -sha256; done`
> (plug-in CA — the current OpenSSL-cert setup; also compare the distributed `istio-ca-root-cert`
> ConfigMap, §9 step 1) — the SHAs MUST be identical or cross-cluster mTLS fails the handshake.

## 9. Reference

### Rules of thumb

1. One routing API per service. HTTPRoute or VirtualService, not both.
2. Only the fronted Service (`testapp`) is waypoint-fronted, never the per-version targets.
3. Mesh capture is set on the Deployment or namespace, the waypoint on the Service. Two labels, two places.
4. L4 identity/port authorization is enforced at ztunnel; L7 (methods, paths, http limits) plus all circuit-breaking / connection-pool limits and outlier detection are enforced at the waypoint. ztunnel does not read `DestinationRule`.
5. Authorization is allow-by-default until the first ALLOW policy selects a workload, then deny-by-default for it. Get the SPIFFE principals exact.
6. `Accepted=True` doesn't mean enforced. Confirm in the proxy with `istioctl proxy-config`.

### Certificates (cert-manager and Venafi via istio-csr) — PLANNED, not yet in use

> **Current state: the clusters use OpenSSL-generated certs via the plug-in CA (`cacerts`) —
> see "Shared root of trust" below, which is the active setup + verification.** This section
> documents the intended future state (Venafi issuance through istio-csr) for when it lands.

In that future state, the mesh's workload certs are issued by Venafi, not istiod. cert-manager's istio-csr agent serves the mesh CA endpoint in place of istiod and forwards signing requests to a Venafi issuer:

```
Venafi (TPP / Control Plane)
  <- cert-manager Venafi ClusterIssuer
    <- istio-csr (serves the Istio CA gRPC endpoint)
      <- CSRs from ztunnel / workloads
```

The Venafi issuer signs against your Venafi zone; istio-csr references it via `issuerRef` (kind `ClusterIssuer` or `Issuer`, name, group), so every workload SVID chains up to Venafi while keeping its normal SPIFFE identity.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer          # or Issuer in istio-system
metadata:
  name: venafi-issuer
spec:
  venafi:
    zone: "TLS/SSL\\Certificates\\Istio"   # Venafi TPP policy folder / Control Plane zone
    tpp:
      url: https://tpp.example.com/vedsdk
      credentialsRef:
        name: venafi-tpp-secret
```

Verify the chain end to end:

```bash
kubectl get clusterissuer venafi-issuer -o wide                       # Ready=True
kubectl get pods -n cert-manager -l app.kubernetes.io/name=cert-manager-istio-csr
kubectl get certificaterequest -A --sort-by=.metadata.creationTimestamp | tail   # signed, not Pending
# ambient: the workload SVID is held by ztunnel (no per-pod Envoy) — use ztunnel-config, NOT proxy-config
ZT=$(kubectl get pod -n kube-system -l app=ztunnel -o name | head -1)   # ztunnel ns (split install)
istioctl ztunnel-config certificate ${ZT#pod/} -n kube-system          # workload SPIFFE identities + validity
# confirm the chain is Venafi's (not istiod self-signed): the signed CertificateRequests above prove issuance;
# the trust root every workload receives:
kubectl get configmap istio-ca-root-cert -n istio-ns-a -o jsonpath='{.data.root-cert\.pem}' \
  | openssl x509 -noout -issuer -dates
```

Docs:

- istio-csr overview: https://cert-manager.io/docs/usage/istio-csr/
- istio-csr installation: https://cert-manager.io/docs/usage/istio-csr/installation/
- istio-csr Helm values / `issuerRef`: https://github.com/cert-manager/istio-csr
- Venafi issuer configuration: https://cert-manager.io/docs/configuration/venafi/
- Issuer vs ClusterIssuer: https://cert-manager.io/docs/configuration/

Note: cert-manager's newer docs label Venafi as "CyberArk," but the API field is still `spec.venafi`.

### Shared root of trust across clusters (one root → per-cluster intermediate) — CURRENT setup

Prerequisite for multicluster mTLS (§7): both clusters must chain to the **same root**. The setup
in use — a single offline **OpenSSL-generated root CA**, and a **distinct intermediate CA per
cluster** signed by that root. Each cluster's istiod signs workload certs from its **own**
intermediate; because both intermediates chain to the one root, cross-cluster (double-HBONE)
mTLS trusts end to end.

**Generate the certs (OpenSSL — extensions match Istio's official `tools/certs` recipe):**
```bash
# ONE root (keep the key offline)  — 4096-bit, 10y, CA:true, same keyUsage set as tools/certs
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 3650 \
  -subj "/O=example/CN=Root CA" \
  -keyout common/root-key.pem -out common/root-cert.pem \
  -addext subjectKeyIdentifier=hash \
  -addext basicConstraints=critical,CA:true \
  -addext keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,keyCertSign

# per-cluster intermediate (repeat with cluster2). NOTE the SAN — the official recipe includes
# istiod's in-cluster DNS name on the intermediate (istiod serves :15012 with this chain).
openssl req -newkey rsa:4096 -sha256 -nodes \
  -subj "/O=example/CN=cluster1 Intermediate CA" \
  -keyout cluster1/ca-key.pem -out cluster1/ca.csr
openssl x509 -req -in cluster1/ca.csr -sha256 -days 3650 \
  -CA common/root-cert.pem -CAkey common/root-key.pem -CAcreateserial \
  -out cluster1/ca-cert.pem \
  -extfile <(printf "subjectKeyIdentifier=hash\nbasicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,keyCertSign\nsubjectAltName=DNS:istiod.istio-system.svc")
# CA:true + keyCertSign are REQUIRED or istiod refuses to load cacerts; keep the SAN matching
# istiod's namespace (istio-system here). Istio ships a Makefile that automates exactly this
# layout — tools/certs in the istio release:
#   make -f Makefile.selfsigned.mk root-ca && make -f Makefile.selfsigned.mk cluster1-cacerts
```

This is the Istio **plug-in CA** model — the `istio-system/cacerts` secret in each cluster, four files:

| file | contents | same on both clusters? |
|---|---|---|
| `root-cert.pem` | the **common root** cert | **YES — identical** |
| `ca-cert.pem` | THIS cluster's **intermediate** cert | no — one per cluster |
| `ca-key.pem` | THIS cluster's intermediate **private key** | no |
| `cert-chain.pem` | `ca-cert.pem` + `root-cert.pem` (this cluster's chain to root) | no |

> Later, with **istio-csr** (the planned Venafi setup above) the same idea applies — the
> per-cluster intermediate becomes the cert-manager **CA/Issuer** in that cluster; both issue from
> the one root. Verification (roots identical) is the same either way.

**Set up (per cluster) — the intermediate must come first, before istiod issues any certs:**
```bash
# root-cert.pem = the ONE common root; ca-cert.pem/ca-key.pem = THIS cluster's intermediate.
cat cluster1/ca-cert.pem common/root-cert.pem > cluster1/cert-chain.pem     # chain = intermediate + root
#   (multi-level PKI: cert-chain.pem = every intermediate in order, then the root)

kubectl --context $C1 create namespace istio-system 2>/dev/null || true
kubectl --context $C1 -n istio-system create secret generic cacerts \
  --from-file=root-cert.pem=common/root-cert.pem \
  --from-file=ca-cert.pem=cluster1/ca-cert.pem \
  --from-file=ca-key.pem=cluster1/ca-key.pem \
  --from-file=cert-chain.pem=cluster1/cert-chain.pem
# repeat on $C2 with cluster2's intermediate + THE SAME common/root-cert.pem

# roll the CA consumers so they pick up cacerts (ambient: istiod + ztunnel + waypoints)
kubectl --context $C1 -n istio-system rollout restart deploy/istiod
kubectl --context $C1 -n kube-system  rollout restart daemonset/ztunnel   # ztunnel ns (split install)
```
> **Live cluster caveat:** if istiod already issued certs from a *different* root, don't hot-swap —
> add the new root to the workload **trust bundle first** (both roots trusted), roll workloads, then
> switch signing. See Istio "plug-in CA / cert rotation" to avoid an mTLS outage.

**Verify the two clusters share a common root — run all four:**

1) **Roots identical across clusters** (the decisive check — all fingerprints must match):
```bash
for c in $C1 $C2; do
  echo -n "$c cacerts root      : "; kubectl --context $c -n istio-system get secret cacerts \
    -o jsonpath='{.data.root-cert\.pem}' | base64 -d | openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//'
  echo -n "$c distributed root  : "; kubectl --context $c -n istio-ns-a get configmap istio-ca-root-cert \
    -o jsonpath='{.data.root-cert\.pem}' | openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//'
done
# all four SHA-256s MUST be equal → that is the common root.
```

2) **Intermediates differ but each chains to the common root:**
```bash
for c in $C1 $C2; do
  echo "== $c intermediate =="
  kubectl --context $c -n istio-system get secret cacerts -o jsonpath='{.data.ca-cert\.pem}' \
    | base64 -d | openssl x509 -noout -subject -issuer
done
# subjects differ (per-cluster); ISSUER is the common root on both.
# prove the chain validates to the root:
kubectl --context $C1 -n istio-system get secret cacerts -o jsonpath='{.data.root-cert\.pem}'  | base64 -d > /tmp/root.pem
kubectl --context $C1 -n istio-system get secret cacerts -o jsonpath='{.data.ca-cert\.pem}'    | base64 -d > /tmp/c1-int.pem
openssl verify -CAfile /tmp/root.pem /tmp/c1-int.pem     # → /tmp/c1-int.pem: OK   (repeat for $C2)
```

3) **A live workload cert chains to the common root** (ambient → ztunnel holds the SVID):
```bash
ZT=$(kubectl --context $C1 get pod -n kube-system -l app=ztunnel -o name | head -1)
istioctl --context $C1 ztunnel-config certificate ${ZT#pod/} -n kube-system -o json \
  | jq -r '.certificates[0].certChain[-1].pem' | openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//'
# last cert in the chain = the root; its fingerprint must equal the common root from step 1.
# (field shape varies slightly by istioctl version — if .pem is missing, inspect the JSON and
#  take the PEM of the LAST certChain element.)
```

4) **`multicluster check` agrees + a real cross-cluster call succeeds:**
```bash
istioctl multicluster check --contexts=$C1,$C2 -i istio-system   # Intermediate Certs Compatibility Check ✓
# then the definitive proof — remote-only cross-cluster curl from §8.
```

**Also confirm trust domains match** — a shared root is necessary but not sufficient; cross-cluster
identity also needs the same SPIFFE `trustDomain` (default `cluster.local`) on both clusters, or
explicit trust-domain federation. Mismatched trust domains fail mTLS even with an identical root.

Docs: [Istio plug-in CA certs](https://istio.io/latest/docs/tasks/security/cert-management/plugin-ca-cert/) ·
[Solo — Istio certificate management](https://docs.solo.io/istio/1.30.x/sidecar/security/certs-ov/) ·
[Istio cert rotation (avoid mTLS outage)](https://istio.io/latest/docs/tasks/security/cert-management/plugin-ca-cert/#configure-and-check-the-cluster).
Verified 2026-08-20 against Istio + Solo docs.

## 10. Troubleshooting (appendix)

Troubleshooting collected from the sections above — single-cluster first, then multicluster.

### Mesh graph nodes not appearing

> Working notes for the customer engagement (cluster `cluster1`, ns `istio-ns-a` for the
> mesh, ns `solo-enterprise` for the UI/telemetry). OpenShift + OVN-Kubernetes.

#### ✅ RESOLVED (2026-08-19): the "Show Infrastructure" toggle was off

**Root cause: a UI display toggle, not telemetry.** In the Solo Enterprise for Istio graph,
waypoints, ingress/egress gateways, and ztunnel are **"infrastructure" nodes**, hidden by
default. They render only when **"Show Infrastructure"** is enabled in the graph controls.

**Fix: turn on "Show Infrastructure" in the graph UI.** The waypoint, ingress, and egress
appeared immediately — the metrics were being scraped and stored the whole time.

**Check this FIRST**, before any telemetry digging:
1. Graph controls → enable **Show Infrastructure** (labels may read "Show Infra" / "Infrastructure nodes").
2. Confirm the time window covers live traffic and Cluster/Namespace/Workspace filters include `istio-ns-a`.
3. Drive real HTTP through the ingress→`testapp`→egress path (the `blue/green→backend` demo hop exercises no gateways).

The ClickHouse/collector pipeline below is only relevant if nodes are **still** missing after
Show Infrastructure is on — kept for reference, but it was NOT the cause here.

<details>
<summary>Telemetry deep-dive (reference only — was not the root cause)</summary>

#### Architecture for THIS deployment (ClickHouse-backed Solo Enterprise UI)

Identify the product by its pods in `solo-enterprise`:
`solo-enterprise-ui`, `solo-enterprise-telemetry-collector`, `solo-management-clickhouse`.
That means the graph is **ClickHouse + OpenTelemetry backed** (NOT a standalone Prometheus
server — that's the older Gloo Mesh Enterprise `gloo-mesh-ui`). Pipeline:

```
mesh proxies (:15020 Prometheus metrics)
   → collector PROMETHEUS RECEIVER (scrapes :15020)
   → collector CLICKHOUSE EXPORTER (writes platformdb.otel_metrics_{sum,gauge,histogram})
   → solo-enterprise-ui queries ClickHouse
   → graph
```

A proxy shows up only if: **traffic traverses it → it's scraped → stored in ClickHouse →
queried → within the UI's view/filters/window.** Stop at the first broken link.

#### Namespaces (this deployment — cluster `cluster1`, OpenShift / OVN-Kubernetes)

| Namespace | What runs there | Relevant to the graph |
|---|---|---|
| `solo-enterprise` | `solo-enterprise-ui`, `solo-enterprise-telemetry-collector` (+ `solo-enterprise-telemetry-gateway`), `solo-management-clickhouse` (DB **`platformdb`**) | the UI, the scraping collector, and the ClickHouse store — the whole graph backend |
| `istio-ns-a` | the mesh app + all gateways: `testapp-blue`, `testapp-green`, `backend`, `backend-waypoint`, `testapp-waypoint`, `testapp-egress-gateway`, `testapp-ingress-istio` | the scrape targets (waypoint/egress/ingress on `:15020`) |
| `kube-system` | ambient **`ztunnel`** DaemonSet (`ztunnel-*`) | also scraped on `:15020` (job `ztunnel`) |

The collector in `solo-enterprise` scrapes proxies **cross-namespace** into `istio-ns-a` and
`kube-system`. (Handy: `oc get po -o wide -n istio-ns-a` for current pod IPs — they change on
restart; the log IPs go stale.)

#### Two failure surfaces in the collector — do NOT confuse them

- **Receiver (scrape):** `"Failed to scrape Prometheus endpoint"` (component `prometheus`,
  kind `receiver`). Reachability/config of the proxy `:15020`.
- **Exporter (ClickHouse):** `"Exporting failed … clickhouse/metrics … Table
  platformdb.otel_metrics_* does not exist"` / `"handshake … read: EOF"` (kind `exporter`).
  Storage.

**A `curl` to `:15020` only tests the receiver's reachability. It says NOTHING about the
exporter.** If the scrape works but the export fails, metrics are collected and dropped →
empty graph, and curl-ability is a red herring.

#### What we've tried so far (as of 2026-08-18)

| # | What we checked | Result |
|---|---|---|
| 1 | Data path — is traffic traversing the waypoint + egress? | ✅ Yes (traffic + egress confirmed) |
| 2 | UI Workloads filter | ✅ All 7 present + selected (`backend`, `backend-waypoint`, `testapp-blue/green`, `testapp-egress-gateway`, `testapp-ingress-istio`, `testapp-waypoint`) |
| 3 | What the graph actually draws | ⚠️ Only `testapp-blue/green → backend` (trace-derived); ingress/waypoint/egress absent. Focus `istio-ns-a`, **Depth: 1 Hop**, Traffic mode |
| 4 | Collector logs | ❌ TWO errors: `Failed to scrape Prometheus endpoint` for ztunnel + waypoint + egress `:15020` (recurring → 08-17), AND `Exporting failed … Table platformdb.otel_metrics_{sum,gauge,histogram} does not exist` + `handshake … read: EOF` (08-11, setup) |
| 5 | Is there a standalone Prometheus? | ❌ No — only `collector` / `gateway` / `clickhouse` / `ui` services. Graph = ClickHouse-backed |
| 6 | Connectivity: test pod in `solo-enterprise` → proxy `:15020` | ✅ `curl http://<ip>:15020/stats/prometheus` returns metrics for all proxies → **network is NOT the blocker** |
| 7 | The `gateway` scrape job config | ✅ 100% annotation-driven (scheme/path/port from the pod `prometheus.io/*`); nothing hard-coded |
| 8 | Proxy pod annotations | ✅ Correct: `path=/stats/prometheus`, `port="15020"`, `scrape="true"`, **no `scheme` (→ http)** → collector's target == the working curl. NOT a scheme/path problem |
| 9 | Collector is distroless | ⚠️ No curl/shell in-pod → must test from a separate pod or an `oc debug` clone |

**Where that leaves us:** config is correct and the endpoints are reachable from the
collector's namespace, yet the collector still errors — so the live problem is one (or both)
of:
- **(a) Exporter / ClickHouse side** — *very likely*, the metrics store (`platformdb.otel_metrics_*`)
  was missing, so scraped metrics have nowhere to land → empty graph. **Not yet re-verified.**
- **(b) A scrape difference `curl` doesn't reproduce** — `scrape_timeout` vs a large `:15020`
  payload, or the **collector's own capture identity** differs from the test pod. **Not yet tested.**

#### Not yet tried (do these next — see "Start here")
- [ ] Categorize the **live** collector errors (receiver vs exporter) — `--since=15m`
- [ ] `SHOW TABLES FROM platformdb` — do `otel_metrics_*` exist now?
- [ ] If still scrape errors: payload size vs `scrape_timeout`, and an `oc debug` clone of the collector
- [ ] Once metrics land: query ClickHouse for `reporter="waypoint"` vs TCP (L4/L7)
- [ ] UI: Depth > 1 Hop, Cluster+NS+Workspace filters, drive HTTP on ingress/egress paths

#### Start here (next session, in order)

**A. Which surface is failing NOW?** (receiver vs exporter)
```bash
oc -n solo-enterprise logs solo-enterprise-telemetry-collector-0 --since=15m \
  | grep -oiE "Failed to scrape|Exporting failed|does not exist|handshake|clickhouse" \
  | sort | uniq -c
```

**B. Does the ClickHouse store exist?** (the 08-11 export errors)
```bash
oc -n solo-enterprise exec solo-management-clickhouse-shard0-0 -- \
  clickhouse-client -q "SHOW TABLES FROM platformdb"
# missing otel_metrics_* ⇒ exporter isn't creating schema. Check create_schema / auth /
# the handshake EOF to :9000. Nothing stores (⇒ empty graph) until this is fixed.
oc -n solo-enterprise logs solo-management-clickhouse-shard0-0 --tail=100 \
  | grep -iE "error|reject|auth|exception|space"
```

**C. If the LIVE errors are scrape (not export) even though curl works:**
```bash
# c1) payload size vs scrape_timeout — curl (no timeout, piped to head) hides this
oc -n solo-enterprise exec <test-pod> -- sh -c \
  'curl -s http://<waypoint-ip>:15020/stats/prometheus | wc -c'
grep -nE "scrape_timeout|scrape_interval|body_size_limit|sample_limit" /tmp/collector-cm.yaml
#   context deadline exceeded ⇒ raise scrape_timeout;  exceeded body/sample limit ⇒ raise limit

# c2) collector's OWN network identity (capture) — a debug clone inherits its labels/SCC
oc debug -n solo-enterprise pod/solo-enterprise-telemetry-collector-0 --image=nicolaka/netshoot
#   inside: curl -sS -m5 http://<waypoint-ip>:15020/stats/prometheus | head
#   clone FAILS but a plain test pod works ⇒ collector labels / ambient capture
oc get ns solo-enterprise -o jsonpath='{.metadata.labels}' | tr ',' '\n' | grep -i dataplane
istioctl ztunnel-config workloads 2>/dev/null | grep -i telemetry-collector   # HBONE ⇒ captured
#   fix if captured: set istio.io/dataplane-mode: none on the collector (via Solo values)
```

**D. Once metrics land in ClickHouse — confirm the data + L4/L7** (adjust table/cols to the
schema `SHOW TABLES` reveals):
```bash
CH="oc -n solo-enterprise exec solo-management-clickhouse-shard0-0 -- clickhouse-client"
$CH -q "SELECT count(), max(TimeUnix) FROM platformdb.otel_metrics_sum"
$CH -q "SELECT DISTINCT MetricName FROM platformdb.otel_metrics_sum WHERE MetricName LIKE 'istio%'"
# waypoint L7 present? and is the traffic actually TCP (L4)?
$CH -q "SELECT Attributes['reporter'] r, Attributes['destination_workload'] d, count()
        FROM platformdb.otel_metrics_sum
        WHERE MetricName='istio_requests_total' AND TimeUnix > now()-INTERVAL 15 MINUTE
        GROUP BY r,d ORDER BY count() DESC LIMIT 30"
$CH -q "SELECT count() FROM platformdb.otel_metrics_sum
        WHERE MetricName='istio_tcp_connections_opened_total' AND TimeUnix > now()-INTERVAL 15 MINUTE"
```

**E. UI-side, once data exists:** raise **Depth** past 1 Hop; confirm Cluster + Namespace +
Workspace selected and the time window covers traffic; and **drive HTTP traffic on the real
paths** (ingress→`testapp`, and the egress call to the external host) — the
`blue/green→backend` demo hop exercises none of the gateways.

#### What SHOULD appear (and the L4 caveat)

- **Waypoint** → `WAYPOINT_PROXY_WORKLOAD` node / two-hop on the `testapp` path (L7/HTTP only).
- **Egress external host** → `EXTERNAL_WORKLOAD` node in Traffic mode — needs a
  **source-reported HTTP series with `destination_service`=host**. TLS-passthrough
  (`protocol: TLS`, L4) emits only `istio_tcp_*`, so the external node may show as an IP or
  not at all; use an **L7 egress** (`protocol: HTTP` + `DestinationRule tls.mode: SIMPLE`)
  for a named node.
- **L4/TCP traffic** DOES render (dashed edges, from `istio_tcp_*`), just without the L7
  richness (HTTP rates/codes, waypoint hop, named egress). Dashed `blue→backend` = TCP.

#### Quick decision table

| Symptom | Where | Fix |
|---|---|---|
| **Waypoint / gateways / ztunnel missing from graph** | **UI** | **← THE ACTUAL FIX HERE: enable "Show Infrastructure" in graph controls. Infra nodes are hidden by default. Check this before anything below.** |
| Live errors are `Exporting failed` / `platformdb.otel_metrics_* does not exist` | exporter | fix ClickHouse schema/auth/handshake — nothing stores until then |
| Live errors are `Failed to scrape`, but curl to `:15020` works | receiver | scrape_timeout / body_size_limit (big payload), or collector ambient-capture |
| `curl` works from test pod but debug-clone of collector fails | receiver | collector's labels / `istio.io/dataplane-mode` (capture) |
| `platformdb` has istio metrics but no `reporter="waypoint"` / high TCP | data | traffic is L4 — send HTTP through the paths |
| Data in ClickHouse but graph empty | UI | Depth > 1 Hop, Cluster+NS+Workspace filters, time window, right traffic path |

</details>

### Egress not routing through the gateway

Both of these are silent — no error, the ServiceEntry just never binds and traffic never reaches the gateway (no logs). Both were hit in a live setup.

- **`metadata.label` vs `metadata.labels`.** The `use-waypoint` binding is a Kubernetes label, so it must live under `metadata.labels` (plural). A manifest with `metadata.label:` (singular) is not a real field — the API server drops it, so the ServiceEntry ends up with no label and never binds. Check it's actually set:
  ```bash
  kubectl get serviceentry <name> -n istio-ns-a -o jsonpath='{.metadata.labels}'; echo   # must show istio.io/use-waypoint
  ```
- **Gateway `waypoint-for: service` vs `all`.** A ServiceEntry is not a Kubernetes Service, so a waypoint labeled `istio.io/waypoint-for: service` (the default) won't capture it. It must be `all`.
  ```bash
  kubectl get gateway <egress-gw> -n istio-ns-a -o jsonpath='{.metadata.labels}'; echo   # must show waypoint-for: all
  ```

The one command that tells you whether the binding actually took, regardless of the YAML:

```bash
istioctl ztunnel-config services -n istio-ns-a | grep -i <egress-host-or-se-name>
# WAYPOINT column must name the egress gateway. If it's None, the binding didn't take —
# it's one of the two above. Fix, re-check this, then look for logs.
```

### Multicluster check (split namespaces and NodePort)

This cluster runs a **split install**: **istiod → `istio-system`**, **istio-cni + ztunnel →
`kube-system`**. `istioctl multicluster check` assumes istiod and the CNI live in the **same**
`-i`/`--istioNamespace`, so **no single `-i` value passes every check** — it will *always*
exit non-zero (`Error: multicluster check found issues`) for this topology. **That exit code
is not a reliable pass/fail here — read the individual check lines.**

Run it twice and merge the results:
```bash
istioctl multicluster check --precheck -i istio-system   # ✅ istiod, License, Network, Certs
istioctl multicluster check --precheck -i kube-system    # ✅ CNI DNS Capture (AMBIENT_DNS_CAPTURE enabled)
```
- With `-i istio-system` the **CNI** check false-fails (`istio-cni-config` not found — it's in kube-system).
- With `-i kube-system` the **istiod / License / Network / Shared-Services** checks false-fail
  (`no istiod deployment found in namespace "kube-system"`).
- Both are namespace-lookup **artifacts, not real faults.** Confirmed-healthy real state: DNS
  capture enabled, istiod/ztunnel/eastwest pods healthy. (Root-cert match across clusters must
  be verified separately — the single-context check only prints the local SHA; see §9 shared root.)

Full cross-cluster pass (runs the Peers / Stale / SA checks precheck skips) — use the istiod ns:
```bash
istioctl multicluster check --contexts=$C1,$C2 -i istio-system
```
The one **genuine** finding that appears in *both* runs is the NodePort E-W gateway (below).

### Multicluster troubleshooting table

| Symptom | Likely cause | Check / fix |
|---|---|---|
| Cross-cluster calls fail with TLS/handshake errors | **Root CA mismatch** between clusters | Compare `istio-system/cacerts` `root-cert.pem` AND the distributed `istio-ca-root-cert` ConfigMap across clusters — all must be identical (§9 shared root, verification step 1). Fix: re-issue the per-cluster intermediates from the one common root and reload `cacerts`. (Future istio-csr/Venafi: point both issuers at the same root.) |
| Global service has **no remote endpoints** | Namespace-sameness or label missing on the other cluster | Same `svc`+`ns` name in both; `solo.io/service-scope=global` applied in **both**; check `ztunnel-config services`/`workloads` shows remote endpoints |
| No failover to the remote cluster | Default `PreferNetwork` keeps traffic local until local is fully unhealthy | Confirm local endpoints are actually down; or set `traffic-distribution` (e.g. `PreferClose`) |
| `istioctl multicluster check` shows peers not linked / proxies not SYNCED | Peering not established, or E-W gateway not reachable | Re-run `multicluster link`; confirm the E-W gateway has an address and `:15008`/`:15012` are reachable **between** clusters |
| Cross-cluster works pod-to-pod but not from ingress | HTTPRoute references the wrong host | `backendRefs.name` must be the global `<svc>.<ns>.mesh.internal`, not the local Service |
| E-W gateway `:15008/:15012` unreachable across clusters | LoadBalancer/firewall (OpenShift + OVN-K) | Ensure the E-W gateway's LB IP is routable between clusters and no `EgressFirewall`/NetworkPolicy blocks `:15008`/`:15012` (same class as the egress §5 gotchas) |
| E-W gateway missing from the Solo UI graph | Telemetry, not routing | See §10 appendix (mesh graph) — same collector-scrape / ClickHouse pipeline; the E-W gateway is scraped like any other proxy |
| `multicluster check` exits `found issues` but the mesh is fine | **Split install** — istiod in `istio-system`, cni/ztunnel in `kube-system`; the tool assumes one namespace | Expected for this topology. No single `-i` passes all — run twice (`-i istio-system` and `-i kube-system`) and read the individual lines, not the exit code (see above) |
| E-W gateway (NodePort) warns *"reporting ClusterIP — node address discovery may have failed"* | istiod is resolving the gateway to its **ClusterIP** instead of `NodeIP:nodePort`. With **no ExternalIP** on the nodes (bare metal), NodePort address discovery doesn't fall through unless it's told to prefer NodePort. RBAC to `list nodes` is necessary but **not sufficient** on its own. | Set **`peering.solo.io/preferred-data-plane-service-type: NodePort`** on each cluster's **own** E-W gateway (annotation, or Helm `dataplaneServiceTypes: nodeport`) — this is what makes istiod advertise a NodeIP. Confirm RBAC: `oc auth can-i list nodes --as=system:serviceaccount:istio-system:istiod` (want `yes`). Then verify: `kubectl -n istio-eastwest get gateway istio-eastwest -o yaml \| grep -iA6 address` shows a node IP, not the ClusterIP. Note: a NodePort Service always has a ClusterIP, so some `check` versions keep warning even when the NodeIP is correctly advertised — validate with `--contexts=$C1,$C2` + a real cross-cluster call, not the exit code. |
| `Network Configuration Check` ❌ — *"eastwest gateway has network X but cluster network is Y"* / *"istio proxy pod(s) with mismatched ISTIO_META_NETWORK"* | The network name isn't consistent across the cluster — a **local** component is tagged with the **peer's** network name (e.g. the local E-W gateway or a proxy pod wears the remote network). Ambient maps endpoints→gateway by network name, so a mismatch breaks cross-cluster HBONE routing. | Pick ONE canonical network name per cluster (the value on `istio-system`'s `topology.istio.io/network` label — the mesh majority). Fix only the mismatched objects, **not** the correct namespaces: `kubectl -n istio-eastwest label gateway istio-eastwest topology.istio.io/network=<local-net> --overwrite` (and fix the Helm/install `global.network` value if that's the source, else the operator reverts the label), `kubectl label ns istio-eastwest topology.istio.io/network=<local-net> --overwrite`, then `rollout restart` the E-W gateway + the mismatched proxy's owner. Find the bad pod: `kubectl get pods -A -o custom-columns='NS:.metadata.namespace,POD:.metadata.name,NET:.spec.containers[*].env[?(@.name=="ISTIO_META_NETWORK")].value' \| grep <peer-net>`. The peer's name must appear **only** on the remote network object (`istio-remote` Gateway), never on anything local. Check the peer cluster for the mirror bug. |
| Peering stream flaps 60s: `deltaadsc disconnected … remote error: tls: bad certificate` + istiod info `Could not verify certificate: no cert pool found for trust domain <peer>` | **Trust-domain trust anchors missing** — distinct per-cluster trustDomains, and istiod has no cert pool for the peer's domain. Root fingerprints can all match and this still fails. | Either add `meshConfig.caCertificates` with the common root + `trustDomains: [<peer>]` (keeps distinct domains), or move both clusters to a **common trustDomain** — see the §7 trust-domain note. Restart istiod (+ full re-roll for a domain change). |
| istiod: `serverca … impersonation failed for identity spiffe://… caller (Pod{ztunnel-…, ServiceAccount: ztunnel}) is not allowed to impersonate` | ztunnel runs in a namespace istiod doesn't trust for node-delegated cert requests (split installs; ns can differ per cluster) | Set **`trustedZtunnelNamespace: "<ns where ztunnel runs>"`** in that cluster's istiod values (`oc get ds -A \| grep ztunnel` to confirm), restart istiod then ztunnel — §7 note |
| istiod controller retry loop: `failed to apply required labels on node WE …; either no SE found or SE missing required labels; ignore if nodeport peering is not enabled` | The peer item lacks the NodePort fields, so the SE representing the peer's E-W gateway in nodeport mode was never generated | Ensure that side's `remote.items` has `preferredDataplaneServiceType: nodeport` **and** `nodeport: <peer's 15012 nodePort>`. Healthy end-state = `NetworkGateway/<peer>` + `autogen.node.<peer>…` rows in `ztunnel-config workloads` (§8) |
| External curl → `SSL_ERROR_ZERO_RETURN`; ztunnel access log: `connection closed due to policy rejection: explicitly denied by: istio-system/istio_converted_static_strict` | An **unmeshed caller in plaintext** hit a workload under **STRICT `PeerAuthentication`** — e.g. an OpenShift Route pointing **directly at the app Service** (router → pod bypasses the mesh's ingress gateway) | Point the Route at the **meshed ingress gateway** (passthrough) so the caller into the workload is the in-mesh gateway; keep STRICT. Check `oc get pa -A` for the enforcing policies. Deleting/PERMISSIVE-ing the PA "fixes" the curl but drops the zero-trust posture — temporary debugging move only |
| External curl → `curl: (35) SSL routines::packet length too long` | TLS bytes delivered to a **plaintext responder** — same bypass Route as above (**passthrough** Route pointing at the plain-HTTP **app Service**: with STRICT off, the pod answers HTTP mid-TLS-handshake), or a Route whose `targetPort` hits a non-TLS port on the gateway Service | `oc get route -o custom-columns='NAME:.metadata.name,HOST:.spec.host,SVC:.spec.to.name,PORT:.spec.port.targetPort,TLS:.spec.tls.termination'` — the working Route targets the **gateway Service's TLS listener port** with `passthrough`, and the Route host must EQUAL the Gateway listener `hostname:` (SNI selects the listener). **Verify testers use the gateway Route's hostname** — a stale direct-to-Service Route with a similar name produced two sessions of false "mesh is broken" reports. Delete the bypass Route |

### Session log: multicluster COMPLETE (2026-08-21)

Cross-cluster traffic + failover **verified working end to end**: shared OpenSSL root →
common `cluster.local` trust domain → NodePort peering → `testapp` global (`7/7` = 6 local +
1 remote network) → ingress HTTPRoute → `Hostname` backendRef → failover (local scaled to 0 →
peer answers; restore → returns local, `PreferNetwork`). The "in-mesh apps can't talk" and
external-URL reports both traced to a **bypass Route** pointing straight at the app Service
(see the §10 table rows for `SSL_ERROR_ZERO_RETURN` / `packet length too long`). The
solo-enterprise UI crashloop after the trust cutover self-healed (namespace wasn't in the
restart sweep — see §7 cutover note).

Remaining cleanup checklist: delete the bypass Route · `oc apply -f bup.yaml` (restore STRICT
PeerAuthentications) · drop the stray `istio.io/use-waypoint` label from the ingress Service ·
old-trust-domain grep sweep across values/YAML + authz principals.

<details><summary>Prior session state (2026-08-20 — superseded)</summary>

State as of 2026-08-20 end of day — multicluster peering is UP (common `cluster.local` trust
domain, `trustedZtunnelNamespace` set, NodePort node-discovery populating `NetworkGateway` +
`autogen.node` entries). Two workload **STRICT `PeerAuthentication`s (`testapp`, `backend`) were
DELETED** as a debugging step (backed up to `bup.yaml` on the jump host) because an OpenShift
Route pointing directly at the `testapp` Service let the unmeshed router hit the pod in
plaintext → STRICT rejected it → external curl returned `SSL_ERROR_ZERO_RETURN`.

**Start here, in order:**
1. **Fix the ingress path** so north-south enters through the mesh:
   - Route must target the **ingress gateway** (passthrough), not the app Service; stop using /
     delete the direct-to-service Route (`oc -n istio-ns-a get route -o custom-columns='HOST:.spec.host,TO:.spec.to.name,TLS:.spec.tls.termination'`).
   - Fix the ingress Gateway's HTTPS listener — it currently has **no HTTPRoute attached**
     (istiod warn: `…with no vhosts; Setting up a default 404 vhost`). Check
     `attachedRoutes:` in the Gateway status + the HTTPRoute's `Accepted`/`ResolvedRefs` reasons.
   - Curl through the gateway Route → expect the app response (not 404, not SSL errors).
2. **Restore STRICT:** `oc apply -f bup.yaml` (the saved PeerAuthentications) → re-curl through
   the gateway (must still work — the gateway is meshed) → confirm the direct path is now
   properly refused.
3. **Finish peering validation:** mirror `ztunnel-config workloads` check on the second cluster
   (`NetworkGateway`/`autogen.node` rows) → label `testapp` global on BOTH → the remote-only
   cross-cluster curl (§8 step 5).
4. **Sweep for leftovers:** `grep -rn "<old-per-cluster-domains>"` across values/YAML + authz
   principals; confirm zero `bad certificate` / `no cert pool` / `impersonation failed` in
   istiod logs on both clusters.

</details>

Docs (Solo Enterprise for Istio 1.30.x — Enterprise license required):
[multicluster install](https://docs.solo.io/istio/1.30.x/ambient/multicluster/install/) ·
[flat network (advanced)](https://docs.solo.io/istio/1.30.x/ambient/multicluster/install/flat-network/) ·
[expose apps across clusters](https://docs.solo.io/istio/1.30.x/ambient/multicluster/multi-apps/overview/) ·
[Solo UI — global services view](https://docs.solo.io/istio/1.30.x/setup/explore/)
