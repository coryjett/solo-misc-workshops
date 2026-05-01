# Troubleshooting — Why UI-created AccessPolicies didn't enforce

This is the debug history that drove the final shape of `setup.sh`. Future-you will hit some subset of these. Each issue silently disabled the chain at a different layer.

> **TL;DR for the UI flow.** kagent-enterprise 0.3.19 has two translation bugs that make UI-created AccessPolicies no-op (Issues 1 and 1b below). `setup.sh` installs an `access-policy-patcher` Deployment in the `kagent` namespace that watches for the auto-generated `EnterpriseAgentgatewayPolicy` and rewrites the broken bits within ~5s — no manual step required. The standalone `activate-ui-policy.sh` is kept for one-shot manual fixes.

## The chain

```
UI → AccessPolicy CRD
     → AccessPolicy controller (in kagent-controller)
        → translates to EnterpriseAgentgatewayPolicy + Istio AuthorizationPolicy
           → AGW controller attaches to Gateway
              → waypoint pod enforces JWT + CEL on every request
```

Any of these layers can no-op without a clear error.

## Issue 1 — Translation targeted HTTPRoute instead of Gateway

**Symptom:** AccessPolicy created. EnterpriseAgentgatewayPolicy auto-generated. Status: `Attached: False`. Requests went through unfiltered.

**Cause:** kagent-enterprise's waypoint translator (`waypoint_translator_plugin.go`) generates the agent's HTTPRoute with **Service** parentRefs only. The AccessPolicy translator then generates an `EnterpriseAgentgatewayPolicy` targeting that HTTPRoute. AGW's policy attachment logic looks for the HTTPRoute's *Gateway* parentRefs to decide which Gateway to attach to — sees none → `Attached: False`.

**Fix:** Manually create (or patch) the `EnterpriseAgentgatewayPolicy` with `targetRefs` pointing directly at the auto-provisioned waypoint Gateway (`agent-{name}-waypoint`).

```yaml
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: agent-security-auditor-waypoint
```

**Workshop workaround:** `activate-ui-policy.sh <accesspolicy-name>` watches for the auto-generated EAP and patches its `targetRefs` + CEL.

## Issue 1b — Auto-generated CEL is string-equality on an array claim

**Symptom:** Even with the EAP attached, every user — including admin — got `403 authorization failed`.

**Cause:** kagent-enterprise translates a `UserGroup` subject to CEL `jwt.<ClaimName> == "<ClaimValue>"` (see `access_policy_translation.go:479`, `makeCELExpressionForSubject`). The propagated `Groups` claim is an **array** (`["admins"]`), not a string. `["admins"] == "admins"` is always false → 403 for everyone.

**Fix:** Rewrite to `jwt.<ClaimName>.exists(g, g == "<ClaimValue>")` (array-contains).

```yaml
authorization:
  policy:
    matchExpressions:
      - 'jwt.Groups.exists(g, g == "admins")'
```

`activate-ui-policy.sh` does this rewrite automatically.

## Issue 1c — UI "Access Policies" tab stays empty even after creating one

**Symptom:** AccessPolicy exists in the cluster (`kubectl get accesspolicy -A` shows it) but the kagent UI's Access Policies tab says "No Access Policies Found".

**Cause:** The Solo Enterprise UI lists AccessPolicies from **ClickHouse**, not from the Kubernetes API. The `k8sobjects-collector` sidecar in the UI pod populates ClickHouse by watching CRDs. If the collector starts **before** the AccessPolicy CRD is registered (Helm install order: management plane first → CRDs install second), it logs `resource not found: accesspolicies` once and never retries. The watch is never set up; the table is never populated.

**Fix:** Restart the UI deployment after the kagent-enterprise CRDs are installed:

```bash
kubectl rollout restart deploy/solo-enterprise-ui -n kagent
```

`setup.sh` does this automatically at the end of section 8.

## Issue 2 — Wrong JWKS (Keycloak vs. kagent OBO)

**Symptom:** Even after fixing Issue 1, requests returned `401 unknown key`.

**Cause:** UI-generated policy validated against Keycloak's JWKS (the user's OIDC token issuer). Real traffic to the agent does **not** carry the user's Keycloak token — it carries an **OBO (On-Behalf-Of) token** that kagent mints, signed with kagent's own RSA key. Issuer is `kagent.kagent` (`<service>.<namespace>`), not the Keycloak realm URL.

**Fix:** Fetch JWKS from kagent controller's `/jwks.json` endpoint (port-forward `svc/kagent` port 8083), embed inline in the policy, set `issuer: kagent.kagent`.

`setup.sh` does this and writes the result to `access-policy.yaml`.

## Issue 3 — `Groups` claim missing from OBO token

**Symptom:** With right keys, admin still got `403 authorization failed`. CEL `jwt.Groups.exists(g, g == "admins")` evaluated false for everyone.

**Cause:** kagent doesn't propagate OIDC claims into the OBO token by default. Decoding the OBO token showed only `sub`, `iss`, `aud`, `exp` — no `Groups`.

**Fix:** kagent helm values:

```yaml
oidc:
  oboClaimsToPropagate:
    - Groups
```

Then restart `kagent-controller` so the propagation list is reloaded.

## Prerequisite — No Istio ambient mesh

**Symptom:** AccessPolicy created in UI. Nothing happened. No EnterpriseAgentgatewayPolicy ever generated.

**Cause:** AccessPolicy controller logged `Required CRDs not found, skipping AccessPolicyController setup` and exited early. It needs `AuthorizationPolicy.security.istio.io` (Istio's CRD) because it generates one alongside the AGW policy.

**Fix:** Install Istio ambient (base + istiod + cni + ztunnel) before kagent.

## Prerequisite — `kagent.solo.io/waypoint` label missing

**Symptom:** No waypoint Gateway provisioned for the agent. No target for the policy to attach to.

**Cause:** kagent only provisions a waypoint when the Agent CR carries `kagent.solo.io/waypoint: "true"` (label, not annotation; value `"true"`, not the waypoint name).

**Fix:** `setup.sh` puts the label on `security-auditor`. Other agents stay un-waypointed (no policy can target them — by design).

## Prerequisite — Cluster identity mismatch

**Symptom:** Waypoint pod ran initially, then started failing cert renewal:
```
client claims to be in cluster "kagent-security", but we only know about local cluster "Kubernetes"
```
Once cert expired, all enforcement died.

**Cause:** AGW waypoint defaulted its cluster ID to `kagent-security` (the k3d cluster name), but istiod's local cluster is `Kubernetes` (Istio default). SPIFFE identity mismatched, istiod refused to issue a new cert.

**Fix:** Create `AgentgatewayParameters` with `CLUSTER_ID=Kubernetes`, then patch `enterprise-agentgateway-waypoint` GatewayClass with `parametersRef` pointing at it.

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayParameters
metadata:
  name: agentgateway-waypoint-params
  namespace: agentgateway-system
spec:
  env:
    - {name: CLUSTER_ID, value: "Kubernetes"}
    - {name: NETWORK, value: ""}
```

## How to verify each layer is alive

| Layer | Command | What "good" looks like |
|---|---|---|
| Istio ambient | `kubectl get pods -n istio-system` | `istiod`, `istio-cni`, `ztunnel` all Running |
| AccessPolicy controller | `kubectl logs -n kagent deploy/kagent-controller \| grep -i accesspolicy` | No "skipping" messages |
| Waypoint provisioning | `kubectl get gateway -n demo` | `agent-security-auditor-waypoint` exists |
| Waypoint pod | `kubectl get pods -n demo -l gateway.networking.k8s.io/gateway-name=agent-security-auditor-waypoint` | Running |
| Cert renewal | `kubectl logs -n demo <waypoint-pod>` | `Successfully fetched certificate for identity: spiffe://...` |
| OBO claims propagation | `kubectl get deploy -n kagent kagent-controller -o yaml \| grep OBO_CLAIMS` | Contains `Groups` |
| Policy attached | `kubectl get enterpriseagentgatewaypolicy -n demo -o yaml` | `status.ancestors[].conditions[type=Attached].status=True` |
| End-to-end | Chat as reader with `security-auditor` in UI | `403 authorization failed` |
