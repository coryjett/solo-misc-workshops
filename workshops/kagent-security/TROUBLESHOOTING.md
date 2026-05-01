# Troubleshooting — Why UI-created AccessPolicies didn't enforce

This is the debug history that drove the final shape of `setup.sh`. Future-you will hit some subset of these. Each issue silently disabled the chain at a different layer.

> **TL;DR for the UI flow.** Two translation bugs used to make UI-created AccessPolicies no-op:
> - **Issue 1** (HTTPRoute target) — fixed by AGW `v2.4.0-beta.0` (auto-attaches now). `setup.sh` pins this version.
> - **Issue 1b** (string-eq CEL on array claim) — worked around by emitting a string `role` claim from Keycloak and targeting `claimName: role` in the AccessPolicy instead of the array `Groups` claim. `setup.sh` configures the realm to ship `role`.
>
> Result: create the AccessPolicy in the UI, hit Save, it enforces. No patcher, no activate script.

## The chain

```
UI → AccessPolicy CRD
     → AccessPolicy controller (in kagent-controller)
        → translates to EnterpriseAgentgatewayPolicy + Istio AuthorizationPolicy
           → AGW controller attaches to Gateway
              → waypoint pod enforces JWT + CEL on every request
```

Any of these layers can no-op without a clear error.

## Issue 1 — Translation targeted HTTPRoute instead of Gateway *(fixed in AGW v2.4.0-beta.0)*

**Symptom:** AccessPolicy created. EnterpriseAgentgatewayPolicy auto-generated. Status: `Attached: False`. Requests went through unfiltered.

**Cause:** kagent-enterprise's waypoint translator (`waypoint_translator_plugin.go`) generates the agent's HTTPRoute with **Service** parentRefs only. The AccessPolicy translator then generates an `EnterpriseAgentgatewayPolicy` targeting that HTTPRoute. AGW's policy attachment logic in v2.3.x looked for the HTTPRoute's *Gateway* parentRefs to decide which Gateway to attach to — saw none → `Attached: False`.

**Fix:** AGW `v2.4.0-beta.0` recognizes service-bound HTTPRoute attachment. `setup.sh` pins this version (`AGW_VERSION=v2.4.0-beta.0`). EAPs auto-generated from AccessPolicies now reach `Attached: True` on their own.

## Issue 1b — Auto-generated CEL is string-equality on an array claim *(worked around)*

**Symptom:** Even with the EAP attached, every user — including admin — got `403 authorization failed`.

**Cause:** kagent-enterprise translates a `UserGroup` subject to CEL `jwt.<ClaimName> == "<ClaimValue>"` (see `access_policy_translation.go:479`, `makeCELExpressionForSubject`). The standard OIDC `Groups` claim is an **array** (`["admins"]`), not a string. `["admins"] == "admins"` is always false → 403 for everyone.

**Workaround:** Use a string-valued claim instead of `Groups`. `setup.sh` configures the Keycloak realm to add a single-valued `role` user attribute (`admin` / `writer` / `reader`) and a `oidc-usermodel-attribute-mapper` that emits it as a string claim. The AccessPolicy targets `claimName: role, claimValue: admin`, which produces CEL `jwt.role == "admin"` — that one matches.

`oboClaimsToPropagate` in the kagent helm values now includes both `Groups` and `role`, so the `role` claim survives into the OBO token kagent mints.

**Real fix:** kagent-enterprise should emit array-aware CEL (`jwt.<claim>.exists(g, g == "<value>")`) when the source claim is array-typed. Two-line change in `access_policy_translation.go`. Not yet upstreamed.

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
