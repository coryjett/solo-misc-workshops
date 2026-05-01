# Troubleshooting — Why UI-created AccessPolicies didn't enforce

This is the debug history that drove the final shape of `setup.sh`. Future-you will hit some subset of these. Each issue silently disabled the chain at a different layer.

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

**Cause:** The auto-generated EnterpriseAgentgatewayPolicy targeted an HTTPRoute whose `parentRefs` pointed at Services, not Gateways. The AGW controller only recognizes Gateway parentRefs as valid attachment targets.

**Fix:** Manually create an `EnterpriseAgentgatewayPolicy` with `targetRefs` pointing directly at the auto-provisioned waypoint Gateway (`agent-security-auditor-waypoint`).

```yaml
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: agent-security-auditor-waypoint
```

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
