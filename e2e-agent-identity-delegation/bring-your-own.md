# Bring your own components

Every piece of this lab is optional if you already run it. This is what to skip
and what to adjust for each one. Read it before Step 1 if you are running
against an existing cluster rather than a fresh KinD one.

Each piece is optional if you already run it. Everything the lab creates is confined to its own namespaces (`e2e-demo`, `keycloak`, `wp-a`, `kagent`, `agentregistry-system`) and its own Gateways `e2e-gw` and `agentregistry-gateway`. Existing gateways, routes, and policies are not touched.

| You already have | Skip | Adjust |
|---|---|---|
| Kubernetes cluster | `00-kind.sh` | Point `kubectl` at your cluster and run `00-platform.sh`. The lab requires no StorageClass and no LoadBalancer, since the gateways are reached by Service DNS. An internal LoadBalancer is still a fine addition if you want to reach them from outside the cluster. |
| Enterprise Agentgateway | Step 1, but still `kubectl apply -f 00-client.yaml` (the client's SA is the actor identity) | The chart names the controller Service `enterprise-agentgateway` regardless of release name, so only a different namespace changes the STS address. Update it in `05-sts-values.yaml` (`issuer`), `05-api-authz.yaml` and `05-mcp-api-authz.yaml` (provider `issuer` and JWKS `backendRef` namespace), and Step 12's exchange URL, and export it as `AGW_NAMESPACE` for `01-ui.sh` and `10-kagent-install.sh`. Step 12's `helm upgrade` restarts your controller and must target your release name and namespace; the release must be a version with `tokenExchange` (validated on v2026.9.0). If your GatewayClass is not named `enterprise-agentgateway`, change it in `05-gateway.yaml` and `04-registry-gateway.yaml`. |
| Keycloak | `00-keycloak.yaml` | Import `realm/workshop-additions.json` into your `agentregistry` realm (Step 2 shows the partial import). Then set the issuer in `01-ui.sh`, `03-registry-values.yaml`, the `05-*` policies, and `05-sts-values.yaml` to your Keycloak URL. A realm built from the Agentregistry Enterprise docs already carries the `Groups` claim these policies use. |
| Agentregistry Enterprise | `03-registry-install.sh` | Export `ARCTL_API_BASE_URL` and `KEYCLOAK_URL` before sourcing `03-registry-env.sh`. Steps 6 to 8 then run against your registry. For Step 7 the label on `04-registry-gateway.yaml` must match a Virtual runtime in your registry. |
| A real agent workload | The httpbin stand-in in `02-workloads.yaml` | Route to it and use its ServiceAccount as the `may_act` subject and in Step 13's `jwt.act.sub`. |
| Solo UI (management chart) | `01-ui.sh` | Export `MGMT_RELEASE` and `MGMT_NAMESPACE` for Step 16, set the tracing `backendRef.namespace` in `05-gateway.yaml`, and enable `products.agentgateway` on the release if it is not already. Validated only with the lab's own release in namespace `kagent`; upgrading a release in another namespace with the kagent product has not been run here. |
| Solo Enterprise for kagent | `10-kagent-install.sh` | Run `10-register-kagent-runtime.sh` with `KAGENT_URL` pointing at your controller and `AGENTREGISTRY_CLIENT_SECRET` set to your client secret. |
| Istio or ambient mesh | Nothing | The lab's namespaces are not mesh-enrolled and do not need to be. |
