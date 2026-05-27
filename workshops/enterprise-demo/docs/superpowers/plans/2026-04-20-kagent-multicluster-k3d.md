# Kagent Enterprise Multicluster k3d Setup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy kagent enterprise in multicluster mode on two local k3d clusters and verify telemetry OTLP configuration.

**Architecture:** Two k3d clusters — `kagent-mgmt` (management plane with ClickHouse, telemetry collector, UI) and `kagent-relay` (workload plane with relay collector forwarding to management). AutoAuth enabled (no external OIDC). Telemetry flows: apps → local collector → (relay forwards via OTLP :4316) → management collector → ClickHouse.

**Tech Stack:** k3d, Helm 4, kagent-enterprise 0.3.13, OCI Helm charts from `us-docker.pkg.dev/solo-public`

**Environment variables used throughout:**
```bash
export MGMT_CLUSTER=kagent-mgmt
export MGMT_CONTEXT=k3d-kagent-mgmt
export REMOTE_CLUSTER=kagent-relay
export REMOTE_CONTEXT=k3d-kagent-relay
export KAGENT_LICENSE_KEY="REDACTED-SOLO-LICENSE-KEY"
export OPENAI_API_KEY="${OPENAI_API_KEY}"
export KAGENT_ENT_VERSION=0.3.13
```

---

### Task 1: Tear down existing k3d cluster and create two new clusters

**Files:**
- No files created

- [ ] **Step 1: Delete existing k3d-agentgateway cluster**

```bash
k3d cluster delete agentgateway
```

Expected: `INFO[0000] Deleting cluster 'agentgateway'`

- [ ] **Step 2: Create management cluster**

```bash
k3d cluster create kagent-mgmt \
  --agents 1 \
  --k3s-arg "--disable=traefik@server:0" \
  --port "8443:443@loadbalancer" \
  --port "8080:80@loadbalancer" \
  --wait
```

Expected: `INFO[0000] Cluster 'kagent-mgmt' created successfully`

- [ ] **Step 3: Create relay/workload cluster**

```bash
k3d cluster create kagent-relay \
  --agents 1 \
  --k3s-arg "--disable=traefik@server:0" \
  --port "9443:443@loadbalancer" \
  --port "9080:80@loadbalancer" \
  --wait
```

Expected: `INFO[0000] Cluster 'kagent-relay' created successfully`

- [ ] **Step 4: Verify both clusters and contexts**

```bash
k3d cluster list
kubectl config get-contexts | grep kagent
kubectl get nodes --context k3d-kagent-mgmt
kubectl get nodes --context k3d-kagent-relay
```

Expected: Both clusters running, 2 nodes each (1 server + 1 agent).

---

### Task 2: Set environment variables

- [ ] **Step 1: Export all required variables**

```bash
export MGMT_CLUSTER=kagent-mgmt
export MGMT_CONTEXT=k3d-kagent-mgmt
export REMOTE_CLUSTER=kagent-relay
export REMOTE_CONTEXT=k3d-kagent-relay
export KAGENT_LICENSE_KEY="REDACTED-SOLO-LICENSE-KEY"
export KAGENT_ENT_VERSION=0.3.13
```

- [ ] **Step 2: Verify OPENAI_API_KEY is set**

```bash
echo "OPENAI_API_KEY: ${OPENAI_API_KEY:+SET}"
```

Expected: `OPENAI_API_KEY: SET`

---

### Task 3: Deploy management platform chart

**Files:**
- Create: `/tmp/kagent-mgmt-values.yaml`

- [ ] **Step 1: Create management values file**

```bash
cat > /tmp/kagent-mgmt-values.yaml <<'EOF'
cluster: kagent-mgmt

products:
  kagent:
    enabled: true

licensing:
  licenseKey: "${KAGENT_LICENSE_KEY}"

# AutoAuth — no external OIDC needed
oidc:
  issuer: ""

telemetry:
  traces:
    enabled: true
  metrics:
    enabled: true
  selfMonitoring:
    enabled: true
EOF
```

- [ ] **Step 2: Install management chart**

```bash
helm upgrade -i kagent-mgmt \
  oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/management \
  --kube-context ${MGMT_CONTEXT} \
  -n kagent --create-namespace \
  --version ${KAGENT_ENT_VERSION} \
  --values /tmp/kagent-mgmt-values.yaml \
  --set licensing.licenseKey="${KAGENT_LICENSE_KEY}"
```

- [ ] **Step 3: Wait for pods to come up**

```bash
kubectl get pods -n kagent --context ${MGMT_CONTEXT} -w
```

Expected: ClickHouse, telemetry-collector, solo-enterprise-ui pods running. May take 2-3 minutes.

- [ ] **Step 4: Verify telemetry collector ConfigMap has correct exporters**

```bash
kubectl get cm solo-enterprise-telemetry-collector-config -n kagent \
  --context ${MGMT_CONTEXT} -o yaml | grep -A5 "exporters:"
```

Expected: `clickhouse/telemetry`, `clickhouse/metrics`, `clickhouse/k8sobjects` — NO `otlp` exporter.

- [ ] **Step 5: Verify collector receives on :4317 and :4316**

```bash
kubectl get cm solo-enterprise-telemetry-collector-config -n kagent \
  --context ${MGMT_CONTEXT} -o yaml | grep "endpoint: 0.0.0.0:43"
```

Expected:
```
endpoint: 0.0.0.0:4316   (otlp/remote)
endpoint: 0.0.0.0:4317   (otlp/local)
```

- [ ] **Step 6: Verify telemetry gateway service exists**

```bash
kubectl get svc -n kagent --context ${MGMT_CONTEXT} | grep -E "telemetry|solo-enterprise-ui"
```

Expected: `solo-enterprise-ui` service with LoadBalancer (or ClusterIP on k3d) exposing ports including 4316 and 4317.

---

### Task 4: Create JWT secret and install kagent-enterprise on management cluster

- [ ] **Step 1: Generate JWT signing key**

```bash
openssl genrsa -out /tmp/key.pem 2048
kubectl create secret generic jwt -n kagent --context ${MGMT_CONTEXT} \
  --from-file=jwt=/tmp/key.pem --dry-run=client -o yaml | \
  kubectl apply --context ${MGMT_CONTEXT} -f -
```

Expected: `secret/jwt created`

- [ ] **Step 2: Create kagent values file for management**

```bash
cat > /tmp/kagent-mgmt-kagent.yaml <<EOF
licensing:
  licenseKey: "${KAGENT_LICENSE_KEY}"
providers:
  default: openAI
  openAI:
    apiKey: "${OPENAI_API_KEY}"
otel:
  tracing:
    enabled: true
    exporter:
      otlp:
        endpoint: "solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317"
        insecure: true
EOF
```

- [ ] **Step 3: Install kagent CRDs**

```bash
helm upgrade -i kagent-crds \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise-crds \
  --kube-context ${MGMT_CONTEXT} \
  -n kagent \
  --version 0.3.13
```

- [ ] **Step 4: Install kagent-enterprise**

```bash
helm upgrade -i kagent \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise \
  --kube-context ${MGMT_CONTEXT} \
  -n kagent \
  --version 0.3.13 \
  --values /tmp/kagent-mgmt-kagent.yaml
```

- [ ] **Step 5: Verify kagent controller pod is running**

```bash
kubectl get pods -n kagent --context ${MGMT_CONTEXT} | grep kagent
```

- [ ] **Step 6: Verify otel.tracing endpoint on kagent controller**

```bash
kubectl get deploy -n kagent --context ${MGMT_CONTEXT} -o yaml | grep -A2 "OTEL"
```

Expected: env var `OTEL_EXPORTER_OTLP_ENDPOINT` = `solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317`

---

### Task 5: Get tunnel address and register remote cluster

- [ ] **Step 1: Get management LB address**

For k3d, the LoadBalancer may not get an external IP. Check:

```bash
kubectl get svc -n kagent solo-enterprise-ui --context ${MGMT_CONTEXT} \
  -o jsonpath="{.status.loadBalancer.ingress[0]['hostname','ip']}"
```

If empty (k3d doesn't provision LB IPs by default), use the ClusterIP or the k3d host network approach:

```bash
# Fallback: get ClusterIP
export TUNNEL_ADDRESS=$(kubectl get svc -n kagent solo-enterprise-ui \
  --context ${MGMT_CONTEXT} -o jsonpath="{.spec.clusterIP}")
echo "TUNNEL_ADDRESS: ${TUNNEL_ADDRESS}"
```

**Note:** For k3d cross-cluster communication, clusters need to share a Docker network. If they don't, create them on the same network or use `k3d-kagent-mgmt-serverlb` container IP visible from the relay cluster's Docker network.

- [ ] **Step 2: Connect k3d clusters on same Docker network (if needed)**

```bash
# Check if clusters share a network
docker network ls | grep k3d

# Connect relay cluster nodes to mgmt network (if separate)
docker network connect k3d-kagent-mgmt k3d-kagent-relay-server-0
docker network connect k3d-kagent-mgmt k3d-kagent-relay-agent-0
```

Then get the management service IP accessible from relay:

```bash
export TUNNEL_ADDRESS=$(kubectl get svc -n kagent solo-enterprise-ui \
  --context ${MGMT_CONTEXT} -o jsonpath="{.spec.clusterIP}")
```

- [ ] **Step 3: Register remote cluster on management**

```bash
kubectl apply --context ${MGMT_CONTEXT} -f- <<EOF
apiVersion: kagent-enterprise.solo.io/v1alpha1
kind: KubernetesCluster
metadata:
  name: ${REMOTE_CLUSTER}
  namespace: kagent
EOF
```

Expected: `kubernetescluster.kagent-enterprise.solo.io/kagent-relay created`

---

### Task 6: Deploy relay chart on workload cluster

- [ ] **Step 1: Install relay chart**

```bash
helm upgrade -i kagent-relay \
  oci://us-docker.pkg.dev/solo-public/solo-enterprise-helm/charts/relay \
  --kube-context ${REMOTE_CONTEXT} \
  -n kagent --create-namespace \
  --version ${KAGENT_ENT_VERSION} \
  --set cluster=${REMOTE_CLUSTER} \
  --set tunnel.fqdn=${TUNNEL_ADDRESS} \
  --set telemetry.fqdn=${TUNNEL_ADDRESS}
```

- [ ] **Step 2: Verify relay pods**

```bash
kubectl get pods -n kagent --context ${REMOTE_CONTEXT}
```

Expected: relay telemetry-collector pod(s) running.

- [ ] **Step 3: Verify relay collector OTLP exporter has correct endpoint**

```bash
kubectl get cm solo-enterprise-telemetry-collector-config -n kagent \
  --context ${REMOTE_CONTEXT} -o yaml | grep -A5 "otlp:"
```

Expected:
```yaml
otlp:
  endpoint: <TUNNEL_ADDRESS>:4316
  tls:
    insecure: true
```

NOT an empty endpoint.

- [ ] **Step 4: Verify telemetry.fqdn was set**

```bash
helm get values kagent-relay -n kagent --context ${REMOTE_CONTEXT} | grep -A3 telemetry
```

Expected:
```yaml
telemetry:
  fqdn: "<TUNNEL_ADDRESS>"
```

---

### Task 7: Install kagent-enterprise on workload cluster

- [ ] **Step 1: Create kagent workload values file**

```bash
cat > /tmp/kagent-relay-kagent.yaml <<EOF
licensing:
  licenseKey: "${KAGENT_LICENSE_KEY}"
providers:
  default: openAI
  openAI:
    apiKey: "${OPENAI_API_KEY}"
otel:
  tracing:
    enabled: true
    exporter:
      otlp:
        endpoint: "kagent-enterprise-relay.kagent.svc.cluster.local:4317"
        insecure: true
EOF
```

- [ ] **Step 2: Install kagent CRDs on relay**

```bash
helm upgrade -i kagent-crds \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise-crds \
  --kube-context ${REMOTE_CONTEXT} \
  -n kagent \
  --version 0.3.13
```

- [ ] **Step 3: Install kagent-enterprise on relay**

```bash
helm upgrade -i kagent \
  oci://us-docker.pkg.dev/solo-public/kagent-enterprise-helm/charts/kagent-enterprise \
  --kube-context ${REMOTE_CONTEXT} \
  -n kagent \
  --version 0.3.13 \
  --values /tmp/kagent-relay-kagent.yaml
```

- [ ] **Step 4: Verify kagent controller running on relay**

```bash
kubectl get pods -n kagent --context ${REMOTE_CONTEXT} | grep kagent
```

- [ ] **Step 5: Verify otel.tracing endpoint on relay kagent controller**

```bash
kubectl get deploy -n kagent --context ${REMOTE_CONTEXT} -o yaml | grep -A2 "OTEL"
```

Expected: `OTEL_EXPORTER_OTLP_ENDPOINT` = `kagent-enterprise-relay.kagent.svc.cluster.local:4317`

---

### Task 8: Verify end-to-end telemetry configuration

- [ ] **Step 1: Verify management collector — no "missing address" errors**

```bash
kubectl logs -l app=solo-enterprise-telemetry-collector -n kagent \
  --context ${MGMT_CONTEXT} --tail=50 | grep -i "error\|missing"
```

Expected: No "missing address" or "delegating_resolver" errors.

- [ ] **Step 2: Verify relay collector — no "missing address" errors**

```bash
kubectl logs -l app=solo-enterprise-telemetry-collector -n kagent \
  --context ${REMOTE_CONTEXT} --tail=50 2>/dev/null || \
kubectl logs -l app=kagent-enterprise-relay -n kagent \
  --context ${REMOTE_CONTEXT} --tail=50 | grep -i "error\|missing"
```

Expected: No "missing address" errors. May see connection errors if network not fully bridged.

- [ ] **Step 3: Verify relay can reach management telemetry gateway on :4316**

```bash
kubectl exec -n kagent --context ${REMOTE_CONTEXT} \
  $(kubectl get pod -n kagent --context ${REMOTE_CONTEXT} -l app=kagent-enterprise-relay -o jsonpath='{.items[0].metadata.name}' 2>/dev/null) \
  -- wget -qO- --timeout=3 http://${TUNNEL_ADDRESS}:4316 2>&1 || echo "connection test done"
```

Expected: Protocol error (gRPC endpoint, not HTTP) = good. Connection refused = bad.

- [ ] **Step 4: Summarize all OTLP endpoints**

```bash
echo "=== MANAGEMENT CLUSTER ==="
echo "--- Collector exporters (should be clickhouse only) ---"
kubectl get cm solo-enterprise-telemetry-collector-config -n kagent \
  --context ${MGMT_CONTEXT} -o yaml | grep "endpoint:"

echo ""
echo "--- Kagent controller otel.tracing ---"
kubectl get deploy -n kagent --context ${MGMT_CONTEXT} -o yaml | grep -B1 "OTEL_EXPORTER"

echo ""
echo "=== RELAY CLUSTER ==="
echo "--- Collector exporters (should be otlp to mgmt:4316) ---"
kubectl get cm solo-enterprise-telemetry-collector-config -n kagent \
  --context ${REMOTE_CONTEXT} -o yaml | grep "endpoint:"

echo ""
echo "--- Kagent controller otel.tracing ---"
kubectl get deploy -n kagent --context ${REMOTE_CONTEXT} -o yaml | grep -B1 "OTEL_EXPORTER"
```

Expected summary:

| Component | Cluster | Endpoint |
|---|---|---|
| Management collector exporters | mgmt | `tcp://<clickhouse>:9000` (ClickHouse) |
| Management collector receivers | mgmt | `0.0.0.0:4317` (local), `0.0.0.0:4316` (remote) |
| Management kagent controller | mgmt | `solo-enterprise-telemetry-collector.kagent.svc.cluster.local:4317` |
| Relay collector exporter | relay | `<TUNNEL_ADDRESS>:4316` (OTLP to mgmt) |
| Relay collector receiver | relay | `0.0.0.0:4317` (local) |
| Relay kagent controller | relay | `kagent-enterprise-relay.kagent.svc.cluster.local:4317` |

- [ ] **Step 5: Check ClickHouse for incoming data (if traces are flowing)**

```bash
kubectl exec -n kagent --context ${MGMT_CONTEXT} \
  $(kubectl get pod -n kagent --context ${MGMT_CONTEXT} -l app=clickhouse -o jsonpath='{.items[0].metadata.name}') \
  -- clickhouse-client --query "SELECT count() FROM platformdb.otel_traces_json"
```

Expected: Some number >= 0. If > 0, traces are flowing.
