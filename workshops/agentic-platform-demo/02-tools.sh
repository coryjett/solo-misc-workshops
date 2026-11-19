#!/usr/bin/env bash
# Builds the demo tool servers and runs them in $TOOLS_NS: MCP servers (records = customer PII, inventory,
# workiq and github stand-ins), three A2A agents, and one plain REST API (ops-api) that the gateway exposes as MCP tools from its OpenAPI spec.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"; K="kubectl --context $KCTX"
docker build -q -t "$TOOLS_IMAGE" "$DIR/tools" >/dev/null
kind load docker-image "$TOOLS_IMAGE" --name "$CLUSTER" >/dev/null
$K create namespace "$TOOLS_NS" --dry-run=client -o yaml | $K apply -f - >/dev/null
for svc in records-mcp:records.py inventory-mcp:inventory.py ops-api:ops_api.py workiq-mcp:workiq.py github-mcp:github_mock.py; do
  name="${svc%%:*}"; file="${svc#*:}"
  if [ "$name" = ops-api ]; then cmd='["uvicorn","ops_api:app","--host","0.0.0.0","--port","8000"]'; proto=http
  else cmd="[\"python\",\"$file\"]"; proto=agentgateway.dev/mcp; fi
  cat <<YAML | $K apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: { name: ${name}, namespace: ${TOOLS_NS}, labels: { app: ${name} } }
spec:
  replicas: 1
  selector: { matchLabels: { app: ${name} } }
  template:
    metadata: { labels: { app: ${name} } }
    spec:
      containers:
        - name: ${name}
          image: ${TOOLS_IMAGE}
          imagePullPolicy: Never
          command: ${cmd}
          env: [ { name: TOOLS_NS, value: "${TOOLS_NS}" } ]
          ports: [ { containerPort: 8000, name: http } ]
          readinessProbe: { tcpSocket: { port: 8000 }, periodSeconds: 3 }
---
apiVersion: v1
kind: Service
metadata: { name: ${name}, namespace: ${TOOLS_NS}, labels: { app: ${name} } }
spec:
  selector: { app: ${name} }
  ports: [ { name: http, port: 8000, targetPort: 8000, appProtocol: ${proto} } ]
YAML
done
# A2A agents: agent-a (users reach it) delegates to agent-b and agent-c through the gateway with its own
# client-credentials identity; agent-b also tries agent-c so the gateway refusal shows live.
GW_IN=http://mcp-gateway.agentgateway-system.svc.cluster.local:8080
for agent in agent-a agent-b agent-c; do
  case "$agent" in
    agent-a) desc="Coordinator: the only agent users can reach; delegates to agent-b and agent-c"; peers="agent-b=$GW_IN/a2a/agent-b,agent-c=$GW_IN/a2a/agent-c";;
    agent-b) desc="Data specialist"; peers="agent-c=$GW_IN/a2a/agent-c";;
    agent-c) desc="Policy checker"; peers="";;
  esac
  cat <<YAML | $K apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: { name: ${agent}, namespace: ${TOOLS_NS}, labels: { app: ${agent} } }
spec:
  replicas: 1
  selector: { matchLabels: { app: ${agent} } }
  template:
    metadata: { labels: { app: ${agent} } }
    spec:
      containers:
        - name: ${agent}
          image: ${TOOLS_IMAGE}
          imagePullPolicy: Never
          command: ["python","-u","a2a_agent.py"]
          env:
            - { name: AGENT_NAME, value: "${agent}" }
            - { name: AGENT_DESC, value: "${desc}" }
            - { name: PUBLIC_URL, value: "${GW_URL}/a2a/${agent}/" }
            - { name: TOKEN_URL, value: "http://keycloak.keycloak.svc.cluster.local:8080/realms/${KC_REALM}/protocol/openid-connect/token" }
            - { name: CLIENT_ID, value: "${agent}" }
            - { name: CLIENT_SECRET, value: "${agent}-demo-secret-not-for-prod" }
            - { name: PEERS, value: "${peers}" }
          ports: [ { containerPort: 8000, name: http } ]
          readinessProbe: { httpGet: { path: /healthz, port: 8000 }, periodSeconds: 3 }
---
apiVersion: v1
kind: Service
metadata: { name: ${agent}, namespace: ${TOOLS_NS}, labels: { app: ${agent} } }
spec:
  selector: { app: ${agent} }
  ports: [ { name: http, port: 8000, targetPort: 8000, appProtocol: agentgateway.dev/a2a } ]
YAML
done
$K -n "$TOOLS_NS" rollout status deploy --timeout=180s >/dev/null
# OpenAPI spec for the gateway's OpenAPI-to-MCP target, taken from the running API (3.0.x for the gateway).
SPEC="$($K -n "$TOOLS_NS" exec deploy/ops-api -- python -c 'import json,urllib.request;d=json.load(urllib.request.urlopen("http://localhost:8000/openapi.json"));d["openapi"]="3.0.3";print(json.dumps(d))')"
$K create namespace agentgateway-system --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n agentgateway-system create configmap opsapi-openapi --from-literal=schema="$SPEC" --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n "$TOOLS_NS" get pods
echo TOOLS-READY
