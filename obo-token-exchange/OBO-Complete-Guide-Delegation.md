# OBO Walkthrough: Delegation (On-Behalf-Of) via STS with Keycloak and Solo Enterprise for Agentgateway 2.1.x

This guide runs the **delegation** flow: the STS issues an OBO token that includes both the user (`sub`) and the actor (`act`). The subject token must contain a `may_act` claim authorizing the actor. We use Keycloak’s built-in **hardcoded-claim** protocol mapper to add `may_act` to the access token (no custom Keycloak image required).

### Delegation flow in brief

1. **User** authenticates with Keycloak and receives a **user JWT** that includes a `may_act` claim (authorizing a specific actor).
2. Your app or agent calls the **STS** with that user JWT as `subject_token` and a second token (e.g. Kubernetes service account) as `actor_token`.
3. The STS validates both tokens, checks that `may_act` authorizes the actor, and issues an **OBO token** with `sub` (user) and `act` (actor).
4. Downstream services can use the OBO token and rely on both `sub` and `act` for authz and audit.

---

## Prerequisites

- Kubernetes cluster, **kubectl**, **helm** (v3+), **jq**, **curl**
- **Solo Enterprise license:** Set `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`.
- Run all steps in the same shell so variables persist.

---

## Step 1: Deploy Keycloak and create realm, client, and user

### 1.1 Install Keycloak

```bash
kubectl create namespace keycloak 2>/dev/null || true

kubectl apply -n keycloak -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: keycloak
  labels:
    app: keycloak
spec:
  ports:
  - port: 8080
    targetPort: http
    name: http
  selector:
    app: keycloak
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak-discovery
  namespace: keycloak
  labels:
    app: keycloak
spec:
  selector:
    app: keycloak
  clusterIP: None
  type: ClusterIP
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: keycloak
  namespace: keycloak
  labels:
    app: keycloak
spec:
  serviceName: keycloak-discovery
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:26.5.2
        args: ["start"]
        env:
        - name: KC_BOOTSTRAP_ADMIN_USERNAME
          value: "admin"
        - name: KC_BOOTSTRAP_ADMIN_PASSWORD
          value: "admin"
        - name: KC_PROXY_HEADERS
          value: "xforwarded"
        - name: KC_HTTP_ENABLED
          value: "true"
        - name: KC_HOSTNAME_STRICT
          value: "false"
        - name: KC_HEALTH_ENABLED
          value: "true"
        - name: KC_DB_URL_DATABASE
          value: "keycloak"
        - name: KC_DB_URL_HOST
          value: "postgres"
        - name: KC_DB
          value: "postgres"
        - name: KC_DB_PASSWORD
          value: "keycloak"
        - name: KC_DB_USERNAME
          value: "keycloak"
        ports:
        - name: http
          containerPort: 8080
        startupProbe:
          httpGet:
            path: /health/started
            port: 9000
          periodSeconds: 5
          failureThreshold: 60
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 9000
          periodSeconds: 10
          failureThreshold: 3
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: keycloak
  labels:
    app: postgres
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_USER
          value: "keycloak"
        - name: POSTGRES_PASSWORD
          value: "keycloak"
        - name: POSTGRES_DB
          value: "keycloak"
        ports:
        - name: postgres
          containerPort: 5432
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-data
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: keycloak
  labels:
    app: postgres
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
EOF
kubectl wait -n keycloak statefulset/keycloak --for=condition=Ready --timeout=300s
```

### 1.2 Port-forward Keycloak and create realm, client, user

```bash
pkill -f "port-forward.*keycloak.*8080" 2>/dev/null || true
sleep 1
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &
sleep 3
export KEYCLOAK_URL="http://localhost:8080"
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token')
curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"realm":"obo-realm","enabled":true}'

curl -s -X POST "${KEYCLOAK_URL}/admin/realms/obo-realm/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "agw-client",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "secret": "agw-client-secret",
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": false
  }'

curl -s -X POST "${KEYCLOAK_URL}/admin/realms/obo-realm/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "testuser@example.com",
    "emailVerified": true,
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "requiredActions": [],
    "credentials": [{"type": "password", "value": "testuser", "temporary": false}]
  }'
export KEYCLOAK_JWKS_URL="http://keycloak.keycloak.svc.cluster.local:8080/realms/obo-realm/protocol/openid-connect/certs"
```

---

## Step 2: Deploy Solo Enterprise for Agentgateway 2.1.x (with OBO token exchange)

### 2.1 Gateway API CRDs and install (token exchange enabled)

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml
echo "KEYCLOAK_JWKS_URL=${KEYCLOAK_JWKS_URL:?Run step 1.2 first}"
echo "${AGENTGATEWAY_LICENSE_KEY:?Set AGENTGATEWAY_LICENSE_KEY before running}"
helm upgrade -i --create-namespace --namespace kgateway-system \
  --version 2.1.1 enterprise-agentgateway-crds oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds
helm upgrade -i -n kgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version 2.1.1 --set-string licensing.licenseKey=$AGENTGATEWAY_LICENSE_KEY \
  --set tokenExchange.enabled=true \
  --set tokenExchange.issuer="enterprise-agentgateway.kgateway-system.svc.cluster.local:7777" \
  --set tokenExchange.tokenExpiration=24h \
  --set tokenExchange.subjectValidator.validatorType=remote \
  --set tokenExchange.subjectValidator.remoteConfig.url="$KEYCLOAK_JWKS_URL" \
  --set tokenExchange.actorValidator.validatorType=k8s \
  --set controller.logLevel=debug
```

### 2.2 Create Gateway (data plane)

```bash
kubectl apply -f - <<EOF
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: agentgateway-debug
  namespace: kgateway-system
spec:
  logging:
    level: debug
    format: text
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway
  namespace: kgateway-system
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: agentgateway-debug
  listeners:
  - name: http
    port: 80
    protocol: HTTP
EOF
kubectl get pods,gateway,svc -n kgateway-system
```

---

## Step 3: Delegation — exchange for OBO token with actor

### 3.1 Port-forward the STS

```bash
pkill -f "port-forward.*7777" 2>/dev/null || true
sleep 1
kubectl port-forward -n kgateway-system svc/enterprise-agentgateway 7777:7777 &
sleep 2
export STS_URL="http://localhost:7777"
```

### 3.2 Get actor token and decode for may_act

Requires **Kubernetes 1.24+** for `kubectl create token`. We decode the actor token so Keycloak can add a `may_act` claim that authorizes this actor.

```bash
kubectl create serviceaccount sts-exchange-client -n kgateway-system 2>/dev/null || true
export ACTOR_TOKEN=$(kubectl create token sts-exchange-client -n kgateway-system --duration=3600s)
_pl=$(echo "$ACTOR_TOKEN" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_pl} % 4)) -ne 0 ]; do _pl="${_pl}="; done; _pl=$(echo "$_pl" | base64 -d 2>/dev/null)
export MAY_ACT_SUB=$(echo "$_pl" | jq -r '.sub')
export MAY_ACT_ISS=$(echo "$_pl" | jq -r '.iss')
```

### 3.3 Add may_act to the subject token

Add a Keycloak hardcoded-claim mapper so the user token includes `may_act` (actor identity), then fetch a fresh user JWT.

```bash
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=admin" -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token')
CLIENT_UUID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/obo-realm/clients?clientId=agw-client" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id')
MAY_ACT_JSON=$(jq -nc --arg sub "$MAY_ACT_SUB" --arg iss "$MAY_ACT_ISS" '{sub: $sub, iss: $iss}')
MAPPER_JSON=$(jq -n \
  --arg claim_name "may_act" \
  --arg claim_value "$MAY_ACT_JSON" \
  '{
    name: "may-act",
    protocol: "openid-connect",
    protocolMapper: "oidc-hardcoded-claim-mapper",
    config: {
      "claim.name": $claim_name,
      "claim.value": $claim_value,
      "jsonType.label": "JSON",
      "access.token.claim": "true",
      "id.token.claim": "false"
    }
  }')
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/obo-realm/clients/${CLIENT_UUID}/protocol-mappers/models" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" -d "$MAPPER_JSON"
export USER_JWT=$(curl -s -X POST "${KEYCLOAK_URL}/realms/obo-realm/protocol/openid-connect/token" \
  -d "username=testuser" -d "password=testuser" -d "grant_type=password" \
  -d "client_id=agw-client" -d "client_secret=agw-client-secret" | jq -r '.access_token')
```

### 3.4 Call the STS (delegation)

Send both `subject_token` (user JWT with `may_act`) and `actor_token` (Kubernetes SA token). The STS returns an OBO token with `sub` and `act`.

```bash
export STS_RESPONSE=$(curl -s -X POST "${STS_URL}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer ${USER_JWT}" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${USER_JWT}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "actor_token=${ACTOR_TOKEN}" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:jwt")
echo "$STS_RESPONSE" | jq '.' 2>/dev/null || echo "$STS_RESPONSE"
```

### 3.5 Decode the OBO token (optional)

```bash
export OBO_JWT=$(echo "$STS_RESPONSE" | jq -r '.access_token // empty')
seg=$(echo "$OBO_JWT" | cut -d'.' -f2 | tr '_-' '/+'); while [ $((${#seg} % 4)) -ne 0 ]; do seg="${seg}="; done; echo "$seg" | base64 -d 2>/dev/null | jq '.'
```

---

## Cleanup

```bash
pkill -f "port-forward.*keycloak" 2>/dev/null || true
pkill -f "port-forward.*kgateway-system" 2>/dev/null || true
pkill -f "port-forward.*7777" 2>/dev/null || true
sleep 1
kubectl delete gateway agentgateway -n kgateway-system
kubectl delete enterpriseagentgatewayparameters agentgateway-debug -n kgateway-system 2>/dev/null || true
helm uninstall enterprise-agentgateway -n kgateway-system
helm uninstall enterprise-agentgateway-crds -n kgateway-system
kubectl delete namespace kgateway-system
kubectl delete namespace keycloak
```

