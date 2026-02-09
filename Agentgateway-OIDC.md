# Configure Keycloak as OIDC Identity Provider for Enterprise Agentgateway

## Pre-requisites

- Kubernetes cluster, **kubectl**, **helm** (v3+), **jq**, **curl**
- **Solo Enterprise license:** Set `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`.
- Run all steps in the same shell so variables persist.

---

## Step 1: Deploy Keycloak and PostgreSQL

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
kubectl wait -n keycloak statefulset/keycloak --for=condition=Ready --timeout=420s
```

---

## Step 2: Install Enterprise Agentgateway

### Gateway API CRDs

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml
```

### Install CRDs and control plane

```bash
echo "${AGENTGATEWAY_LICENSE_KEY:?Set AGENTGATEWAY_LICENSE_KEY before running}"
helm upgrade -i --create-namespace --namespace kgateway-system \
  --version 2.1.1 enterprise-agentgateway-crds oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds
helm upgrade -i -n kgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version 2.1.1 --set-string licensing.licenseKey=$AGENTGATEWAY_LICENSE_KEY
```

### Create Gateway (data plane)

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
```

### Verify

```bash
kubectl get pods,gateway,svc -n kgateway-system
```

---

## Step 3: Port-forward Keycloak and create realm, client, and user

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
  -d '{"realm":"oidc-realm","enabled":true}'

curl -s -X POST "${KEYCLOAK_URL}/admin/realms/oidc-realm/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "agentgateway-client",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "secret": "agentgateway-client-secret",
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": false
  }'

curl -s -X POST "${KEYCLOAK_URL}/admin/realms/oidc-realm/users" \
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
```

---

## Step 4: Deploy Gateway, HTTPRoute, and backend

```bash
kubectl create namespace default --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: echo-backend
  namespace: default
spec:
  ports:
  - port: 8080
    targetPort: 8080
    name: http
  selector:
    app: echo-backend
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-backend
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo-backend
  template:
    metadata:
      labels:
        app: echo-backend
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:latest
        args: ["-listen=:8080", "-text=echo-backend"]
        ports:
        - containerPort: 8080
EOF
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayParameters
metadata:
  name: agentgateway-oidc-params
  namespace: default
spec:
  logging:
    level: info
    format: text
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: enterprise-agentgateway
  namespace: default
spec:
  gatewayClassName: enterprise-agentgateway
  infrastructure:
    parametersRef:
      group: enterpriseagentgateway.solo.io
      kind: EnterpriseAgentgatewayParameters
      name: agentgateway-oidc-params
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: oidc-route
  namespace: default
spec:
  parentRefs:
  - name: enterprise-agentgateway
    namespace: default
  hostnames:
  - "oidc.example.com"
  rules:
  - backendRefs:
    - name: echo-backend
      port: 8080
EOF
```

---

## Step 5: Attach JWT authentication

```bash
kubectl apply -f - <<'EOF'
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: keycloak-jwt-policy
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: oidc-route
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
      - issuer: "http://keycloak.keycloak.svc.cluster.local:8080/realms/oidc-realm"
        jwks:
          remote:
            jwksPath: "realms/oidc-realm/protocol/openid-connect/certs"
            backendRef:
              kind: Service
              name: keycloak
              namespace: keycloak
              port: 8080
EOF
```

---

## Step 6: Obtain a token from Keycloak

```bash
export USER_JWT=$(curl -s -X POST "${KEYCLOAK_URL}/realms/oidc-realm/protocol/openid-connect/token" \
  -H "Host: keycloak.keycloak.svc.cluster.local:8080" \
  -d "username=testuser" \
  -d "password=testuser" \
  -d "grant_type=password" \
  -d "client_id=agentgateway-client" \
  -d "client_secret=agentgateway-client-secret" | jq -r '.access_token')

_b=$(echo "$USER_JWT" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_b} % 4)) -ne 0 ]; do _b="${_b}="; done; echo "$_b" | base64 -d 2>/dev/null | jq '.iss'
```

---

## Step 7: Call the protected route

```bash
pkill -f "port-forward.*8888" 2>/dev/null || true
sleep 1
kubectl port-forward -n default svc/enterprise-agentgateway 8888:80 &
sleep 2
```

### Without token (expect 401)

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: oidc.example.com" http://localhost:8888/
```

### With token (expect 200)

```bash
curl -s -w "\nHTTP_CODE:%{http_code}" -H "Host: oidc.example.com" -H "Authorization: Bearer ${USER_JWT}" http://localhost:8888/
```

---

## Step 8: Validate JWT payload (optional)

```bash
_b=$(echo "$USER_JWT" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#_b} % 4)) -ne 0 ]; do _b="${_b}="; done; echo "$_b" | base64 -d 2>/dev/null | jq '.'
```

---

## Cleanup

```bash
pkill -f "port-forward.*keycloak" 2>/dev/null || true
pkill -f "port-forward.*8888" 2>/dev/null || true
kubectl delete enterpriseagentgatewaypolicy keycloak-jwt-policy -n default
kubectl delete httproute oidc-route -n default
kubectl delete deployment echo-backend -n default
kubectl delete service echo-backend -n default
kubectl delete gateway enterprise-agentgateway -n default
kubectl delete enterpriseagentgatewayparameters agentgateway-oidc-params -n default
kubectl delete namespace keycloak
kubectl delete gateway agentgateway -n kgateway-system
kubectl delete enterpriseagentgatewayparameters agentgateway-debug -n kgateway-system 2>/dev/null || true
helm uninstall enterprise-agentgateway -n kgateway-system
helm uninstall enterprise-agentgateway-crds -n kgateway-system
kubectl delete namespace kgateway-system
```

---

**References:** [Enterprise Agentgateway Workshop](https://github.com/solo-io/fe-enterprise-agentgateway-workshop), [Keycloak](https://www.keycloak.org/), [Gateway API](https://gateway-api.sigs.k8s.io/).
