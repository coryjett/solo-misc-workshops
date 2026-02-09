# Quick Walkthrough: OBO (On-Behalf-Of) via STS with Keycloak and Solo Enterprise for Agentgateway 2.1.x

This walkthrough uses [Solo Enterprise for agentgateway 2.1.x](https://docs.solo.io/agentgateway/2.1.x/) with **Keycloak**: deploy Keycloak and agentgateway with OBO token exchange, get a user JWT, then curl the STS to exchange it for an OBO token (RFC 8693).

### Flow in brief

1. **User authenticates** with Keycloak (e.g. username/password or OIDC) and receives a **user JWT** (identity token).
2. Your app or agent calls the **Agentgateway STS** (Security Token Service) with that user JWT in the `Authorization` header and as `subject_token`, using the token-exchange grant.
3. The STS validates the user JWT (via your IdP’s JWKS), then issues an **OBO token** (a JWT signed by Agentgateway) that represents the same user and scopes.
4. You use the **OBO token** to call downstream APIs or agent backends *on behalf of* that user: e.g. `Authorization: Bearer <OBO_TOKEN>`. Downstream services trust the Agentgateway issuer and can rely on `sub` and `scope` for authz. This keeps user identity and scopes consistent without passing the original IdP token through your stack.

---

## Prerequisites

- Kubernetes cluster, **kubectl**, **helm** (v3+), **jq**, **curl**
- **Solo Enterprise license:** Set `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`. A valid key is required; an empty or invalid key will cause the Helm install in step 2.2 to fail.
- **Shell:** Run all steps in the same shell so `KEYCLOAK_URL`, `KEYCLOAK_JWKS_URL`, `USER_JWT`, and `STS_URL` persist. If you use a new shell, re-export those variables (or re-run the steps that set them).

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
```

Wait for Keycloak to be ready (startup can take 1–2 minutes):

```bash
kubectl wait -n keycloak statefulset/keycloak --for=condition=Ready --timeout=300s
```

### 1.2 Port-forward Keycloak and get admin token

```bash
pkill -f "port-forward.*keycloak.*8080" 2>/dev/null || true
sleep 1
kubectl port-forward -n keycloak svc/keycloak 8080:8080 &
sleep 3
export KEYCLOAK_URL="http://localhost:8080"

ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')
echo "Admin token obtained"
```

### 1.3 Create realm, confidential client, and user

Re-running this step is safe; creating the realm, client, or user again may return 409.

```bash
# Create realm obo-realm
curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"realm":"obo-realm","enabled":true}'

# Create confidential client agw-client (for resource-owner password grant)
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

# Create user testuser with full profile (email, firstName, lastName required by Keycloak 24+/26; emailVerified and requiredActions: [] so token grant works)
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
```

### 1.4 Keycloak JWKS URL (in-cluster)

```bash
export KEYCLOAK_JWKS_URL="http://keycloak.keycloak.svc.cluster.local:8080/realms/obo-realm/protocol/openid-connect/certs"
echo "KEYCLOAK_JWKS_URL=$KEYCLOAK_JWKS_URL"
```

---

## Step 2: Deploy Solo Enterprise for Agentgateway 2.1.x (with OBO token exchange)

### 2.1 Gateway API CRDs

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml
```

### 2.2 Install CRDs and control plane (token exchange enabled)

```bash
echo "KEYCLOAK_JWKS_URL=${KEYCLOAK_JWKS_URL:?Run step 1.4 first}"
echo "${AGENTGATEWAY_LICENSE_KEY:?Set AGENTGATEWAY_LICENSE_KEY before running step 2.2}"

helm upgrade -i --create-namespace \
  --namespace kgateway-system \
  --version 2.1.1 enterprise-agentgateway-crds oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds

helm upgrade -i -n kgateway-system \
  enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version 2.1.1 \
  --set-string licensing.licenseKey=$AGENTGATEWAY_LICENSE_KEY \
  --set tokenExchange.enabled=true \
  --set tokenExchange.issuer="enterprise-agentgateway.kgateway-system.svc.cluster.local:7777" \
  --set tokenExchange.tokenExpiration=24h \
  --set tokenExchange.subjectValidator.validatorType=remote \
  --set tokenExchange.subjectValidator.remoteConfig.url="$KEYCLOAK_JWKS_URL" \
  --set tokenExchange.actorValidator.validatorType=k8s \
  --set controller.logLevel=debug
```

If the control plane does not come up, check `kubectl get pods -n kgateway-system` and the controller logs.

### 2.3 Create Gateway (data plane)

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

### 2.4 Verify

```bash
kubectl get pods,gateway,svc -n kgateway-system
kubectl get svc -n kgateway-system
```

Confirm **enterprise-agentgateway** lists port **7777** and pods are **Running**.

---

## Step 3: Get user JWT from Keycloak

Use the same Keycloak port-forward as step 1.2.

### 3.1 Get the token

```bash
# If port-forward was stopped, run: pkill -f "port-forward.*keycloak.*8080" 2>/dev/null; kubectl port-forward -n keycloak svc/keycloak 8080:8080 & sleep 3; export KEYCLOAK_URL="http://localhost:8080"
export USER_JWT=$(curl -s -X POST "${KEYCLOAK_URL}/realms/obo-realm/protocol/openid-connect/token" \
  -d "username=testuser" \
  -d "password=testuser" \
  -d "grant_type=password" \
  -d "client_id=agw-client" \
  -d "client_secret=agw-client-secret" | jq -r '.access_token')
```

### 3.2 Display and decode the user JWT

```bash
echo "========== User JWT =========="
echo "$USER_JWT"
echo ""
echo "--- User JWT Payload ---"
seg=$(echo "$USER_JWT" | cut -d'.' -f2 | tr '_-' '/+'); while [ $((${#seg} % 4)) -ne 0 ]; do seg="${seg}="; done; echo "$seg" | base64 -d 2>/dev/null | jq '.'
```

---

## Step 4: Exchange user JWT for OBO token (STS)

Use the user JWT from **Step 3**. STS endpoint: **`/token`** on port **7777**.

### 4.1 Port-forward the STS

```bash
pkill -f "port-forward.*7777" 2>/dev/null || true
sleep 1
kubectl port-forward -n kgateway-system svc/enterprise-agentgateway 7777:7777 &
sleep 2
export STS_URL="http://localhost:7777"
```

If port **7777** is already in use, use a different local port (e.g. `7778:7777`) and set `export STS_URL="http://localhost:7778"`.

### 4.2 Call the STS token endpoint

```bash
export STS_RESPONSE=$(curl -s -X POST "${STS_URL}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer ${USER_JWT}" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${USER_JWT}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt")

echo "========== STS response (\$STS_RESPONSE) =========="
echo "$STS_RESPONSE" | jq '.' 2>/dev/null || echo "$STS_RESPONSE"
```

**Expected response:**

```json
{
  "access_token": "eyJ...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

**If you get 401:** Ensure you use the **user JWT from Step 3** in both the `Authorization` header and as `subject_token`, that the Keycloak port-forward (1.2) is running, and that `KEYCLOAK_JWKS_URL` (1.4) was set when you ran step 2.2.

### 4.3 Display and decode the OBO token

```bash
export OBO_JWT=$(echo "$STS_RESPONSE" | jq -r '.access_token // empty')
echo "========== OBO JWT =========="
echo "$OBO_JWT"
echo ""
echo "--- OBO JWT Payload ---"
seg=$(echo "$OBO_JWT" | cut -d'.' -f2 | tr '_-' '/+'); while [ $((${#seg} % 4)) -ne 0 ]; do seg="${seg}="; done; echo "$seg" | base64 -d 2>/dev/null | jq '.'
```


---

## Cleanup

Gateway and parameters are deleted before Helm so custom resources are removed before CRDs are uninstalled.

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

---

**Version:** 4.0  
**Changelog (vs 3.5):** License key and shell prerequisites; idempotent namespace and port-forward cleanup; 2.2 license guard; 2.4 verify hint; 4.1 port conflict note and 7777 kill; 401 troubleshooting line; cleanup order and 7777 kill; re-run note for 1.3. Actor-token section removed (impersonation flow does not send actor token).
