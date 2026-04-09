#!/usr/bin/env bash
# Deploy Keycloak + PostgreSQL and configure a realm with a client and test user.
#
# Inputs (set before sourcing):
#   KEYCLOAK_REALM  - realm name (default: "agw-realm")
#   KEYCLOAK_CLIENT - client ID  (default: "agw-client")
#   KEYCLOAK_SECRET - client secret (default: "agw-client-secret")
#   KEYCLOAK_PORT   - local port-forward port (default: 8080)
#
# Outputs (exported):
#   KEYCLOAK_URL       - http://localhost:<port>
#   KEYCLOAK_ISSUER    - in-cluster issuer URL
#   KEYCLOAK_JWKS_URL  - in-cluster JWKS URL

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers.sh"

KEYCLOAK_REALM="${KEYCLOAK_REALM:-agw-realm}"
KEYCLOAK_CLIENT="${KEYCLOAK_CLIENT:-agw-client}"
KEYCLOAK_SECRET="${KEYCLOAK_SECRET:-agw-client-secret}"
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8080}"

export KEYCLOAK_URL="http://localhost:${KEYCLOAK_PORT}"
export KEYCLOAK_ISSUER="http://keycloak.keycloak.svc.cluster.local:8080/realms/${KEYCLOAK_REALM}"
export KEYCLOAK_JWKS_URL="${KEYCLOAK_ISSUER}/protocol/openid-connect/certs"

# ── Deploy Keycloak + PostgreSQL ─────────────────────────────────────────────
info "Deploying Keycloak..."
kubectl create namespace keycloak 2>/dev/null || true

kubectl apply -n keycloak -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: keycloak
spec:
  ports:
  - port: 8080
    targetPort: http
    name: http
  selector:
    app: keycloak
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak-discovery
  namespace: keycloak
spec:
  selector:
    app: keycloak
  clusterIP: None
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: keycloak
  namespace: keycloak
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
        - containerPort: 5432
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
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
EOF

info "Waiting for Keycloak (this takes ~2 min)..."
kubectl wait -n keycloak statefulset/keycloak --for=jsonpath='{.status.readyReplicas}'=1 --timeout=420s
ok "Keycloak deployed"

# ── Port-forward ─────────────────────────────────────────────────────────────
kill_pf "keycloak.*${KEYCLOAK_PORT}"
kubectl port-forward -n keycloak svc/keycloak "${KEYCLOAK_PORT}:8080" &>/dev/null &
sleep 3

# ── Configure realm, client, user ────────────────────────────────────────────
info "Configuring Keycloak realm: ${KEYCLOAK_REALM}..."
ADMIN_TOKEN=$(get_admin_token "${KEYCLOAK_URL}")

# Create realm
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"realm\":\"${KEYCLOAK_REALM}\",\"enabled\":true}" || true

# Create client
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"clientId\": \"${KEYCLOAK_CLIENT}\",
    \"enabled\": true,
    \"clientAuthenticatorType\": \"client-secret\",
    \"secret\": \"${KEYCLOAK_SECRET}\",
    \"directAccessGrantsEnabled\": true,
    \"serviceAccountsEnabled\": false,
    \"redirectUris\": [\"*\"],
    \"webOrigins\": [\"*\"]
  }" || true

# Create test user
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "testuser@example.com",
    "emailVerified": true,
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "credentials": [{"type":"password","value":"testuser","temporary":false}]
  }' || true

# Relax DCR policies (needed for MCP OAuth flow)
for POLICY_NAME in "trusted-hosts" "allowed-client-templates"; do
  POLICY_ID=$(curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" \
    | jq -r ".[] | select(.name==\"${POLICY_NAME}\") | .id")
  [[ -n "$POLICY_ID" ]] && curl -sf -X DELETE \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/components/${POLICY_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" || true
done

ok "Keycloak configured (realm=${KEYCLOAK_REALM}, client=${KEYCLOAK_CLIENT}, user=testuser/testuser)"
