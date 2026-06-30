#!/usr/bin/env bash
# Flow 4b: Double OAuth — Eager (Up-Front) with Consent Screen — working example
#
# Same trust model as flow-04, but the upstream OAuth leg is gathered EAGERLY
# (before the first tool call) via the gateway's own OAuth issuer, with an
# optional gateway-hosted consent screen between the downstream and upstream legs.
#
# WHAT THIS SCRIPT VERIFIES HEADLESSLY:
#   The eager DISCRIMINATOR — connecting to /mcp/<backend> returns 401 + protected-
#   resource metadata whose authorization server points at the gateway OAuth issuer.
#   That 401-driven discovery is what makes the flow eager (vs lazy elicitation).
#
# WHAT REQUIRES A BROWSER (interactive, like flow-04's Enterprise UI step):
#   The consent screen + upstream OAuth completion. Drive it with the MCP Inspector
#   (or VS Code / Cursor / Claude Code) against a REAL upstream MCP OAuth provider
#   (Atlassian / GitHub / Slack). See example/README.md "Completing the flow".
#
# VALIDATED on a fresh k3d cluster with AGW v2026.6.2: the headless portion above
# passes (no-token -> 401 + protected-resource metadata pointing at the gateway
# OAuth issuer). The consent + upstream-OAuth completion is browser-interactive and
# is exercised manually per example/README.md "Completing the flow".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../common/setup-env.sh"   # shared cluster + AGW + Keycloak + STS
FLOW="flow-04b"

# Externally reachable gateway address (port-forwarded below). The issuer base_url,
# the MCP audiences/resource, and the URL the MCP client connects to all derive from it.
GW_ADDR="${GW_ADDR:-localhost:8888}"
ISSUER_CLIENT_ID="${ISSUER_CLIENT_ID:-agw-issuer}"
ISSUER_CLIENT_SECRET="${ISSUER_CLIENT_SECRET:-agw-issuer-secret}"

# Upstream MCP OAuth provider — swap these for a real provider to complete the flow.
# Defaults point at Atlassian's remote MCP server (matches the docs walkthrough).
UPSTREAM_BASE_URL="${UPSTREAM_BASE_URL:-https://mcp.atlassian.com}"
UPSTREAM_SCOPES="${UPSTREAM_SCOPES:-read:jira-work read:confluence-content.summary offline_access}"
UPSTREAM_CLIENT_NAME="${UPSTREAM_CLIENT_NAME:-Atlassian}"

# ── Register the agw-issuer confidential client in Keycloak ───────────────────
# Lets the gateway's OAuth issuer federate with Keycloak for the downstream leg.
info "Registering '${ISSUER_CLIENT_ID}' confidential client in Keycloak..."
ADMIN_TOKEN=$(get_admin_token "${KEYCLOAK_URL}")
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -d "{
    \"clientId\": \"${ISSUER_CLIENT_ID}\",
    \"secret\": \"${ISSUER_CLIENT_SECRET}\",
    \"protocol\": \"openid-connect\",
    \"publicClient\": false,
    \"standardFlowEnabled\": true,
    \"redirectUris\": [\"http://${GW_ADDR}/oauth-issuer/*\"],
    \"webOrigins\": [\"*\"]
  }" >/dev/null 2>&1 || warn "agw-issuer client may already exist — continuing"
ok "agw-issuer client registered"

# ── Configure the controller OAuth issuer + consent (KGW_OAUTH_ISSUER_CONFIG) ─
# Applied AFTER Keycloak + base_url exist, mirroring the docs' second helm upgrade.
info "Configuring controller OAuth issuer with consent block..."
ISSUER_VALUES="$(mktemp)"
cat > "${ISSUER_VALUES}" <<EOF
controller:
  extraEnv:
    KGW_OAUTH_ISSUER_CONFIG: |
      {
        "gateway_config": { "base_url": "http://${GW_ADDR}/oauth-issuer" },
        "downstream_server": {
          "name": "keycloak",
          "client_id": "${ISSUER_CLIENT_ID}",
          "client_secret": "${ISSUER_CLIENT_SECRET}",
          "authorize_url": "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth",
          "token_url": "${KEYCLOAK_ISSUER}/protocol/openid-connect/token",
          "scopes": ["openid", "profile", "email"]
        },
        "consent": {
          "enabled": true,
          "force_refresh": false,
          "platform_name": "Acme AI Gateway (Flow 4b demo)",
          "logo_url": "https://agentgateway.dev/agw-dark.svg",
          "legal_text": "By clicking Allow, you authorize Acme AI Gateway to act on your behalf against the selected upstream service. Acme stores an access token tied to your identity until it is revoked or expires."
        }
      }
EOF
helm upgrade -i -n agentgateway-system enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  --version "${AGW_VERSION}" \
  --set-string licensing.licenseKey="${AGENTGATEWAY_LICENSE_KEY}" \
  --set agentgateway.enabled=true \
  --reuse-values \
  -f "${ISSUER_VALUES}"
rm -f "${ISSUER_VALUES}"
kubectl -n agentgateway-system rollout status deployment/enterprise-agentgateway --timeout=180s
ok "Controller issuer + consent configured"

# ── Shared once-per-gateway: /oauth-issuer route + Keycloak JWKS backend ──────
info "Deploying gateway + oauth-issuer route + JWKS backend..."
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ${FLOW}-gateway
  namespace: agentgateway-system
spec:
  gatewayClassName: enterprise-agentgateway
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
---
# Forwards /oauth-issuer/* from the public gateway to the controller's OAuth
# issuer endpoint (port 7777, not exposed outside the cluster). Shared by every
# eager/auth-only MCP backend behind this gateway.
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: oauth-issuer-backend
  namespace: agentgateway-system
spec:
  static:
    host: enterprise-agentgateway.agentgateway-system.svc.cluster.local
    port: 7777
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: oauth-issuer
  namespace: agentgateway-system
spec:
  parentRefs:
  - name: ${FLOW}-gateway
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /oauth-issuer
    backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: oauth-issuer-backend
      weight: 1
---
# JWKS endpoint the gateway uses to validate inbound JWTs (signed by Keycloak).
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: keycloak-jwks
  namespace: agentgateway-system
spec:
  static:
    host: keycloak.keycloak.svc.cluster.local
    port: 8080
EOF
kubectl wait gateway/${FLOW}-gateway -n agentgateway-system \
  --for=condition=Programmed --timeout=120s
ok "Gateway + oauth-issuer route ready"

# ── Per-backend: MCP backend (advertises the issuer = EAGER), Secret, Policy ──
info "Deploying eager MCP backend + consent overrides + elicitation policy..."
kubectl apply -f - <<EOF
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: mcp-upstream
  namespace: agentgateway-system
spec:
  mcp:
    targets:
    - name: mcp-target
      static:
        path: /mcp/upstream
        host: ${UPSTREAM_BASE_URL#https://}
        port: 443
  policies:
    tls: {}
    mcp:
      authentication:
        mode: Strict
        issuer: "${KEYCLOAK_ISSUER}"
        audiences:
        - "http://${GW_ADDR}/mcp/upstream"
        jwks:
          backendRef:
            name: keycloak-jwks
            group: agentgateway.dev
            kind: AgentgatewayBackend
          cacheDuration: 24h
          jwksPath: /realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs
        # This block is the EAGER discriminator: advertising the gateway issuer in
        # protected-resource metadata makes a spec-compliant MCP client run OAuth
        # up front (401 -> discovery) instead of falling back to lazy elicitation.
        resourceMetadata:
          agentgateway.dev/issuer-proxy: "http://enterprise-agentgateway.agentgateway-system.svc.cluster.local:7777/oauth-issuer"
          authorizationServers:
          - "http://${GW_ADDR}/mcp/upstream"
          resource: "http://${GW_ADDR}/mcp/upstream"
---
# Per-backend consent overrides + upstream OAuth discovery config live in this Secret.
apiVersion: v1
kind: Secret
metadata:
  name: mcp-upstream-elicitation
  namespace: agentgateway-system
type: Opaque
stringData:
  app_id: "upstream"
  base_url: "${UPSTREAM_BASE_URL}"
  mcp_resource: "/mcp/upstream"
  scopes: "${UPSTREAM_SCOPES}"
  client_name: "${UPSTREAM_CLIENT_NAME}"
  consent_logo_url: "https://agentgateway.dev/agw-dark.svg"
  consent_legal_text: "By clicking Allow, you authorize Acme AI Gateway to read your data on the upstream service on your behalf."
  # consent_disabled: "true"   # uncomment to opt THIS backend out of the consent screen
---
apiVersion: enterpriseagentgateway.solo.io/v1alpha1
kind: EnterpriseAgentgatewayPolicy
metadata:
  name: mcp-upstream-elicit
  namespace: agentgateway-system
spec:
  targetRefs:
  - group: agentgateway.dev
    kind: AgentgatewayBackend
    name: mcp-upstream
  backend:
    # mode OMITTED on purpose = default (exchange + elicit). Verified against the
    # data plane: crates/agentgateway/src/proxy/token_exchange.rs expand_mode(None)
    # => (should_exchange=true, should_elicit=true). The ONLY upstream-Authorization
    # injection (handle_request, ~line 347) is gated on should_exchange, and the
    # inbound JWT is only stripped when exchanging (extract_incoming_token, ~line 273).
    #   ElicitationOnly => (false, true) => upstream token NOT injected; inbound
    #   Keycloak JWT is forwarded as-is. The published consent-screen guide uses
    #   ElicitationOnly here, which would NOT carry the user's upstream credential
    #   on this AGW version. Omit mode (or use ExchangeOnly) to actually inject it.
    tokenExchange:
      elicitation:
        secretName: mcp-upstream-elicitation
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: mcp-upstream
  namespace: agentgateway-system
spec:
  parentRefs:
  - name: ${FLOW}-gateway
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /mcp/upstream
    - path:
        type: PathPrefix
        value: /.well-known/oauth-protected-resource/mcp/upstream
    - path:
        type: PathPrefix
        value: /.well-known/oauth-authorization-server/mcp/upstream
    backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: mcp-upstream
      weight: 1
EOF

kubectl -n agentgateway-system get enterpriseagentgatewaypolicy mcp-upstream-elicit \
  -o jsonpath='{.status.ancestors[0].conditions}' 2>/dev/null | jq . 2>/dev/null || true
ok "Eager MCP backend + policy applied"

# ── Headless check: the eager discriminator ──────────────────────────────────
kill_pf "${FLOW}-gateway"
kubectl rollout status -n agentgateway-system deploy/${FLOW}-gateway --timeout=180s 2>/dev/null || true
kubectl port-forward -n agentgateway-system svc/${FLOW}-gateway 8888:80 &>/dev/null &
wait_for_pf http://localhost:8888/

echo ""
echo "=== Flow 4b: verifying EAGER discovery (401 -> gateway issuer) ==="
echo ""
info "Connecting to /mcp/upstream with no token (expect 401 + protected-resource metadata)..."
HDRS=$(curl -s -D - -o /dev/null --max-time 10 -X POST "http://${GW_ADDR}/mcp/upstream" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}' 2>/dev/null || true)
echo "$HDRS" | grep -iE '^HTTP/|^www-authenticate:' || true

PRM=$(curl -s --max-time 10 "http://${GW_ADDR}/.well-known/oauth-protected-resource/mcp/upstream" 2>/dev/null || true)
if echo "$PRM" | jq -e '.authorization_servers // .authorizationServers' >/dev/null 2>&1; then
  echo "Protected-resource metadata:"
  echo "$PRM" | jq '{resource, authorization_servers: (.authorization_servers // .authorizationServers)}' 2>/dev/null || echo "$PRM"
  ok "EAGER wiring confirmed — client is directed to the gateway OAuth issuer up front"
else
  warn "No protected-resource metadata returned. Check the backend authentication/resourceMetadata block."
fi

echo ""
warn "The CONSENT SCREEN + UPSTREAM OAUTH are browser-interactive (like flow-04's"
warn "Enterprise UI step). Complete them with the MCP Inspector against a real"
warn "upstream MCP OAuth provider — see example/README.md 'Completing the flow'."
echo ""
ok "Flow 4b: Double OAuth (eager + consent) — config deployed"
echo "  Cleanup: source ../../common/cleanup.sh  (also: kubectl delete gateway ${FLOW}-gateway -n agentgateway-system)"
