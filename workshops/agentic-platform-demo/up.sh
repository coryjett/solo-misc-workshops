#!/usr/bin/env bash
# One command to build or recover the whole agentic platform demo (safe to rerun after a Mac or Docker restart):
# kind cluster, Keycloak (IdP stand-in), agentregistry Enterprise + arctl, OSS kagent runtime, the demo tool
# servers, agentgateway Enterprise with the governance config, then the catalog seed (reset.sh).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
"$DIR/00-cluster.sh" && "$DIR/01-keycloak.sh" && "$DIR/02-registry.sh"
"$DIR/deploy/install-kagent.sh" >/dev/null && echo KAGENT-READY
"$DIR/02-tools.sh" && "$DIR/03-agentgateway.sh" && "$DIR/04-gateway-config.sh"
"$DIR/reset.sh" | tail -3
. "$DIR/env.sh" >/dev/null
cat <<EOF

Ready.
  agentregistry UI   $ARE_UI_URL/are/          (admin / admin; others: approver, eng-dev, sales-dev, auditor, password = username)
  agentgateway UI    http://localhost:${UI_HOST_PORT}
  Keycloak           $KC_URL                   (admin / admin, realm $KC_REALM)
  Gateway            $GW_URL/mcp (platform federated endpoint)   $GW_URL/registry/<server> (registry-published)
                     $GW_URL/v1/chat/completions (LLM)
  ./verify.sh && ./verify-gateway.sh     registry + gateway checks
  ./inspector.sh eng-dev [url]      MCP Inspector as a user
  ./reset.sh                             back to the pre-demo state (about 40 s)
EOF
