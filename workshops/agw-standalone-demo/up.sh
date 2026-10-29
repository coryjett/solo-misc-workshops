#!/usr/bin/env bash
# Brings the whole demo up (idempotent): Keycloak (IdP stand-in), the backend systems, the gateway.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
load_license >/dev/null; load_openai_key >/dev/null; load_local_llm_key
"$DIR/keycloak.sh" start
"$DIR/tools.sh" start
"$DIR/gateway.sh" start
cat <<EOF

Ready.
  MCP endpoint      $MCP_URL                  (Bearer token required)
  LLM endpoint      $LLM_URL  (OpenAI-compatible)
  Plain REST route  $GW_URL/api/ops/sites/site-112/hours
  Gateway UI        $UI_URL
  Keycloak          $KC_URL  (admin / admin, realm $KC_REALM)
  Users (password = username): support-agent (support), ops-manager (operations), security-analyst (security)

  ./verify.sh                     every demo claim, PASS/FAIL
  ./inspector.sh support-agent    MCP Inspector as a user
  ./chat.py <user> <model> "..."  ./mcpcli.py <user> list|call ...   ./logs.sh
EOF
