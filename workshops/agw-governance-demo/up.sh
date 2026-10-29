#!/usr/bin/env bash
# Build or recover the whole demo (idempotent; safe after a Mac or Docker restart).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
"$DIR/00-cluster.sh" && "$DIR/01-keycloak.sh" && "$DIR/02-tools.sh" && "$DIR/03-agentgateway.sh" && "$DIR/04-gateway-config.sh" && "$DIR/openwebui.sh" up
