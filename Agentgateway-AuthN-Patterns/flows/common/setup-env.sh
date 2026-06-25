#!/usr/bin/env bash
# Shared, idempotent environment for ALL flow examples — source this once per flow.
#
# Brings up the expensive, common infrastructure exactly once and reuses it on every
# subsequent flow run:
#   - k3d cluster + Gateway API CRDs + AGW Enterprise   (common/setup-base.sh)
#   - Keycloak + PostgreSQL + a shared realm/client/user (common/deploy-keycloak.sh)
#   - AGW token-exchange / STS, validated against the shared realm
#
# All flows share one realm (default: agw-demo) so the issuer/JWKS/STS config is
# configured once. A flow can still override KEYCLOAK_REALM before sourcing if it
# needs its own realm.
#
# Each flow's setup.sh should source THIS (not setup-base/deploy-keycloak directly),
# then deploy only its flow-specific Gateway/HTTPRoute/policy and run its test.

ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Shared realm for every flow unless the caller overrides it.
export KEYCLOAK_REALM="${KEYCLOAK_REALM:-agw-demo}"

source "${ENV_DIR}/setup-base.sh"        # k3d cluster + AGW Enterprise (reused if present)
source "${ENV_DIR}/deploy-keycloak.sh"   # Keycloak + shared realm (idempotent)
enable_sts "${KEYCLOAK_REALM}"           # AGW STS, validated against the shared realm
