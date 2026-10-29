#!/usr/bin/env bash
# Keycloak 26 in Docker as the IdP stand-in (swap the issuer for Entra/Okta in config.yaml for a real one).
# Realm imported at every start; the signing key is fixed in .secrets/ so restarts never break the gateway's JWKS.
# Usage: ./keycloak.sh start | stop
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh"
case "${1:-start}" in
  start)
    mkdir -p "$DIR/.secrets"
    python3 "$DIR/tools/make_realm.py" "$KC_REALM" "$COMPANY" "http://localhost:3000" "$DIR/.secrets" > "$DIR/.secrets/realm.json"; chmod 600 "$DIR/.secrets/realm.json"
    if docker ps --format '{{.Names}}' | grep -qx "$KC_CONTAINER"; then echo "keycloak: already running"; else
      docker rm -f "$KC_CONTAINER" >/dev/null 2>&1 || true
      docker run -d --name "$KC_CONTAINER" -p "127.0.0.1:${KC_PORT}:8080" \
        -v "$DIR/.secrets/realm.json:/opt/keycloak/data/import/realm.json:ro" \
        -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
        -e KC_HOSTNAME="$KC_URL" -e KC_HTTP_ENABLED=true \
        quay.io/keycloak/keycloak:26.0 start-dev --import-realm >/dev/null
    fi
    for i in $(seq 1 90); do
      ISS="$(curl -s -m 3 "${OIDC_ISSUER}/.well-known/openid-configuration" | python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' 2>/dev/null || true)"
      [ "$ISS" = "$OIDC_ISSUER" ] && break; sleep 2
    done
    [ "$ISS" = "$OIDC_ISSUER" ] || { echo "keycloak not ready (issuer '$ISS')" >&2; docker logs --tail 20 "$KC_CONTAINER" >&2; exit 1; }
    echo "keycloak: $OIDC_ISSUER (admin/admin at $KC_URL)";;
  stop) docker rm -f "$KC_CONTAINER" >/dev/null 2>&1 && echo "keycloak stopped" || true;;
esac
