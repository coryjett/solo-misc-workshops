#!/usr/bin/env bash
# Register the kagent runtime connection and the deployable MCP server (as admin). Idempotent.
# Prereq: deploy/install-kagent.sh. Does NOT create the Deployment; that is the live demo step.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; . "$DIR/env.sh" >/dev/null
SECRET="$(sed -n 's/^  clientSecret: "\(.*\)"/\1/p' "$DIR/values.yaml")"
[ -n "$SECRET" ] || { echo "no oidc clientSecret in values.yaml" >&2; exit 1; }
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
sed "s|__CLIENT_SECRET__|$SECRET|" "$DIR/deploy/kagent-runtime.yaml.tmpl" > "$TMP"
as_user admin >/dev/null
arctl apply -f "$TMP"
