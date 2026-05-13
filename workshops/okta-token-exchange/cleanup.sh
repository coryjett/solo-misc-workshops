#!/usr/bin/env bash
# Tears down everything this workshop installed.
# Okta-side resources (auth server, apps, user) are not deleted — clean those
# up from the Okta admin console if you want a full reset.
set -euo pipefail

pkill -f "port-forward.*workshop-gateway" 2>/dev/null || true

echo "==> Removing workshop namespace"
kubectl delete namespace okta-tx --ignore-not-found --wait=false

echo "==> Removing AGW chart"
helm -n agentgateway-system uninstall enterprise-agentgateway 2>/dev/null || true
helm -n agentgateway-system uninstall enterprise-agentgateway-crds 2>/dev/null || true
kubectl delete namespace agentgateway-system --ignore-not-found --wait=false

echo "==> Done. Okta resources (auth server, apps, test user) are untouched."
