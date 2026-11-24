#!/usr/bin/env bash
# kagent lab state (run by reset.sh step 6): the gateway-backed agent, group-based RBAC, and egress
# trust for the gateway's HTTPS listener. Removes agents and templates made during a demo. Idempotent.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; ENV_QUIET=1 . "$DIR/env.sh"; K="kubectl --context $KCTX"

# Lab-only: the Substrate egress proxy re-originates TLS and trusts only its system CA bundle, so add the
# lab CA to that bundle. In production the gateway's certificate comes from a CA the proxy already trusts.
if [ -f "$DIR/.secrets/lab-ca.crt" ]; then
  # Base bundle: the kind node's Debian CA store (current public roots), plus the lab CA.
  { docker exec "${CLUSTER}-control-plane" cat /etc/ssl/certs/ca-certificates.crt; cat "$DIR/.secrets/lab-ca.crt"; } > "$DIR/.secrets/egress-ca-bundle.pem"
  $K -n ate-system create configmap egress-ca-bundle --from-file=ca-certificates.crt="$DIR/.secrets/egress-ca-bundle.pem" \
    --dry-run=client -o yaml | $K apply --server-side --force-conflicts -f - >/dev/null   # too big for client-side apply
  SUM="$(shasum -a 256 "$DIR/.secrets/egress-ca-bundle.pem" | cut -c1-16)"
  if ! $K -n ate-system get deploy atenet-egress -o jsonpath='{.spec.template.spec.volumes[*].name}' | grep -qw egress-ca-bundle; then
    $K -n ate-system patch deploy atenet-egress --type json -p '[
      {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"egress-ca-bundle","configMap":{"name":"egress-ca-bundle"}}},
      {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"egress-ca-bundle","mountPath":"/etc/ssl/certs/ca-certificates.crt","subPath":"ca-certificates.crt","readOnly":true}}]' >/dev/null
  fi
  if [ "$($K -n ate-system get deploy atenet-egress -o jsonpath='{.spec.template.metadata.annotations.demo/ca-bundle-sha}')" != "$SUM" ]; then
    $K -n ate-system patch deploy atenet-egress --type merge -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"demo/ca-bundle-sha\":\"$SUM\"}}}}}" >/dev/null
  fi
  $K -n ate-system rollout status deploy/atenet-egress --timeout=120s >/dev/null
  echo "  egress proxy trusts the lab CA"
fi

# Remove what a demo created, then put the lab objects back.
# Recreating platform-assistant too drops any edit made in the UI (egress policies, prompt).
$K -n kagent delete agents --all --wait >/dev/null 2>&1 || true
$K -n kagent delete agenttemplates --all >/dev/null 2>&1 || true
$K -n kagent delete egresspolicies --all >/dev/null 2>&1 || true
$K apply -f "$DIR/deploy/kagent-lab.yaml" >/dev/null
$K -n kagent wait agent/platform-assistant --for=condition=Ready --timeout=180s >/dev/null && echo "  platform-assistant Ready"
