#!/usr/bin/env bash
# Kit-only: the Substrate egress proxy re-originates TLS and trusts only its system CA bundle, so add the
# kit CA to it. A Substrate Helm upgrade drops this patch; demo/start.sh reapplies it. In production the
# gateway's certificate comes from a CA the proxy already trusts.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; export KUBECONFIG="$DIR/kubeconfig"; S="$DIR/.secrets"
[ -f "$S/kit-ca.crt" ] || exit 0
{ docker exec kagent-ent-control-plane cat /etc/ssl/certs/ca-certificates.crt; cat "$S/kit-ca.crt"; } > "$S/egress-ca-bundle.pem"
kubectl -n ate-system create configmap egress-ca-bundle --from-file=ca-certificates.crt="$S/egress-ca-bundle.pem" \
  --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f - >/dev/null
SUM="$(shasum -a 256 "$S/egress-ca-bundle.pem" | cut -c1-16)"
if ! kubectl -n ate-system get deploy atenet-egress -o jsonpath='{.spec.template.spec.volumes[*].name}' | grep -qw egress-ca-bundle; then
  kubectl -n ate-system patch deploy atenet-egress --type json -p '[
    {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"egress-ca-bundle","configMap":{"name":"egress-ca-bundle"}}},
    {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"egress-ca-bundle","mountPath":"/etc/ssl/certs/ca-certificates.crt","subPath":"ca-certificates.crt","readOnly":true}}]' >/dev/null
fi
if [ "$(kubectl -n ate-system get deploy atenet-egress -o jsonpath='{.spec.template.metadata.annotations.demo/ca-bundle-sha}')" != "$SUM" ]; then
  kubectl -n ate-system patch deploy atenet-egress --type merge -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"demo/ca-bundle-sha\":\"$SUM\"}}}}}" >/dev/null
fi
kubectl -n ate-system rollout status deploy/atenet-egress --timeout=120s >/dev/null
echo "egress proxy trusts the kit CA"
