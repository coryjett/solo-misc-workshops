#!/usr/bin/env bash
# kind cluster $CLUSTER with host ports mapped straight to NodePorts (no port-forwards to babysit).
# Idempotent: creates the cluster if missing, starts the node container if stopped, re-applies
# registry mirrors and the CoreDNS rewrite. Touches no other cluster.
set -euo pipefail
. "$(dirname "$0")/env.sh"
NODE="${CLUSTER}-control-plane"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  for p in "$KC_HOST_PORT" "$GW_HOST_PORT" "$UI_HOST_PORT"; do
    if nc -z 127.0.0.1 "$p" 2>/dev/null; then echo "host port $p is in use; change it in env.sh" >&2; exit 1; fi
  done
  PREV_CTX="$(kubectl config current-context 2>/dev/null || true)"
  cat <<EOF | kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - { containerPort: ${KC_NODE_PORT},  hostPort: ${KC_HOST_PORT},  listenAddress: "127.0.0.1" }
  - { containerPort: ${GW_NODE_PORT}, hostPort: ${GW_HOST_PORT}, listenAddress: "127.0.0.1" }
  - { containerPort: ${UI_NODE_PORT}, hostPort: ${UI_HOST_PORT}, listenAddress: "127.0.0.1" }
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF
  # kind switches the default kubectl context; put the previous one back (scripts always pass --context).
  [ -n "$PREV_CTX" ] && kubectl config use-context "$PREV_CTX" >/dev/null
elif [ "$(docker inspect -f '{{.State.Running}}' "$NODE" 2>/dev/null)" != "true" ]; then
  echo "starting stopped node $NODE"; docker start "$NODE" >/dev/null
fi
# kind restarts the node with restart=on-failure; make it come back after a Docker Desktop restart too.
docker update --restart=unless-stopped "$NODE" >/dev/null
# Pin the node's IP on the kind network. A Docker restart otherwise hands it a new address while
# certs and kubelet keep the old one (the node goes NotReady). Static IPs survive restarts.
IP="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$NODE")"
if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind.IPAMConfig}}' "$NODE")" = "null" ]; then
  docker stop "$NODE" >/dev/null; docker network disconnect kind "$NODE"; docker network connect --ip "$IP" kind "$NODE"; docker start "$NODE" >/dev/null
  echo "pinned $NODE to $IP"
fi


# Optional pull-through caches: use any of the local mirror containers that exist on the kind network.
for pair in docker.io=docker us-docker.pkg.dev=us-docker quay.io=quay ghcr.io=ghcr gcr.io=gcr; do
  reg="${pair%%=*}" mirror="${pair#*=}"
  if docker inspect -f '{{json .NetworkSettings.Networks}}' "$mirror" 2>/dev/null | grep -q '"kind"'; then
    docker exec "$NODE" mkdir -p "/etc/containerd/certs.d/$reg"
    printf '[host."http://%s:5000"]\n  capabilities = ["pull", "resolve"]\n' "$mirror" |
      docker exec -i "$NODE" tee "/etc/containerd/certs.d/$reg/hosts.toml" >/dev/null
  fi
done

kubectl --context "$KCTX" wait --for=condition=Ready node --all --timeout=180s

# CoreDNS: pods resolve keycloak.localhost to the Keycloak Service, so the server sees the same issuer the browser does.
COREFILE="$(kubectl --context "$KCTX" -n kube-system get cm coredns -o jsonpath='{.data.Corefile}')"
if ! grep -q "rewrite name exact ${KC_HOSTNAME}" <<<"$COREFILE"; then
  NEW="$(awk -v l="    rewrite name exact ${KC_HOSTNAME} keycloak.keycloak.svc.cluster.local" '{print} /^\.:53 \{/{print l}' <<<"$COREFILE")"
  kubectl --context "$KCTX" -n kube-system create cm coredns --from-literal=Corefile="$NEW" --dry-run=client -o yaml |
    kubectl --context "$KCTX" apply -f - >/dev/null
  kubectl --context "$KCTX" -n kube-system rollout restart deploy/coredns >/dev/null
fi
kubectl --context "$KCTX" -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null
kubectl --context "$KCTX" get nodes
echo CLUSTER-READY
