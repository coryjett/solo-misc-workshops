#!/usr/bin/env bash
# Creates a local KinD cluster for this lab. Skip this script if you are bringing your own cluster.
set -euo pipefail
CLUSTER="${CLUSTER:-agw-e2e}"
kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER"
kubectl config use-context "kind-$CLUSTER"
kubectl get nodes
