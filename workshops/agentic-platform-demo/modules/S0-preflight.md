# S0 · Pre-flight (do before every demo)

<!-- nav:start -->
[All modules](README.md) · [Setup](README.md#setup) · Next: [P1](P1-platform-on-kubernetes.md)
<!-- nav:end -->

**Area:** Setup

**Proves:** The environment is healthy and in its starting state.

**Needs:** Cluster running (`kind get clusters` shows `agentic-demo`). If Docker or the Mac restarted: `./down.sh && ./up.sh` first (about 15 min).

**Windows:** Solo UI http://localhost:8082 · Registry http://localhost:12121/are/ (admin/admin; Incognito window for eng-dev/eng-dev)

## Steps

```bash
cd ~/Documents/Workspace/Solo/solo-misc-workshops/workshops/agentic-platform-demo
./verify.sh && ./verify-gateway.sh && ./reset.sh     # both ALL-PASS, then back to start state
. ./env.sh; clear
```
Terminal 2 (live gateway log, used by many modules):
```bash
kubectl --context kind-agentic-demo -n agentgateway-system logs deploy/mcp-gateway -f | grep --line-buffered -E 'protocol=(a2a|mcp|llm)'
```

## Expect

`ALL-PASS` twice, then `pending: 1` from reset (the approval used in R3).

## Say

- Run `./reset.sh` again between back-to-back demos (about 40 seconds).

## Cleanup

None. To return everything to the starting state at any time: `./reset.sh` (about 40 seconds).

<!-- nav:start -->
[All modules](README.md) · [Setup](README.md#setup) · Next: [P1](P1-platform-on-kubernetes.md)
<!-- nav:end -->
