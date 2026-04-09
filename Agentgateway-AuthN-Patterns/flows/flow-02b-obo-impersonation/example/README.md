# Flow 2b: OBO Impersonation — Working Example

Same as Flow 2a but without an actor token. The STS issues a JWT with the same `sub` and scopes but no `act` claim. The original IdP token is replaced.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

## Key difference from 2a

In impersonation mode, the exchanged token has no `act` claim — downstream services see only the user's identity. The agent identity is not tracked.

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 2b description](../README.md) · [Auth Patterns overview](../../../README.md)
