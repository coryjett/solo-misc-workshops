# Flow 4: Double OAuth — Working Example

Two sequential OAuth flows: OIDC authentication (Phase 1) + upstream credential gathering via elicitation (Phase 2).

**Note:** Phase 2 completion requires the Solo Enterprise UI. This example demonstrates the OIDC auth and elicitation trigger.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

## Key config

```yaml
# Default mode (empty = both exchange + elicit)
tokenExchange: {}
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 4 description](../README.md) · [Auth Patterns overview](../../../README.md)
