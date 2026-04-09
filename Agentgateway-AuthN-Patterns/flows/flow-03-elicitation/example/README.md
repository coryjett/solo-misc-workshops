# Flow 3: Elicitation — Working Example

Demonstrates the elicitation trigger: when no upstream OAuth token is available, the gateway returns a `PENDING` status with an elicitation URL.

**Note:** Completing the elicitation (the user opening the URL and authorizing access) requires the Solo Enterprise UI. This example shows the trigger mechanism only.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

## Key config

```yaml
tokenExchange:
  mode: ElicitOnly    # Only elicit, don't try exchange first
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 3 description](../README.md) · [Auth Patterns overview](../../../README.md)
