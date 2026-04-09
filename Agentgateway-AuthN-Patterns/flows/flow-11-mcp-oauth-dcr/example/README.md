# Flow 11: MCP OAuth + Dynamic Client Registration — Working Example

MCP clients register dynamically via DCR, complete OAuth, then connect with a JWT. This example deploys the full infrastructure and tests both the discovery endpoints and authenticated MCP access.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- Optional: Node.js 18+ for MCP Inspector

## Run

```bash
./setup.sh
```

## Full DCR flow with MCP Inspector

After setup, connect with an MCP client to test the full DCR + OAuth flow:

```bash
npx @modelcontextprotocol/inspector@latest
# URL: http://localhost:8888/mcp
# Transport: Streamable HTTP
```

The inspector will discover the OAuth endpoints, register dynamically, and prompt you to log in via Keycloak.

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [Flow 11 description](../README.md) · [Auth Patterns overview](../../../README.md)
