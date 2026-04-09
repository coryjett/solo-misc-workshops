# Snowflake Token Exchange Workshop

Demonstrates credential isolation for agentic AI: a user authenticates via OIDC, Agent Gateway exchanges the JWT for an opaque token, and the mock Snowflake MCP server validates the opaque token via Keycloak introspection. The sensitive backend never sees the original JWT.

## Architecture

```
User (browser)
  │
  ▼
oauth2-proxy ──► kagent UI ──(JWT)──► AGW Enterprise ──(opaque token)──► kagent Agent Pod
                                          │                                    │
                                          │ token exchange                     │ direct
                                          ▼                                    ▼
                                      Keycloak                       Mock Snowflake MCP Server
                                          ▲                                    │
                                          │ introspection                      │
                                          └────────────────────────────────────┘
```

### How it works

1. **User opens kagent UI** → oauth2-proxy redirects to Keycloak OIDC login
2. **User authenticates** → Keycloak returns JWT → oauth2-proxy proxies to kagent UI
3. **User chats** with the Snowflake Analyst agent
4. **kagent sends request** with JWT → **AGW** (via `proxy.url`)
5. **AGW exchanges JWT** for an opaque token at Keycloak (RFC 8693 token exchange)
6. **AGW forwards** the opaque token → **kagent Agent Pod**
7. **Agent calls** `query_sales` or `list_tables` → **Mock Snowflake MCP server**
8. **Snowflake MCP introspects** the opaque token against Keycloak
9. **Results returned** with introspection metadata proving credential isolation

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- `export OPENAI_API_KEY="<your-openai-key>"`

## Quick Start

```bash
./setup.sh
```

Then open `http://localhost:8080`, log in as `testuser` / `testuser`, select the **Snowflake Analyst** agent, and ask "Show me the sales data".

## What to look for

The agent's response includes **introspection metadata** alongside the query results:

```json
{
  "token_type": "opaque",
  "introspection": {
    "active": true,
    "sub": "testuser",
    "scope": "openid email",
    "client_id": "agw-exchange"
  },
  "query_result": [
    {"region": "WEST", "total_sales": 142500},
    {"region": "EAST", "total_sales": 198300}
  ]
}
```

This proves:
- The Snowflake MCP server received an **opaque token** (not a JWT)
- It validated the token by calling Keycloak's **introspection endpoint**
- It knows the user's identity (`sub: testuser`) without ever seeing the original JWT

## Cleanup

```bash
./cleanup.sh
```
