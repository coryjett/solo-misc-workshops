# Snowflake Token Exchange Workshop — Design Spec

## Goal

Demonstrate enterprise security posture for agentic AI: sensitive backends (Snowflake) never see raw JWTs, only opaque tokens they can validate via introspection. A user authenticates once via OIDC, and the token is exchanged for an opaque token before reaching the agent — proving credential isolation across the entire stack.

## Architecture

```
User (browser)
  │
  ▼
kagent UI ──(JWT)──► AGW Enterprise ──(opaque token)──► kagent Agent Pod
                         │                                    │
                         │ token exchange                     │ direct call
                         ▼                                    ▼
                     Keycloak                        Mock Snowflake MCP Server
                         ▲                                    │
                         │ introspection                      │
                         └────────────────────────────────────┘
```

### OIDC Login for kagent UI

kagent OSS does not have built-in OIDC authentication. To gate access to the kagent UI with Keycloak OIDC login, we deploy **oauth2-proxy** in front of kagent's UI service. oauth2-proxy handles the Authorization Code Flow with PKCE, sets a session cookie, and passes the JWT to kagent via the `Authorization` header on proxied requests. kagent UI then includes this JWT when making requests to agent pods (which route through AGW via `proxy.url`).

### Data Flow

1. User opens kagent UI in browser → oauth2-proxy redirects to Keycloak OIDC login
2. User authenticates → Keycloak returns JWT → oauth2-proxy sets session cookie and proxies to kagent UI
3. kagent UI is now authenticated with the user's JWT
4. User chats: "Show me the sales data"
5. kagent UI sends request with user's JWT → AGW (via kagent's `proxy.url` config)
6. AGW validates the JWT against Keycloak's JWKS endpoint
7. AGW exchanges the JWT for an opaque token at Keycloak's token endpoint (RFC 8693 token exchange)
8. AGW forwards the request with the opaque token → kagent Agent Pod
9. Agent Pod decides to call the `query_sales` tool
10. Agent Pod sends request with opaque token → Mock Snowflake MCP server (direct, in-cluster)
11. Snowflake MCP server calls Keycloak's `/token/introspect` endpoint with the opaque token
12. Keycloak returns token metadata: `{active: true, sub: "testuser", scope: "openid email", client_id: "agw-exchange"}`
13. Snowflake MCP server returns query results + introspection metadata → Agent Pod → kagent UI → User

### Key Security Property

The mock Snowflake MCP server never receives or processes a JWT. It only sees an opaque token, which it validates by calling Keycloak's introspection endpoint. This is the credential isolation pattern — the sensitive backend trusts only what the introspection response tells it.

## Components

### 1. Keycloak

**Namespace:** `keycloak`

**Realm:** `snowflake-workshop`

**Clients:**

| Client | Type | Purpose |
|---|---|---|
| `kagent-ui` | Public | Browser-based OIDC login for kagent UI (Authorization Code Flow + PKCE) |
| `agw-exchange` | Confidential | Used by AGW to perform RFC 8693 token exchange. Configured to issue opaque/reference tokens. |

### 1b. oauth2-proxy

**Namespace:** `kagent`

Deployed in front of kagent's UI service. Handles OIDC login with Keycloak, sets a session cookie, and passes the user's JWT to kagent UI via the `Authorization` header.

**Config:**
- Provider: Keycloak OIDC
- Client ID: `kagent-ui` (public client with PKCE)
- Redirect URL: `http://localhost:8080/oauth2/callback`
- Upstream: kagent UI service

### Keycloak Features

**Features required:**
- OIDC Authorization Code Flow with PKCE (for `kagent-ui` client)
- Token exchange grant type (`urn:ietf:params:oauth:grant-type:token-exchange`) enabled on `agw-exchange`
- Opaque/reference token format on `agw-exchange` (not JWT)
- Token introspection endpoint enabled on `agw-exchange`

**Test user:** `testuser` / `testuser`

**Realm config** exported as JSON for repeatable deployment.

### 2. AGW Enterprise

**Namespace:** `agentgateway-system`

**Role:** Sits between kagent UI and kagent Agent Pod. Validates inbound JWT, exchanges it for an opaque token via Keycloak, forwards the opaque token to the Agent Pod.

**Resources:**

| Resource | Purpose |
|---|---|
| `Gateway` | Listener for kagent UI traffic |
| `HTTPRoute` | Routes to the Agent Pod backend |
| `EnterpriseAgentgatewayPolicy` | JWT validation (Keycloak JWKS) + token exchange (Keycloak token endpoint) |

**Token exchange config:**
- Validates the user JWT against Keycloak's JWKS endpoint
- Sends RFC 8693 token exchange request to Keycloak with `subject_token=user JWT`
- Keycloak returns an opaque token
- AGW replaces the Authorization header with the opaque token before forwarding

### 3. kagent OSS

**Namespace:** `kagent`

**Deployment:** Helm chart from `ghcr.io/kagent-dev/kagent/helm/kagent`

**Key Helm values:**
```yaml
proxy:
  url: "http://<agw-gateway-service>.default.svc.cluster.local:80"

providers:
  openAI:
    apiKey: <user-provided>
```

The `proxy.url` setting routes UI-to-Agent traffic through AGW. The controller rewrites internal URLs and sets the `x-kagent-host` header so AGW can route to the correct Agent Pod.

**CRDs:**

| CRD | Name | Purpose |
|---|---|---|
| `Agent` | `snowflake-analyst` | System prompt: "You are a Snowflake data analyst." References Snowflake MCP tools. |
| `ModelConfig` | `openai-config` | OpenAI provider config with user-provided API key |
| `RemoteMCPServer` | `snowflake-mcp` | Points to mock Snowflake MCP server's in-cluster address |

### 4. Mock Snowflake MCP Server

**Namespace:** `default`

**Implementation:** Python HTTP server (same pattern as existing auth flow examples)

**Tools:**

| Tool | Description |
|---|---|
| `query_sales` | Returns mock sales data by region |
| `list_tables` | Returns a list of available mock tables |

**Auth behavior:**
- Extracts the opaque token from the `Authorization: Bearer <token>` header
- Calls Keycloak's introspection endpoint: `POST /realms/snowflake-workshop/protocol/openid-connect/token/introspect` with `token=<opaque_token>&client_id=agw-exchange&client_secret=<secret>`
- If `active: true`, proceeds with the request
- Returns query results alongside introspection metadata so the demo clearly shows what the MCP server learned about the token

**Example response from `query_sales`:**
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
    {"region": "EAST", "total_sales": 198300},
    {"region": "CENTRAL", "total_sales": 167800}
  ]
}
```

**Example response from `list_tables`:**
```json
{
  "token_type": "opaque",
  "introspection": {
    "active": true,
    "sub": "testuser"
  },
  "tables": [
    {"schema": "SALES", "name": "ORDERS", "row_count": 15420},
    {"schema": "SALES", "name": "CUSTOMERS", "row_count": 3200},
    {"schema": "ANALYTICS", "name": "DAILY_REVENUE", "row_count": 365}
  ]
}
```

## Workshop Structure

```
Snowflake-Token-Exchange-Workshop/
├── README.md                  # Workshop overview, architecture, step-by-step guide
├── setup.sh                   # Single script to deploy everything
├── cleanup.sh                 # Tear down k3d cluster
├── keycloak/
│   └── realm-config.json      # Realm export with clients, token exchange, introspection
├── snowflake-mcp/
│   └── server.py              # Mock Snowflake MCP server with introspection
└── k8s/
    ├── snowflake-mcp.yaml     # Deployment + Service for the MCP server
    ├── agw.yaml               # Gateway + HTTPRoute + EnterpriseAgentgatewayPolicy
    └── kagent.yaml            # Agent + ModelConfig + RemoteMCPServer CRDs
```

## Setup Script Flow

`setup.sh` deploys everything from scratch:

1. **Create k3d cluster** (`snowflake-workshop`)
2. **Install Gateway API CRDs**
3. **Install AGW Enterprise** with token exchange enabled
4. **Deploy oauth2-proxy** in front of kagent UI for OIDC login
5. **Deploy Keycloak** with pre-configured realm (`snowflake-workshop`): OIDC clients, token exchange grant, opaque tokens, introspection
6. **Deploy mock Snowflake MCP server** with Keycloak introspection config
7. **Install kagent OSS** via Helm with `proxy.url` pointing at AGW's in-cluster address
8. **Apply kagent CRDs** (Agent, ModelConfig, RemoteMCPServer)
9. **Port-forward oauth2-proxy** to `localhost:8080`
10. **Print instructions** for the user to open the browser and start chatting

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- `export OPENAI_API_KEY="<your-openai-key>"` (or other LLM provider)

## User Experience

1. Run `./setup.sh`
2. Open `http://localhost:8080` in browser
3. Keycloak OIDC login page appears → log in as `testuser` / `testuser`
4. Select the "Snowflake Analyst" agent in kagent UI
5. Chat: "Show me the sales data" or "What tables are available?"
6. Agent calls Snowflake MCP tools → response includes:
   - Mock query results (sales data, table listings)
   - Introspection metadata proving the MCP server received an opaque token and validated it against Keycloak
7. The user can see that the MCP server never received the original JWT — only an opaque token that it verified via introspection

## What This Proves

- **Credential isolation:** The Snowflake MCP server never sees the user's JWT. It only receives an opaque token.
- **Token exchange works:** AGW successfully exchanges the JWT for an opaque token at Keycloak.
- **Introspection validates identity:** The MCP server can still determine who the user is by calling Keycloak's introspection endpoint.
- **End-to-end security:** User identity flows through every hop without exposing the original credential to the sensitive backend.
