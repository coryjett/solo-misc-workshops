# G4 · Token flow: on-behalf-of, the backend never sees the user's token

**Area:** Identity · **Time:** 4 min

**Proves:** The user's identity reaches the backend, but as a short-lived token the gateway issued, not the raw sign-in token.

**Needs:** S0.

## Steps

```bash
export MCP_URL=$GW_URL/frontdoor/mcp
./mcp.py sales-dev call workiq_whoami '{}'
```

## In the UI

MCP Inspector as sales-dev on `/frontdoor/mcp`: run `workiq_whoami`. Solo UI **Policies**: `frontdoor-mcp-obo`.

## Expect

"caller: sales-dev (sub ...); token issued by enterprise-agentgateway...:7777" (the gateway's token service).

## Say

- Three hops: user signs in to the IdP (Keycloak here; Entra, Okta, Ping in production); the gateway validates and authorizes; the gateway exchanges (RFC 8693) and the backend gets a token for the same user.

## Don't claim

- An exchange performed by the customer's IdP (for example Entra's OBO grant) is not shown here: offer a working session on their tenant.
