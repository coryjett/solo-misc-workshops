# G4 · Token flow: on-behalf-of, the backend never sees the user's token

<!-- nav:start -->
[All modules](README.md) · [Identity](README.md#identity) · Previous: [G3](G3-mcp-guardrails.md) · Next: [G5](G5-mcp-tool-search.md)
<!-- nav:end -->

**Area:** Identity · **Time:** 4 min

## Framing

- Backends need to know who is acting without handling raw login tokens.
- Passing the user's own credentials to every service spreads them far and wide.
- Next: the backend sees the real user, with a token the gateway issued.

**Proves:** The user's identity reaches the backend, but as a short-lived token the gateway issued, not the raw sign-in token.

**Needs:** [S0](S0-preflight.md).

## Steps

```bash
export MCP_URL=$GW_URL/frontdoor/mcp
./mcp.py sales-dev call workiq_whoami '{}'
```

- The caller is sales-dev.
- `token issued by enterprise-agentgateway...:7777`: the gateway's token service, not the IdP.

**Then in the UI**

- MCP Inspector: `./inspector.sh sales-dev http://localhost:8081/frontdoor/mcp`. Then open http://127.0.0.1:6274 and click **Connect**.
- Run `workiq_whoami` (no arguments).
- Solo UI **Policies**: `frontdoor-mcp-obo`.

## Say

- Three hops: sign in to the IdP (Keycloak here; Entra, Okta or Ping in production), the gateway validates, then exchanges the token (RFC 8693).
- The backend gets a token for the same user, never the original.

## Don't claim

- An exchange performed by the customer's IdP (for example Entra's OBO grant) is not shown here: offer a working session on their tenant.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [Identity](README.md#identity) · Previous: [G3](G3-mcp-guardrails.md) · Next: [G5](G5-mcp-tool-search.md)
<!-- nav:end -->
