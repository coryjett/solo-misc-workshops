# Flow 4b: Double OAuth Flow (Eager) — Working Example

Deploys the **eager** double-OAuth config: the MCP backend advertises the gateway's
own OAuth issuer, so a spec-compliant MCP client runs the full OAuth handshake
**up front** — downstream login → gateway consent screen → upstream OAuth — with no
`PENDING` URL and no separate approval UI.

**What `setup.sh` does headlessly:** stands up k3d + AGW Enterprise + Keycloak,
registers the `agw-issuer` client, sets the controller `KGW_OAUTH_ISSUER_CONFIG`
(issuer + `consent`), wires the `/oauth-issuer` route, and deploys the eager MCP
backend + elicitation Secret + policy. It then verifies the **eager discriminator**:
connecting to `/mcp/upstream` returns `401` + protected-resource metadata pointing
at the gateway issuer.

**What needs a browser** (interactive — like flow-04's Enterprise UI step): the
consent screen + upstream OAuth completion. See [Completing the flow](#completing-the-flow).

> ⚠️ **Not run end-to-end against a live cluster by the author.** The config is built
> from the [MCP consent screen](https://docs.solo.io/agentgateway/latest/mcp/token-exchange/elicitations/consent-screen/)
> guide, **with one deliberate deviation**: this example **omits** `tokenExchange.mode`
> (the doc uses `ElicitationOnly`). See [the `mode` finding](#tokenexchangemode--code-verified) — `ElicitationOnly` does not inject the upstream token.

## Prerequisites

- Docker, kubectl, helm, curl, jq
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`
- A real upstream MCP OAuth provider to complete the flow (defaults target Atlassian).
  Override with `UPSTREAM_BASE_URL`, `UPSTREAM_SCOPES`, `UPSTREAM_CLIENT_NAME`.

## Run

```bash
./setup.sh
```

## Key config — what makes it eager

The eager-vs-lazy switch is **not** `tokenExchange.mode`. It is the MCP backend
advertising the gateway issuer in its protected-resource metadata:

```yaml
# on the AgentgatewayBackend, under policies.mcp.authentication
mode: Strict                       # inbound JWT required up front
resourceMetadata:
  agentgateway.dev/issuer-proxy: "http://…:7777/oauth-issuer"   # ← the discriminator
  authorizationServers: ["http://<GW_ADDR>/mcp/upstream"]
  resource: "http://<GW_ADDR>/mcp/upstream"
```

Remove that `resourceMetadata` issuer advertising and the flow degrades to **lazy**
elicitation (STS `PENDING` URL on first tool call) — i.e. [flow-04](../../flow-04-double-oauth/).

Consent is controlled at two levels:

```yaml
# controller KGW_OAUTH_ISSUER_CONFIG
"consent": { "enabled": true, "force_refresh": false, "platform_name": "…" }
```
```yaml
# per-backend elicitation Secret (overrides controller defaults)
consent_platform_name / consent_logo_url / consent_legal_text
consent_disabled: "true"   # opt THIS backend out, even when consent is enabled globally
```

### `tokenExchange.mode` — code-verified

The published consent-screen guide sets `mode: ElicitationOnly`. **That does not inject
the upstream token.** Verified in the data plane (`crates/agentgateway/src/proxy/token_exchange.rs`):

```
expand_mode -> (should_exchange, should_elicit)
  ExchangeOnly      => (true,  false)   # inject upstream token, no elicit
  ElicitOnly        => (false, true)    # elicit only — NO injection
  <omitted/Unspec.> => (true,  true)    # inject AND elicit   ← this example
```

The only upstream `Authorization` write (`handle_request`, ~line 347) is gated on
`should_exchange`; the inbound JWT is stripped only when exchanging
(`extract_incoming_token`, ~line 273). So with `ElicitationOnly` the upstream MCP
server receives the **inbound Keycloak JWT**, not the user's Atlassian/GitHub token —
the delegation silently doesn't happen.

**This example omits `mode`** (default = exchange + elicit) so the upstream token is
actually injected. `ExchangeOnly` also injects but disables the data-plane elicit
fallback. Treat the doc's `ElicitationOnly` as drift; still re-confirm on your exact
AGW build, since this was read from source, not run live.

## Completing the flow

The consent + upstream OAuth legs are browser-driven. Use the
[MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) (or VS Code /
Cursor / Claude Code):

```bash
npx @modelcontextprotocol/inspector#0.21.2
```

1. **Transport:** `Streamable HTTP`. **URL:** `http://localhost:8888/mcp/upstream`. Click **Connect**.
2. The Inspector opens your browser for OAuth. **Log in to Keycloak** (`testuser` / `testuser`).
3. The gateway renders the **consent screen** (your `platform_name` / logo / legal text). Click **Allow**.
4. The browser is redirected to the **upstream provider's** OAuth page — authorize there.
5. The Inspector reconnects; list/call the upstream MCP tools. The gateway injects the stored upstream token.

Consent is recorded per `(user, backend)` for the refresh-token lifetime — reconnects
reuse it. Set `consent.force_refresh: true` to prompt every time.

## Cleanup

```bash
source ../../common/cleanup.sh
kubectl delete gateway flow-04b-gateway -n agentgateway-system 2>/dev/null || true
```

Back to [Flow 4b description](../README.md) · [Auth Patterns overview](../../../README.md)
