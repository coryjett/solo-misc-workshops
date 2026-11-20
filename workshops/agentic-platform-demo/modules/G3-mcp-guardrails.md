# G3 · Guardrails on tool calls: block destructive tools, mask PII

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [G2](G2-mcp-down-scoped-saas.md) · Next: [G4](G4-token-flow-obo.md)
<!-- nav:end -->

**Area:** MCP · **Time:** 4 min

## Framing

- Companies fear AI tools accidentally deleting critical data or exposing private information.
- Those checks belong outside the model, where a clever prompt cannot talk its way past them.
- Next: a destructive tool blocked and personal details masked, even for an authorized user.

**Proves:** Platform rules no tool may break: destructive tools blocked for everyone, personal data masked in results.

**Needs:** [S0](S0-preflight.md).

## Steps

**1. Look up a customer**

```bash
export MCP_URL=$GW_URL/mcp
./mcp.py eng-dev call records_lookup_customer '{"customer_id":"C-1001"}'
```
- Sensitive fields like DOB and phone are redacted.
- Masking occurs before data reaches the client.

**2. Try a delete**

```bash
./mcp.py eng-dev call records_delete_customer_record '{"customer_id":"C-1001"}'
```
- Delete operation returns policy violation error.
- Destructive tools remain unavailable for this user.

Editor:
- `gateway/22-guardrails.yaml`.

## In the UI

- MCP Inspector as eng-dev on `/mcp`: run `records_lookup_customer` with `C-1001`.
- Point at the masked fields.
- Solo UI **Policies**: `mcp-guardrails`.

## Expect

`[DOB REDACTED]`, `[PHONE REDACTED]`; the delete returns "destructive tools are not available".

## Say

- Masking happens on the response, before the data reaches the AI client or the model.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [MCP](README.md#mcp) · Previous: [G2](G2-mcp-down-scoped-saas.md) · Next: [G4](G4-token-flow-obo.md)
<!-- nav:end -->
