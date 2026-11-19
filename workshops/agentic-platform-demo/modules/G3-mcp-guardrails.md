# G3 · Guardrails on tool calls: block destructive tools, mask PII

**Area:** MCP · **Time:** 4 min

**Proves:** Platform rules no tool may break: destructive tools blocked for everyone, personal data masked in results.

**Needs:** S0.

## Steps

```bash
export MCP_URL=$GW_URL/mcp
./mcp.py eng-dev call records_lookup_customer '{"customer_id":"C-1001"}'         # DOB and phone masked
./mcp.py eng-dev call records_delete_customer_record '{"customer_id":"C-1001"}'  # blocked
```
Editor: `gateway/22-guardrails.yaml`.

## In the UI

MCP Inspector as eng-dev on `/mcp`: run `records_lookup_customer` with `C-1001` and show the masked fields. Solo UI **Policies**: `mcp-guardrails`.

## Expect

`[DOB REDACTED]`, `[PHONE REDACTED]`; the delete returns "destructive tools are not available".

## Say

- Masking happens on the response, before the data reaches the AI client or the model.

## Cleanup

None: this module only reads or calls things; it leaves no state behind.
