#!/usr/bin/env bash
# Generates a little fresh traffic so the observability and audit modules have something to show on
# their own: MCP tool calls (allowed and refused), one A2A delegation, one LLM call. Quiet; one summary line.
set -uo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"; cd "$DIR"; . ./env.sh >/dev/null 2>&1
MCP_URL=$GW_URL/mcp ./mcp.py eng-dev call records_lookup_customer '{"customer_id":"C-1001"}' >/dev/null 2>&1
MCP_URL=$GW_URL/frontdoor/mcp ./mcp.py eng-dev call github_list_repos '{}' >/dev/null 2>&1
MCP_URL=$GW_URL/frontdoor/mcp ./mcp.py sales-dev call workiq_send_mail '{"to":"x@example.com","subject":"s","body":"b"}' >/dev/null 2>&1
UT="$(are_token sales-dev)"
curl -s -o /dev/null -H "Authorization: Bearer $UT" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"kind":"message","messageId":"t1","role":"user","parts":[{"kind":"text","text":"status check"}]}}}' \
  "$GW_URL/a2a/agent-a/"
./chat.py eng-dev auto 'In one sentence, what is an API gateway?' >/dev/null 2>&1
echo "traffic sent: MCP (allowed + refused), A2A (agent-a to b and c), LLM; give the UI about 15 seconds"
