"""Formats gateway access logs as a readable audit trail: who called which tool or model, and what happened."""
import re, sys

def g(line, key):
    m = re.search(re.escape(key) + r'=("[^"]*"|\S+)', line)
    return m.group(1).strip('"') if m else ""

for line in sys.stdin:
    if "mcp-gateway" not in line:
        continue
    t, user, status = line[11:19], g(line, "user") or "anonymous", g(line, "http.status")
    err = g(line, "error") or ""
    if g(line, "http.path") == "/v1/chat/completions" or g(line, "gen_ai.operation.name"):
        asked, got = g(line, "agw.ai.original_model") or g(line, "gen_ai.request.model"), g(line, "gen_ai.response.model")
        toks = f"in={g(line, 'gen_ai.usage.input_tokens')} out={g(line, 'gen_ai.usage.output_tokens')}" if got else ""
        cost = g(line, "agw.ai.usage.cost.total")
        print(f"{t}  user={user:17} LLM   asked={asked:15} answered={got or '-':26} {toks:16} {('$' + cost) if cost else '':11} status={status} {err}", flush=True)
        continue
    method = g(line, "mcp.method.name")
    if method not in ("tools/list", "tools/call") and status != "401":
        continue
    tool, target = g(line, "gen_ai.tool.name"), g(line, "mcp.target")
    what = f"{target}/{tool}" if tool else ""
    print(f"{t}  user={user:17} MCP   {method or 'http':11} {what:34} status={status} {err}", flush=True)
