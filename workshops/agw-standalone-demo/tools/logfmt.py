"""Formats the standalone gateway's access log as a readable audit trail: who called which tool or model, tokens,
cost, and what happened. Reads the gateway log on stdin (./logs.sh)."""
import re, sys

def g(line, key):
    m = re.search(r'(?:^|\s)' + re.escape(key) + r'=("[^"]*"|\S+)', line)
    return m.group(1).strip('"') if m else ""

for line in sys.stdin:
    if "\trequest " not in line or "protocol=" not in line:
        continue
    t, user, group, status = line[11:19], g(line, "user") or "anonymous", g(line, "group"), g(line, "http.status")
    who = f"{user}/{group}" if group else user
    err = g(line, "error")
    reason = g(line, "reason")
    proto = g(line, "protocol")
    if proto == "llm":
        asked = g(line, "agw.ai.original_model") or g(line, "gen_ai.request.model")
        got = g(line, "gen_ai.response.model")
        toks = f"in={g(line, 'gen_ai.usage.input_tokens')} out={g(line, 'gen_ai.usage.output_tokens')}" if got else ""
        cost = g(line, "agw.ai.usage.cost.total") or g(line, "gen_ai.usage.cost") or g(line, "agw.ai.cost")
        note = f"{reason}: {err}" if err else ""
        print(f"{t}  {who:28} LLM  asked={asked:13} answered={got or '-':28} {toks:16} {('$' + cost) if cost else '':10} {status} {note}", flush=True)
    elif proto == "mcp":
        method = g(line, "mcp.method.name")
        if method not in ("tools/list", "tools/call") and status not in ("401", "403"):
            continue
        tool, target = g(line, "gen_ai.tool.name"), g(line, "mcp.target")
        what = f"{target}/{tool}" if tool else ""
        note = f"{reason}: {err}" if err else ""
        print(f"{t}  {who:28} MCP  {method or 'http':11} {what:32} {status} {note}", flush=True)
    elif proto == "http" and g(line, "http.path").startswith("/api/"):
        note = f"{reason}: {err}" if err else ""
        print(f"{t}  {who:28} API  {g(line, 'http.method'):4} {g(line, 'http.path'):40} {status} {note}", flush=True)
