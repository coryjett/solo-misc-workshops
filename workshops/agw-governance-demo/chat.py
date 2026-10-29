#!/usr/bin/env python3
"""Tiny OpenAI-compatible chat client for the demo (any app pointed at the gateway works the same way).
  ./chat.py <user|none> <model> "<prompt>"
Gets a Keycloak token for <user> (password = username), calls localhost:8081/v1/chat/completions, prints who answered."""
import json, os, sys, time, urllib.request, urllib.parse, urllib.error

ISSUER = os.environ.get("OIDC_ISSUER", "http://keycloak.localhost:8080/realms/demo")
URL = os.environ.get("LLM_URL", "http://localhost:8081/v1/chat/completions")

def token(user):
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "mcp-inspector", "username": user,
                                   "password": user, "scope": "openid"}).encode()
    return json.load(urllib.request.urlopen(ISSUER + "/protocol/openid-connect/token", data))["access_token"]

user, model, prompt = sys.argv[1], sys.argv[2], sys.argv[3]
h = {"content-type": "application/json"}
if user != "none":
    h["Authorization"] = "Bearer " + token(user)
body = {"model": model, "max_tokens": 200, "stream": True, "messages": [{"role": "user", "content": prompt}]}
t0 = time.time()
try:
    resp = urllib.request.urlopen(urllib.request.Request(URL, json.dumps(body).encode(), h), timeout=120)
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}: {e.read().decode()[:300]}"); sys.exit(0)
answered_by, text = None, []
for line in resp:  # stream: print words as they arrive
    if not line.startswith(b"data:") or b"[DONE]" in line:
        continue
    chunk = json.loads(line[5:])
    answered_by = chunk.get("model") or answered_by
    for c in chunk.get("choices") or []:
        piece = (c.get("delta") or {}).get("content") or ""
        if piece:
            if not text: print(f"[{user} asked for {model}; answered by {answered_by}]", flush=True)
            text.append(piece); print(piece, end="", flush=True)
print(f"\n[{time.time()-t0:.1f}s]")
