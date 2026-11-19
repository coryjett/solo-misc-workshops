"""Minimal A2A protocol v0.3 agent for a gateway demo (standard library only)."""

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AGENT_NAME = os.getenv("AGENT_NAME", "agent-a")
AGENT_DESC = os.getenv("AGENT_DESC", f"{AGENT_NAME} demo agent")
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:8000/")
PEERS = [tuple(p.split("=", 1)) for p in os.getenv("PEERS", "").split(",") if "=" in p]
TOKEN_URL = os.getenv("TOKEN_URL", "")
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")

_skill_id = f"{AGENT_NAME}-skill"
_skill_desc = AGENT_DESC
if PEERS:
    _peer_names = ", ".join(p[0] for p in PEERS)
    _skill_desc = f"{AGENT_DESC}; delegates to peers: {_peer_names}"

CARD = {
    "name": AGENT_NAME,
    "description": AGENT_DESC,
    "url": PUBLIC_URL,
    "version": "1.0.0",
    "protocolVersion": "0.3.0",
    "preferredTransport": "JSONRPC",
    "capabilities": {"streaming": False},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [
        {
            "id": _skill_id,
            "name": AGENT_NAME,
            "description": _skill_desc,
            "tags": ["a2a", "demo"],
        }
    ],
}

_token_cache = {"token": None, "expires_at": 0.0}


def get_token():
    now = time.time()
    if _token_cache["token"] and _token_cache["expires_at"] > now + 30:
        return _token_cache["token"]
    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
    ).encode()
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
    token = payload["access_token"]
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + int(payload.get("expires_in", 3600))
    return token


def caller(handler):
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return "anonymous"
    jwt = auth[len("Bearer ") :].strip()
    try:
        payload_b64 = jwt.split(".")[1]
        pad = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode())
    except Exception:
        return "anonymous"
    client = payload.get("azp") or payload.get("client_id") or ""
    user = payload.get("preferred_username", "")
    if client and user:
        return f"{client} ({user})"
    if client:
        return client
    if user:
        return user
    return "anonymous"


def first_text_part(obj):
    try:
        for part in obj.get("result", {}).get("parts", []):
            if part.get("kind") == "text" or part.get("type") == "text":
                return part.get("text", "")
    except Exception:
        pass
    return ""


def text_from_message(message):
    parts = message.get("parts", [])
    texts = []
    for p in parts:
        if p.get("kind") == "text" or p.get("type") == "text":
            texts.append(p.get("text", ""))
    return " ".join(texts)


def peer_call(peer_name, peer_url, text):
    try:
        token = get_token()
    except Exception as e:
        return f"  -> {peer_name}: error getting token: {e}"

    body = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "messageId": str(uuid.uuid4()),
                "role": "user",
                "parts": [{"kind": "text", "text": text}],
            }
        },
    }
    req = urllib.request.Request(
        peer_url,
        data=json.dumps(body).encode(),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        return f"  -> {peer_name}: " + first_text_part(data).replace("\n", "\n     ")
    except urllib.error.HTTPError as e:
        return f"  -> {peer_name}: DENIED by gateway (HTTP {e.code})"
    except Exception as e:
        return f"  -> {peer_name}: error {e}"


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
            self._send_json(200, CARD)
            print(f"{AGENT_NAME} GET {self.path} -> card")
        elif self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            print(f"{AGENT_NAME} GET {self.path} -> ok")
        else:
            self._send_json(404, {"error": "not found"})
            print(f"{AGENT_NAME} GET {self.path} -> 404")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw.decode())
        except Exception:
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            print(f"{AGENT_NAME} POST {self.path} -> parse error")
            return

        method = req.get("method")
        rid = req.get("id")

        if method != "message/send":
            self._send_json(
                200,
                {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}},
            )
            print(f"{AGENT_NAME} POST {self.path} -> unknown method {method}")
            return

        params = req.get("params", {}) or {}
        message = params.get("message", {}) or {}
        text = text_from_message(message)
        ctx = message.get("contextId") or str(uuid.uuid4())
        who = caller(self)

        lines = [f"{AGENT_NAME} handled: {text}", f"{AGENT_NAME} was called by: {who}"]
        for name, url in PEERS:
            lines.append(peer_call(name, url, text))

        reply_text = "\n".join(lines)
        result = {
            "kind": "message",
            "messageId": str(uuid.uuid4()),
            "role": "agent",
            "contextId": ctx,
            "parts": [{"kind": "text", "text": reply_text}],
        }
        self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": result})
        print(f"{AGENT_NAME} POST {self.path} -> handled from {who}")

    def log_message(self, format, *args):
        return


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    print(f"{AGENT_NAME} listening on :8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
