"""External STS: RFC 8693 token exchange + RFC 7662 introspection.

Receives a JWT subject_token, extracts claims, issues an opaque token
(random hex string). Stores claims in memory for introspection.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, sys, base64, secrets, urllib.parse


token_store = {}


def decode_jwt_payload(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:
        return {"error": str(e)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/.well-known/oauth-authorization-server':
            self.send_json(200, {
                "issuer": "external-sts",
                "token_endpoint": "http://external-sts.default.svc.cluster.local:9000/token",
                "introspection_endpoint": "http://external-sts.default.svc.cluster.local:9000/introspect",
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
                "token_endpoint_auth_methods_supported": ["none"],
            })
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
        params = urllib.parse.parse_qs(body)
        if self.path == '/token':
            self.handle_exchange(params)
        elif self.path == '/introspect':
            self.handle_introspect(params)
        else:
            self.send_json(404, {"error": "not_found"})

    def handle_exchange(self, params):
        if params.get('grant_type', [''])[0] != 'urn:ietf:params:oauth:grant-type:token-exchange':
            return self.send_json(400, {"error": "unsupported_grant_type"})
        subject_token = params.get('subject_token', [''])[0]
        if not subject_token:
            return self.send_json(400, {"error": "invalid_request"})
        claims = decode_jwt_payload(subject_token)
        if not claims:
            return self.send_json(400, {"error": "invalid_request"})
        opaque = secrets.token_hex(32)
        token_store[opaque] = claims
        sys.stderr.write(
            f"\nTOKEN EXCHANGE: JWT (sub={claims.get('sub', '?')}) "
            f"-> opaque {opaque[:16]}... ({len(token_store)} active)\n"
        )
        sys.stderr.flush()
        self.send_json(200, {
            "access_token": opaque,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 3600,
        })

    def handle_introspect(self, params):
        token = params.get('token', [''])[0]
        claims = token_store.get(token)
        if claims:
            sys.stderr.write(f"INTROSPECT: {token[:16]}... -> active (sub={claims.get('sub')})\n")
            sys.stderr.flush()
            self.send_json(200, {
                "active": True,
                "sub": claims.get('sub'),
                "username": claims.get('preferred_username'),
                "iss": "external-sts",
                "token_type": "Bearer",
                "original_issuer": claims.get('iss'),
            })
        else:
            self.send_json(200, {"active": False})

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    sys.stderr.write("External STS on :9000 (POST /token, POST /introspect, GET /.well-known/oauth-authorization-server)\n")
    sys.stderr.flush()
    HTTPServer(('', 9000), Handler).serve_forever()
