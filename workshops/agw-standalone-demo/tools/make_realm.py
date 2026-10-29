"""Builds the Keycloak realm JSON for the demo. Usage: make_realm.py <realm> <company> <owui_url> <secrets_dir>
Creates (once) a fixed RSA signing key and the Open WebUI client secret in <secrets_dir>, so Keycloak restarts
keep the same signing key (a changed key breaks gateway JWT validation until its JWKS cache refreshes)."""
import json, os, secrets, subprocess, sys

realm, company, owui, sdir = sys.argv[1:5]
os.makedirs(sdir, mode=0o700, exist_ok=True)
key, crt, sec = (os.path.join(sdir, f) for f in ("realm-signing.key", "realm-signing.crt", "openwebui-client.secret"))
if not os.path.exists(key):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                    "-days", "3650", "-subj", "/CN=agw-demo"], check=True, capture_output=True)
if not os.path.exists(sec):
    open(sec, "w").write(secrets.token_urlsafe(24))
for f in (key, crt, sec):
    os.chmod(f, 0o600)
pem = lambda p: "".join(l for l in open(p).read().splitlines() if not l.startswith("-----"))

def user(i, u, first, last, group):
    return {"id": f"00000000-0000-0000-0000-0000000002{i:02d}", "username": u, "enabled": True, "emailVerified": True,
            "email": f"{u}@{company.lower()}-demo.example", "firstName": first, "lastName": last,
            "credentials": [{"type": "password", "value": u, "temporary": False}], "groups": [f"/{group}"]}

mappers = [
    {"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
     "config": {"claim.name": "groups", "full.path": "false", "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}},
    {"name": "aud-agentgateway", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
     "config": {"included.custom.audience": "agentgateway", "access.token.claim": "true", "id.token.claim": "false"}},
]
print(json.dumps({
    "realm": realm, "displayName": f"{company} SSO", "enabled": True, "sslRequired": "none",
    "accessTokenLifespan": 28800, "ssoSessionIdleTimeout": 36000, "ssoSessionMaxLifespan": 86400,
    "groups": [{"name": "support"}, {"name": "operations"}, {"name": "security"}],
    "users": [user(1, "support-agent", "Pat", "Support", "support"),
              user(2, "ops-manager", "Sam", "Operations", "operations"),
              user(3, "security-analyst", "Alex", "Security", "security")],
    "clients": [
        {"clientId": "mcp-inspector", "name": "Demo CLI / MCP client", "enabled": True, "publicClient": True,
         "directAccessGrantsEnabled": True, "standardFlowEnabled": True,
         "redirectUris": ["http://localhost:6274/*", "http://127.0.0.1:6274/*"], "webOrigins": ["http://localhost:6274", "http://127.0.0.1:6274"],
         "attributes": {"pkce.code.challenge.method": "S256"}, "protocolMappers": mappers},
        {"clientId": "open-webui", "name": "Open WebUI", "enabled": True, "publicClient": False, "secret": open(sec).read().strip(),
         "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "redirectUris": [f"{owui}/oauth/oidc/callback"],
         "webOrigins": [owui], "attributes": {"post.logout.redirect.uris": f"{owui}/*"}, "protocolMappers": mappers},
    ],
    "components": {"org.keycloak.keys.KeyProvider": [{"name": "demo-fixed-rsa", "providerId": "rsa", "subComponents": {},
        "config": {"privateKey": [pem(key)], "certificate": [pem(crt)], "priority": ["200"], "enabled": ["true"],
                   "active": ["true"], "algorithm": ["RS256"]}}]},
}, indent=2))
