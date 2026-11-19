#!/usr/bin/env bash
# End-to-end check: UI, browser-style OIDC login (PKCE, real Keycloak form post), arctl as admin,
# approval workflow (non-admin submit -> pending -> admin approve), audit events. Cleans up after itself.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_QUIET=1 . "$DIR/env.sh"
FAILED=0; pass() { echo "PASS  $*"; }; fail() { echo "FAIL  $*"; FAILED=1; }
TEST=verify-approval-probe

# 1. UI shell + runtime config served from the Mac URL
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$ARE_UI_URL/")
CFG_ISS=$(curl -s "$ARE_UI_URL/env-config.js" | sed -n 's/.*"OIDC_ISSUER":"\([^"]*\)".*/\1/p')
[ "$CODE" = 200 ] && [ "$CFG_ISS" = "$OIDC_ISSUER" ] && pass "UI $ARE_UI_URL/ HTTP $CODE, UI issuer $CFG_ISS" || fail "UI HTTP $CODE issuer '$CFG_ISS'"

# 2. Browser login flow exactly as the UI does it: discovery via the server proxy, PKCE auth request,
#    Keycloak login form post, code exchange at Keycloak from the UI origin (CORS), then whoami.
OUT=$(ARE_UI_URL="$ARE_UI_URL" python3 - admin admin <<'PY'
import base64, hashlib, html, http.cookiejar, json, os, re, secrets, sys, urllib.parse, urllib.request
ui=os.environ["ARE_UI_URL"]; user,pw=sys.argv[1],sys.argv[2]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k): return None
class LoopbackPolicy(http.cookiejar.DefaultCookiePolicy):
    # Keycloak 26 marks cookies Secure even on http; browsers accept that on *.localhost, urllib does not.
    def return_ok_secure(self, cookie, request): return True
jar=http.cookiejar.CookieJar(policy=LoopbackPolicy())
op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),NoRedirect)
def get(u,data=None,headers={}):
    r=urllib.request.Request(u,data=data,headers=headers)
    try: resp=op.open(r)
    except urllib.error.HTTPError as e: resp=e
    return resp.status, resp.headers, resp.read().decode()
_,_,body=get(ui+"/api/oidc/discovery"); disc=json.loads(body)
ver=secrets.token_urlsafe(48); chal=base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
redirect=ui+"/callback"
q=urllib.parse.urlencode({"client_id":"are-cli","scope":"openid email profile","response_type":"code","state":"s1",
  "code_challenge":chal,"code_challenge_method":"S256","redirect_uri":redirect})
st,_,page=get(disc["authorization_endpoint"]+"?"+q)
m=re.search(r'action="([^"]+)"',page); assert st==200 and m, "no login form (HTTP %s)"%st
st,h,_=get(html.unescape(m.group(1)),urllib.parse.urlencode({"username":user,"password":pw}).encode())
loc=h.get("Location","")
assert st==302 and loc.startswith(redirect), "login post HTTP %s -> %s"%(st,loc[:120])
code=urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]
st,h,body=get(disc["token_endpoint"],urllib.parse.urlencode({"grant_type":"authorization_code","client_id":"are-cli",
  "code":code,"redirect_uri":redirect,"code_verifier":ver}).encode(),{"Origin":ui})
tok=json.loads(body); acao=h.get("Access-Control-Allow-Origin")
assert "access_token" in tok, body[:200]
claims=json.loads(base64.urlsafe_b64decode(tok["access_token"].split(".")[1]+"=="))
st,_,who=get(ui+"/v0/user/whoami",headers={"Authorization":"Bearer "+tok["access_token"]})
print("issuer=%s groups=%s CORS=%s whoami_http=%s whoami=%s"%(claims["iss"],claims.get("groups"),acao,st,who[:300]))
PY
)
RC=$?
echo "      $OUT"
[ $RC = 0 ] && grep -q "whoami_http=200" <<<"$OUT" && grep -q "CORS=$ARE_UI_URL" <<<"$OUT" && pass "browser OIDC login for admin (PKCE + form post + token exchange + whoami)" || fail "browser OIDC login"

# 3. arctl as admin
ADMIN=$(are_token admin); CLIN=$(are_token eng-dev)
OUTG=$(ARCTL_API_TOKEN=$ADMIN arctl get mcps 2>&1); RC=$?
echo "$OUTG" | sed 's/^/      /'
[ $RC = 0 ] && pass "arctl get mcps as admin" || fail "arctl get mcps as admin"

# 4. Approval workflow
cat > "$DIR/.verify-mcp.yaml" <<EOF
apiVersion: ar.dev/v1alpha1
kind: MCPServer
metadata:
  name: $TEST
  tag: "0.0.1"
spec:
  title: verify probe
  description: Temporary object created by verify.sh; deleted at the end.
  remote:
    type: streamable-http
    url: http://example.invalid/mcp
EOF
OUTA=$(ARCTL_API_TOKEN=$CLIN arctl apply -f "$DIR/.verify-mcp.yaml" 2>&1); echo "      eng-dev apply: $OUTA"
PEND=$(curl -s -H "Authorization: Bearer $ADMIN" "$ARE_UI_URL/v0/approve")
echo "      pending (admin view): $(python3 -c 'import json,sys; print([(i.get("kind"),i.get("name"),i.get("tag"),i.get("state") or i.get("status"),i.get("submittedBy")) for i in json.load(sys.stdin)["items"]])' <<<"$PEND")"
VISIBLE_BEFORE=$(ARCTL_API_TOKEN=$ADMIN arctl get mcps 2>/dev/null | grep -c "$TEST")
grep -q "\"name\":\"$TEST\"" <<<"$PEND" && [ "$VISIBLE_BEFORE" = 0 ] && pass "non-admin apply staged for approval, not in catalog yet" || fail "staging (visible_before=$VISIBLE_BEFORE)"
DENY=$(curl -s -X POST -H "Authorization: Bearer $CLIN" -H 'Content-Type: application/json' \
  -d "{\"action\":\"approve\",\"items\":[{\"kind\":\"MCPServer\",\"namespace\":\"default\",\"name\":\"$TEST\",\"tag\":\"0.0.1\"}]}" "$ARE_UI_URL/v0/approve")
ITEM=$(python3 -c "import json,sys; i=[x for x in json.load(sys.stdin)['items'] if x['name']=='$TEST'][0]; print(json.dumps({k:i[k] for k in ('kind','namespace','name','tag')}))" <<<"$PEND" 2>/dev/null)
APR=$(curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "{\"action\":\"approve\",\"items\":[$ITEM]}" "$ARE_UI_URL/v0/approve")
echo "      eng-dev self-approve: $DENY"
echo "      admin approve: $APR"
sleep 1
ARCTL_API_TOKEN=$ADMIN arctl get mcps 2>/dev/null | grep "$TEST" | sed 's/^/      /'
ARCTL_API_TOKEN=$ADMIN arctl get mcps 2>/dev/null | grep -q "$TEST" && grep -q '"status":"approved"' <<<"$APR" && grep -q '"status":"failed"' <<<"$DENY" && pass "eng-dev cannot self-approve; admin approved, now in catalog" || fail "approve"

# 5. Audit events reached ClickHouse through the telemetry collector
AUD=$(kubectl --context "$KCTX" -n agentregistry-system exec agentregistry-enterprise-clickhouse-shard0-0 -- clickhouse-client --password password -d agentregistry \
  -q "SELECT count() FROM otel_logs_json WHERE Timestamp > now() - INTERVAL 15 MINUTE AND positionCaseInsensitive(toString(LogAttributes), '$TEST') > 0" 2>&1)
[ "${AUD:-0}" -gt 0 ] 2>/dev/null && pass "audit events for the probe in ClickHouse: $AUD" || fail "audit events in ClickHouse: $AUD"

# Cleanup
ARCTL_API_TOKEN=$ADMIN arctl delete mcp "$TEST" --tag 0.0.1 >/dev/null 2>&1
curl -s -o /dev/null -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"action\":\"revoke\",\"items\":[{\"kind\":\"MCPServer\",\"namespace\":\"default\",\"name\":\"$TEST\",\"tag\":\"0.0.1\"}]}" "$ARE_UI_URL/v0/approve"
rm -f "$DIR/.verify-mcp.yaml"
LEFT=$(ARCTL_API_TOKEN=$ADMIN arctl get mcps 2>/dev/null | grep -c "$TEST"); PLEFT=$(curl -s -H "Authorization: Bearer $ADMIN" "$ARE_UI_URL/v0/approve" | grep -c "$TEST")
[ "$LEFT" = 0 ] && [ "$PLEFT" = 0 ] && pass "cleanup: probe removed" || fail "cleanup left catalog=$LEFT pending=$PLEFT"

echo; [ $FAILED = 0 ] && echo ALL-PASS || echo SOME-FAILED
exit $FAILED
