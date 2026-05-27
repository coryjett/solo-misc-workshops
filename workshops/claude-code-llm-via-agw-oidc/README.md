# Route Claude Code LLM Traffic Through Agentgateway with Okta Auth

Configure Claude Code (the CLI) to send every LLM call through Solo's
**agentgateway enterprise** with a per-user **Okta-issued Bearer JWT**.
The gateway validates the token, applies whatever policies you've
configured (rate limits, prompt guard, observability, audit logging),
and forwards the request to the real upstream LLM (Anthropic, Bedrock,
Vertex, etc.) using its own provider credentials.

End users authenticate with their own Okta identity. The org-wide LLM
API key never lives on a developer's laptop.

## Architecture

```
┌────────────┐    Authorization: Bearer <okta-jwt>    ┌─────────────────┐    x-api-key: <org-key>   ┌──────────────┐
│ Claude Code│ ─────────────────────────────────────> │ agentgateway    │ ────────────────────────> │ Anthropic    │
│  (CLI)     │                                        │  enterprise     │                           │ (or Bedrock, │
└────────────┘ <──────────────────────────────────── │  - JWT validate │ <──────────────────────── │  Vertex)     │
                  Anthropic Messages API response     │  - rate limit   │     LLM response          └──────────────┘
                                                      │  - prompt guard │
                                                      │  - audit log    │
                                                      └─────────────────┘
                       ▲
                       │ apiKeyHelper script runs every N min
                       │ returns fresh JWT (handles refresh transparently)
                       │
              ┌────────┴────────┐
              │ Token source:    │
              │  - oidc-agent    │  (Option A — recommended)
              │  - bash script   │  (Option B — no extra install)
              └──────────────────┘
```

Claude Code's `apiKeyHelper` is a tiny shell command that prints a fresh
bearer token to stdout. Claude Code re-runs it on a TTL you control and
uses the output as the `Authorization` header on every LLM call. You
own what the helper does — anywhere from a one-line wrapper around
`oidc-agent` to a self-contained bash script that talks to Okta directly.

## Prerequisites

1. **Agentgateway enterprise** with an Anthropic (or Bedrock / Vertex)
   route in front of an LLM provider. The route must:
   - Accept `POST /v1/messages` and `POST /v1/messages/count_tokens`
     (Anthropic Messages API shape)
   - Validate the incoming Bearer JWT against your Okta JWKS
   - Strip the user's `Authorization` header and re-attach your own
     provider credential (`x-api-key` for Anthropic) before forwarding
   - Forward `anthropic-beta` and `anthropic-version` headers
2. **Okta tenant** with admin access to register an OIDC app
3. **Claude Code** CLI installed (`npm install -g @anthropic-ai/claude-code` or via your installer)
4. **`jq` + `curl`** for the bash-script option (almost always already present)

## Step 1 — Register the OIDC client in Okta

Same Okta app works for both Option A (oidc-agent) and Option B (bash script).
One-time per organization.

1. Okta admin console → **Applications** → **Create App Integration**
2. **OIDC** → **Native Application**
3. Settings:
   - **Grant types**: `Authorization Code`, `Refresh Token`
   - **Sign-in redirect URI**: `http://localhost:8080/callback` *(adjust port if needed; oidc-agent will tell you which one to add during `oidc-gen`; the bash script uses 8800 by default — see below)*
   - **Sign-out redirect URI**: (leave empty)
   - **Controlled access**: assign to the user groups that should be allowed to use Claude Code through AGW
4. Note the resulting **Client ID** — you'll need it in step 2.
5. Confirm your tenant's **Issuer URL** — typically
   `https://YOUR-TENANT.okta.com/oauth2/default` for the default
   authorization server.

> **Optional but recommended**: configure a **custom scope** on the
> Okta auth server (e.g. `agw-llm`) and tell AGW's JWT validator to
> require that scope. Lets you grant Claude Code access without
> implicitly granting everything else the user is authorized for.

## Step 2 — Pick a token-source option

### Option A — `oidc-agent` (recommended for daily use)

Best for users who'll use Claude Code regularly. Handles refresh
transparently, integrates with the OS keyring, audited open-source
project (used widely in research computing).

**A1. Install**

```bash
# macOS
brew install oidc-agent

# Debian / Ubuntu
sudo apt install oidc-agent

# Fedora
sudo dnf install oidc-agent

# Other platforms: see https://github.com/indigo-dc/oidc-agent#installation
```

**A2. Start the daemon (add to your shell profile)**

```bash
# ~/.zshrc or ~/.bashrc
eval "$(oidc-agent-service use)"
```

Reload your shell.

**A3. Bootstrap an account**

```bash
oidc-gen agw-okta
```

You'll be prompted for:

| Prompt | Value |
|---|---|
| Issuer URL | `https://YOUR-TENANT.okta.com/oauth2/default` |
| Client ID | *paste from Okta admin console* |
| Client Secret | *(leave blank — native PKCE app)* |
| Scopes | `openid email profile offline_access` *(plus `agw-llm` if you set a custom scope in Okta)* |
| Redirect URI | accept the default `http://localhost:8080/` or pick another free port |
| Encryption passphrase | *(used to encrypt the on-disk config; remember this)* |

`oidc-gen` will open your default browser, you log into Okta, the agent
captures the authorization code, exchanges it for tokens, and stores
the encrypted refresh token in `~/.config/oidc-agent/agw-okta`.

If you want to skip the passphrase prompt every shell session, append
`--pw-store` so the passphrase lives in your OS keyring:

```bash
oidc-gen agw-okta --pw-store
```

**A4. Test**

```bash
oidc-token agw-okta
# should print a JWT — starts with `eyJ...`
```

`oidc-agent` is now your token source. Skip to **Step 3**.

### Option B — Bash script (no extra install)

Best for one-off testing, ephemeral environments, or organizations
that can't approve third-party daemons. Uses only `curl` + `jq`.
Encrypted-at-rest cache in `~/.cache/agw-okta-token.json` with
`chmod 600`.

> **First-time auth uses Okta's Device Authorization Grant** — you
> get a short user code, visit a URL on any device, paste the code,
> approve. No localhost listener needed (so it works on remote /
> headless boxes). Requires Device Authorization to be enabled on
> the Okta app — set **Grant types** to include `Device Authorization`
> in the Okta admin console (Step 1 above).

**B1. Save the helper script**

Save the following as `~/bin/agw-okta-token` (or any path on your `$PATH`)
and `chmod +x` it:

```bash
#!/usr/bin/env bash
# agw-okta-token — fetch + cache + refresh Okta JWT for use as bearer
# against agentgateway enterprise. Outputs a fresh access token to stdout.
#
# Requires env vars:
#   OKTA_ISSUER     e.g. https://YOUR-TENANT.okta.com/oauth2/default
#   OKTA_CLIENT_ID  the client_id from your Okta OIDC native app
#   OKTA_SCOPE      space-separated scopes; default: "openid email profile offline_access"
set -euo pipefail

: "${OKTA_ISSUER:?must be set}"
: "${OKTA_CLIENT_ID:?must be set}"
SCOPE="${OKTA_SCOPE:-openid email profile offline_access}"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}"
mkdir -p "$CACHE_DIR"
CACHE="$CACHE_DIR/agw-okta-token.json"
EXPIRY_BUFFER=300  # refresh 5 min before actual expiry

now() { date +%s; }

# 1. Cached + fresh? Return it.
if [ -f "$CACHE" ]; then
  EXP=$(jq -r '.expires_at // 0' "$CACHE")
  if [ "$EXP" -gt "$(($(now) + EXPIRY_BUFFER))" ]; then
    jq -r '.access_token' "$CACHE"
    exit 0
  fi
fi

# 2. Have refresh token? Try refresh.
REFRESH=$(jq -r '.refresh_token // empty' "$CACHE" 2>/dev/null || true)
if [ -n "$REFRESH" ]; then
  RESP=$(curl -sf -X POST "$OKTA_ISSUER/v1/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token" \
    -d "refresh_token=$REFRESH" \
    -d "client_id=$OKTA_CLIENT_ID" \
    -d "scope=$SCOPE" 2>/dev/null) || RESP=""
  if [ -n "$RESP" ] && [ "$(echo "$RESP" | jq -r '.access_token // empty')" != "" ]; then
    EXPIRES_IN=$(echo "$RESP" | jq -r '.expires_in')
    EXPIRES_AT=$(($(now) + EXPIRES_IN))
    # Okta rotates refresh tokens — fall back to the previous one if a
    # new one isn't issued, otherwise pick up the new one.
    NEW_REFRESH=$(echo "$RESP" | jq -r '.refresh_token // empty')
    [ -z "$NEW_REFRESH" ] && NEW_REFRESH="$REFRESH"
    echo "$RESP" | jq --argjson e "$EXPIRES_AT" --arg r "$NEW_REFRESH" \
      '. + {expires_at: $e, refresh_token: $r}' > "$CACHE"
    chmod 600 "$CACHE"
    jq -r '.access_token' "$CACHE"
    exit 0
  fi
fi

# 3. No cache or refresh failed — Device Authorization Grant.
#    Prompt the user to authorize on any browser. Works on headless boxes.
echo >&2
echo "── Okta auth required ─────────────────────────────────────" >&2
DEV_RESP=$(curl -sf -X POST "$OKTA_ISSUER/v1/device/authorize" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$OKTA_CLIENT_ID" \
  -d "scope=$SCOPE")

DEVICE_CODE=$(echo "$DEV_RESP" | jq -r '.device_code')
USER_CODE=$(echo "$DEV_RESP" | jq -r '.user_code')
VERIFY_URL=$(echo "$DEV_RESP" | jq -r '.verification_uri_complete // .verification_uri')
INTERVAL=$(echo "$DEV_RESP" | jq -r '.interval // 5')
EXPIRES_IN=$(echo "$DEV_RESP" | jq -r '.expires_in')

echo "1. Open: $VERIFY_URL" >&2
echo "2. Enter code: $USER_CODE" >&2
echo "(expires in $EXPIRES_IN seconds)" >&2
echo >&2

# Open the browser if we're in an interactive desktop session.
if command -v open >/dev/null 2>&1; then
  open "$VERIFY_URL" >/dev/null 2>&1 &
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$VERIFY_URL" >/dev/null 2>&1 &
fi

DEADLINE=$(($(now) + EXPIRES_IN))
while [ "$(now)" -lt "$DEADLINE" ]; do
  sleep "$INTERVAL"
  TOKEN_RESP=$(curl -s -X POST "$OKTA_ISSUER/v1/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    -d "device_code=$DEVICE_CODE" \
    -d "client_id=$OKTA_CLIENT_ID")
  ERR=$(echo "$TOKEN_RESP" | jq -r '.error // empty')
  case "$ERR" in
    authorization_pending|"" )
      # "" means no error and we got a token; check next
      if [ "$(echo "$TOKEN_RESP" | jq -r '.access_token // empty')" != "" ]; then
        EXPIRES_IN=$(echo "$TOKEN_RESP" | jq -r '.expires_in')
        EXPIRES_AT=$(($(now) + EXPIRES_IN))
        echo "$TOKEN_RESP" | jq --argjson e "$EXPIRES_AT" '. + {expires_at: $e}' > "$CACHE"
        chmod 600 "$CACHE"
        echo "── Authorized ✓ ─────────────────────────────────────────" >&2
        jq -r '.access_token' "$CACHE"
        exit 0
      fi
      ;;
    slow_down) INTERVAL=$((INTERVAL + 5)) ;;
    access_denied|expired_token)
      echo "Auth failed: $ERR" >&2
      exit 1
      ;;
    *)
      echo "Unexpected error: $TOKEN_RESP" >&2
      exit 1
      ;;
  esac
done

echo "Device authorization timed out before user completed login" >&2
exit 1
```

**B2. Set the required env vars (add to `~/.zshrc` / `~/.bashrc`)**

```bash
export OKTA_ISSUER="https://YOUR-TENANT.okta.com/oauth2/default"
export OKTA_CLIENT_ID="0oaXXXXXXXXXXXXXXX"
# Optional — defaults to "openid email profile offline_access"
# export OKTA_SCOPE="openid email profile offline_access agw-llm"
```

**B3. Test**

```bash
agw-okta-token
# First run: prints a URL + code, waits for you to authorize in a browser
# Subsequent runs: silent — outputs a fresh JWT from cache/refresh
```

After the first run, the script keeps the refresh token in
`~/.cache/agw-okta-token.json` (mode 600). Okta access tokens typically
last 1 hour; the script transparently uses the refresh token to get
fresh access tokens on demand. Refresh tokens last whatever your Okta
admin configured (typically 30 days, sliding window) — when they
finally expire you'll be prompted to re-authorize.

## Step 3 — Configure Claude Code

Pick one of the following (env-var or settings-file). They do the same thing.

### Env-var approach (per-shell, easy to switch on/off)

Add to `~/.zshrc` / `~/.bashrc`:

```bash
export ANTHROPIC_BASE_URL="https://YOUR-AGW.example.com/anthropic"
export CLAUDE_CODE_API_KEY_HELPER_TTL_MS=300000  # re-run helper every 5 min
```

And run Claude Code with the helper:

```bash
# Option A
ANTHROPIC_AUTH_TOKEN="$(oidc-token agw-okta)" claude

# Option B
ANTHROPIC_AUTH_TOKEN="$(agw-okta-token)" claude
```

Or — better — wire the helper into Claude Code via settings so it re-runs
automatically on the TTL cadence (next section).

### Settings-file approach (recommended for ongoing use)

Edit `~/.claude/settings.json` (global) or `<project>/.claude/settings.json` (per-project):

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://YOUR-AGW.example.com/anthropic",
    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "300000"
  },
  "apiKeyHelper": "oidc-token agw-okta"
}
```

For the bash-script option, swap the `apiKeyHelper` value:

```json
{
  "apiKeyHelper": "agw-okta-token"
}
```

Claude Code re-runs `apiKeyHelper` every 5 minutes (or whatever you set
the TTL to), takes the stdout as the bearer token, and attaches it as
`Authorization: Bearer ...` on every LLM request. Both
options transparently refresh from cache, so the actual latency is
near-zero.

## Step 4 — Verify

```bash
claude
# In the Claude Code prompt, ask it to do something trivial
> hi
```

Then in another terminal, check AGW's access logs to confirm requests
are arriving with the expected user identity:

```bash
kubectl logs -n agentgateway-system deploy/agentgateway -f | grep "/anthropic"
```

You should see entries showing:
- The request path (`/anthropic/v1/messages`)
- The authenticated user (extracted from the JWT's `sub` or `email` claim)
- A 200 response

If you see `401 Unauthorized` instead, the JWT failed validation at the
gateway. Most common causes:
- JWKS URL on the AGW JWT validator doesn't match your Okta tenant
- The required audience / issuer claim doesn't match the AGW config
- The token expired between helper invocations (very rare — both
  options have a 5-min buffer)

## Troubleshooting

### `oidc-add agw-okta` prompts for passphrase every shell

Use `--pw-store` to integrate with the OS keyring:
```bash
oidc-gen agw-okta --reauthenticate --pw-store
```

### `oidc-token agw-okta` says "account not loaded"

The agent restarted (system reboot, terminal closed, etc.). Reload:
```bash
oidc-add agw-okta
```

### Bash script returns the same token even after Okta admin rotated the signing key

The cache is local. Delete it to force a fresh token:
```bash
rm ~/.cache/agw-okta-token.json
agw-okta-token   # re-auths via device flow
```

### Bash script device-flow URL doesn't open the browser

The script tries `open` (macOS) and `xdg-open` (Linux) automatically. On
remote/headless boxes, copy the URL by hand. Works from any device — you
can authorize the JWT-needing machine from your phone, for example.

### AGW returns `401` with `WWW-Authenticate: Bearer` but token looks fine

JWT validator config on AGW. Quick checks:
- `kubectl get agentgatewaypolicy -A` → find the policy targeting your
  Anthropic route → check `spec.jwt.providers[*]`
- The `issuer` field must match your `OKTA_ISSUER` exactly (trailing slash matters)
- The `audiences` list must contain whatever audience your Okta auth
  server is configured to issue (often the auth server's audience setting
  or a custom scope)
- `jwks.uri` must be reachable from inside the AGW pod

### Claude Code never seems to refresh the token

Check the TTL:
```bash
echo $CLAUDE_CODE_API_KEY_HELPER_TTL_MS
```
If unset, Claude Code uses a default (typically 1 hour). For Okta's
1-hour access tokens, set this to 5-10 min so the helper has ample
runway to refresh before the cached token actually expires.

### Want to verify what JWT Claude Code is actually sending?

Point `ANTHROPIC_BASE_URL` temporarily at a request inspector:
```bash
export ANTHROPIC_BASE_URL="https://webhook.site/your-unique-url"
claude
# webhook.site shows the full request including the Authorization header
unset ANTHROPIC_BASE_URL  # restore your AGW URL when done
```

## Comparison: Option A vs Option B

| Aspect | oidc-agent | Bash script |
|---|---|---|
| Initial setup | 5 min, requires `brew install` / `apt install` | 2 min, no install if `curl` + `jq` already present |
| First-time auth UX | Opens browser via localhost listener | Device flow: code + URL prompt (works headless) |
| Token storage | Encrypted on disk + held in memory by daemon | Plain JSON file (mode 600) in `~/.cache/` |
| Refresh handling | Built-in, robust, battle-tested | Inline in the script — adequate but you own it |
| Multi-account support | Native (`oidc-gen <name>` for each account) | One account per script; copy + rename for more |
| Passphrase prompts | Configurable (none with `--pw-store`) | None — uses the OS file permissions for protection |
| Cross-platform | Linux + macOS solid, Windows experimental | macOS + Linux + WSL all fine; Windows native untested |
| Restricted enterprise | May need security approval to install daemon | Plain bash, usually pre-approved |
| Maintenance | Solo doesn't own — community project | You maintain it |

**Recommendation**: start with the bash script for testing / one-off
demos / restricted environments. Move to oidc-agent once you've
validated the end-to-end flow and are using Claude Code through AGW
daily — better operational hygiene long-term.

## What this gets you on the AGW side

Now that Claude Code reaches AGW with a per-user Okta JWT, AGW can:

- **Rate limit per user** (`sub` claim or `email`) instead of per-API-key
- **Apply prompt-guard policies** with per-user / per-group exceptions
- **Audit log every LLM call** with the actual user identity, not a service account
- **Block specific users or groups** by manipulating Okta group membership — instant revocation, no key rotation
- **Token-exchange for downstream services** if your LLM tool-calls hit
  protected APIs (the user's Okta JWT carries identity AGW can exchange
  for whatever downstream credential is needed)

None of these are possible when the developer holds the LLM provider's
raw API key on their laptop.

## Cleanup

To remove everything:

```bash
# Option A
oidc-agent --kill
rm -rf ~/.config/oidc-agent/agw-okta*

# Option B
rm ~/bin/agw-okta-token
rm ~/.cache/agw-okta-token.json

# Claude Code config
# Remove the apiKeyHelper + env keys from ~/.claude/settings.json
# Remove ANTHROPIC_BASE_URL + CLAUDE_CODE_API_KEY_HELPER_TTL_MS exports
# from ~/.zshrc / ~/.bashrc

# In the Okta admin console, deactivate or delete the OIDC app if no
# longer needed.
```
