# Route Claude Code LLM Traffic Through Agentgateway with Okta Auth

Configure Claude Code (the CLI) to send every LLM call through Solo's
**agentgateway enterprise** with a per-user **Okta-issued Bearer JWT**.
The gateway validates the token, applies whatever policies you've
configured (rate limits, prompt guard, observability, audit logging),
and forwards the request to whatever upstream LLM AGW is configured
for (Anthropic, OpenAI, Bedrock, Vertex, Azure OpenAI, self-hosted…)
using its own provider credentials. AGW handles protocol translation,
so the upstream provider doesn't have to match the API shape Claude
Code sends.

End users authenticate with their own Okta identity. The org-wide LLM
API key never lives on a developer's laptop.

## Architecture

```
┌────────────┐   Authorization: Bearer <okta-jwt>   ┌─────────────────┐   upstream's own credential   ┌──────────────┐
│ Claude Code│ ───────────────────────────────────> │ agentgateway    │ ────────────────────────────> │ Any upstream │
│  (CLI)     │   Anthropic Messages API request     │  enterprise     │   (translated to whatever     │ LLM AGW      │
└────────────┘ <─────────────────────────────────── │  - JWT validate │    the upstream expects)      │ supports —   │
                Anthropic Messages API response     │  - rate limit   │ <──────────────────────────── │ Anthropic,   │
                                                    │  - prompt guard │       LLM response            │ OpenAI,      │
                                                    │  - protocol xlat│                               │ Bedrock,     │
                                                    │  - audit log    │                               │ Vertex, …    │
                                                    └─────────────────┘                               └──────────────┘
                       ▲
                       │ apiKeyHelper script runs every N min
                       │ returns fresh JWT (handles refresh transparently)
                       │
              ┌────────┴────────┐
              │ Token source:   │
              │  - oidc-agent   │  (Option A — recommended)
              │  - bash script  │  (Option B — no extra install)
              └─────────────────┘
```

Claude Code's `apiKeyHelper` is a tiny shell command that prints a fresh
bearer token to stdout. Claude Code re-runs it on a TTL you control and
uses the output as the `Authorization` header on every LLM call. You
own what the helper does — anywhere from a one-line wrapper around
`oidc-agent` to a self-contained bash script that talks to Okta directly.

## Prerequisites

1. **Agentgateway enterprise** with an LLM route configured to serve
   Claude Code. The route must:
   - Accept the shape Claude Code sends. By default Claude Code speaks
     **Anthropic Messages API** (`POST /v1/messages`,
     `POST /v1/messages/count_tokens`), so the AGW route exposes those
     paths. If you instead set `CLAUDE_CODE_USE_BEDROCK=1` or
     `CLAUDE_CODE_USE_VERTEX=1`, Claude Code sends the corresponding
     Bedrock or Vertex shape — point the AGW route at the matching
     Claude-Code env var (`ANTHROPIC_BEDROCK_BASE_URL` /
     `ANTHROPIC_VERTEX_BASE_URL`).
   - Validate the incoming Bearer JWT against your Okta JWKS.
   - Forward to whatever upstream LLM you want (Anthropic, OpenAI,
     Bedrock, Vertex, Azure OpenAI, a self-hosted model…). AGW's LLM
     policy handles protocol translation between what the client sent
     and what the upstream expects, so the upstream provider doesn't
     have to match the client-facing shape.
   - Strip the user's `Authorization` header and attach the upstream's
     own credential (`x-api-key` for Anthropic, AWS SigV4 for Bedrock,
     a GCP token for Vertex, etc.) before forwarding.
   - For the Anthropic shape specifically, forward `anthropic-beta` and
     `anthropic-version` headers through.
2. **Okta tenant** with admin access to register an OIDC app.
3. **Claude Code** CLI installed (`npm install -g @anthropic-ai/claude-code` or via your installer).
4. **`jq` + `curl`** for the bash-script option (almost always already present).

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
project (used widely in research computing). Project home:
[github.com/indigo-dc/oidc-agent](https://github.com/indigo-dc/oidc-agent).

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
that can't approve third-party daemons. Uses only `curl` + `jq`. Cache
lives at `~/.okta/claude-code-token` (mode 600).

> **Every Okta auth uses the Device Authorization Grant** — you get a
> short user code, visit a URL on any device, paste the code, approve.
> No localhost listener (works on remote / headless boxes). Requires
> Device Authorization to be enabled on the Okta app — set **Grant
> types** to include `Device Authorization` in the Okta admin console
> (Step 1 above).
>
> The script intentionally does **not** request a refresh token (no
> `offline_access` scope) so every token rollover requires fresh human
> consent. Okta's default access-token TTL is 1 hour — expect a browser
> prompt about that often. If your team wants silent refresh instead,
> switch to Option A (oidc-agent) which manages refresh tokens in
> encrypted storage.

**B1. Save the helper script**

Save the following as `~/bin/get-okta-token-for-claude-code.sh` (or any
path on your `$PATH`) and `chmod +x` it:

<details>
<summary><strong>Click to expand: <code>get-okta-token-for-claude-code.sh</code></strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077   # any file this script creates is mode 600 by default

# Claude Code apiKeyHelper for Okta device-flow authentication.
#
# Required environment variables:
#   OKTA_DOMAIN     - Okta tenant hostname, e.g. dev-12345.okta.com
#                     (no scheme, no path — script normalizes either way)
#   OKTA_CLIENT_ID  - Native app client ID with Device Authorization grant enabled
#
# Cache:  ~/.okta/claude-code-token  (mode 600, full Okta JSON response)
# Stdout: plain access_token  (Claude Code sends as Authorization: Bearer)
# Stderr: all prompts / status / errors  (so stdout is pure token)

TOKEN_CACHE="${HOME}/.okta/claude-code-token"
SCOPE="openid profile"   # no offline_access — every rollover requires fresh consent

: "${OKTA_DOMAIN:?OKTA_DOMAIN environment variable is required}"
: "${OKTA_CLIENT_ID:?OKTA_CLIENT_ID environment variable is required}"

# Normalize OKTA_DOMAIN — accept either "dev-12345.okta.com" or a full URL.
OKTA_DOMAIN="${OKTA_DOMAIN#https://}"
OKTA_DOMAIN="${OKTA_DOMAIN#http://}"
OKTA_DOMAIN="${OKTA_DOMAIN%/}"

DEVICE_URL="https://${OKTA_DOMAIN}/oauth2/default/v1/device/authorize"
TOKEN_URL="https://${OKTA_DOMAIN}/oauth2/default/v1/token"

# Cap polling so a stuck network / abandoned auth flow can't hang Claude
# Code (apiKeyHelper is in the hot path of every LLM call).
POLL_DEADLINE_SECS=600   # 10-min ceiling above Okta's own expires_in
HTTP_TIMEOUT_SHORT=10    # device-authorize, token-poll
HTTP_TIMEOUT_LONG=30     # final token exchange after user approves

is_token_valid() {
  local token_file="$1"
  [[ -f "$token_file" ]] || return 1

  local access_token
  access_token=$(jq -r '.access_token // empty' "$token_file" 2>/dev/null)
  [[ -n "$access_token" ]] || return 1

  # Decode JWT payload (base64url second segment) and check exp.
  # More accurate than tracking expires_at at write time — survives
  # system-clock drift between cache write and read.
  local payload
  payload=$(
    echo "$access_token" | cut -d. -f2 | tr '_-' '/+' |
      awk '{ pad = (4 - length($0) % 4) % 4; for (i=0;i<pad;i++) $0 = $0 "="; print }' |
      base64 -d 2>/dev/null
  ) || return 1

  local exp now
  exp=$(echo "$payload" | jq -r '.exp // 0')
  now=$(date +%s)
  [[ "$exp" -gt $((now + 60)) ]]
}

do_device_flow() {
  local resp device_code user_code verification_uri interval

  resp=$(curl -sf --max-time "$HTTP_TIMEOUT_SHORT" -X POST "$DEVICE_URL" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "client_id=${OKTA_CLIENT_ID}&scope=${SCOPE}") || {
    echo "Failed to initiate device flow (network / Okta unreachable)" >&2
    exit 1
  }

  device_code=$(echo "$resp" | jq -r '.device_code')
  user_code=$(echo "$resp" | jq -r '.user_code')
  verification_uri=$(echo "$resp" | jq -r '.verification_uri_complete // .verification_uri')
  interval=$(echo "$resp" | jq -r '.interval // 5')

  echo "" >&2
  echo "Opening browser for Okta authentication..." >&2
  echo "  URL: ${verification_uri}" >&2
  echo "  Code: ${user_code}" >&2
  echo "" >&2

  # Auto-open browser (macOS: open, Linux: xdg-open). Best-effort — on
  # headless boxes the user copies the URL manually.
  if command -v open &>/dev/null; then
    open "$verification_uri" 2>/dev/null || true
  elif command -v xdg-open &>/dev/null; then
    xdg-open "$verification_uri" 2>/dev/null || true
  fi

  echo "Waiting for authentication..." >&2

  local deadline=$(($(date +%s) + POLL_DEADLINE_SECS))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    sleep "$interval"

    local token_resp error
    token_resp=$(curl -s --max-time "$HTTP_TIMEOUT_LONG" -X POST "$TOKEN_URL" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d "client_id=${OKTA_CLIENT_ID}&device_code=${device_code}&grant_type=urn:ietf:params:oauth:grant-type:device_code")

    error=$(echo "$token_resp" | jq -r '.error // empty')

    case "$error" in
      authorization_pending) continue ;;
      slow_down) interval=$((interval + 5)); continue ;;
      "")
        mkdir -p "$(dirname "$TOKEN_CACHE")"
        chmod 700 "$(dirname "$TOKEN_CACHE")"
        echo "$token_resp" >"$TOKEN_CACHE"
        chmod 600 "$TOKEN_CACHE"

        # Friendly "valid until" line so users know when the next prompt will land.
        local exp_human
        exp_human=$(
          echo "$token_resp" | jq -r '.access_token' | cut -d. -f2 | tr '_-' '/+' |
            awk '{ pad = (4 - length($0) % 4) % 4; for (i=0;i<pad;i++) $0 = $0 "="; print }' |
            base64 -d 2>/dev/null |
            jq -r '.exp | strftime("%Y-%m-%d %H:%M:%S %Z")'
        ) || exp_human="unknown"
        echo "Authentication successful. Token valid until ${exp_human}" >&2
        return 0
        ;;
      *)
        echo "Authentication error: $(echo "$token_resp" | jq -r '.error_description // .error')" >&2
        exit 1
        ;;
    esac
  done

  echo "Device authorization timed out (script ceiling: ${POLL_DEADLINE_SECS}s)" >&2
  exit 1
}

if ! is_token_valid "$TOKEN_CACHE"; then
  do_device_flow
fi

# Plain access token to stdout — Claude Code sends as Authorization: Bearer
jq -r '.access_token' "$TOKEN_CACHE"
```

</details>

**B2. Set the required env vars (add to `~/.zshrc` / `~/.bashrc`)**

```bash
export OKTA_DOMAIN="YOUR-TENANT.okta.com"      # just the hostname — script strips scheme if you paste a URL
export OKTA_CLIENT_ID="0oaXXXXXXXXXXXXXXX"     # Okta native app with Device Authorization grant
```

**B3. Test**

```bash
get-okta-token-for-claude-code.sh
# First run: prints URL + code to stderr, opens your browser, waits for Okta auth
# Subsequent runs: silent — prints fresh JWT from cache to stdout
# When the JWT's exp claim is within 60s: triggers fresh device flow
```

After auth, the JWT lives in `~/.okta/claude-code-token` (mode 600,
directory mode 700). Validity is checked by decoding the JWT's `exp`
claim each call — accurate even when the system clock drifts. When the
token expires (Okta default: 1 hour), the next invocation triggers a
fresh device-flow prompt — see the security note above.

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
ANTHROPIC_AUTH_TOKEN="$(get-okta-token-for-claude-code.sh)" claude
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
  "apiKeyHelper": "get-okta-token-for-claude-code.sh"
}
```

Claude Code re-runs `apiKeyHelper` every 5 minutes (or whatever you set
the TTL to), takes the stdout as the bearer token, and attaches it as
`Authorization: Bearer ...` on every LLM request. Option A serves from
oidc-agent's in-memory cache (silent refresh); Option B serves from its
file cache until the JWT expires, then prompts the user for a fresh
device-flow authentication.

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
rm ~/.okta/claude-code-token
get-okta-token-for-claude-code.sh   # re-auths via device flow
```

### Bash script device-flow URL doesn't open the browser

The script tries `open` (macOS) and `xdg-open` (Linux) automatically. On
remote/headless boxes, copy the URL by hand. Works from any device — you
can authorize the JWT-needing machine from your phone, for example.

### AGW returns `401` with `WWW-Authenticate: Bearer` but token looks fine

JWT validator config on AGW. Quick checks:
- `kubectl get agentgatewaypolicy -A` → find the policy targeting your
  Anthropic route → check `spec.jwt.providers[*]`
- The `issuer` field must match `https://${OKTA_DOMAIN}/oauth2/default` exactly (trailing slash matters)
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
| Auth UX | Browser via localhost listener (one-time) | Device flow: code + URL prompt (works headless) |
| Token storage | Encrypted on disk + held in memory by daemon | Plain JSON file (mode 600) at `~/.okta/claude-code-token` |
| Token rollover | Silent refresh — user doesn't notice | Fresh device-flow prompt every Okta token TTL (default 1h) |
| Security posture | Refresh tokens stored encrypted, ~30-day sliding window | No refresh tokens — every rollover = fresh human consent (auditable) |
| Multi-account support | Native (`oidc-gen <name>` for each account) | One account per script; copy + rename for more |
| Passphrase prompts | Configurable (none with `--pw-store`) | None — uses OS file perms + `umask 077` |
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
rm ~/bin/get-okta-token-for-claude-code.sh
rm -rf ~/.okta/claude-code-token

# Claude Code config
# Remove the apiKeyHelper + env keys from ~/.claude/settings.json
# Remove ANTHROPIC_BASE_URL + CLAUDE_CODE_API_KEY_HELPER_TTL_MS exports
# from ~/.zshrc / ~/.bashrc

# In the Okta admin console, deactivate or delete the OIDC app if no
# longer needed.
```
