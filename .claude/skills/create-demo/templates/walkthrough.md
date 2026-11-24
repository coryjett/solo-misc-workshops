# <Customer> · <title> · <date> · <time> ET

**Links**
- Meeting: <link>
- Diagram: https://claude.ai/artifact/GioU2sMc25yq8szmCvGgFW#tour-<IDs>
- Modules: `workshops/agentic-platform-demo/modules/`

**Who**
- <name>: <one line>

**What they asked** (<date>)
- <their words, one per bullet>

**Chain:** S0 > <IDs> · about <n> min

| # | Module | Min | For <Customer> |
|---|---|---|---|
| 0 | [S0](<pages URL>/S0-preflight.html) | - | Before the call |
| 1 | [<ID>](<pages URL>/<ID>-<slug>.html) | <n> | <3-6 words tied to their ask> |

**Say**
- <one claim per bullet, true of the running lab>

**Don't claim**
- <limits; copy from the module cards>

**Ask**
- <discovery questions>

**Owed from last call**
- <item>

## Day of

**T-15**
```bash
cd workshops/agentic-platform-demo
./verify.sh && ./verify-gateway.sh && ./reset.sh
. ./env.sh; clear
```

**Terminal 2**
```bash
kubectl --context kind-agentic-demo -n agentgateway-system logs deploy/mcp-gateway -f \
  | grep --line-buffered -E 'protocol=(a2a|mcp|llm)'
```

**Windows**
- Solo UI: http://localhost:8082
- kagent: http://localhost:8084 (sign in beforehand, private window per user)

**Live**
- <module-specific fallbacks>

**Expected refusals**
- No token: `HTTP 401`
- Hidden tool: `unknown resource`
- Guard: `HTTP 403`
