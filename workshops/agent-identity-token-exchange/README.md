# Agent Identity and Token Exchange

Securing an agentic call chain with Solo Enterprise for Agentgateway on a local KinD cluster:
a user authenticates, an agent calls MCP servers on their behalf, and every hop authorizes on
a signed claim rather than a header.

## Objectives

- Authorize each hop (user to agent, agent to MCP) on JWT claims with CEL
- Exchange the user token for a delegated token via RFC 8693, carrying **`sub`** for the user
  and **`act`** for the agent, separately inspectable
- Keep the user's original credential from travelling past the gateway
- Bind tokens to an audience, so a token minted for one MCP server is refused by another
- Accept two identity providers on one route and identify users by issuer, not group name
- Show which claims survive the exchange, and why

## Scope

| Part | Min | |
|---|---|---|
| Step 0 | 10 | Will your Okta tenant exchange a token issued by a different IdP |
| 1 | 20 | The delegation chain |
| 2 | 20 | Exchange at the built-in STS |
| 3 | 25 | Exchange at your own Okta authorization server |
| 4 | 20 | Two identity providers, audience binding |
| 5 | 15 | Consent across MCP servers (design walkthrough) |
| 6 | 5 | Which claims survive |
| Appendix | | A real external IdP as subject issuer |

Parts 1, 2, 4 and 6 need only a cluster. **Steps 0 and 3 require an Okta tenant whose
authorization server advertises the token-exchange grant**; where it does not, the appendix
reaches the same outcome with the IdP issuing and the built-in STS exchanging.

## Flow

```
1. PRECONFIG.md, Step 0a      which path your tenant supports
2. PRECONFIG.md, Part A       Okta setup, if Steps 0 and 3 are in scope
3. ./00-kind.sh               local cluster
4. ./00-platform.sh           Gateway API CRDs, Agentgateway, test client   (needs LICENSE_KEY)
5. 00-keycloak.yaml + 00-setup-realm.sh
6. 01-agent-authz.yaml, 02-mcp-authz.yaml
7. WORKSHOP.md from Part 1
```

## Prerequisites

- A cluster, or Docker and `kind`
- `kubectl`, `helm`, `jq`, `envsubst`
- A Solo enterprise license key
- For Steps 0 and 3 only: an Okta tenant, configured per `PRECONFIG.md`

Written against Enterprise Agentgateway **v2026.9.0**. `WORKSHOP.md` records which parts are
clean-room verified and which are not.
