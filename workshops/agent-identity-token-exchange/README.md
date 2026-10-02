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

| Part | | Manifests |
|---|---|---|
| [Part 1](WORKSHOP.md#part-1--the-delegation-chain) | The delegation chain | [`01-agent-authz.yaml`](01-agent-authz.yaml), [`02-mcp-authz.yaml`](02-mcp-authz.yaml) |
| [Part 2](WORKSHOP.md#part-2--exchange-for-a-delegated-token) | Exchange at the built-in STS | [`sts-values.yaml`](sts-values.yaml) |
| [Part 3](WORKSHOP.md#part-3--exchange-at-your-okta-authorization-server) | Exchange at your own Okta authorization server | |
| [Part 4](WORKSHOP.md#part-4--multiple-identity-providers) | Two identity providers, audience binding | [`00-setup-realm-multi.sh`](00-setup-realm-multi.sh), [`40-multi-idp-policy.yaml`](40-multi-idp-policy.yaml) |
| [Part 5](WORKSHOP.md#part-5--consent-across-multiple-mcp-servers) | Consent across MCP servers (design walkthrough) | |
| [Part 6](WORKSHOP.md#part-6--which-claims-survive-the-exchange) | Which claims survive | |
| [Appendix](WORKSHOP.md#appendix--running-with-a-real-external-idp-as-the-subject-issuer) | A real external IdP as subject issuer | [`50-okta-agent-authz.yaml`](50-okta-agent-authz.yaml), [`51-sts-values-okta.yaml`](51-sts-values-okta.yaml) |

Parts 1, 2, 4 and 6 need only a cluster. **Part 3 needs Okta to perform the exchange**, which
requires the token-exchange grant on the service app and in the access policy rule, and a
subject token Okta itself issued: measured with a control, Okta refuses a subject token minted
by another IdP. **Any flow that crosses identity providers therefore uses the built-in STS**,
per the appendix.

## Flow

| | Step | File |
|---|---|---|
| 1 | Which path your tenant supports | [`PRECONFIG.md` Step 0a](PRECONFIG.md#step-0a--confirm-the-grant-is-enabled-do-this-first) |
| 2 | Okta setup: A1, A2, A5. A3 and A4 only for Part 3 | [`PRECONFIG.md` Part A](PRECONFIG.md#part-a--okta-configuration) |
| 3 | Local cluster | [`00-kind.sh`](00-kind.sh) |
| 4 | Gateway API CRDs, Agentgateway, test client (needs `LICENSE_KEY`) | [`00-platform.sh`](00-platform.sh), [`00-client.yaml`](00-client.yaml) |
| 5 | Identity provider and realm | [`00-keycloak.yaml`](00-keycloak.yaml), [`00-setup-realm.sh`](00-setup-realm.sh) |
| 6 | Per-hop authorization | [`01-agent-authz.yaml`](01-agent-authz.yaml), [`02-mcp-authz.yaml`](02-mcp-authz.yaml) |
| 7 | Run the workshop | [`WORKSHOP.md`](WORKSHOP.md) from [Part 1](WORKSHOP.md#part-1--the-delegation-chain) |

## Prerequisites

- A cluster, or Docker and `kind`
- `kubectl`, `helm`, `jq`, `envsubst`
- A Solo enterprise license key
- For Part 3 only: an Okta tenant, configured per [`PRECONFIG.md`](PRECONFIG.md)

Written against Enterprise Agentgateway **v2026.9.0**. [`WORKSHOP.md`](WORKSHOP.md) records
which parts are clean-room verified and which are not.
