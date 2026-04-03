# Double OAuth Flow (OIDC + Elicitation)

Two sequential user-facing OAuth flows orchestrated by the gateway. First, the user authenticates via OIDC (downstream) to get a bearer JWT. Then, when the gateway needs to call an upstream API requiring separate OAuth credentials, it triggers an elicitation — the user completes a second OAuth flow (upstream) via the Solo Enterprise UI to authorize access. The STS stores the upstream token, and subsequent requests are forwarded with both the downstream JWT (for gateway auth) and the injected upstream token (for API access).

> **Docs:** [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/) · [Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/elicitations/)
> **API:** [TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode)

![Diagram](../images/4-double-oauth.png)

Back to [Auth Patterns overview](../README.md)
