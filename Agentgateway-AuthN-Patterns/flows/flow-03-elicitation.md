# Flow 3: Elicitation (Credential Gathering for Upstream APIs)

When a request needs to call an upstream API on behalf of a user but no upstream OAuth token is available yet, the gateway triggers an elicitation. The proxy returns the **elicitation URL** to the client with a `PENDING` status. The user opens that URL in the **Solo Enterprise UI** to complete the upstream OAuth flow (e.g., GitHub authorization). Once the elicitation is `COMPLETED`, the client retries the original request and the gateway injects the stored upstream token.

### How it works

1. **Client sends request** (needs upstream OAuth token) → Agentgateway Proxy
2. **Proxy requests upstream token** → Token Exchange Server (STS)
3. **STS returns elicitation URL** (status: `PENDING`) → Proxy
4. **Proxy returns elicitation URL** (status: `PENDING`) → Client
5. **User opens the elicitation URL** in the Solo Enterprise UI → completes the OAuth authorization flow with the external provider
6. **STS stores the upstream token** (status: `COMPLETED`)
7. **Client retries the original request** → Proxy fetches the stored token from STS → forwards the request with the injected upstream OAuth token
8. **Upstream API responds** → Proxy returns the result to the client

> **Docs:** [Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/elicitations/) · [About OBO & Elicitations](https://docs.solo.io/agentgateway/2.2.x/security/obo-elicitations/about/)
> **API:** [TokenExchangeMode](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#tokenexchangemode)

![Diagram](../images/3-elicitation.png)

Back to [Auth Patterns overview](../README.md)
