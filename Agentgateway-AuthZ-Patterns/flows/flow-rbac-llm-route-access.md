# RBAC — LLM Route Access Control

CEL-based access control applied to LLM backend routes. After authentication, the gateway evaluates CEL expressions against JWT claims to determine whether a user or group can access a specific LLM provider or model. For example, restrict GPT-4 access to `premium` tier users while allowing GPT-3.5 for all authenticated users.

> **Docs:** [CEL-based RBAC](https://docs.solo.io/agentgateway/2.2.x/llm/rbac/)
> **API:** [EnterpriseAgentgatewayPolicy](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#enterpriseagentgatewaytrafficpolicy)

![Diagram](../images/rbac-llm-route-access.png)

Back to [AuthZ Patterns overview](../README.md)
