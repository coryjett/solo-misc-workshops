# Agent Gateway Authorization Patterns

Comprehensive audit of all authorization patterns supported by [Solo Enterprise for Agent Gateway](https://docs.solo.io/agentgateway/2.2.x/).

All patterns documented in **[agentgateway-authz-patterns.md](agentgateway-authz-patterns.md)** (single-page reference) and as individual pages linked below.

## AuthZ Patterns

| Category | Pattern | Description |
|---|---|---|
| **Access Control** | **[RBAC — MCP Tool-Level Access](flows/flow-rbac-mcp-tool-access.md)** | Per-tool access control via CEL expressions on JWT claims for MCP tools |
| | **[RBAC — LLM Route Access](flows/flow-rbac-llm-route-access.md)** | CEL-based access control for LLM backends (per-user/group model access) |
| **Rate Limiting** | **[Rate Limiting — LLM](flows/flow-rate-limit-llm.md)** | Per-user/group token and request rate limits for LLM backends |
| | **[Rate Limiting — MCP](flows/flow-rate-limit-mcp.md)** | Per-user/group rate limits for MCP tool invocations |
| **Guardrails** | **[Regex Guardrails](flows/flow-guardrail-regex.md)** | Regex-based request/response filtering (PII masking, prompt injection detection) |
| | **[Moderation Guardrails](flows/flow-guardrail-moderation.md)** | LLM-based content moderation (OpenAI moderation API) |
| | **[AWS Bedrock Guardrails](flows/flow-guardrail-bedrock.md)** | AWS Bedrock Guardrails integration for content safety |
| | **[Google Model Armor](flows/flow-guardrail-model-armor.md)** | Google Model Armor integration for content safety |
| | **[Webhook Guardrails](flows/flow-guardrail-webhook.md)** | Custom guardrail logic via external webhook |
| | **[Multi-Layered Guardrails](flows/flow-guardrail-multi-layer.md)** | Composing multiple guardrail types in sequence |
| **Network Policy** | **[CORS](flows/flow-cors.md)** | Cross-origin resource sharing policy configuration |

## Reference

- [Agent Gateway Docs](https://docs.solo.io/agentgateway/2.2.x/)
- [Enterprise API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/)
- [OSS API Reference](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/)
- [Helm Values Reference](https://docs.solo.io/agentgateway/2.2.x/reference/helm/agentgateway/)
