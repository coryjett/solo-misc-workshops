# Guardrails — Google Model Armor

Content safety guardrail using Google Cloud Model Armor. The gateway calls the Model Armor `SanitizeUserPrompt` API (and `SanitizeModelResponse` for responses) with a configured template in a GCP project and location. Model Armor evaluates content for jailbreak attempts, malicious URLs, prompt injection, and sensitive data leakage. Returns BLOCK or ALLOW with detailed findings. Applied to requests (pre-LLM), responses (post-LLM), or both.

> **Docs:** [Google Model Armor](https://docs.solo.io/agentgateway/2.2.x/llm/guardrails/google-model-armor/)
> **API:** [ModelArmor](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#modelarmor)

![Diagram](../images/guardrail-model-armor.png)

Back to [AuthZ Patterns overview](../README.md)
