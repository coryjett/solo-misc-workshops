# Mutual TLS (mTLS) Authentication

Two independent TLS features that can be used separately or combined for end-to-end TLS:

- **FrontendTLS (inbound mTLS):** Clients authenticate by presenting an X.509 certificate during the TLS handshake. The gateway validates the client certificate against a trusted CA root configured in the listener's `TLSConfig.root` field (proto) / `spec.tls.frontend.default.validation.caCertificateRefs` (Gateway resource). Two mTLS modes are supported: `Strict` (default — reject invalid/missing certs) and `AllowInsecureFallback` (accept connections even without a valid client cert). No application-layer credentials needed — the TLS handshake itself is the authentication.

- **BackendTLS (outbound TLS origination):** The gateway originates a new TLS connection to the backend. Configured either as a standalone Kubernetes `BackendTLSPolicy` resource (applied to Services) or inline via the `BackendTLS` field in `EnterpriseAgentgatewayPolicy`. Verifies the backend's server certificate against `caCertificateRefs` (ConfigMap) or `wellKnownCACertificates: System`. Used when backends only accept TLS connections (in-cluster or external services).

> **Docs:** [Set up mTLS (FrontendTLS)](https://docs.solo.io/agentgateway/latest/setup/listeners/mtls/) · [BackendTLS](https://docs.solo.io/agentgateway/latest/security/backendtls/)
> **API:** [FrontendTLS](https://docs.solo.io/agentgateway/latest/reference/api/api/#frontendtls) · [BackendTLS](https://docs.solo.io/agentgateway/latest/reference/api/solo/#backendtls)

### How it works

**Inbound: FrontendTLS (mTLS)**

1. **Client initiates TLS handshake** → `ClientHello` → Agent Gateway
2. **Gateway responds** with `ServerHello` + server certificate + `CertificateRequest` (trusted CA list)
3. **Client presents its X.509 certificate** + `CertificateVerify` → Agent Gateway
4. **Gateway validates the client certificate** against the configured CA root (`TLSConfig.root`)
5. **If the client cert is valid:** mTLS session is established → client requests flow over the encrypted channel
6. **If the client cert is invalid or missing:** TLS handshake fails (connection refused — no HTTP layer reached). In `AllowInsecureFallback` mode, connections without valid certs are still accepted.

**Outbound: BackendTLS (TLS Origination)**

7. **Gateway initiates a new TLS connection** → `TLS ClientHello` → Backend Service (TLS-only)
8. **Backend presents its server certificate** → Agent Gateway
9. **Gateway verifies the backend certificate** against `caCertificateRefs` (ConfigMap) or `wellKnownCACertificates: System`
10. **Gateway forwards the request** over the new TLS connection → Backend
11. **Backend responds** (encrypted) → Agent Gateway → Client

![Diagram](../../images/mtls.png)

> Diagram source: [`../../diagrams/mtls.mmd`](../../diagrams/mtls.mmd)

> **Working Example:** [example/](example/) — deploy from scratch with k3d + AGW Enterprise

Back to [Auth Patterns overview](../../README.md)
