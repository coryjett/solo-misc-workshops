# Mutual TLS (mTLS) Authentication

Two independent TLS features that can be used separately or combined for end-to-end TLS:

- **FrontendTLS (inbound mTLS):** Clients authenticate by presenting an X.509 certificate during the TLS handshake. The gateway validates the client certificate against a trusted CA root configured in the listener's `TLSConfig.root`. No application-layer credentials needed — the TLS handshake itself is the authentication. If the client cert is invalid or missing, the connection is refused at the TLS layer (no HTTP reached).

- **BackendTLSPolicy (outbound TLS origination):** The gateway originates a new TLS connection to the backend, verifying the backend's server certificate against `caCertificateRefs` (ConfigMap) or `wellKnownCACertificates: System`. Used when backends only accept TLS connections (in-cluster or external services).

> **Docs:** [Set up mTLS (FrontendTLS)](https://docs.solo.io/agentgateway/2.2.x/setup/listeners/mtls/) · [BackendTLS](https://docs.solo.io/agentgateway/2.2.x/security/backendtls/)
> **API:** [TLSConfig](https://docs.solo.io/agentgateway/2.2.x/reference/api/api/#tlsconfig) · [BackendTLSPolicy](https://docs.solo.io/agentgateway/2.2.x/reference/api/solo/#backendtls)

![Diagram](../images/mtls.png)

Back to [Auth Patterns overview](../README.md)
