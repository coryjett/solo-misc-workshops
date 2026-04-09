# Flow: Mutual TLS (mTLS) — Working Example

FrontendTLS (inbound mTLS): clients authenticate with X.509 certificates during the TLS handshake. The gateway validates client certs against a trusted CA root.

## Prerequisites

- Docker, kubectl, helm, curl, jq, openssl
- `export AGENTGATEWAY_LICENSE_KEY="<your-license-key>"`

## Run

```bash
./setup.sh
```

This script:
1. Creates a k3d cluster and installs Enterprise Agentgateway
2. Generates a CA, server cert, and client cert
3. Creates a Gateway with HTTPS listener + mTLS validation
4. Tests: no client cert (rejected), valid client cert (200)

## Key config

```yaml
listeners:
- name: https
  port: 443
  protocol: HTTPS
  tls:
    mode: Terminate
    certificateRefs:
    - name: flow-mtls-server-cert
    options:
      gateway.networking.k8s.io/tls-frontend-validation: |
        caCertificateRefs:
        - name: flow-mtls-ca-cert
```

## Testing

After running `setup.sh`, the gateway is port-forwarded to `localhost:8443`. Cert files are generated in `/tmp/flow-mtls-certs/`:

```bash
CERT_DIR="/tmp/flow-mtls-certs"

# No client cert → rejected
curl -sk -o /dev/null -w "%{http_code}" https://localhost:8443/

# Valid client cert → 200
curl -sk -o /dev/null -w "%{http_code}" \
  --cert "${CERT_DIR}/client.crt" --key "${CERT_DIR}/client.key" \
  https://localhost:8443/
```

## Cleanup

```bash
source ../../common/cleanup.sh
```

Back to [mTLS description](../README.md) · [Auth Patterns overview](../../../README.md)
