apiVersion: v1
kind: Secret
metadata:
  name: okta-client
  namespace: okta-tx
type: Opaque
stringData:
  # From "agw-token-exchange-client" in Okta — Apps → Applications → API Services
  client_id: "${OKTA_CLIENT_ID}"
  client_secret: "${OKTA_CLIENT_SECRET}"
