#!/usr/bin/env bash
# For an existing Keycloak that already has the agentregistry realm (for example one built from the
# Agentregistry Enterprise docs): imports only the workshop additions into that realm.
# Usage, from inside the Keycloak pod or anywhere kcadm can reach the server:
#   kubectl exec -i -n keycloak deploy/keycloak -- bash -c 'cat > /tmp/add.json && /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin && /opt/keycloak/bin/kcadm.sh create partialImport -r agentregistry -s ifResourceExists=SKIP -o -f /tmp/add.json' < realm/workshop-additions.json
set -euo pipefail
echo "See the usage line at the top of this file."
