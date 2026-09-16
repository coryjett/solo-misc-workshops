#!/usr/bin/env bash
# Run INSIDE the keycloak pod: kubectl exec -i -n keycloak deploy/keycloak -- bash < 00-setup-realm.sh
# Creates realm agent-demo: alice (agent-x-users) + bob, confidential client with
# groups claim and a may_act claim authorizing the agent identity (RFC 8693 delegation).
set -e
AGENT_SA="${AGENT_SA:-system:serviceaccount:wp-a:default}"   # the agent's k8s identity
KC=/opt/keycloak/bin/kcadm.sh
for i in $(seq 1 60); do
  $KC config credentials --server http://localhost:8080 --realm master --user admin --password admin && break
  echo "waiting for keycloak admin api ($i)"; sleep 5
done
$KC create realms -s realm=agent-demo -s enabled=true
$KC create groups -r agent-demo -s name=agent-x-users
for u in alice bob; do
  $KC create users -r agent-demo -s username=$u -s enabled=true -s email=$u@example.com \
    -s emailVerified=true -s firstName=$u -s lastName=Demo -s 'requiredActions=[]'
  $KC set-password -r agent-demo --username $u --new-password pw
done
GID=$($KC get groups -r agent-demo --fields id,name | grep -B1 agent-x-users | grep '"id"' | cut -d'"' -f4)
AID=$($KC get users -r agent-demo -q username=alice --fields id | grep '"id"' | cut -d'"' -f4)
$KC update users/$AID/groups/$GID -r agent-demo -s realm=agent-demo -s userId=$AID -s groupId=$GID -n
$KC create clients -r agent-demo -s clientId=agw-client -s enabled=true -s publicClient=false \
  -s secret=agw-client-secret -s directAccessGrantsEnabled=true -s protocol=openid-connect
CID=$($KC get clients -r agent-demo -q clientId=agw-client --fields id | grep '"id"' | cut -d'"' -f4)
cat > /tmp/groups-mapper.json <<JSON
{ "name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
  "config": { "claim.name": "groups", "full.path": "false", "id.token.claim": "true", "access.token.claim": "true" } }
JSON
$KC create clients/$CID/protocol-mappers/models -r agent-demo -f /tmp/groups-mapper.json
cat > /tmp/mayact-mapper.json <<JSON
{ "name": "may-act", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
  "config": { "claim.name": "may_act", "claim.value": "{\"sub\":\"$AGENT_SA\"}",
    "jsonType.label": "JSON", "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false" } }
JSON
$KC create clients/$CID/protocol-mappers/models -r agent-demo -f /tmp/mayact-mapper.json
echo REALM-READY
