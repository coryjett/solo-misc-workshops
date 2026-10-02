#!/usr/bin/env bash
# Run INSIDE the keycloak pod:
#   kubectl exec -i -n keycloak deploy/keycloak -- env REALM=idp-a GROUP=agent-x-users bash < 00-setup-realm-multi.sh
#
# Parameterized variant of 00-setup-realm.sh. Creates one realm with one user and one group,
# so the same script can stand up two realms that act as two identity providers.
set -e
REALM="${REALM:?set REALM}"
GROUP="${GROUP:-agent-x-users}"
USERNAME="${USERNAME:-alice}"
AGENT_SA="${AGENT_SA:-system:serviceaccount:wp-a:default}"
KC=/opt/keycloak/bin/kcadm.sh
for i in $(seq 1 60); do
  $KC config credentials --server http://localhost:8080 --realm master --user admin --password admin && break
  echo "waiting for keycloak admin api ($i)"; sleep 5
done
# Idempotent: re-running for an extra user in an existing realm must not fail.
$KC get realms/$REALM >/dev/null 2>&1 || $KC create realms -s realm=$REALM -s enabled=true
$KC create groups -r $REALM -s name=$GROUP >/dev/null 2>&1 || echo "group $GROUP already exists"
$KC create users -r $REALM -s username=$USERNAME -s enabled=true -s email=$USERNAME@example.com \
  -s emailVerified=true -s firstName=$USERNAME -s lastName=Demo -s 'requiredActions=[]' \
  >/dev/null 2>&1 || echo "user $USERNAME already exists"
$KC set-password -r $REALM --username $USERNAME --new-password pw
GID=$($KC get groups -r $REALM --fields id,name | grep -B1 "\"$GROUP\"" | grep '"id"' | cut -d'"' -f4 | head -1)
UID_=$($KC get users -r $REALM -q username=$USERNAME --fields id | grep '"id"' | cut -d'"' -f4 | head -1)
$KC update users/$UID_/groups/$GID -r $REALM -s realm=$REALM -s userId=$UID_ -s groupId=$GID -n
$KC create clients -r $REALM -s clientId=demo-client -s enabled=true -s publicClient=false \
  -s secret=demo-secret -s directAccessGrantsEnabled=true -s protocol=openid-connect \
  >/dev/null 2>&1 || echo "client demo-client already exists"
CID=$($KC get clients -r $REALM -q clientId=demo-client --fields id | grep '"id"' | cut -d'"' -f4 | head -1)
cat > /tmp/g.json <<JSON
{ "name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
  "config": { "claim.name": "groups", "full.path": "false", "id.token.claim": "true", "access.token.claim": "true" } }
JSON
$KC get clients/$CID/protocol-mappers/models -r $REALM 2>/dev/null | grep -q '"groups"' \
  || $KC create clients/$CID/protocol-mappers/models -r $REALM -f /tmp/g.json
cat > /tmp/m.json <<JSON
{ "name": "may-act", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
  "config": { "claim.name": "may_act", "claim.value": "{\"sub\":\"$AGENT_SA\"}",
    "jsonType.label": "JSON", "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false" } }
JSON
$KC get clients/$CID/protocol-mappers/models -r $REALM 2>/dev/null | grep -q '"may-act"' \
  || $KC create clients/$CID/protocol-mappers/models -r $REALM -f /tmp/m.json
echo "REALM-READY $REALM"
