#!/usr/bin/env bash
# Run inside the Keycloak pod:
#   kubectl exec -i -n keycloak deploy/keycloak -- bash -s < 05-setup-realm-registry.sh
# Adds the clients, groups, and users that Agentregistry Enterprise and Solo Enterprise for kagent need
# to the existing agent-demo realm. Idempotent enough to re-run after a Keycloak restart together with 00-setup-realm.sh.
set -e
REALM="${REALM:-agent-demo}"
KC=/opt/keycloak/bin/kcadm.sh
for i in $(seq 1 60); do
  $KC config credentials --server http://localhost:8080 --realm master --user admin --password admin && break
  echo "waiting for keycloak admin api ($i)"; sleep 5
done

for g in admins readers writers agentregistry; do
  $KC create groups -r $REALM -s name=$g 2>/dev/null || true
done
gid() { $KC get groups -r $REALM -q search=$1 --fields id,name | python3 -c "import json,sys; print([g['id'] for g in json.load(sys.stdin) if g['name']=='$1'][0])"; }
uid() { $KC get users -r $REALM -q username=$1 --fields id | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['id'])"; }

mkuser() { # name group
  $KC create users -r $REALM -s username=$1 -s enabled=true -s email=$1@example.com -s emailVerified=true -s firstName=$1 -s lastName=Demo -s 'requiredActions=[]' 2>/dev/null || true
  $KC set-password -r $REALM --username $1 --new-password $1
  $KC update users/$(uid $1)/groups/$(gid $2) -r $REALM -s realm=$REALM -s userId=$(uid $1) -s groupId=$(gid $2) -n
}
mkuser admin-user admins
mkuser reader readers
mkuser writer writers

groups_mapper() { cat <<JSON
{ "name": "Groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
  "config": { "claim.name": "Groups", "full.path": "false", "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true" } }
JSON
}
aud_mapper() { cat <<JSON
{ "name": "ar-backend-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
  "config": { "included.client.audience": "ar-backend", "id.token.claim": "false", "access.token.claim": "true" } }
JSON
}
cid() { $KC get clients -r $REALM -q clientId=$1 --fields id | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['id'])"; }
add_mapper() { # clientId mapper-json
  echo "$2" > /tmp/m.json; $KC create clients/$(cid $1)/protocol-mappers/models -r $REALM -f /tmp/m.json 2>/dev/null || true
}

# Agentregistry Enterprise: backend (confidential) and a public password-grant client for scripted logins.
$KC create clients -r $REALM -s clientId=ar-backend -s enabled=true -s publicClient=false -s secret=ar-backend-secret \
  -s serviceAccountsEnabled=true -s directAccessGrantsEnabled=true -s protocol=openid-connect 2>/dev/null || true
$KC create clients -r $REALM -s clientId=ar-cli-password -s enabled=true -s publicClient=true \
  -s directAccessGrantsEnabled=true -s protocol=openid-connect 2>/dev/null || true
add_mapper ar-backend "$(groups_mapper)"
add_mapper ar-cli-password "$(groups_mapper)"
add_mapper ar-cli-password "$(aud_mapper)"

# Solo Enterprise for kagent: backend (confidential) and UI (public).
$KC create clients -r $REALM -s clientId=kagent-backend -s enabled=true -s publicClient=false -s secret=kagent-backend-secret \
  -s directAccessGrantsEnabled=true -s protocol=openid-connect 2>/dev/null || true
$KC create clients -r $REALM -s clientId=kagent-ui -s enabled=true -s publicClient=true -s 'redirectUris=["*"]' -s 'webOrigins=["*"]' \
  -s 'attributes={"pkce.code.challenge.method":"S256"}' -s protocol=openid-connect 2>/dev/null || true
add_mapper kagent-backend "$(groups_mapper)"
add_mapper kagent-ui "$(groups_mapper)"

# The registry authenticates to the kagent controller with this client (client credentials).
# Its service-account user sits in group agentregistry, which kagent maps to global.Writer.
$KC create clients -r $REALM -s clientId=agentregistry -s enabled=true -s publicClient=false -s secret=agentregistry-secret \
  -s serviceAccountsEnabled=true -s protocol=openid-connect 2>/dev/null || true
add_mapper agentregistry "$(groups_mapper)"
SA=$($KC get clients/$(cid agentregistry)/service-account-user -r $REALM --fields id | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
$KC update users/$SA/groups/$(gid agentregistry) -r $REALM -s realm=$REALM -s userId=$SA -s groupId=$(gid agentregistry) -n
echo REGISTRY-REALM-READY
