#!/usr/bin/env bash
# Merge realm/workshop-additions.json into an existing Keycloak realm ConfigMap.
#
# Why this exists: the Agentregistry docs deploy Keycloak with
#   args: ["start-dev", "--import-realm"]
# and an embedded H2 store with no database and no volume. Everything lives in
# memory and only the realm ConfigMap is re-imported at boot, so anything added
# with `kcadm create partialImport` is LOST on every restart, eviction or drain.
# Merging the additions into the ConfigMap makes them survive.
#
# Usage:
#   ./realm/merge-additions.sh <configmap-name> [namespace] [key]
# Example, against the Agentregistry docs install:
#   ./realm/merge-additions.sh keycloak-agentregistry-realm keycloak
#
# It prints the merged ConfigMap to stdout. Review it, then apply and restart:
#   ./realm/merge-additions.sh keycloak-agentregistry-realm keycloak > /tmp/cm.yaml
#   kubectl apply -f /tmp/cm.yaml
#   kubectl rollout restart deploy/keycloak -n keycloak
set -euo pipefail
CM="${1:?configmap name required}"
NS="${2:-keycloak}"
KEY="${3:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"

kubectl get configmap "$CM" -n "$NS" -o json > /tmp/.realm-cm.json
python3 - "$CM" "$NS" "$KEY" "$DIR/workshop-additions.json" <<'PY'
import json, sys
cm_name, ns, key, add_path = sys.argv[1:5]
cm = json.load(open('/tmp/.realm-cm.json'))
data = cm.get('data', {})
if not key:
    cands = [k for k in data if k.endswith('.json')]
    if len(cands) != 1:
        sys.exit(f"cannot pick a key automatically, found {list(data)}; pass one as the 3rd argument")
    key = cands[0]
realm = json.loads(data[key])
add = json.load(open(add_path))

added = []
for section in ('clients', 'groups', 'users'):
    existing = realm.setdefault(section, [])
    ident = 'clientId' if section == 'clients' else ('name' if section == 'groups' else 'username')
    have = {e.get(ident) for e in existing}
    for item in add.get(section, []):
        if item.get(ident) in have:
            continue
        existing.append(item)
        added.append(f"{section[:-1]} {item.get(ident)}")

data[key] = json.dumps(realm, indent=2)
cm['data'] = data
for f in ('resourceVersion', 'uid', 'creationTimestamp', 'managedFields'):
    cm.get('metadata', {}).pop(f, None)
sys.stderr.write(f"merged into {cm_name}/{key}: {len(added)} added\n")
for a in added:
    sys.stderr.write(f"  + {a}\n")
if not added:
    sys.stderr.write("  (nothing to add; already present)\n")
print(json.dumps(cm, indent=2))
PY
rm -f /tmp/.realm-cm.json
