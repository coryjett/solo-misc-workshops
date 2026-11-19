#!/usr/bin/env bash
# Segment 4: what each persona can see, with arctl acting as that user. Read-only.
DIR="$(cd "$(dirname "$0")" && pwd)"; . "$DIR/env.sh" >/dev/null
for u in ${@:-admin auditor eng-dev sales-dev}; do
  as_user "$u" >/dev/null
  echo "################ $u"
  for k in agents mcps models skills prompts; do
    printf '%-8s ' "$k:"; arctl get "$k" -o json 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
items=d if isinstance(d,list) else (d.get("items") or [])
names=sorted({i["metadata"]["name"] for i in items})
print(len(names), " ".join(names) if names else "(none)")'
  done
done
