# R2 · Who sees what in the catalog

**Area:** Registry · **Time:** 3 min

**Proves:** Teams see and deploy only their own items plus shared platform items.

**Needs:** S0. Incognito window signed in as eng-dev.

## Steps

Registry UI (eng-dev): **Catalog** shows engineering and shared items only, no sales items.
Optional terminal: `./who-sees-what.sh`

## Expect

eng-dev sees no sales agents.

## Say

- Scoping is an access policy on identity-provider groups (`policies/teams.yaml`).

## Cleanup

None: this module only reads or calls things; it leaves no state behind.
