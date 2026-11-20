# R2 · Who sees what in the catalog

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R1](R1-registry-catalog.md) · Next: [R3](R3-registry-approval.md)
<!-- nav:end -->

**Area:** Registry · **Time:** 3 min

## Framing

- Teams need to see only resources relevant to their specific work.
- Everyone seeing everything is noise, and a risk when entries describe sensitive data.
- Next: two developers, two different catalogs.

**Proves:** Teams see and deploy only their own items plus shared platform items.

**Needs:** [S0](S0-preflight.md). Incognito window on http://localhost:12121/are/, signed in as eng-dev (password `eng-dev`).

## Steps

Registry UI (eng-dev): **Catalog** shows engineering and shared items only, no sales items.
Optional terminal: `./who-sees-what.sh`

- Look for: no sales agents in eng-dev's catalog.

## Say

- Scoping is an access policy on identity-provider groups (`policies/teams.yaml`).

## Cleanup

None: this module only reads or calls things; it leaves no state behind.

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R1](R1-registry-catalog.md) · Next: [R3](R3-registry-approval.md)
<!-- nav:end -->
