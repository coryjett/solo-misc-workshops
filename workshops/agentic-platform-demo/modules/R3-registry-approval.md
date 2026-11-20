# R3 · A change request and its approval

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R2](R2-registry-team-scoping.md) · Next: [R4](R4-registry-publish-to-gateway.md)
<!-- nav:end -->

**Area:** Registry · **Time:** 6 min

## Framing

- Developers often publish changes without proper review, leading to compliance issues.
- Manual approval processes are slow and lack clear visibility into modifications.
- Next: a developer's request, and the approver reviewing exactly what changes.

**Proves:** Developers request, they do not publish; an approver sees the diff and approves.

**Needs:** [S0](S0-preflight.md) (reset stages the pending item). Two windows on http://localhost:12121/are/: eng-dev in Incognito (password `eng-dev`) and admin (`admin`).

**Changes state:** approves the staged item. Once per reset.

## Steps

Registry UI (eng-dev): **Catalog** > **Administrative Requests**: `release-readiness-checker 2.0.0` pending, Withdraw only.
Registry UI (admin):
- **Administrative Requests** > open it: the diff of what changes.
- **Approve**.
- Open 2.0.0 > **Agent Composition**: the new `data-masking-mcp` dependency.

- Look for: 1.0.0 stays live until the approval.

## Say

- 2.0.0 moves the data class from pii to restricted: exactly what a human should review.

## Cleanup

```bash
as_user admin; arctl delete agent release-readiness-checker --tag 2.0.0
as_user eng-dev; arctl apply -f catalog/pending/release-readiness-checker-2.0.0.yaml
```
- Deletes the approved 2.0.0, then re-stages the request.

<!-- nav:start -->
[All modules](README.md) · [Registry](README.md#registry) · Previous: [R2](R2-registry-team-scoping.md) · Next: [R4](R4-registry-publish-to-gateway.md)
<!-- nav:end -->
