# R3 · A change request and its approval

**Area:** Registry · **Time:** 6 min

**Proves:** Developers request, they do not publish; an approver sees the diff and approves.

**Needs:** S0 (reset stages the pending item). Two windows: eng-dev (Incognito) and admin.

## Steps

Registry UI (eng-dev): **Catalog** > **Administrative Requests**: `release-readiness-checker 2.0.0` pending, Withdraw only.
Registry UI (admin): **Administrative Requests** > open it (diff of what changes) > **Approve**. Open 2.0.0 > **Agent Composition**: the new `data-masking-mcp` dependency.

## Expect

Pending for eng-dev; approved by admin; 1.0.0 was served until approval.

## Say

- 2.0.0 moves the data class from pii to restricted: exactly what a human should review.
