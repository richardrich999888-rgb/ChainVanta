# policy-engine

Status: **Partially implemented.** `exceptions/` is implemented; `policies/`, `evaluators/` and
`rule-versioning/` remain planned.

`exceptions/` projects append-only finding events into an effective status per
(assessment, rule) at an injected evaluation instant:

1. The latest event wins (`createdAt`, then event id as a deterministic tie-break, matching the
   repository's `DISTINCT ON ... ORDER BY created_at DESC, id DESC`).
2. `excepted` with `expiresAt <= now` reverts to `open` with basis `expired-exception`.
   A missing expiry is treated as expired (fail closed).
3. No event means `open` with basis `default`.

Effective status is a review workflow state, not a risk score.

See the [root README](../../README.md) for the working milestone and activation criteria.
