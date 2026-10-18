# ADR-0006: The state directory is traversable by consumers

- Status: accepted
- Date: 2026-10-18

## Context

ADR-0005 sets `/var/lib/hanko` to `hanko:hanko` mode `0750` and each certificate directory below it to `hanko:<consumer group>` mode `2750`. A consumer reads `/var/lib/hanko/<name>/key.pem` as its own user (genkan ADR 0004 and 0006: `key = "/var/lib/hanko/git/key.pem"`, read through genkan's group). With `0750` on the parent, a user outside group `hanko` cannot traverse `/var/lib/hanko`, so the consumer's group on the certificate directory is never reached: every consumer fails with a permission error. Found while writing the M1 `nixosTest`, whose dummy consumer must read its key.

## Decision

- `/var/lib/hanko` is mode **`0751`** (`StateDirectoryMode` and the tmpfiles rule), owner `hanko:hanko`. Others may traverse it, not list it.
- Nothing else changes: certificate directories stay `2750` with the consumer's group, files `0640`, the ACME account key `0600`. A user outside a certificate's group still cannot open its files or list its directory.

## Alternatives considered

- **Consumers join group `hanko`.** Every consumer could then read every certificate directory's parent and the lock file's name, and the per-certificate group would no longer be the only gate. Rejected.
- **Certificate directories outside the state directory** (e.g. `/var/lib/hanko-certs/<name>`). Same traversal question on the new parent, plus a second writable path in the unit. Rejected.
- **Consumers read through `LoadCredential`.** Needs a restart, not a reload, to pick up a renewed file (credentials are copied at start), against ADR-0001's reload model. Rejected.

## Consequences

- Names of certificate directories are guessable but not listable; their content stays gated by the consumer's group.
- Amends one line of ADR-0005; applied in the module and checked by the M1 `nixosTest` (consumer reads its key, `nobody` does not, the consumer cannot list `/var/lib/hanko`).
