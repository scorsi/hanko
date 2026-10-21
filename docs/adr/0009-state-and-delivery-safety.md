# ADR-0009: Verify state and persist delivery failures

- Status: accepted (owner, 2026-10-21)
- Date: 2026-10-21

## Context

Review findings H6–H8 found that existing state could bypass the intended ownership and
permission boundary, and that a failed reload disappeared once the new files were valid.
The latter follows ADR-0001's exit rule but can leave an active consumer serving an old
certificate indefinitely. Batch 2 requests verification and durable delivery failures.

## Decision

- Open the state and certificate directories once and perform reads, staging, renames and
  syncing relative to those handles. Reject a symlink at either boundary. Trusted system
  ancestors such as `/var` may be symlinks; the configured state path is an absolute, clean
  path. Directory ownership must be the process identity; state group is its primary group,
  and no group or other write is permitted. Certificate directories must be exactly `2750`.
- Add required per-certificate `group` metadata to the TOML, generated from the existing Nix
  option. Resolve that name at runtime (numeric gids also work); compare the directory and
  existing files against it, including on runs with nothing due. This supersedes ADR-0002's
  statement that `group` is not in the file and ADR-0005's consequence that a wrong group is
  discovered only by the consumer. hanko gains no supplementary groups or capabilities.
- State reads reject symlinks, special files, hardlinks, unexpected owners/groups and excess
  permissions. The account key remains directly under the state directory, with no group or
  other access; certificate files allow at most `0640`. Secret-provider TSIG symlinks outside
  the state directory remain supported. Unsafe files are refused, never silently chmodded.
- Before an order, persist and sync `.reload-pending` in that certificate's directory. Once
  the pair is installed, attempt each currently configured consumer. Clear and sync the
  marker only after all consumers reload successfully or are confirmed not active. A crash
  before delivery or a reload failure leaves the marker for the next run, which retries
  delivery of a valid pair without ordering another certificate. Retrying consumers that
  already succeeded is intentional; the current configuration remains the authority.
- Each reload gets a separate one-minute deadline under the run's cancellation context,
  independent of the ten-minute issuance deadline and detached DNS cleanup.
- Any delivery failure fails the run and counts that certificate in `failed`; successful
  installation still counts in `renewed`. This supersedes ADR-0001's exit rule for valid files
  and updates the meaning of ADR-0007's existing events; no new event is introduced.
- Query `LoadState`, `ActiveState` and `CanReload` using `systemctl show`. Missing units,
  malformed property responses and command/transport failures are errors. Inactive, failed,
  activating and deactivating consumers are skipped, preserving ADR-0005's boot ordering.
  Restart only with `CanReload=no`; a failed supported reload is never followed by a restart.
  The polkit rule still grants only reload/restart for the configured unit names.

## Alternatives considered

- **Log delivery failures only.** Loses both notification and retry, the defect being fixed.
- **Fail without saving intent.** Triggers OnFailure once but does not recover after a crash.
- **Change ownership or join every consumer group.** Hides provisioning defects and widens
  privilege, contrary to ADR-0005.

## Consequences

- Hand-written configuration must add `group`; the Nix module supplies it automatically.
- Restored files with unsafe ownership, links or permissions now fail even if their
  certificate contents are valid. Correct provisioning is required before retrying.
- Directory handles confine filesystem operations, not privileged mount changes or an
  attacker already running as hanko/root. A correctly provisioned empty replacement is
  indistinguishable from a fresh certificate directory; account continuity still depends
  on ADR-0008 and backups.
- A successful inactive skip is complete delivery: a later start reads the new files.
- Two certificate-file renames remain separate, as in H3/H5; the pair check still recovers an
  interruption between them. Pending intent covers a crash after both renames as well.

## Amendment (2026-10-21): resume an interrupted publication

Review re-check of batch 2 (H3): an interrupted or failed publication between the two renames
spent a CA order to recover. Once an order returns, hanko now replaces the `.reload-pending`
content with the issued chain followed by its key (still `0600`, synced) before publishing.
A later run that finds a matching, not-yet-due pair there which differs from the published
files publishes it again without ordering, then delivers as above. The marker written before
the order keeps holding no pair. Concurrent readers can still observe a mixed pair during the
two renames; consumers are reloaded only after both.
