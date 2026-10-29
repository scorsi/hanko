# ADR-0011: `hanko status` and the persisted last run result

- Status: accepted
- Date: 2026-10-29

## Context

M3 asks for `hanko status`: every certificate with issuer, names, expiry and last run result,
read from the files, usable by the deployment's monitoring, and showing a certificate still
valid after a failed run. Issuer and configured hosts are in the configuration (ADR-0002), names
and expiry in `fullchain.pem`, but the outcome of a run lived only in the journal (ADR-0007):
nothing in the state directory recorded it.

## Decision

- **Persisted result**: every run that held the lock writes `<state>/.last-run` once its
  certificates are handled, through the same staged, synced rename as every state file
  (ADR-0009), owner-only (`0600`). It holds the run's UTC time and, for each configured
  certificate, `ok` or `failed` with the error text already logged by `certificate-failed`.
  A run that stops before the lock (`run-failed`) or is killed leaves the previous file. A
  failed write fails the run and logs `last-run-write-failed` (error, `err`); `run-completed`'s
  `failed` still counts certificates only.
- **Command**: `hanko status <config.toml>` reads the state directory with the same checks as
  `run` (ADR-0009), so it runs as the state's owner (user `hanko`); it takes no lock and makes
  no network request. For each configured certificate it writes one schema v1 line (ADR-0007)
  on **stdout**, event `certificate-status`, fields `certificate`, `issuer`, `hosts` (the
  leaf's names), `not_after`, `valid`, `reason` (when not valid: absent, unreadable, key absent
  or not matching, expired or not yet valid, or a directory/file check failure), `last_run`,
  `last_result` (`ok`, `failed`, or `none` when no run has recorded the certificate) and `err`
  (the last run's error). Level `info`, `warn` when the last run failed, `error` when the
  certificate is not valid now. An unreadable state directory or `.last-run` writes
  `status-failed` (error, `err`).
- **Exit status**: 1 when a certificate is not valid now or the state cannot be read, else 0.
  A failed last run alone exits 0: the published pair is still served, and run failures already
  reach the deployment through the unit's exit status and `OnFailure=` (ADR-0001).

## Alternatives considered

- **A human table plus a `--json` flag.** Two formats to keep stable; ADR-0007 already chose
  one format everywhere, and a schema v1 line is readable as is and parseable by `jq` and by
  nisshi when monitoring runs `status` in a unit.
- **Reading the last result from the journal.** Not "from the files", needs journal access and
  depends on retention.
- **A result file per certificate directory.** Misses failures before the directory is opened
  (missing or misprovisioned directory, ADR-0009) and adds a name consumers can list.
- **Non-zero exit on a failed last run.** Duplicates `OnFailure=` and hides the distinction
  M3 asks for: a failed run with a certificate still valid.

## Consequences

- The state directory gains one owner-only file; restoring it from a backup is harmless.
- Monitoring runs `hanko status` as `hanko`, e.g. from a unit with `User=hanko`; wiring it is the
  deployment's job.
