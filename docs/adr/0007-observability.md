# ADR-0007: Observability: schema v1 logs, no metrics endpoint yet

- Status: accepted
- Date: 2026-10-20

## Context

The house observability stack (hikyaku the agent, nisshi the log store, masu the metric store) reads every house service's journal and scrapes its loopback `/metrics`. nisshi's log schema v1 and its ADR 0009 fix how a service writes logs: one JSON object per line on stderr, `v`, `ts` (UTC, RFC 3339, exactly 9 fractional digits), `level`, a kebab-case `event`, optional `msg`, `err` only at `warn` or `error`; names the agent and the store add (`node`, `service`, `stream`, `seq`, `source`, `recv_ts`, `_*`) are reserved. Until now hanko wrote `log/slog` text lines (`msg="certificate valid" certificate=home`), which the agent can only wrap as `line`.

hanko is a oneshot that listens on nothing (ADR-0001): there is no process alive for a scraper between runs. M3 asked for "structured logs with one summary line per run".

## Decision

- **Logs**: `hanko run` and `hanko check` write schema v1 lines on stderr through `internal/logging`, a copy of nisshi's Go reference (`log/slog` JSON handler, a `ReplaceAttr` for the 9-digit UTC `ts` and the lowercase level, empty `msg` dropped, `v:1`). Copied, not shared (nisshi ADR 0004), as genkan does. The usage text for a wrong command line stays plain.
- **Events**:

  | Event | Level | Fields |
  |---|---|---|
  | `config-invalid` | error | `err` |
  | `run-failed` (the run stopped before any certificate: lock file) | error | `err` |
  | `certificate-valid` | info | `certificate`, `not_after` |
  | `certificate-renewing` | info | `certificate`, `reason`, `hosts` |
  | `acme-account-register` | info | `directory` |
  | `certificate-written` | info | `certificate`, `not_after` |
  | `reload-skipped` (unit not active, ADR-0005) | info | `certificate`, `unit` |
  | `reload-failed` | error | `certificate`, `unit`, `err` |
  | `challenge-delete-failed` | warn | `name`, `err` |
  | `certificate-failed` | error | `certificate`, `err` |
  | `run-completed`, once per run that held the lock | info | `certificates`, `renewed`, `failed`, `dur_us` |

  `not_after` is the leaf's expiry in the `ts` format. `run-completed` is the per-run summary of M3, pulled forward; it is written whether certificates failed or not, the exit status (ADR-0001) still says which.
- **No journald rate limit default** in the module: a run writes a few lines per certificate.
- **No `/metrics` now.** A oneshot has nothing to serve between runs. Metrics come with the daemon side (`hanko-ca`, v1, ADR-0004), on the loopback listener of masu's convention (`services.hanko.metrics.listen`). Expected series, future work: `hanko_build_info{version}`, `hanko_certificate_expiry_timestamp_seconds{certificate}`, `hanko_renewals_total{certificate,result}`; `hanko-ca`'s own series are decided with it. Until then, expiry is read from the `not_after` of the last `certificate-valid` or `certificate-written`.

## Alternatives considered

- **Text logs kept.** The agent wraps them as `line`: no field queries, no `event`. Rejected.
- **A textfile for node-exporter-style collection, written by each run.** No such collector in the house stack; a second output format to keep valid. Rejected.
- **`hanko check` silent or plain text.** Owner decision: one format everywhere, like genkan.

## Consequences

- The M1 `nixosTest` matches full `"event":"…"` members and pipes `journalctl _SYSTEMD_UNIT=hanko.service -o cat` and the same for `hanko-renew.service` into `nisshi validate --logs`, after asserting the expected events exist (empty input passes). nisshi is a test-only flake input; never the package or the module.
- An event added later must keep the schema: kebab-case name, `err` only at `warn` or `error`, no reserved field.
- M3's summary-line item is done; `hanko status` and the `OnFailure=` wiring remain.
