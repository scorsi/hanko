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
  | `certificate-renewing` (`reason` includes "key absent or not matching the certificate") | info | `certificate`, `reason`, `hosts`, `not_after` (amended 2026-10-29, see below) |
  | `account-key-missing` (no account key and `create_account` off, ADR-0008; the certificate then fails) | error | `path`, `err` |
  | `acme-account-register` (before the registration request) | info | `directory` |
  | `acme-account` (amended 2026-10-21, see below) | info | `directory`, `uri` |
  | `certificate-written` | info | `certificate`, `not_after` |
  | `reload-skipped` (unit not active, ADR-0005) | info | `certificate`, `unit` |
  | `reload-failed` | error | `certificate`, `unit`, `err` |
  | `challenge-delete-failed` | warn | `name`, `err` |
  | `certificate-failed` (also a certificate directory that is missing or not as the module makes it, before any order) | error | `certificate`, `not_after` (amended 2026-10-29), `err` |
  | `run-completed`, once per run that held the lock | info | `certificates`, `renewed`, `failed`, `exit` (amended 2026-10-29), `dur_us` |

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

## Amendment 2026-10-21: the account URL is logged

The deployment pins hanko's ACME account in its CAA records (RFC 8657 `accounturi=`), so the owner must be able to read the account URL; until now only the key was kept. Owner decision: hanko logs it, nothing new is stored. `acme-account` (info, `directory`, `uri`) is written by every run that contacts the CA, once the account is known: after a registration (following `acme-account-register`) and when the key's account already exists (the `onlyReturnExisting` lookup already returns the URL, no extra request). A run with nothing due stays offline (ADR-0001, ADR-0003) and so does not write it; the URL is stable for a given account key, so the last `acme-account` line in the journal or in nisshi gives it. `acme-account-register` keeps its place before the request, so a failed registration still leaves a trace; one event carrying `uri` in both cases keeps a single query for the URL.

## Amendment 2026-10-29: `hanko-ca` events

`hanko-ca` (ADR-0004) writes schema v1 lines on stderr through the same `internal/logging`; grpc-go's own logger is routed into it so stderr stays schema v1. `hanko-ca check` logs `config-invalid` like `hanko check`. No metrics yet: `hanko-ca`'s series remain future work.

| Event | Level | Fields |
|---|---|---|
| `ca-started` (listening) | info | `listen`, `hosts` (count), `ca_not_after` |
| `ca-failed` (key, certificate or listener unusable, or serving stopped on an error) | error | `err` |
| `svid-signed` | info | `peer`, `spiffe_id`, `serial` (hex), `not_after` |
| `sign-refused` (ID not allowed for the address, a CSR refused, or the CA certificate expired; `spiffe_id` cut at 256 bytes) | warn | `peer`, `spiffe_id`, `err` |
| `bundle-refused` (`Bundle()` from an address not in `hosts`) | warn | `peer`, `err` |
| `grpc-error` (an error line of grpc-go) | error | `err` |
| `ca-expiring` (amended 2026-10-29, see below) | warn, error once expired | `ca_not_after` |
| `connection-limit` (amended 2026-10-29, see below) | warn | `scope`, `limit`, `peer` (scope `peer`), `count` |

## Amendment 2026-10-29: the internal issuer

The `internal` issuer (ADR 0004) writes the events above with `svid.pem` as the certificate;
`certificate-renewing` carries `spiffe_id` instead of `hosts`. One event is added:

| Event | Level | Fields |
|---|---|---|
| `bundle-written` (the trust bundle changed while the SVID was not due; its units are then reloaded as for a certificate) | info | `certificate` |

A run that cannot reach `hanko-ca` fails the certificate (`certificate-failed`) even when its SVID
is still valid: the bundle is refreshed on every run, and a stale one must reach `OnFailure=`.

## Amendment 2026-10-29: observability through logs only (owner decision)

`hanko-node` is a oneshot and `hanko-ca` serves gRPC only: neither has an HTTP server, and
adding one for a scrape is not wanted. Owner decision: **neither exposes metrics**; the
`/metrics` paragraph above and the "series remain future work" of the `hanko-ca` amendment are
withdrawn. Everything an operator or an alerting rule needs is a schema v1 log event, collected
from journald by the deployment's log agent. The rules themselves come with the observability
stack; the events they will need:

- **A certificate close to expiry or expired** (ACME or SVID): every run writes the served
  leaf's `not_after` for every certificate, in `certificate-valid`, `certificate-written`, and
  now `certificate-renewing` and `certificate-failed` (absent when no pair is served yet). A
  failing certificate thus carries its remaining time on the failure line itself.
- **A failed run and its class**: `run-completed` gains `exit`, the status `hanko-node` exits
  with (ADR-0001): `0`, `1` (transient, retried) or `10` (a quick retry cannot fix it). A run
  that stops before the lock writes `run-failed` and exits 1.
- **The signing CA close to expiry**: `hanko-ca` writes `ca-expiring` (`ca_not_after`) at
  start and then every 24 h while the signing CA certificate ends within **30 days**, the
  threshold of `hanko status` (ADR-0011 amendment): `warn`, `error` once it has expired (`Sign`
  is then refused, ADR-0004). On the hosts, `hanko status` keeps its `ca_expiring` field.
- **Refused calls**: `sign-refused` and `bundle-refused`, unchanged.
- **Connection limits hit**: `connection-limit` (`warn`) when `hanko-ca` holds a connection
  back because a limit is reached. `scope` is `all` for the global cap (`limit` 64, the
  connection waits for a free slot; no `peer`) or `peer` for the per-address cap (`limit` 4,
  ADR-0004 amendment; the connection is closed, `peer` is its source address). At most one
  line per scope per minute, so a
  flood cannot flood the journal; `count` is the hits since the previous line of that scope,
  this one included.
