# hanko — milestones

Each milestone ends with a passing `nixosTest` (ADR-0001). Versions: v0 = public certificates in production; v1 = internal identities, opened only when a consumer needs them. Technical milestones, no calendar. A breakage seen on the real hosts becomes a `nixosTest` case before it is fixed.

## External dependencies

| Dependency | Blocks |
|---|---|
| annai M3 (`soto` mode, RFC 2136 with TSIG) as a flake input | the `nixosTest` of M1 |
| annai M4 (annai is the public nameserver) | M2, the first real certificate |
| A consumer that needs service identity | v1 as a whole: met, hikyaku and azukari (2026-10-29) |

## M0 — Foundations

- Repository on Forgejo with GitHub mirror; flake with `buildGoModule`, devShell, `nix flake check` running `go vet` and the unit tests.
- Configuration schema (ADR-0002) with `go-toml/v2`, `hanko check <file>` rejecting unknown keys, mismatched issuer keys, unused issuer tables, duplicate names.
- NixOS module skeleton: options mirroring the file, TOML rendered with `pkgs.formats.toml`, `hanko check` run in a derivation at build time, static user and group, state directory, per-certificate directories with the consumer's group (ADR-0005).
- Done when: `hanko check` accepts the example of ADR-0002 and rejects every invalid fixture; the module evaluates and a typo in it fails the build.

## M1 — ACME issuer (v0.1)

- ACME flow with `x/crypto/acme`: account creation under the state directory, one order per certificate, DNS-01 authorizations, finalisation with a fresh P-256 key, renewal rule at a third of the lifetime (ADR-0003).
- RFC 2136 client with TSIG HMAC-SHA256 (`miekg/dns`): add and delete of `_acme-challenge.*` TXT, fan-out to every nameserver, abort on any failed UPDATE, propagation check by address with timeout.
- Atomic file writing, `fullchain.pem` then `key.pem`, permissions of ADR-0005; reload of the listed units through the polkit rule.
- systemd unit `Type=oneshot` with `RemainAfterExit`, timer with `Persistent=true` and randomised delay, `restartTriggers` on the configuration file, `OnFailure=` hook option (ADR-0001).
- Unit tests: ACME against a fake directory, UPDATE against a fake nameserver, propagation check with one lagging nameserver, file writing and reload ordering.
- `nixosTest`: Pebble as the CA, **two annai `soto` VMs** loading the same zone with hanko's TSIG key, one host running hanko with a wildcard certificate and a second certificate for two names; both nameservers receive the TXT, the certificate lands with the right group and mode, the listed unit is reloaded, a second run renews nothing, and with a short certificate validity configured in Pebble a run renews the certificate once it is due.
- Done when: the `nixosTest` is green in CI.

## M2 — Production (v0.2 = v0 complete)

- First certificates against Let's Encrypt staging, then production, through annai's public nameservers (annai M4): the internal wildcard and the public names genkan serves.
- genkan reloaded by hanko and serving with those certificates; its certificates use hanko's `group = "genkan"`, genkan's own group (ADR-0005).
- A `switch` that adds a certificate issues it during activation, before the consumer is reloaded.
- Done when: genkan serves every declared name with a hanko certificate, an added certificate appears in the same `switch`, and the timer path (`hanko-renew.service`) ran and renewed nothing.

## M3 — Operations (v0.3)

- ~~`hanko status`: every certificate with issuer, names, expiry and last run result, read from the files; usable by the deployment's monitoring~~: done (ADR-0011, proposed); the M1 `nixosTest` breaks the TSIG key, the run fails and `hanko status` shows both certificates still valid.
- ~~Structured logs with one summary line per run~~: done ahead of M3 (ADR-0007, schema v1 lines, `run-completed`).
- Failure notification wired through `OnFailure=` in the deployment.
- Done when: a deliberately broken TSIG key produces a non-zero exit, a notification, and `hanko status` showing the certificate still valid.

## v1 — Internal identity (scheduled, opened 2026-10-29)

Opened by the owner on 2026-10-29: two consumers now need service identity, hikyaku (log shipping) and azukari (storage and backup), whose calls are authorised on the caller's SPIFFE ID. The formats were fixed in ADR-0004 so that v0 files never change.

- ~~`hanko-ca`: daemon holding the CA key, gRPC `Sign` and `Bundle` under `proto/hanko/ca/v1/` with buf, overlay-address to allowed-IDs mapping, static user and hardening (ADR-0004, ADR-0005). NixOS module `ca`~~: done; unit and loopback gRPC tests, `module-eval` covers the `ca` module.
- `internal` issuer in `hanko`: CSR with the SPIFFE ID as URI SAN, `svid.pem`, `key.pem`, `bundle.pem`, 24 h lifetime renewed at half.
- `nixosTest`: `hanko-ca` on one VM, `hanko` on two others, a service on each authenticating the other by SPIFFE ID over mTLS; a request for an ID not allowed for the caller's address is refused; the bundle is refreshed on every run.
- Deployment side: `tcp/4900` allowed from every hanko host in kekkai's per-peer rules; the node carrying `hanko-ca` chosen and its risk recorded privately.
- Done when: two services on two hosts authenticate each other by SPIFFE ID, and a rotation happens through the timer without a restart of either.

## Not planned

`hanko-agent` and the Workload API (reserved in ADR-0001), JWT-SVIDs, federation, CA rotation procedures, HTTP-01, TLS-ALPN-01, any registrar API, any listening socket in `hanko`.
