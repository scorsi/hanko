# ADR-0001: Scope, components and the oneshot model

- Status: accepted
- Date: 2026-10-17

## Context

The homelab network stack is four products with one domain each: annai owns DNS, kekkai owns the overlay, genkan serves sites and services through a reverse proxy, **hanko (判子, the seal) makes certificates available to services**. Whatever the certificate is for, public TLS or service-to-service identity, and whatever issues it, Let's Encrypt or a private CA, it is hanko's job. No product shares code with another; inside hanko the components do.

Consumers are declared in Nix: genkan's certificates, and later the author's own Go and Rust services. Nothing in the homelab asks for a certificate at runtime; a new consumer appears through a `switch`.

NixOS `security.acme` (lego) was rejected on purpose: its RFC 2136 provider updates a single nameserver and checks propagation through the system resolver, which annai's split horizon defeats (annai ADR-0004, ADR-0006). The author also wants to own this piece.

## Decision

### Components

One product, components named by suffix, as in kekkai:

- **`hanko`**: the per-host **oneshot**. It reads its configuration, renews what is due, writes files, reloads the units it is told to, and exits. It obtains public certificates from an ACME CA (ADR-0003) and, later, internal identities from `hanko-ca` (ADR-0004). This is the only component of v0.
- **`hanko-ca`** (v1): the internal signer. A small daemon that holds the private CA key and signs X.509-SVIDs for the `hanko` instances of other hosts, reached over the overlay (ADR-0004). A daemon because a key that signs must not be copied to every host.
- **`hanko-agent`** (reserved, not planned): a SPIFFE Workload API agent, if a consumer ever needs a socket instead of files. Same CA, same SVID format, different delivery. Nothing is built for it; ADR-0004 fixes the formats so that it would need no change to them.

### The oneshot model

`hanko` is **not a daemon**. It has two triggers, both running the same idempotent binary:

- a **systemd timer**, default hourly, `Persistent=true` so a run missed during downtime happens at boot, with a randomised delay;
- **activation**: the NixOS module sets `restartTriggers` on the configuration file, so a `switch` that adds or changes a certificate runs `hanko` during activation, before the dependent units are reloaded. A new service therefore gets its certificate in the same `switch` that declares it.

Unit shape: `Type=oneshot`, `RemainAfterExit=yes`. Dependent units declare `After=hanko.service` and `Wants=hanko.service`, never `Requires=`: a failed run (ACME outage at boot) must not keep a service with valid files on disk from starting; the service itself fails on a missing file, which is the right signal (genkan ADR 0003).

Exit status: zero when every certificate is valid at exit, whether or not something was renewed; non-zero when a certificate that was due could not be obtained. The module attaches an `OnFailure=` unit of the deployment's choice.

Renewal is decided per certificate by the issuer's rule (ADR-0003, ADR-0004); the timer period only bounds how late a renewal can be. A certificate's lifetime must be several timer periods; both are configuration.

### Language and dependencies

Go, stdlib first, as in genkan. Allowed modules, any addition needs an ADR:

| Need | Module | Why not stdlib |
|---|---|---|
| ACME (RFC 8555) | `golang.org/x/crypto/acme` | JWS, nonces, orders, DNS-01 token; maintained by the Go team. Not `autocert`: it only does TLS-ALPN-01 and HTTP-01. |
| RFC 2136 and TSIG | `github.com/miekg/dns` | A correct UPDATE client with TSIG is a few hundred lines to write and test; the library is the reference implementation in Go. |
| TOML | `github.com/pelletier/go-toml/v2` | Same choice and reason as genkan (`DisallowUnknownFields`). |
| gRPC for `hanko-ca` (v1) | `google.golang.org/grpc`, buf tooling | Same conventions as kekkai's control API. |

### Repository and testing

- One repository, Apache-2.0, English, hosted on Forgejo with a GitHub mirror, like the other products. Flake outputs: `packages.hanko`, `packages.hanko-ca` (v1), `nixosModules.default` (the oneshot and its timer), `nixosModules.ca` (v1), `devShells.default`, `checks`.
- Unit tests on the ACME flow against a fake directory, on the RFC 2136 client against a fake nameserver, on file writing and permissions.
- `nixosTest` with a Pebble ACME server and **two annai `soto` VMs** (annai as a flake input), proving fan-out to every NS and the per-NS propagation check. For v1, a `nixosTest` with `hanko-ca` on one VM and `hanko` on two others.
- A breakage seen on the real hosts becomes a `nixosTest` case before it is fixed.

## Alternatives considered

- **A resident daemon with an internal scheduler.** Equivalent to the timer with a process to keep alive and a config-watching problem Nix already solves with `restartTriggers`. Rejected.
- **The Workload API from the start.** A daemon per host, attestation of processes, gRPC streaming: a lot of surface for consumers that are all declared in Nix and read files. Reserved, not built.
- **ACME inside genkan or NixOS `security.acme`.** Rejected in genkan ADR 0004 and annai ADR-0006.
- **Two products, public certificates and internal identity.** Both make certificates available to services; the taxonomy of the stack puts them in one product, with separate components where the privilege differs, as kekkai does.

## Consequences

- hanko listens on nothing in v0; its attack surface is outbound only.
- Adding a certificate is a Nix change that takes effect in the same `switch`, at the cost of the issuance time (about a minute for DNS-01).
- `hanko-ca` is the only component that will ever hold a signing key of the homelab's own.

## Amendment 2026-10-29: a failed boot or switch run is retried

Owner decision. `hanko.service` (boot and `switch`) gets `Restart=on-failure` with
`RestartSec=30s`, `StartLimitIntervalSec=1h` and `StartLimitBurst=5`: after a full outage,
`hanko-ca`'s host or the overlay may come up a minute after this host, and the next attempt
should not wait for the hourly timer. The limit is per hour, not per few minutes, so that runs
which fail slowly (an ACME order runs up to ten minutes) still stop after four retries; ADR 0010's
`.retry-after` makes a retry within a CA deadline fail offline. `OnFailure=` fires once systemd
gives up, not on each retry; `switch` resets failed units, so the limit never blocks a later
`switch`. The timer's `hanko-renew.service` is not retried: its next attempt is the next period.
Dependent units keep `After=` and `Wants=` `hanko.service`, as above.

## Amendment 2026-10-29: failures a quick retry cannot fix are not retried

Owner decision. With the retry above, an ACME certificate whose validation keeps failing would
be ordered five times an hour, Let's Encrypt's failed-validation limit per hostname, against
ADR 0010's "never loops over failed validations". ADR 0010's `.retry-after` does not prevent it:
a deadline is saved only when the CA gives one or rate-limits, and a failed validation carries
neither, so a retry 30 s later places a new order.

`hanko run` therefore exits with:

| Code | Meaning | `hanko.service` |
|---|---|---|
| 0 | every certificate valid at exit | done |
| 1 | a failure a retry may fix: hanko-ca or the ACME CA unreachable, DNS UPDATE or propagation failure, a run-level error (state, lock) | retried as above |
| 10 | some certificate failed for a reason a quick retry cannot fix: any problem document from the ACME CA (a failed validation or order among them), a CA retry deadline (ADR 0010, saved or still pending), CA output not matching the order, or hanko-ca's refusal (`InvalidArgument`, `PermissionDenied`, `FailedPrecondition`) | not retried (`RestartPreventExitStatus=10`); the unit fails and `OnFailure=` fires |

10 wins when one run has both kinds: a retry runs every due certificate again and would order
the failed one again. The other certificate waits for the next timer run, at most one period.
ADR 0010 already lets a pending deadline fail offline; this exit code adds the no-retry rule
for failures without a deadline. `hanko-renew.service` is unchanged: it is never retried.

## Amendment 2026-10-29: component names

Owner decision. The per-host oneshot described above is now `hanko-node` (units
`hanko-node.service`, `hanko-node-renew.service`, `hanko-node.timer`, option
`services.hanko-node`, flake output `packages.hanko-node`), and `hanko` is the operator CLI
(`status`, `check`). User, state directory and configuration file are unchanged. See ADR-0014.
