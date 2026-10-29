# ADR-0013: Consumers reload internal certificates themselves

- Status: accepted (owner decision, 2026-10-29)
- Date: 2026-10-29

## Context

ADR-0004 delivers an X.509-SVID like a public certificate: hanko writes the files and reloads
the units listed in the certificate's `reload` (ADR-0002, ADR-0005). An SVID lives 24 h and is
renewed at half, and the bundle may change on any run (ADR-0012), so every service holding an
identity gets a signal at least twice a day. hanko then has to know how each service reloads,
the polkit rule grows with every service, and a service that cannot reload is restarted. The
consumers of internal identities are the author's own Go and Rust services, which can watch
their files.

## Decision

- For the `internal` issuer, hanko writes `svid.pem`, `key.pem` and `bundle.pem` atomically as
  today (ADR-0005: staged, synced, renamed, `key.pem` last) and **reloads or restarts no unit**.
  The write is the whole delivery. `hanko check` refuses `reload` on an `internal` certificate,
  so a stale list fails the build instead of being silently ignored.
- **Each consumer watches its files** and swaps its identity in-process: before a handshake
  (or on a short poll) it compares the files' inode and mtime with the last ones loaded; when
  they changed it loads the pair and the bundle, and if the pair does not load or match
  (caught between two renames) it keeps the previous one and tries again on the next check.
  - Go: a `tls.Config` whose `GetConfigForClient` (server: `Certificates` and `ClientCAs`) and
    `GetClientCertificate` plus a `VerifyPeerCertificate` against the current bundle (client)
    call a shared loader doing the check above under a mutex.
  - Rust: a rustls `ResolvesServerCert` and `ResolvesClientCert` returning the current
    `Arc<CertifiedKey>`, and a client/server certificate verifier delegating to one rebuilt from
    the current bundle, all backed by the same loader.
- Reloads stay for the `acme` issuer: its consumers are third parties (genkan, later annai) that
  reload on a signal, and nothing changes for them.

## Alternatives considered

- **Keep hanko's reloads for SVIDs.** Works, but couples hanko to each service's reload
  mechanism, sends a SIGHUP twice a day per service, and needs polkit for every one. Rejected.
- **Reload as an option per internal certificate.** Two delivery models for one issuer, and the
  only consumers planned can watch files. Rejected; a third-party consumer of an SVID would make
  this a new ADR.
- **The Workload API (`hanko-agent`).** Rotation in-process is what it gives, at the cost of a
  daemon per host and attestation (ADR-0001). File watching gets the same rotation for services
  declared in Nix; the agent stays reserved for dynamic workloads.

## Consequences

- Identity rotates in-process, like a Workload API without an agent; no unit is signalled, and
  polkit only lists the units of `acme` certificates.
- ADR-0004's "consumers reload on the signal hanko sends" and the "reloaded about twice a day"
  of its lifetime line, ADR-0007's "its units are then reloaded" for `bundle-written`, and
  ADR-0012's "reloads its services" now mean the services re-read the files hanko wrote.
- A consumer that does not watch its files keeps its old SVID until it restarts and fails its
  peers once that SVID expires: this is the service's bug, visible in its own logs.
- A third-party service needing an SVID and a reload is a new ADR.
