# ADR-0003: ACME issuer: DNS-01 through RFC 2136, fan-out, renewal

- Status: accepted
- Date: 2026-10-17

## Context

Public certificates come from Let's Encrypt. Internal names (`*.uchi.example.org`) are unreachable from the Internet, and the primary domain's TLD forces HTTPS (annai ADR-0005), so DNS-01 is the only challenge that works for them. annai is the public nameserver and accepts dynamic `_acme-challenge.*` TXT records through RFC 2136 with TSIG, on every `soto` instance independently, without replication (annai ADR-0006). The internal annai is authoritative for the internal zone and answers `NXDOMAIN` for challenge names (annai ADR-0004).

## Decision

- **DNS-01 only.** No TLS-ALPN-01, no HTTP-01: both would couple issuance to the proxy and to the public edge. DNS-01 covers every name, internal and public, because annai's public zone accepts `_acme-challenge.*` for any name under the apex.
- **One DNS backend, RFC 2136 with TSIG (HMAC-SHA256, RFC 8945)**, the key coming from sops. No registrar API, no interim backend: hanko has no job before annai is the public nameserver, and that switch is reversible at the registrar.
- **Fan-out**: the TXT record is added on **every** nameserver in `dns.nameservers`, by address. A failed UPDATE on any of them aborts the order (the CA may query that one). After validation the record is deleted on every nameserver; a failed delete is logged, not fatal, since annai expires dynamic records by itself.
- **Propagation check by address, never through a resolver**: before asking the CA to validate, hanko queries each nameserver directly for the TXT record until every one answers it or `dns.propagation_timeout` elapses. The system resolver is the internal annai, which would answer `NXDOMAIN` forever.
- **Order flow** (RFC 8555): one order per certificate with all its hosts, one authorization per host, all challenge records placed, then all checked, then all validated, then finalised with a fresh key. Keys are ECDSA P-256, generated per issuance, never reused.
- **Account**: one ACME account per host, key created by hanko on first run under its state directory, mode `0600`. Terms of service are accepted explicitly by a configuration key; no contact e-mail by default.
- **Renewal rule**: a certificate is due when it is absent, when its hosts changed, when less than a third of its lifetime remains, or when the CA's ACME Renewal Information (ARI) says so, if the library exposes it. With 90-day certificates and an hourly timer this is 30 days of margin; with short-lived profiles the same rule gives a third of their lifetime.
- **Rate limits**: Let's Encrypt limits certificates per registered domain and identical certificates per week. hanko never re-issues an unchanged, non-due certificate, so a loop of failed `switch`es cannot burn the limit on duplicates; validation failures are retried by the next timer run, not in a loop. The published limits are checked when this is implemented, not quoted from memory.
- **Staging**: `acme.directory` is configurable; the `nixosTest` uses Pebble, manual trials use Let's Encrypt staging.
- **Output**: `fullchain.pem` (leaf then intermediates) and `key.pem`, written atomically (ADR-0005), then the `reload` units.

## Alternatives considered

- **TLS-ALPN-01 or HTTP-01** for public names: rejected, see above and genkan ADR 0004.
- **The registrar's API** as a DNS backend: throwaway code, rejected (annai ADR-0006).
- **Checking propagation through the resolver with a public override.** Works with lego's `dnsResolver` trick, but hanko already knows every nameserver by address; asking them directly is both simpler and exact.
- **A single UPDATE to one nameserver, relying on replication.** annai replicates nothing by design; the client loops.

## Consequences

- annai's `soto` instances are the only servers hanko writes to; the contract is annai ADR-0010.
- Issuance takes about a minute: UPDATE fan-out, propagation check, validation, finalisation. A `switch` that adds a certificate waits that long.
- The ACME account key is the only secret hanko ever creates; losing it costs a new account, nothing else.
