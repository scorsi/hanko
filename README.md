# hanko (判子)

The certificate service of the homelab: it makes certificates available to
services. Public ones from Let's Encrypt today, internal service identities in
the SPIFFE model later. Named after the seal stamped on documents.

Status: `hanko check`, `hanko run` (ACME issuer, M1) and `hanko status` (M3) implemented, and the `hanko-ca` signer of v1; not yet in production. Decisions live in
[`docs/adr/`](docs/adr/), the plan in [`docs/milestones.md`](docs/milestones.md).

## Where it sits

Four products, one domain each, no shared code between them:

| Product | Owns |
|---|---|
| annai | DNS: zones, resolution, resolver configuration of the hosts |
| kekkai | the overlay and node-to-node transport, nothing else |
| genkan | reverse proxy; reads certificate files, runs no ACME challenge |
| hanko | certificates, whoever issues them and whatever they are for |

## Shape

- **`hanko`**, a per-host oneshot run by a systemd timer and at every `switch`
  that changes its configuration; writes files, reloads the units it is told
  to, listens on nothing (ADR 0001). Go, stdlib first.
- **ACME issuer**: DNS-01 only, RFC 2136 with TSIG against every annai `soto`
  nameserver, propagation checked by asking each one by address (ADR 0003).
- **Internal issuer**, v1: SPIFFE IDs under the internal zone, X.509-SVIDs of
  24 h, trust bundle, signed by **`hanko-ca`**, a small daemon on one node
  reached over the overlay, with kekkai as node attestation (ADR 0004). The
  Workload API is reserved as `hanko-agent`, not planned.
- Files under `/var/lib/hanko/<name>/`, readable by the consumer's group only;
  static users, no capabilities (ADR 0005).

## Why not NixOS `security.acme`

It is lego: its RFC 2136 provider updates a single nameserver and checks
propagation through the system resolver, which annai's split horizon defeats.
hanko does both correctly, hosts the internal CA, and is a learning project
like the three others.
