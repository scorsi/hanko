# ADR-0004: Internal identity: SPIFFE IDs, X.509-SVIDs and the `hanko-ca` signer

- Status: accepted
- Date: 2026-10-17
- Delivered: v1, after the ACME issuer is in production. Formats are decided now so that v0's file model never changes.

## Context

kekkai authenticates nodes and filters per peer, so service-to-service traffic inside the overlay is already mutually authenticated at the granularity of a host. The author wants identity at the granularity of a **service**, in the SPIFFE model: a URI identity, a short-lived X.509 certificate carrying it, a trust bundle, and authorisation decided on the peer's identity. Public CAs cannot provide this: Let's Encrypt no longer issues certificates usable for client authentication, and public trust is the wrong trust domain for internal calls anyway.

## Decision

### Identities and certificates

- **Trust domain**: the internal zone, `uchi.example.org`. SPIFFE IDs are `spiffe://uchi.example.org/<host>/<service>`, where `<host>` is the node's name in the shared peer list and `<service>` the systemd unit name without suffix. Declared in Nix per certificate (`spiffe_id`, ADR-0002); nothing is registered at runtime.
- **X.509-SVID** per the SPIFFE X.509-SVID standard: the ID as the single URI SAN, no DNS SAN, `keyUsage digitalSignature`, EKU `serverAuth` and `clientAuth`, not a CA, ECDSA P-256 key generated per issuance by the requesting `hanko`.
- **Lifetime 24 h**, renewed when less than half remains; both configurable. With the default hourly timer a service is reloaded about twice a day. A shorter lifetime is a timer-period question (ADR-0001), not a model change.
- **Trust bundle**: the CA certificate(s), written next to every SVID as `bundle.pem` and refreshed on every run. CA rotation is not designed in v1: the bundle can carry two CA certificates, which is the only property the format must keep.
- **Files per certificate** (ADR-0005): `svid.pem`, `key.pem`, `bundle.pem`. Consumers read files and reload on the signal hanko sends; the author's services implement `GetCertificate` or the equivalent reload hook. A third-party service that cannot reload gets a longer lifetime and a restart instead of a reload.

### `hanko-ca`

- A daemon on one node, holding the **CA private key** (ECDSA P-256, from sops) and the CA certificate. It exposes one gRPC service over the overlay, `Sign(csr, spiffe_id) → svid, bundle` and `Bundle()`, protos under `proto/hanko/ca/v1/` with buf, as kekkai does for its control API.
- **Node attestation is kekkai's**: the caller's overlay source address identifies a peer, kekkai guarantees it (its per-peer firewall must allow `tcp/4900` from each `hanko` host, a deployment value). `hanko-ca`'s configuration maps each overlay address to the set of SPIFFE IDs that host may request; a request for any other ID is refused and logged. No second secret between `hanko` and `hanko-ca`: the overlay is the authenticated transport, and bootstrapping mTLS with a certificate the caller does not have yet would be circular.
- **Workload attestation is the file owner**: on each host, a service can only read the SVID directory the module gave its group (ADR-0005). This is what an agent would establish through `SO_PEERCRED`; without an agent, systemd's user model does it.
- `hanko-ca` persists nothing but a log; it serves whatever the CSR asks within the host's allowed IDs. Its own configuration file:

```toml
[ca]
key_file = "/run/secrets/hanko-ca-key"
cert_file = "/etc/hanko/ca.pem"
listen = "[fd12:3456:789a::1]:4900"
svid_lifetime = "24h"

[[hosts]]
address = "fd12:3456:789a::2"
ids = ["spiffe://uchi.example.org/vm/api", "spiffe://uchi.example.org/vm/git"]
```

### Explicitly out of scope

JWT-SVIDs, federation between trust domains, the Workload API (`hanko-agent`, reserved in ADR-0001), per-host intermediate CAs, CA rotation procedures, authorisation policy itself, which belongs to each consumer.

## Alternatives considered

- **SPIRE.** Does all of this and far more; a server, an agent per host, plugins, a datastore. Rejected for scope and for the learning goal, the same reason kekkai is not Tailscale.
- **The CA key in the oneshot, signing locally on every host.** No daemon, but the signing key copied to every host that runs a service: one compromised host is the CA. Rejected; this is the one reason `hanko-ca` is a daemon.
- **kekkai's v1 certificates as the service identity.** They are node identities in a home-grown, non-X.509 format; TLS libraries cannot consume them. The two layers stay separate, with kekkai providing node attestation to this one.
- **An agent and the Workload API from the start.** Rejected in ADR-0001; the formats here make it a pure delivery change later.
- **Long-lived internal certificates** renewed like public ones. Simpler, but the point of a service identity is that a leaked one dies within hours; 24 h with files is the compromise.

## Consequences

- The author's services gain an identity to authorise on; consumers that do not speak SPIFFE still get an ordinary mTLS certificate and bundle.
- `hanko-ca` is the first thing in the stack whose compromise forges identities; it runs on the node the deployment trusts most, with the hardening of ADR-0005.
- Every ID is a line in Nix, so adding a service to the trust domain is reviewed like any other change.

## Amendment 2026-10-29: wire format and CSR checks

Details the implementation fixed within the decision above:

- **Wire format**: `Sign` takes the CSR as PKCS #10 DER and returns the SVID as DER; the bundle, in both replies, is the DER certificates of `cert_file`, the one matching the key first. `Bundle()` answers any caller: CA certificates are public. Plaintext gRPC, the overlay being the transport.
- **CSR at the trust boundary**: the address must be allowed the requested ID before the CSR is read; the CSR must parse, carry a valid self-signature and an ECDSA P-256 key. The certificate is built from `spiffe_id` and the CSR's key only, so a URI SAN in the CSR is optional, but a CSR naming anything else (another or a second URI, any DNS, IP or email SAN) is refused rather than silently narrowed: it means a confused or hostile caller. Refusals are `PermissionDenied` (ID) or `InvalidArgument` (CSR), and logged.
- **Validity**: `NotBefore` is one minute in the past for clock differences between hosts, `NotAfter` is `NotBefore` plus `svid_lifetime`; the serial is random.
- **Configuration checks** (`hanko-ca check`, run by the module at build time without the key): absolute paths, `listen` a specific IP with a port above 1024 (ADR-0005), duplicate addresses refused, every ID `spiffe://<trust domain>/<host>/<service>` with the SPIFFE character rules, one trust domain for all IDs (no federation). At start the key must be ECDSA P-256 and match one CA certificate of `cert_file`.
