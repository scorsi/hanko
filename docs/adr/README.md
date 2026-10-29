# Architecture Decision Records

MADR-lite, as in annai: one decision per file, `NNNN-slug.md`, sections Context / Decision / Alternatives considered / Consequences. A decision is changed by a new ADR that supersedes the old one. Documents stay generic: no host names, no real domains (`example.org` and `uchi.example.org` stand for the public and internal zones), no deployment values.

| ADR | Title |
|---|---|
| [0001](0001-scope-and-components.md) | Scope, components and the oneshot model |
| [0002](0002-configuration.md) | Configuration |
| [0003](0003-acme-issuer.md) | ACME issuer: DNS-01 through RFC 2136, fan-out, renewal |
| [0004](0004-internal-identity.md) | Internal identity: SPIFFE IDs, X.509-SVIDs and the `hanko-ca` signer |
| [0005](0005-identity-and-permissions.md) | Service identity, file permissions and hardening |
| [0006](0006-state-directory-traversal.md) | The state directory is traversable by consumers |
| [0007](0007-observability.md) | Observability: schema v1 logs, no metrics endpoint yet |
| [0008](0008-account-key-continuity.md) | The account key is created on request only (Accepted — 2026-10-21) |
| [0009](0009-state-and-delivery-safety.md) | Verify state and persist delivery failures |
| [0010](0010-acme-retry-deadlines.md) | Persist CA retry deadlines across oneshots |
| [0011](0011-status.md) | `hanko status` and the persisted last run result |
