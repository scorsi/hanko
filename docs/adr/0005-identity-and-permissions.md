# ADR-0005: Service identity, file permissions and hardening

- Status: accepted
- Date: 2026-10-17

## Context

hanko writes private keys that other services read, and nothing else on the host may read them. It reads two secrets from sops (TSIG key, later the CA key for `hanko-ca`) and creates one (the ACME account key). It runs on the host that terminates TLS, and later `hanko-ca` runs on one node of the overlay. The same user model as genkan and kekkai applies: static users, no `DynamicUser`, sops ownership set at activation (genkan ADR 0006, kekkai ADR 0018).

## Decision

- **Users**: static system user and group `hanko` for the oneshot, `hanko-ca` for the signer. No `DynamicUser`, no capabilities, no privileged port (`hanko-ca` listens above 1024).
- **State directory**: `StateDirectory = hanko` (`/var/lib/hanko`), owner `hanko:hanko`, mode `0751` (amended by ADR-0006: `0750` would keep consumers from traversing to their certificate directory). The ACME account key lives at its root, mode `0600`.
- **One directory per certificate**, `/var/lib/hanko/<name>/`, **created by the NixOS module** (tmpfiles), owner `hanko`, group the consumer's (`group` option, ADR-0002), mode `2750`. hanko writes files `0640`; the setgid bit gives them the consumer's group without hanko needing `CAP_CHOWN` or membership in every consumer group. hanko's `group` is set per certificate and is **the consumer's own group** (genkan's certificates: `genkan`); the consumer joins nothing. A dedicated static group is used only when several services share a certificate (e.g. `certs-home`, which they join through `SupplementaryGroups`) or when the consumer uses `DynamicUser` and so has no stable group of its own (e.g. annai once it serves DoT: a static `hanko-annai` group plus `SupplementaryGroups`). A service identity (ADR-0004) uses that service's own group and no other.
- **Atomic writes**: new files are written next to the old ones and renamed into place; `key.pem` is renamed last, after the certificate, so a reader never sees a certificate whose key is missing. Reloads are sent after every file of the certificate is in place.
- **Secrets**: the TSIG key and the CA key are sops files with `owner = "hanko"` (or `hanko-ca`), mode `0400`, read in place. No `LoadCredential`: the file is re-read at every run anyway.
- **Hardening**, both components: `ProtectSystem = "strict"`, `ProtectHome = true`, `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, `RestrictAddressFamilies = AF_INET AF_INET6 AF_UNIX`, `CapabilityBoundingSet=` empty. The oneshot additionally needs no listening socket at all; `hanko-ca` binds its overlay address only.
- **Reload authority**: `systemctl reload <unit>` requires a privilege hanko does not have. The module grants it narrowly through a polkit rule allowing user `hanko` to reload or restart exactly the units listed in its configuration, nothing else. A listed unit that is not active (`systemctl is-active`, a property read needing no polkit authorisation) is skipped with a log line, not reloaded: at boot a consumer ordered `After=hanko.service` still has its start job queued behind hanko, a reload would merge into it and block hanko, and a unit that starts later reads the new files anyway (owner decision, 2026-10-18).
- **Logs**: structured, to stderr, journald. Never a key, never a TSIG secret, never an ACME token in logs.

- **Pair and directory checks** (added 2026-10-21 after the review of `6959360`, H3 and H5; no change to the decisions above): both new files are written and synced before the first rename, and the directory is synced after the last. Two renames cannot be one atomic step, so a run interrupted between them leaves a new certificate with the old key: every run checks that `key.pem` matches `fullchain.pem` and renews when it does not. Before ordering, a due certificate's directory must exist, be owned by hanko, with no group or other write, and take a new file; otherwise the certificate fails without contacting the CA, so a missing or unmounted directory never costs an issued certificate.

## Alternatives considered

- **hanko as a member of every consumer group, chgrp after write.** Works, but the user accumulates groups and a bug in hanko could write a key readable by the wrong group. Setgid directories created by the module make the permission a declarative fact. Rejected.
- **Running the oneshot as root for `systemctl reload`.** The one privilege it needs, bought with all of them. A polkit rule scoped to listed units is the small version. Rejected.
- **`LoadCredential` for the TSIG key.** Fine for a oneshot, but not for `hanko-ca`, and one convention is simpler. Rejected.
- **Consumers reading from `/etc`.** Certificates change outside of `switch`; `/etc` is Nix's. Rejected.

## Consequences

- A wrong `group` on a certificate fails at the consumer, with a permission error, which is the intended signal.
- `hanko-ca` holds a signing key on a host; the deployment chooses that host and documents the risk privately, as kekkai ADR 0025 does for identity keys.
- Adding a writable path or a capability is a new ADR, not a chmod.
