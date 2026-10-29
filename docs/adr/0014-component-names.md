# ADR-0014: `hanko-node` runs, `hanko` is the operator CLI

- Status: accepted (owner decision, 2026-10-29)
- Date: 2026-10-29

## Context

ADR-0001 named the per-host oneshot `hanko`, the product's own name, and `hanko status`
(ADR-0011) made the same binary the operator's tool. kekkai names its components the other way:
`kekkai` is the operator CLI, `kekkai-node` the service each node runs. Two products of the same
stack with opposite conventions make every unit name a lookup.

## Decision

Amends ADR-0001's component list:

- **`hanko-node`**: the per-host oneshot of ADR-0001. Commands `run` and `check`. Units
  `hanko-node.service` (boot and `switch`), its timer twin `hanko-node-renew.service` and
  `hanko-node.timer`; NixOS option `services.hanko-node` (`nixosModules.default`).
- **`hanko`**: the operator CLI. Commands `status` (ADR-0011) and `check`. It installs no unit.
- **`hanko-ca`**: unchanged.

Two thin `cmd/` mains share `internal/`, as `hanko-ca` already does; one build holds every
binary, and the flake outputs `packages.hanko`, `packages.hanko-node` and `packages.hanko-ca`
are that one derivation with `mainProgram` set to each name.

Unchanged on purpose, so a deployed host needs no state migration: the system user and group
`hanko`, the state directory `/var/lib/hanko`, the configuration file `/etc/hanko/hanko.toml`
and its format, the polkit rule (it matches user `hanko`, not a unit name), the exit codes and
the log events. `hanko status` still runs as user `hanko` (ADR-0011).

Earlier ADRs keep their text: read `hanko run`, `hanko.service`, `hanko-renew.service`,
`hanko.timer` and `services.hanko` there as `hanko-node run`, `hanko-node.service`,
`hanko-node-renew.service`, `hanko-node.timer` and `services.hanko-node`.

## Alternatives considered

- **One binary dispatching on `argv[0]` or subcommand.** Saves nothing over two mains of a few
  lines each, and hides which name a unit really runs.
- **Compatibility aliases for the old unit and option names.** One deployed host, redeployed
  by the owner; an alias would outlive its use. Rejected.
- **Renaming the user and state directory too.** A state migration (account key, certificates,
  `.last-run`) for a cosmetic gain. Rejected.

## Consequences

- The deployment repository renames `services.hanko` to `services.hanko-node`, and consumers'
  `after`/`wants` and any `OnFailure=` or monitoring reference to `hanko.service` or
  `hanko-renew.service`. Logs carry no binary name: the journal's `_SYSTEMD_UNIT`, hence the
  `service` field nisshi's agent adds (ADR-0007), changes with the unit name, so log queries
  on the old unit name must follow.
