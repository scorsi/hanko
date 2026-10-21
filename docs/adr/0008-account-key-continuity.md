# ADR-0008: The account key is created on request only

- Status: Accepted — 2026-10-21
- Date: 2026-10-21

## Context

ADR-0003 has hanko create its ACME account key "on first run", and says losing it "costs a new account, nothing else". Two facts make that untrue now:

- The deployment pins hanko's account in its CAA records (RFC 8657 `accounturi=`, ADR-0007 amendment). A new account cannot obtain a certificate for the pinned names until the records change.
- hanko could not tell a first run from a later one: any absent key file meant "create one". A state directory replaced or hidden by a mount, a restored backup without the key, or a changed `account_key_file` path silently registered a new account (with `accept_terms = true`, which stays set in production), and every later order failed CAA. The review of `6959360` (finding H4) reproduced it. The key's creation also did not sync its directory, so a power loss after registration could lose the file of an account the CA already knew.

## Decision

- A new key in the `[acme]` table, **`create_account`** (boolean, default `false`; module option `services.hanko.acme.createAccount`, default `false`).
- When the account key file is absent:
  - with `create_account = true`, hanko creates the key (P-256, PKCS#8, mode `0600`), writes it through a synced temporary file, renames it, **syncs the directory**, and only then uses it with the CA (registration still needs `accept_terms`);
  - otherwise the run logs `account-key-missing` (error, `path`, `err`) and the certificate fails before any request to the CA. Nothing is created.
- An existing key is used whatever `create_account` says; hanko never replaces it.
- `create_account` is meant for a host's first run: the owner sets it, deploys, reads the `acme-account` URL for CAA, and unsets it. Leaving it on restores the old behaviour, and its risk.

## Alternatives considered

- **Infer the first run from the state directory** (no certificate file yet, so the key may be created). The incident it must catch, a state directory hidden or replaced, looks exactly like a first run. Rejected.
- **A `hanko account` command run once by hand.** Explicit too, but it has to run as user `hanko` with the unit's environment, outside the module; a module option is one line in the deployment. Rejected.
- **Storing the expected account URL and comparing it.** Needs a network call on every run, or a second file that can vanish with the first. Rejected for now; the CAA record is that expectation already.

## Consequences

- Supersedes ADR-0003's "key created by hanko on first run" and its consequence "losing it costs a new account, nothing else", and adds a key to ADR-0002's `[acme]` table.
- A fresh host needs `createAccount = true` for its first run; the M1 `nixosTest` sets it, and proves that without it a missing key fails with `account-key-missing` and is not recreated.
- A host already in service has its key: it needs no change. If the key is really lost, the owner sets `create_account`, updates the CAA `accounturi=` to the new URL, then unsets it.
- The key is a secret worth a backup now: losing it means a CAA change, not just a new account.
