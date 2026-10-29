# ADR-0012: CA rotation for `hanko-ca`

- Status: accepted
- Date: 2026-10-29

## Context

ADR-0004 left CA rotation procedures out of v1 and kept one property for it: the trust bundle
can carry several CA certificates. The CA certificate of `hanko-ca` expires, and its key may
have to be replaced before then. Every service trusts exactly the bundle hanko writes next to
its SVID, so a careless switch of the signing key leaves peers holding SVIDs their callers no
longer trust, or the reverse. The pieces a procedure needs are already there: `cert_file` may
hold several CA certificates, the one matching the key signs and all of them form the bundle,
the signing one first (ADR-0004 amendment); `hanko` refreshes `bundle.pem` on every run and
reloads the service when it changed (ADR-0007 amendment), and renews an SVID once less than
half of its lifetime is left or once no CA of the bundle signed it.

## Decision

Rotation is a **manual, two-step** procedure in the deployment, with `hanko-ca` restarted after
each change of its files:

1. **Publish the new CA.** Some days before the switch, the new CA certificate is added to
   `cert_file` next to the old one, the old key still signing, and `hanko-ca` is restarted.
   The bundle now carries both certificates; every host writes it on its next run and reloads
   its services, which then trust SVIDs from either CA.
2. **Switch the signing key**, more than one SVID lifetime later (more than 24 h by default), so
   that every host's timer has refreshed its bundle. The key file is replaced by the new CA's
   key and `hanko-ca` restarted. Existing SVIDs remain valid and trusted, signed by the old CA
   that is still in every bundle; each is renewed by the new key on its normal schedule, so
   within one SVID lifetime every service holds a new-CA SVID. The bundle now lists the new CA
   first.
3. **Retire the old CA** after the last SVID it signed has expired, that is more than one SVID
   lifetime after step 2: it is removed from `cert_file` and `hanko-ca` restarted. An SVID still
   signed by it at that point (a host that was down) is renewed on the host's next run, as no
   CA of the bundle verifies it any more.

A restart is harmless: services read their files and never call `hanko-ca`; a `hanko` run that
hits the restart fails (`certificate-failed`, `OnFailure=`) and the next timer run succeeds; an
SVID is renewed with half its lifetime left, so a failed run or a few missed periods cost
nothing but margin.

The safety net is ADR-0004's cap: `hanko-ca` never issues an SVID past its signing CA's
`NotAfter`, so a forgotten rotation ends in refused signatures and expiring SVIDs, all logged,
never in certificates that outlive their CA. `hanko status` warns 30 days before the signing
CA expires (ADR-0011 amendment).

Automation is out of scope: the CA key comes from secrets (ADR-0005), and generating a new key
inside `hanko-ca` would contradict ADR-0004, where the deployment provides it.

## Alternatives considered

- **Switch key and certificate at once.** Every SVID issued after the switch is untrusted by
  hosts whose bundle has not been refreshed yet, for up to a timer period, and every older SVID
  is untrusted by hosts that have. Rejected.
- **Cross-signing the new CA with the old one.** Works with a single root in every bundle, but
  needs intermediate chains in `svid.pem` and in consumers' verification; two roots in the
  bundle need neither.
- **Automatic rotation by `hanko-ca`.** It would create and persist keys, which ADR-0004 rules
  out for a daemon that persists nothing but its log.

## Consequences

- A full rotation takes at least two SVID lifetimes after step 1, two days with the default
  24 h, plus the days the deployment chooses before step 2.
- The order of the certificates in `cert_file` does not matter; the key decides which signs.
- ADR-0004's "CA rotation procedures" out-of-scope item is replaced by this procedure; the
  automation of it stays out of scope.
