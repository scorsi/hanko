# ADR-0010: Persist CA retry deadlines across oneshots

- Status: accepted (owner, 2026-10-21)
- Date: 2026-10-21

## Context

The ACME library's default retries sleep inside a request, but hanko's order deadline and
oneshot lifetime are shorter than some CA retry windows (review H12). Retrying subsequent
certificates or the next timer run loses that deadline. ADR-0003's next-timer retry policy
needs an explicit HTTP policy and persistent state.

## Decision

- Disable automatic retries of HTTP 429 and server errors. Keep at most three 100 ms
  bad-nonce retries; normal pending authorization/order polling stays in the library under
  the order deadline. hanko never loops over failed validations.
- Before returning a CA error, extract `Retry-After` (seconds or HTTP date), including from
  order and authorization problems, and persist the latest deadline in `.retry-after`,
  mode `0600`, with file and directory sync. Rate limits without a usable deadline get a
  conservative one-hour delay. Other failures without a deadline wait for the next timer.
- The saved scope is the configured directory URL and account-key path, represented by a
  hash. Conservatively defer every due ACME certificate in that scope, even when the CA's
  underlying limit is narrower. On every issuance attempt, check the deadline before DNS,
  account lookup or any CA request. Expired deadlines allow issuance; another directory
  (for example staging) is unaffected. There is only one configured account/directory;
  `.retry-after` stores its latest scope, not a history of previously configured issuers.
- A deferred due certificate fails the run, exposing the UTC deadline in the existing
  `certificate-failed.err` event. Valid certificates and pending consumer reloads still
  work offline. Corrupt or unsafe retry state fails closed. A failure to save the deadline
  is reported and still blocks later orders in that process; storage must be repaired
  before relying on persistence across processes.
- Error diagnostics retain the local operation, HTTP status, an allowlisted ACME problem
  name, and retry deadline. Omit CA details, instance/authorization/order URLs, identifiers,
  subproblem text and arbitrary transport/parser errors. TOML diagnostics give key names
  and positions without source excerpts; syntax/type errors give positions only.

## Alternatives considered

- **Sleep until every deadline.** Conflicts with a bounded oneshot and holds the state lock.
- **Remember only in memory.** Loses the deadline at the next timer run.
- **Implement per-domain limit classification.** Requires CA-specific scope inference;
  conservative account-wide deferral is sufficient for this single-account client.

## Consequences

- Qualifies ADR-0003's rate-limit and future-work paragraphs: a long-running daemon is not
  needed to preserve a retry deadline. No CA quota numbers or ARI behavior are assumed.
- Configuration validation requires HTTPS, except numeric loopback HTTP for local tests;
  numeric nameserver addresses and ports; valid DNS hostnames with optional leftmost
  wildcard (lowercased, no trailing dot); literal unit names; absolute secret/state paths;
  and no account/TSIG/state-file collisions. The TSIG name is canonicalized and its key file
  must contain exactly one record, with an optional trailing LF or CRLF.
- DNS discovery requires an authoritative NOERROR/NXDOMAIN response with an enclosing IN
  SOA. Propagation requires authoritative NOERROR IN TXT answers for the queried owner,
  including all TXT chunks and requested values, on every authority in the same polling
  pass. Response/opcode/question mismatches fail. These unsigned queries validate semantics,
  not cryptographic authenticity; authenticated UPDATE response checks remain unchanged.
