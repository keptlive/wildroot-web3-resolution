# Changelog

## 0.1.0 — initial public release

First public release of Wildroot's Handshake name-resolution stack and its
written standard.

- **`SPEC.md`** — the standard: terminology (RFC 8499), namespace selection,
  the resolution algorithm step by step, the trust states an implementation
  must expose, the `hns://` URL form including the provisional numeric-TLD
  convention, HIP-5 `_op`, DANE-for-HTTPS, DoH and Oblivious DoH transport,
  content pointers, and the security considerations.
- **`REFERENCES.md`** — every standard the implementation reads, with exact
  identifiers, links, and what each is used for.
- **`DEVIATIONS.md`** — every departure from a cited standard, and every place
  we are not confident we have made the right call.
- **`src/`** — the resolution modules, self-contained: no Electron, no browser
  globals. Chain proof through a local hsd SPV node, DNSSEC anchored to the
  on-chain DS with fail-closed semantics, NSEC and NSEC3 authenticated denial,
  DANE `3 1 1` pinning, HIP-5 `_op` resolution against an Optimism registry,
  DoH and ODoH transport, the `hns://` URL form, the SSRF guard, and the
  trust-step model the user interface renders.
- **`tests/`** — 315 deterministic tests and their fixtures, including a real
  authoritative nameserver serving frozen signed zones.
