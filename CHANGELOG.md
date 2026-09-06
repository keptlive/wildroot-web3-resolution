# Changelog

## 0.3.0

The public specification of Wildroot's web3 name resolution: every namespace
the browser resolves, with the reference implementation behind each.

- **`SPEC.md`** — the spine: the shared model (terminology, the two laws, five
  trust verdicts), namespace selection (the scheme registry with its `trust`
  column, the classification order, dispatch and failure), and one chapter per
  namespace under `namespaces/<ns>/SPEC.md`: Handshake; ICANN names; IPFS,
  IPNS and DNSLink; Arweave; ENS and `web3://`; Nostr; DID, AT Protocol and
  ActivityPub; Tor; the key-addressed namespaces (hyper, SSB, Gemini,
  BitTorrent); an experimental chapter for HIP-5 `_op` on-chain resolution and
  numeric Handshake TLDs; and a chapter on native applications on a Handshake
  name — `hns://` as an origin, WebSockets to a Handshake name through the
  loopback CONNECT tunnel, and sign-in with a name.
- **DNSLink as the migration path** — `_dnslink.<name>` is read on the chain
  path and over DoH under the same rules as `ipfs=` (validated on a signed
  zone, absence proven before an address is consulted); the two sources merge
  when they agree and a disagreement is surfaced, never picked.
- **The chain proof survives anonymization** — the authoritative hop is
  dialled through the device-local Tor (`src/socks-dial.js`), the SPV node's
  peers go through hsd's own proxy, ICANN hosts met in a walk are resolved
  through DoH/ODoH in every mode, and a synced chain's "unregistered" is final.
- **`REFERENCES.md`** — every standard the implementation reads: an index of
  every identifier with the chapters that cite it, then each chapter's table
  with what each is used for. Generated from the chapters.
- **`DEVIATIONS.md`** — every departure from a cited standard, every open
  question and every open design decision, per chapter, each open item with a
  recommendation. Generated from the chapters.
- **`DIVERGENCE.md`** — the cross-cutting inventory of where the fast path
  and a private path differ, with a no-trade-off attempt for each row; nine of
  the sixteen both-sides rows are built, and the five that survive are what a
  Private/Fast mode pair is for.
- **`src/`, `namespaces/*/src/`** — the resolution modules, byte-identical to
  the Wildroot browser tree modulo import paths (`scripts/parity.mjs` proves
  it; 66 copied modules, 8 declared factored).
- **`tests/`, `namespaces/*/tests/`** — 900 deterministic tests in 11 suites,
  no network; `npm test` runs them all.
