# Changelog

## 0.2.0

The public specification of Wildroot's web3 name resolution: every namespace
the browser resolves, with the reference implementation behind each.

- **`SPEC.md`** — the spine: the shared model (terminology, the two laws, the
  trust states), namespace selection (the scheme registry, the classification
  order, dispatch and failure), and one chapter per namespace under
  `namespaces/<ns>/SPEC.md`: Handshake; ICANN names; IPFS, IPNS and DNSLink;
  Arweave; ENS and `web3://`; Nostr; DID, AT Protocol and ActivityPub; Tor; the
  key-addressed namespaces (hyper, SSB, Gemini, BitTorrent); and an
  experimental chapter for HIP-5 `_op` on-chain resolution and numeric
  Handshake TLDs; and a chapter on native applications on a Handshake name —
  `hns://` as an origin, WebSockets to a Handshake name through the loopback
  CONNECT tunnel, and sign-in with a name.
- **`REFERENCES.md`** — every standard the implementation reads: an index of
  every identifier with the chapters that cite it, then each chapter's table
  with what each is used for. Generated from the chapters.
- **`DEVIATIONS.md`** — every departure from a cited standard, every open
  question and every open design decision, per chapter, each open item with a
  recommendation. Generated from the chapters.
- **`src/`, `namespaces/*/src/`** — the resolution modules, byte-identical to
  the Wildroot browser tree modulo import paths (`scripts/parity.mjs` proves
  it): the Handshake chain-proof resolver with DNSSEC anchored to the on-chain
  DS and DANE pinning; the ICANN transport plan; the classifier and scheme
  registry; the trust model; the IPFS, Arweave, ENS/CCIP-Read/`web3://`,
  Nostr, DID, onion and Gemini handlers; the magnet grammar; the SSRF guard;
  the URL form.
- **`DIVERGENCE.md`** — the cross-cutting inventory of where the fast path
  and a private path differ, namespace by namespace, with what each private
  path would take.
- **`tests/`, `namespaces/*/tests/`** — 877 deterministic tests in 11 suites,
  no network; `npm test` runs them all. `scripts/parity.mjs` proves the 64
  copied modules byte-identical to the browser and declares the 8 factored ones.
