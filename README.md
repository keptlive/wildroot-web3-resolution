# wildroot-web3-resolution

**How a browser decides which naming system an address belongs to, and how
each of those systems is resolved and verified — with the reference
implementation behind [Wildroot](https://wildroot.io) and the written standard
that describes it.**

An address typed into a browser can belong to any of a dozen namespaces: a
Handshake name, an ICANN domain, a CID, an Arweave transaction, an ENS name, a
Nostr key, a DID, an onion service, a hypercore key. This repository specifies
**resolution** across all of them: choosing exactly one namespace for an input
(and never falling through to another), turning the address into an answer —
an IP, a content pointer, a document, a key — and saying honestly what was
verified on the way and what was taken on somebody's word. It is extracted from
Wildroot so that other people can read it, test it, argue with it and implement
it.

- **[Chapter 11 — Native applications on a Handshake name](namespaces/apps/SPEC.md)**
  — start here if you are building an application, not a resolver: how
  `hns://` makes a name a real origin (storage, cookies, service workers), how a
  WebSocket to a Handshake name is resolved by chain proof and pinned with DANE
  through a loopback tunnel whose whole security boundary is spelled out, how a
  page signs its users in with the names they hold, and what the server side
  needs. The `.pxls` case.
- **[`SPEC.md`](SPEC.md)** — the standard. Part I is the model shared by every
  namespace (terminology, the trust states, the two laws). Part II is namespace
  selection. Part III is one chapter per namespace: Handshake, ICANN, IPFS,
  Arweave, ENS and `web3://`, Nostr, DID / AT Protocol / ActivityPub, Tor, the
  key-addressed networks, an experimental chapter for HIP-5 `_op` on-chain
  resolution and numeric Handshake TLDs, and the native-applications chapter.
  Each chapter is a file under `namespaces/<ns>/SPEC.md`.
- **[`REFERENCES.md`](REFERENCES.md)** — every standard the implementation
  reads, with exact identifiers, links and what each is used *for*.
- **[`DEVIATIONS.md`](DEVIATIONS.md)** — every departure from a cited standard,
  every place we are not sure we are right, and every design decision left
  open, per chapter. Read this one.
- **[`REVIEW.md`](REVIEW.md)** — the open findings: what this implementation
  does not establish, and what it owes, in one short list. If you are deciding
  whether to trust any of this, read it beside `DEVIATIONS.md`.
- **[`DIVERGENCE.md`](DIVERGENCE.md)** — the cross-cutting inventory of every
  place where privacy and speed pull apart: what the fast path does, what the
  private path does, what the code does, and whether a no-trade-off option
  exists. Eighteen rows have one and are built; the five that survive are what
  the **Fast / Private switch** is for (`SPEC.md` §4.2, `src/delivery-mode.js`):
  one control that drives the Tor session proxy — failing closed — and every
  private path together, with the disclosure it carries written out in full.

## Scope

**In scope:** everything between an address and an answer. Which namespace an
input belongs to; the grammar of each address form; the resolution algorithm
of each namespace; what is cryptographically verified in this process and what
is trusted; how a failure is reported without becoming a lookup in another
namespace; the transport a lookup travels over (encrypted DNS, oblivious DNS,
a device-local Tor circuit, a public RPC) and what that transport discloses.

**Out of scope, and where it lives instead:**

| Out of scope | Where it lives |
|---|---|
| **Content transport** — fetching and rendering the bytes once a name has resolved: the IPFS node, the Arweave gateway's bytes, torrent and hypercore engines, media | the browser's `src/hns/ipfs.js`, `src/protocols/*-protocol.js` and `docs/BLOB-LAYER.md`; the chapters say what is and is not *verified* about those bytes, not how they are fetched |
| **Publishing** — how a record gets into a zone, a registry or a relay in the first place | `PUBLISHING-AND-DNS.md` in the browser tree |
| **The trust user interface** — the padlock, the security panel, the address bar | the browser's `src/ui/`; this repository specifies the *model* they render (SPEC Part I §4 and each chapter's trust states), not the rendering |
| **The composition layer** — the Electron protocol handlers that wire these modules to a session, a proxy and a window | the browser's `src/protocols/index.js`, `src/hns/index.js`, `src/index.js`; each chapter specifies their *policy* normatively |

## Running the tests

```sh
npm install
npm test          # every suite: the top-level Handshake suite and one per chapter
npm run lint      # standard
npm run parity    # every module byte-identical to the browser tree (needs ../browser)
npm run docs      # regenerate DEVIATIONS.md and REFERENCES.md from the chapters
```

Requirements: Node ≥ 20 and a `python3` on `PATH` (several Handshake tests
spawn a real authoritative nameserver, `tests/fixtures/resolver/nsd.py`, over
frozen signed zones, so "the signature validated" means a real server served
real wire bytes). Every test is deterministic and needs no network: RPCs,
gateways, relays, directories and Tor are all scripted fakes that misbehave on
purpose.

## Layout

```
SPEC.md                     the spine: the shared model, namespace selection, the chapters
REFERENCES.md               generated from the chapters: an index of every identifier, then each chapter's table
DEVIATIONS.md               generated from the chapters: every deviation, uncertainty and open design item, plus the divergence inventory
DIVERGENCE.md               the privacy-vs-speed inventory (a source file; also appended to DEVIATIONS.md)
REVIEW.md                   the open review findings: what is not established, and what is owed
REVIEW-DOCS-REWRITE-2026-09-12.md   why one proposed documentation rewrite was not merged, and the rule a future one is held to
reviews/                    dated review records, kept as written: the 2026-09-08 reassessment and a candidate HIP outline
CONTRIBUTING.md             how to send a correction, and how the generated documents, the tests and the parity check work
scripts/build-docs.mjs      generates the two files above (npm run docs; npm run docs:check fails when stale)
src/                        the Handshake chapter's modules and the modules every chapter shares
tests/                      the Handshake suite (and the shared modules' tests)
namespaces/router/          Part II — namespace selection (SPEC.md, tests/; its code is src/router.js)
namespaces/handshake/       Chapter 1 (SPEC.md; its code is src/)
namespaces/icann/           Chapter 2 (SPEC.md, src/dns-policy.js, tests/)
namespaces/ipfs/            Chapter 3
namespaces/arweave/         Chapter 4
namespaces/ens/             Chapter 5 — ENS and web3://
namespaces/nostr/           Chapter 6
namespaces/did/             Chapter 7 — DID, AT Protocol, ActivityPub
namespaces/tor/             Chapter 8
namespaces/keys/            Chapter 9 — hyper, SSB, Gemini, BitTorrent
namespaces/experimental/    Chapter 10 — Experimental: HIP-5 _op (code: src/hip5-op.js) and numeric TLDs (code: src/hns-url.cjs)
namespaces/apps/            Chapter 11 — Native applications on a Handshake name (src/ws-proxy.js, ws-proxy-pac.js, tests/)
scripts/parity.mjs          the byte-identity proof and the sync tool
scripts/run-tests.mjs       the test runner
```

Each chapter directory holds the chapter's `SPEC.md`, the modules that belong
to it alone under `src/`, and its tests. Modules several chapters share — the
classifier, the trust model, the pointer grammar, the SSRF guard, the URL form,
the DNS codec — live at the top-level `src/`.

### Every source module is the browser's, byte for byte

Every file under `src/` and `namespaces/*/src/` is a copy of a module in the
Wildroot browser tree, **byte-identical modulo relative import paths** (the
browser keeps its modules in several directories; this repository flattens
them). `scripts/parity.mjs` holds the mapping, reverses the import rewrite and
compares — `npm run parity` fails on any difference — and `npm run sync`
re-copies. A fix in one tree is therefore provably the same fix in the other,
which is the reason the modules were not tidied for this repository: a
divergent copy of a security-relevant classifier is a worse problem than an
over-broad import.

Eight modules are the exception and are declared as such in the script's
`FACTORED` table. They were **lifted out of a larger browser module** whose
remainder is transport or Electron code, so the lifted function is verbatim but
the file is new: `namespaces/icann/src/icann-tld-snapshot.js` (from
`scripts/fetch-icann-tlds.mjs`), `namespaces/ipfs/src/byte-range.js` and
`car-roots.js` (from `src/hns/ipfs.js`), `namespaces/ipfs/src/ipfs-url.js`
(from `src/sia/restore.js`), `namespaces/ipfs/src/source-error.js` (from
`src/files/source.js`), `namespaces/keys/src/torrent-address.js` (from
`src/protocols/torrent-protocol.js`), `namespaces/keys/src/torrent-input.js`
(from `src/hns/torrent-manager.js`) and `namespaces/nostr/src/nip05.js` (from
`src/social.js`). Each file's header says what it was lifted from.

## Status

The implementation is the resolution stack the Wildroot browser ships. The
specification describes that behaviour normatively, in the present tense, and
only the current behaviour: there is no history of defects in these documents.
Where the specification and the code disagree, that is a bug in one of them —
please say which you think it is.

Three things this release commits to are worth naming here. **A setting is not
an observation**: where the implementation cannot see what happened to a
request — an `http(s)` host resolved by the engine out of this process's sight,
a byte check that happens after resolution — the panel names the configuration
that was in force, says the path was not observed, and stops. It does not
convert a setting into a claim about the page, and a route view that cannot
account for every hop says so instead of describing the hops it knows as if
they were the whole story.

**DNSLink is the migration
path**: a Handshake name's content is read from its `ipfs=` record
and from its `_dnslink` record under the same rules, so a site published for
IPFS Companion, Brave or kubo opens in Wildroot unchanged and a Wildroot site
opens there. **The chain proof survives anonymization**: with IP Protection on,
the authoritative hop and the SPV node's peers go through the device-local Tor
and the proof is kept.

Things we would most like argued with are collected in `DEVIATIONS.md`: each
chapter's *"Things we are not sure about"* and *"Open design items"*, the
latter each with our recommendation. The largest are: verifying Arweave bytes
that do not fit in memory (the header is authenticated and a transaction under
8 MiB is hashed against it; chunk proofs are not implemented); resolving
AT Protocol handles locally rather than through an AppView; auditing the
`did:plc` operation log; a private IPFS path for named sites (the local node's
DHT); whether numeric Handshake TLDs are supported at all; and whether `hns:`
should be registered with IANA.

## Licence

The **code** in `src/`, `namespaces/*/src/` and the tests is **Apache-2.0**
(`LICENSE`). These modules were written inside a fork of
[Agregore](https://github.com/AgregoreWeb/agregore-browser), but none of them
is derived from Agregore code — no file here exists upstream — so the copyright
is the author's to license, and Apache-2.0 is chosen deliberately: a reference
implementation that other clients cannot adopt is not a reference
implementation, and Apache-2.0 carries an explicit patent grant.

The **documents** — `SPEC.md`, every `namespaces/*/SPEC.md`, `REFERENCES.md`,
`DEVIATIONS.md` — are **CC-BY-4.0** (`LICENSE-SPEC`), so that another
implementation can copy the normative text without taking on the code's
licence. A specification nobody can quote is not a specification.

Source files carry no licence header, deliberately: they are kept
byte-identical to the same files in the Wildroot tree.

## Citing

> Wildroot, *Web3 name resolution: a specification*, version 0.4.
> https://github.com/keptlive/wildroot-web3-resolution

## Contributing

Corrections against the standards' text are the most welcome thing you can
send. If you find a place where the code and a chapter disagree, the code is
the bug report and the chapter is the claim — say which you think is wrong.
[`CONTRIBUTING.md`](CONTRIBUTING.md) has the working detail: which file to
edit, how the generated documents are built, what the tests need, and what
`npm run parity` and `npm run sync` actually do.
