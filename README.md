# wildroot-web3-resolution

**Handshake name resolution, done from a chain proof rather than from a
resolver's word — with the written standard that describes it.**

This package is about **Handshake name resolution, and nothing else**: how a
Handshake name becomes an answer — an address, a content pointer (`ipfs=`,
`ar=`), a TLSA pin, and a trust state — through the chain (an SPV proof),
DNSSEC anchored to the on-chain DS, DANE, HIP-5 `_op`, DoH/ODoH transport, and
the `hns://` URL form. It is extracted from [Wildroot](https://wildroot.io) (the
HNS.ONE browser) so that other people can read it, test it, argue with it, and
implement it.

**The browser resolves several other naming systems and fetches from several
content networks. None of that is specified here.** Out of scope, and where it
lives instead:

| Out of scope | Where it lives |
|---|---|
| **Fetching content once a name is resolved** — the IPFS, Arweave, Hyper and BitTorrent handlers, and everything about verifying or rendering those bytes | the browser's `src/protocols/` and `src/hns/ipfs.js`; `docs/BLOB-LAYER.md` |
| **Other name systems the browser also resolves** — ENS (`.eth`), Nostr (`npub`/`nprofile`), AT Protocol (`at://`, `did:plc`/`did:web`), Tor (`.onion`), Gemini, SSB, and the ICANN DNS path | `docs/RESOLUTION-ROUTER.md`, and per-system notes in the browser tree |
| **The browser's trust UI** — the padlock, the security panel, the address bar | the browser's `src/ui/`; this package specifies the *model* those render (SPEC §4), not the rendering |
| **Publishing** — how a record gets into a zone in the first place | `PUBLISHING-AND-DNS.md` in the browser tree |

The scope boundary is the one drawn in the browser's own design documents:
`docs/RESOLUTION-ROUTER.md` (which namespace a name belongs to, and the rule
that a failure never crosses a namespace boundary) and `docs/STANDARDS.md` (the
conformance record this specification grew out of). This package implements the
Handshake branch of the first and the Handshake rows of the second.

- **[`SPEC.md`](SPEC.md)** — the standard: terminology, the resolution
  algorithm step by step, the trust states an implementation must expose, the
  `hns://` URL form, HIP-5 `_op`, DANE-for-HTTPS, DoH/ODoH.
- **[`REFERENCES.md`](REFERENCES.md)** — every standard used, with exact
  identifiers, links and what each is used *for*.
- **[`DEVIATIONS.md`](DEVIATIONS.md)** — every departure from a cited standard,
  and every place we are not sure we got it right. Read this one.

---

## What this does

```
hns://hello.14898/
  │  SPV getnameresource("14898")   ← Urkel proof, verified against headers
  │                                    this node checked itself
  │   ├─ TXT ipfs=<cid>  (apex)     → content, verified against the CID
  │   ├─ SYNTH4 <ip>                → an address consensus itself attests
  │   ├─ NS 0x<addr>._op.           → HIP-5: read the records from that
  │   │                                Optimism registry contract
  │   └─ NS ns1.hns.one  (+glue)    → the authoritative walk:
  │        DNSKEY, anchored to the TLD's ON-CHAIN DS
  │        TXT   hello.14898        → a content pointer, signature checked
  │        A     hello.14898        → an address, signature checked
  │        TLSA  _443._tcp.…        → the DANE pin, signature checked
  │        NS    pinner.hns (no SOA) → a REFERRAL: verify the parent's DS,
  │                                    move the anchor, re-enter one level down
```

Four things distinguish it from the usual Handshake client:

1. **The chain is the root of trust, not a resolver.** A local hsd SPV node
   verifies an Urkel tree proof against block headers it checked itself. A
   lying server can withhold an answer; it cannot forge one.
2. **DNSSEC is anchored to the on-chain DS.** Not to ICANN's root. Every record
   a resolution rests on — the pointer, the address, the pin, the DS at each
   cut, and every denial — validates or the resolution fails. A *missing* record
   must be *proven* missing.
3. **DANE pins the TLS certificate.** No CA can issue for a Handshake name, so
   the zone publishes `3 1 1` and the certificate must hash to it. As far as we
   can establish, this is the only shipping browser that validates DANE for
   HTTPS at all.
4. **It reports honestly.** A resolution yields a list of steps, each saying
   what was checked and *who told us*. There are three lock states, not two:
   trustless, trusted-but-not-trustless (which is what ordinary `https://` is),
   and open.

## Who this is for

- **Anyone building a Handshake client** — browser, extension, resolver,
  library. The spec is written to be implemented from, and the deviations are
  written so you can decide which of ours to copy and which to fix.
- **Anyone reviewing our security claims.** `DEVIATIONS.md` §2 is the list of
  things we are not sure about. §11.3 of the spec is a list of downgrades that
  were real, shipped bugs here, so you can test for them in yours.
- **Handshake registry operators**, for §7 (`_op`) — how a registry can stop
  being the trusted third party for the names it sells.
- **DNS and DNSSEC people**, who will find things wrong with this. Please tell
  us.

## Running the tests

```sh
npm install
npm test          # node --test tests/*.test.js
```

**315 tests, deterministic, no network.** Requirements: Node ≥ 20 and a
`python3` on `PATH` (several end-to-end tests spawn a real authoritative
nameserver, `tests/fixtures/resolver/nsd.py`, over frozen signed zones, so
"the signature validated" means a real server served real wire bytes).

What is covered: every DNSSEC algorithm signed and verified with in-test keys
plus flipped-byte negatives; NSEC and NSEC3 denial in every form including the
wildcard and opt-out cases; the delegation walk with a secure and an insecure
child; the address/pointer/pin stripping attacks of SPEC §11.3, each driven
through a DNS proxy that actually removes the record; the `_op` route against a
fake registry keyed with vectors from the independent implementation that
*writes* those records; the SVCB parser against real Cloudflare RDATA; the URL
form; the SSRF guard; the trust-state aggregation.

Not covered here, and honestly so: anything requiring a live network or a
running Handshake node. Those tests stay in the Wildroot tree.

```sh
npx standard      # lint, clean
```

## What is *not* here

This package is the resolution stack. Three things it deliberately excludes,
each described in `DEVIATIONS.md` §3:

1. **The composition layer.** In Wildroot, `src/hns/index.js` is the Electron
   `hns://` protocol handler — it picks the resolver per request, applies the
   DoH fallback policy, opens the TLS connection and checks the pin against the
   peer certificate. It is entirely Electron-bound. Its *policy* is specified
   normatively in SPEC §3, §8 and §9; the code is not extracted. If you are
   implementing from the spec, that layer is yours to write.
2. **Content fetching** — what happens to an `ipfs=` or `ar=` pointer once it
   is resolved.
3. **The browser chrome.** Three tests that assert the address bar and
   stylesheet render these verdicts without recomputing them were removed
   during extraction; they remain in the Wildroot tree.

Everything else is self-contained: no Electron, no browser globals. `src/spv.js`
spawns a real hsd (an *optional* dependency), so it is the one module that needs
something installed beyond this package.

Some comments in `tests/` cite paths under `~/hns/` — the operator toolchain
that *writes* the records these tests read (the zone signer, the authoritative
nameserver, the on-chain registry's own writer). Those repositories are not
public. The paths are kept because they are the provenance of the fixtures: they
say which independent implementation a vector came from, which is the whole
reason a fixture is trustworthy. Nothing in this tree needs them to run.

## Layout

```
SPEC.md          the standard
REFERENCES.md    what it is built on
DEVIATIONS.md    where it departs, and what we are unsure of
src/
  resolver.js          the algorithm: chain proof → the authoritative walk
  spv.js               the hsd SPV node connection (+ hsd-spv-launcher.cjs)
  dns-query.js         minimal TCP DNS client; the SVCB/HTTPS parser
  dnssec.js            RRSIG/DNSKEY/DS validation, RFC 8624 algorithms
  nsec.js nsec3.js     authenticated denial
  denial.js            the one door both schemes go through
  dane.js              TLSA 3 1 1 verification
  doh.js               the DoH fallback (RFC 8484)
  odoh.js              Oblivious DoH (RFC 9230) + odoh-bridge.js
  hip5-op.js           the HIP-5 `_op` route
  trust-path.js        resolution facts → trust steps → a lock verdict
  hns-url.cjs          the URL form, including the numeric-TLD convention
  hns-host.js          is this host a Handshake name? (+ router.js, icann-tlds.cjs)
  safe-address.js      the SSRF guard
  pointers.js          content-pointer parsing (+ contenthash.js for EIP-1577)
tests/                 the above, and fixtures/resolver/ (a real signed zone
                       and a real nameserver)
```

### Three modules reach past the scope line

Kept, but flagged, because a reader should not mistake them for part of the
specification:

- **`router.js`** is the browser's full namespace classifier — eighteen
  namespaces including ENS, Nostr, AT Protocol, Tor, Gemini, SSB, BitTorrent
  and the search fallback. That is `docs/RESOLUTION-ROUTER.md`'s subject, not
  this one's. It is here because `hns-host.js` uses two things from it —
  `classifyHost` and `NAMESPACES` — to answer the one question SPEC §3 asks:
  *is this host a Handshake name?* Only that answer is specified. **`search-url.js`**
  is here only because `router.js` imports it, and is entirely out of scope.
- **`trust-path.js`** contains two functions. `hnsSteps()` is the model SPEC §4
  specifies. `schemeSteps()` covers roughly twenty URL schemes including the
  browser's own internal pages, and belongs to the browser's trust UI.

They are kept rather than trimmed for one reason: every source file here is
byte-identical to its counterpart in the Wildroot tree, so a fix in one is
provably the same fix in the other. Forking `classifyHost` into `hns-host.js`
to make the package tidier would break that, and a divergent copy of a
security-relevant classifier is a worse problem than an over-broad dependency.
`contenthash.js` and `pointers.js` are **in** scope: they are the
pointer-record grammar SPEC §10 specifies, which is what an `ipfs=` TXT string
and an EIP-1577 `contenthash()` read have to be parsed into.

## Status

The implementation in `src/` is the resolution stack the Wildroot browser
ships. It resolves a Handshake name from a chain proof, validates every record
the answer rests on against the top-level name's on-chain DS, proves every
absence it relies on, pins TLS with DANE, reads a HIP-5 `_op` registry when the
chain names one, falls back to DoH with the weaker trust stated rather than
hidden, and reports each step's provenance to the interface. **315
deterministic tests**, no network, lint clean.

`SPEC.md` describes that behaviour normatively. Where the specification and the
code disagree, that is a bug in one of them — please say which you think it is.

The things we would most like argued with are in `DEVIATIONS.md` §2:

- **§2.1 the numeric-TLD `_` convention** — a local invention with no standing,
  forced by the WHATWG URL Standard's IPv4 host rule. Marked PROVISIONAL in the
  spec. We would rather adopt somebody else's convention than defend ours.
- **§2.2** SVCB/HTTPS is parsed and not queried; ECH is blocked on Node.
- **§2.3** registry TLDs that refer, and nameservers that are themselves
  Handshake names.
- **§2.4** what the DoH fallback actually promises.
- **§2.5** DANE pin rotation windows, and the "pinned before" memory we have
  not built.
- **§2.6** what an SPV proof does and does not establish.
- **§2.7** `_op` is chain-pointed and RPC-answered.

## Licence

The **code** in `src/` and `tests/` is **Apache-2.0** (`LICENSE`). These modules
were written inside a fork of [Agregore](https://github.com/AgregoreWeb/agregore-browser),
but none of them is derived from Agregore code — no file here exists upstream,
and the resolution stack was written from scratch — so the copyright is the
author's to license, and Apache-2.0 is chosen deliberately: a reference
implementation that other clients cannot adopt is not a reference
implementation, and Apache-2.0 carries an explicit patent grant that a
permissive licence without one does not.

The **documents** — `SPEC.md`, `REFERENCES.md`, `DEVIATIONS.md` — are
**CC-BY-4.0** (`LICENSE-SPEC`), so that another implementation can copy the
normative text without taking on the code's licence. A specification nobody can
quote is not a specification.

Source files carry no licence header, deliberately: they are kept
**byte-identical** to the same files in the Wildroot tree (modulo the import
paths rewritten for self-containment), so that a fix in one is provably the same
fix in the other.

## Citing

> Wildroot, *Handshake name resolution: a specification*, version 0.1.
> https://github.com/keptlive/wildroot-web3-resolution

## Contributing

Corrections against the RFC text are the most welcome thing you can send. If
you find a place where the code and `SPEC.md` disagree, the code is the bug
report and the spec is the claim — say which you think is wrong.
