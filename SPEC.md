# Web3 name resolution — a specification

**Version:** 0.4 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in this
repository, which ships in the Wildroot browser. Not endorsed by any standards
body. Normative statements describe what an implementation must do *to
interoperate with this one*; where they are inherited from an existing
standard, that standard is cited and its rule governs. One chapter (Chapter 10)
is marked **experimental** and says what that means.
**Licence:** CC-BY-4.0 (`LICENSE-SPEC`). The reference implementation is
licensed separately (Apache-2.0, `LICENSE`).

This document is the **spine**. Part I is the model every namespace shares.
Part II is namespace selection — the one decision made before any resolution.
Part III is one chapter per namespace; each chapter is its own file under
`namespaces/<ns>/SPEC.md`, and each is normative for its namespace. Every
deviation from a cited standard, every open question and every open design
decision is in `DEVIATIONS.md`; every standard cited is in `REFERENCES.md`,
with what it is used for; every place where privacy and speed pull apart is in
`DIVERGENCE.md`. **Those files are part of this specification, not appendices
to it.**

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## Contents

**Part I — The shared model**
1. [What this specifies, and why it exists](#1-what-this-specifies-and-why-it-exists)
2. [Terminology](#2-terminology)
3. [The two laws](#3-the-two-laws)
4. [Trust states](#4-trust-states)

**Part II — Namespace selection**
5. [The scheme registry](#5-the-scheme-registry)
6. [Classification of bare input](#6-classification-of-bare-input)
7. [Dispatch and failure](#7-dispatch-and-failure)

**Part III — The namespaces**
- [Chapter 1 — Handshake](namespaces/handshake/SPEC.md)
- [Chapter 2 — ICANN names](namespaces/icann/SPEC.md)
- [Chapter 3 — IPFS, IPNS and DNSLink](namespaces/ipfs/SPEC.md)
- [Chapter 4 — Arweave](namespaces/arweave/SPEC.md)
- [Chapter 5 — ENS and `web3://`](namespaces/ens/SPEC.md)
- [Chapter 6 — Nostr](namespaces/nostr/SPEC.md)
- [Chapter 7 — DID, AT Protocol and ActivityPub](namespaces/did/SPEC.md)
- [Chapter 8 — Tor](namespaces/tor/SPEC.md)
- [Chapter 9 — Key-addressed namespaces: hyper, SSB, Gemini, BitTorrent](namespaces/keys/SPEC.md)
- [Chapter 10 — Experimental: HIP-5 `_op` on-chain resolution, and numeric Handshake TLDs](namespaces/experimental/SPEC.md)
- [Chapter 11 — Native applications on a Handshake name](namespaces/apps/SPEC.md)

The full text of Part II, with its own security considerations and conformance
section, is [`namespaces/router/SPEC.md`](namespaces/router/SPEC.md); §§5–7
below are the normative summary.

---

# Part I — The shared model

## 1. What this specifies, and why it exists

A browser that resolves more than one naming system has a problem the single
system never had: an address has to be assigned to exactly one system before
anything else can happen, the systems have different roots of trust, and a
failure in one must not quietly become a lookup in another. Handshake names are
proven from a chain; ICANN names come from a resolver; a CID proves its own
bytes; an ENS name is an RPC endpoint's word; an onion address must never be
seen by a DNS server at all. A browser that blurs those together — by falling
back from one to the next, or by drawing one padlock for all of them — is
making claims it cannot support.

This specification does three things.

1. **It chooses one namespace for every input, once** (Part II). The scheme, if
   there is one, decides. Without one, a fixed classification order decides,
   and the decision is final: there is no "try Handshake, and if that fails,
   try DNS".
2. **It specifies each namespace's resolution** (Part III): the address grammar,
   the algorithm, what is verified in this process and what is trusted, and
   the failure modes — each in the namespace's own terms and against the
   standards that define it.
3. **It makes the trust state a first-class output** (§4). Every resolution
   yields an ordered list of steps, each saying what was checked and *who told
   us*. An interface is given that list, not a boolean, and three lock states
   — trustless, trusted, open — are distinguished because the second one is
   what the ordinary web is, and rendering it like the first is a lie.

### 1.1 Scope

**In scope:** everything between an address and an answer. Which namespace an
input belongs to; the grammar of each address form; the resolution algorithm of
each namespace; what is cryptographically verified in this process and what is
taken on somebody's word; how a failure is reported without becoming a lookup
in another namespace; the transport a lookup travels over and what that
transport discloses.

**Out of scope:** content transport (fetching and rendering bytes once a name
has resolved — the chapters state what is and is not *verified* about those
bytes, never how they are fetched); publishing (how a record gets into a zone,
a registry or a relay); the trust user interface (this document specifies the
model an interface is given and the claims it must not make, not a rendering);
and the composition layer that wires these modules to a session, a proxy and a
window (each chapter specifies its policy normatively).

An implementation of this specification is a **resolver**, not a browser. It
answers "what does this address mean, and how sure are we?" and stops there.

## 2. Terminology

- **Namespace** — a distinct address space with its own root of trust. Two
  schemes may share one namespace (`ipfs://`, `ipns://`, `ipld://` and
  `pubsub://` are all IPFS). Failures never cross a namespace boundary (§3).
- **Scheme** — the token before the first `:` of an explicit URL. The registry
  (§5) maps every scheme this implementation dispatches to exactly one
  namespace.
- **Classification** — the assignment of a scheme-less input to one namespace
  (§6).
- **Dispatch** — handing a request to the one handler its scheme names (§7).
- **Resolution** — a namespace's own process from address to answer; each
  chapter defines its answers and their kinds.
- **Trust step** / **trust state** — §4.
- **Content-addressed** — an address that names bytes by a hash of them (a
  CID, an infohash), so that the bytes verify themselves. **Key-addressed** —
  an address that names a signing key (a hypercore key, an SSB feed, a BEP-46
  key, a Nostr key), so that a signature proves *who wrote* the content but
  nothing proves it is the *newest*. The distinction matters to §4 and is
  drawn in Chapter 9 §K.3.
- DNS terms are used as defined in **RFC 8499**; DNSSEC validation states are
  those of **RFC 4033 §5** (Chapter 1 §2 states the mapping this document
  makes).

## 3. The two laws

Everything in Part II, and the boundaries of every chapter, follow from two
rules, which an implementation **MUST** hold structurally — in the one place
that routes — rather than as a convention each handler is trusted to keep.

**L1 — An explicit scheme selects the protocol, always.** `ipfs://vitalik.eth`
is an IPFS request whose host happens to look like an ENS name; it goes to the
IPFS handler and nothing re-sniffs it. An unknown scheme is preserved as itself
and fails as itself (§7); it is never reinterpreted as a host, a domain or a
search. Content is never sniffed to override a scheme.

**L2 — No silent cross-namespace fallback.** A failure in one namespace
surfaces as *that* namespace's failure. A Handshake name that does not resolve
is not looked up in ICANN's DNS; an ENS name with no record is not looked up as
a Handshake name (whoever holds the Handshake TLD `eth` does not receive ENS
traffic); an onion address is never sent to a resolver, valid or not. RFC 9498
§9.10 states the same rule for GNS — resolve in the alternative namespace when
its suffix matches and do not continue into DNS on failure — and this document
adopts it for every namespace it dispatches.

Two things are **not** breaches of L2 and are called out so nobody mistakes
them for one. A **search** for a scheme-less input that classifies to no
namespace (§6) is not a fallback: no protocol was named, so there is nothing to
fall back *from*. A **transport downgrade inside one namespace** — Chapter 1's
retry of a failed chain lookup over DoH, resolving the same Handshake name in
the same namespace with a weaker trust state that is reported — is not a
fallback either: L2 governs a named protocol failing into another.

## 4. Trust states

A resolution does not produce a boolean. It produces an ordered list of
**steps**, each of which says what was checked, who said so, and one of four
states:

| State | Meaning |
|---|---|
| `verified` | checked cryptographically, in this process, in this resolution |
| `unverified` | taken on somebody's word — a resolver, a CA, an RPC endpoint, a directory, a relay, a gateway, the network |
| `failed` | checked and did not pass |
| `none` | does not apply, or is absent and *known* to be absent |

An implementation **MUST** expose these steps, or an equivalent, to the user
interface, and **MUST NOT** collapse them into a single boolean before the user
sees them. Each chapter specifies the steps its namespace produces; the shared
rules are these.

- A step is `verified` only for a check performed in this process during this
  resolution: a chain proof verified against headers this client checked, a
  signature verified against a key the address names, bytes hashed against the
  address they were requested by. Anything read from a server, an endpoint or
  a relay and believed is `unverified`, however reputable the source and
  however encrypted the transport.
- **Under-claiming is as misleading as over-claiming.** A scheme with a real
  verification story (a CID, a Nostr signature) MUST NOT fall through to "no
  verification path"; a scheme with none (a gateway's bytes, a directory's
  document) MUST NOT borrow a content-addressed sentence.
- The source of an `unverified` step MUST be named (which resolver, which RPC,
  which relay set, which gateway), and an oblivious lookup MUST be
  distinguished from a plain one, so that the interface can say who saw the
  question.

### 4.1 Aggregating to a lock

An implementation that shows a single indicator SHOULD distinguish **three**
states, not two:

- **TRUSTLESS** (closed, and marked as such — the "verified" verdict): every
  step is `verified` or `none`. Nobody was believed. A chain-proven Handshake
  name resolving to a content pointer, or to an address with a matched DANE
  pin under a validated zone; an `ipfs://` CID; a `hyper://` key.
- **TRUSTED** (closed, but not trustless — the "partial" verdict): the
  transport is confidential and authenticated, but at least one step is
  `unverified`. **This is what an ordinary `https://` page is**, and it is
  where `ens://`, `ar://`, `did:`, `nostr:`, a DNSLink-resolved `hyper://` name
  and Chapter 10's `_op` resolution sit. An indicator that renders this state
  identically to the one above is lying by omission.
- **OPEN**: the connection itself carries no protection (a `Connection` step
  of `none`: plain HTTP; an onion service's HTTP inside the tunnel is reported
  as `unverified`, not `none`). A step that `failed` is its own verdict.

The rule is the weakest link: a `failed` step MUST NOT aggregate to a closed
lock; a single `unverified` step MUST NOT aggregate to trustless; a plaintext
connection MUST NOT aggregate to the same verdict an encrypted one gets. The
reference implementation's aggregation is `summarize()` in
`src/trust-path.js` — five states: `verified`, `partial`, `open`, `failed`,
`unknown` — and every scheme row in the registry carries the verdict it can at
best reach (`trust`: trustless, trusted, open, refused, builtin), which
`tests/lock-semantics.test.js` holds the panel to.

### 4.2 Modes: Fast and Private

Privacy and speed pull apart in five places across the namespaces this
document specifies ([`DIVERGENCE.md`](DIVERGENCE.md) rows 3, 7, 10, 15 and
19); everywhere else the private path is also the fast one, by construction.
For those five an implementation **MAY** offer two modes, and if it does:

- There **MUST** be exactly **one** control. IP Protection (the session proxy
  through the device-local Tor) and every other private path move together;
  two controls would let a person believe they were private while one of them
  was off. The reference control is `DeliveryMode` in
  `src/delivery-mode.js`, whose `policyFor(mode)` is the single table every
  consumer reads.
- **Private** MUST: route every session fetch through the device-local Tor,
  and **fail closed** when Tor cannot be had — the sessions are pointed at a
  loopback port nothing listens on (`BLACKHOLE_RULES`,
  `namespaces/tor/src/anonymize.js`), never a direct connection; look a
  Handshake name up over DoH obliviously or not at all (Chapter 1 §9,
  `DoHResolver({ strictOblivious })`); look an ICANN name up through the
  oblivious bridge only, nothing plaintext (Chapter 2, `privateDns()`); dial
  a Handshake site, a relay and the WebSocket tunnel through Tor with their
  chain proof and pins unchanged (`src/dane-connect.js`,
  `namespaces/nostr/src/tor-websocket.js`, Chapter 11 §4.4); refuse hyper,
  SSB and BitTorrent discovery with the reason on the page (Chapter 9), and
  serve a Handshake name that publishes a stated origin from that origin
  (Chapter 3 §8).
- **Fast** is the configured behaviour of each chapter with the mode absent.
- Every refusal or failure a mode causes **MUST** name the mode, say what was
  not done (nothing was sent; no unprotected lookup was made), not blame the
  site, and point at the control — one builder, `privateRefusal()`.
- A mode **MUST NOT** change a trust verdict. A verdict is a fact about the
  page (§4.1); the mode is a policy about the route. The disclosure the
  reference control carries is `DISCLOSURE` in `src/delivery-mode.js`, in
  full; the design is the browser's `docs/MODES.md`.

---

# Part II — Namespace selection

Part II is specified in full in [`namespaces/router/SPEC.md`](namespaces/router/SPEC.md)
and implemented by `src/router.js` (the classifier and the registry),
`src/hns-host.js` (the `http(s)`→`hns` rewrite), `src/reserved-names.cjs` and
`src/icann-tlds.cjs` (the two lists every classifier copy reads) and
`src/trust-path.js` (the trust model). What follows is normative and
complete for interoperation; the chapter adds the rationale, the security
considerations and the conformance clauses.

## 5. The scheme registry

An implementation **MUST** keep one table mapping every scheme it dispatches to
exactly one namespace, with a stated verification story, and **MUST** refuse to
wire a handler for a scheme absent from it. The reference table is
`SCHEME_TABLE`; its namespaces are:

| Namespace | Schemes | Verified by (the native layer) |
|---|---|---|
| `hns` | `hns` | SPV chain proof + DANE `3 1 1`, or a content pointer's own hash (Chapter 1) |
| `ipfs` | `ipfs`, `ipns`, `ipld`, `pubsub` | CID; an IPNS record + CID; a pubsub topic is **not** a content address — a message carries only its publisher's libp2p signature (Chapter 3) |
| `arweave` | `ar` | the transaction id's shape and canonical spelling only; bytes are gateway-trusted (Chapter 4) |
| `ens` | `ens` | an EIP-1577 contenthash read over a public Ethereum RPC — RPC-trusted, not chain-proven; the content it names is CID-verified (Chapter 5) |
| `web3` | `web3` | an ERC-4804 EVM read over a public RPC (Chapter 5); there is deliberately **no** `w3://` — `.w3` is a Handshake TLD |
| `nostr` | `nostr` | BIP-340 signature and event id recomputed locally, answer bound to the query; relay completeness not proven (Chapter 6) |
| `atproto` | `at` | recognised and refused: 501 with no network request (Chapter 7) |
| `did` | `did` | a DID document fetched from a directory or the named host, its `id` checked; not proven (Chapter 7) |
| `activitypub` | `activitypub` | recognised and refused: 501 with no network request (Chapter 7) |
| `tor` | `onion` | the onion-service key, reached only through the device-local Tor; never DNS (Chapter 8) |
| `web` | `https`, `http`, `https+raw` | WebPKI; none for `http`. An ICANN name's navigation is an `https://` URL and so carries this namespace on dispatch, while classification reports the finer `icann` (Chapter 2) |
| `gemini` | `gemini` | none — TLS with no certificate verification and nothing pinned (Chapter 9) |
| `hyper` | `hyper` | a hypercore key; a DNSLink name→key binding is resolver-trusted (Chapter 9) |
| `ssb` | `ssb` | a feed signature (Chapter 9) |
| `bittorrent` | `bittorrent`, `bt` | an infohash, or a BEP-46 key (Chapter 9) |
| `magnet` | `magnet` | an infohash; only ever redirects (Chapter 9) |
| `browser` | `wildroot` and its silent aliases `agregore`, `browser`; `paste`, `editor`, `bluesky`, `mastodon`, `media`, `docview` | built into the browser; not part of this specification beyond their presence in the table |
| `search` | `search` | the terminal for "no protocol was named" |

`icann` is a classification result (§6) with no scheme of its own; the
dispatch vocabulary is the table's. The `X-Resolution-Namespace` response
header (§7) speaks the table's vocabulary.

## 6. Classification of bare input

Given an input with no explicit scheme, an implementation **MUST** decide in
this order; the first match is final.

1. **Explicit scheme** (L1): the input is returned as it is, with the
   namespace the table gives its scheme (or none, for an unknown scheme), and
   with a `known` flag so that a navigating caller can refuse `javascript:`,
   `data:` and `file:`. A `host:port` shape (`example.com:8080`) is a host, not
   a scheme.
2. **`@user@host`** — the Fediverse address form — is `activitypub:`. It is
   not a host: the URL parser would read the second `@` as userinfo. Any other
   `@` in a scheme-less input is a search: no namespace has one in an address,
   and the URL constructor would drop what precedes it.
3. **A bare NIP-19 identifier** (`npub`, `note`, `nprofile`, `nevent`,
   `naddr`, `nsec` followed by a bech32 body) is `nostr:` — DECODED before it
   is claimed, so a Handshake name that merely starts with `npub` stays a
   name; an `nsec` is routed on purpose, so the secret reaches the handler's
   refusal page instead of a resolver.
4. **A bare CID** (`bafy…` base32 CIDv1, or `Qm…` base58 CIDv0, *parsed*, not
   shape-matched) is `ipfs://<cid>/`; a CIDv0 is written as its CIDv1 because
   a case-sensitive host does not survive the URL parser. An IPNS key is
   deliberately **not** sniffed: `Qm…` is both a legacy IPNS key and a CIDv0.
5. **`/ipfs/…` and `/ipns/…`** gateway paths are `ipfs://` and `ipns://`.
6. **`localhost[:port]`** is `http://`.
7. **Host classification** (`src/classify-host.cjs`, the ONE implementation
   the router and the omnibox both load), in this order:
   1. any whitespace → no namespace (a search);
   2. `*.onion` → `tor`, valid or not — a mistyped onion address leaks to a
      resolver as effectively as a real one, so the suffix decides;
   3. `*.eth` → `ens`;
   4. a **reserved name** → `web`, reached as `http://` on the platform
      resolver: the labels of RFC 6761 (`localhost`, `invalid`, `test`,
      `example`), RFC 6762 (`local`), RFC 7686 (`onion`, already taken above),
      RFC 8375 (`arpa`, for `home.arpa`) and the home-network labels
      `internal`, `home`, `lan`, `corp`, `intranet`, `private`
      (`src/reserved-names.cjs`). A NAS, a printer or an internal service
      name is the user's own device; sending it to whoever registers the
      Handshake TLD `local` would disclose it and let them answer for it;
   5. an **IP literal**, IPv4 or IPv6 with or without brackets → `web`,
      checked *before* the label count so that `::1` is an address and not a
      bare label;
   6. a single label → step 8;
   7. an all-numeric final label → `hns` (ICANN has no numeric TLDs).
      **Experimental:** whether numeric Handshake TLDs are supported at all is
      undecided, and the URL form such a name needs is Chapter 10 Part B;
   8. a final label in the ICANN root → `icann`, navigated as `https://`;
   9. any other final label → `hns`.
8. **A single bare label** is a Handshake name unless the label is itself an
   ICANN TLD (`com`, `org`, `app` — a word somebody is mid-way through typing),
   which is a **search**.

The ICANN root used in 6.8 is a bundled snapshot of IANA's list of delegated
TLDs, held to the live root by a test (Chapter 2 §2). An internationalized host
is converted to A-labels before comparison (the reference implementation does
so through the WHATWG URL parser; `DEVIATIONS.md` RT records what that means).
The same rule **MUST** be applied on every path that classifies a host — typed
input, a link click, an `http(s)`→`hns` rewrite, a subresource load, a
WebSocket. The reference implementation has one implementation of the host
rule, loaded by the router and the omnibox; the WebSocket PAC script, which
runs in a sandbox with no URL parser, carries an ASCII-only form of it and is
held to the shared answer by a test.

**A search is a terminal, not a fallback.** An input that reaches step 8 and is
an ICANN TLD, or contains whitespace, named no protocol; there is nothing to
fall back from.

## 7. Dispatch and failure

`dispatch(request)` reads the scheme from the URL and nothing else, and has
exactly four outcomes, none of which crosses a namespace:

- **the handler's own response**, returned verbatim — a 404 from the
  Handshake handler is a Handshake 404 and is not retried anywhere;
- **501** when no handler is registered for a scheme, tagged with the scheme's
  namespace; the URL is not reinterpreted as a host, a domain or a search;
- **502** when the handler throws, tagged the same way;
- **400**, untagged, when the input is not a URL and names no scheme.

When the input names a scheme but the URL Standard's parser refuses it — the
canonical AT-URI `at://did:plc:…/…` has a colon in its host — the scheme is
read by prefix and the request still reaches, or fails inside, that scheme's
namespace: a named protocol's failure never escapes its namespace on the way to
the interface.

Every failure response an implementation produces **SHOULD** carry
`X-Resolution-Namespace: <namespace>` (the table's vocabulary), a
machine-readable proof for the interface that the failure stayed where it
started; the reference implementation's namespace handlers carry it on every
response, success included.

---

# Part III — The namespaces

Each chapter is normative for its namespace and follows one shape: what it
specifies and why; terminology; namespace membership (which inputs are its);
the address grammar; the resolution algorithm; what is verified and what is
trusted, as trust steps of §4; failure modes; security considerations. Each
chapter's deviations and open questions are in `DEVIATIONS.md` under the
chapter's prefix.

| Chapter | Namespace | Root of trust | Verdict when it succeeds |
|---|---|---|---|
| [1 — Handshake](namespaces/handshake/SPEC.md) (`HS`) | `hns` | a chain proof from a local SPV node; DNSSEC anchored to the on-chain DS; DANE `3 1 1`; content pointers read from `ipfs=`/`ar=` records AND from DNSLink — the migration path from every other IPFS client | TRUSTLESS for a content pointer or a pinned, validated address; TRUSTED over the DoH fallback; OPEN for a proven-unpinned name over plain HTTP |
| [2 — ICANN names](namespaces/icann/SPEC.md) (`IC`) | `icann` / `web` | WebPKI; the address from encrypted DNS (plain or oblivious) per a transport plan decided once and reported truthfully | TRUSTED |
| [3 — IPFS, IPNS and DNSLink](namespaces/ipfs/SPEC.md) (`IP`) | `ipfs` | the CID: every block hash-checked by the local node; an IPNS record's signature | TRUSTLESS |
| [4 — Arweave](namespaces/arweave/SPEC.md) (`AR`) | `arweave` | the transaction id names immutable bytes, but the bytes are fetched from an ar.io gateway and **not** checked against it | TRUSTED |
| [5 — ENS and `web3://`](namespaces/ens/SPEC.md) (`EN`) | `ens`, `web3` | an EIP-1577 contenthash read over a public Ethereum RPC (with ERC-3668 CCIP-Read and a local ENSIP-21 batch); the content it names is CID-verified | TRUSTED |
| [6 — Nostr](namespaces/nostr/SPEC.md) (`NO`) | `nostr` | every event's id recomputed and BIP-340 signature checked here, and bound to the question asked; relays are a transport | TRUSTED (authorship proven, completeness not) |
| [7 — DID, AT Protocol and ActivityPub](namespaces/did/SPEC.md) (`DI`) | `did`, `atproto`, `activitypub` | a DID document fetched from `plc.directory` or the `did:web` host and checked to be about the DID asked for; `at://` and `activitypub:` recognised and refused | TRUSTED for `did:`; a refusal for the other two |
| [8 — Tor](namespaces/tor/SPEC.md) (`TO`) | `tor` | the onion-service key, at the Tor layer, over the device-local Tor only; the page is HTTP inside the tunnel | TRUSTED |
| [9 — Key-addressed](namespaces/keys/SPEC.md) (`KY`) | `hyper`, `ssb`, `gemini`, `bittorrent`, `magnet` | a hypercore key, an SSB feed key, an infohash or a BEP-46 key verify their own content; Gemini verifies nothing | TRUSTLESS for a key or a hash; TRUSTED for a DNSLink-resolved hyper name and for Gemini |
| [10 — Experimental](namespaces/experimental/SPEC.md) (`OP`, `NT`) | Part A: HIP-5 `_op`, a route within `hns`; Part B: numeric Handshake TLDs and the `_` URL marker | A: the chain proves *which* Optimism registry contract answers; the contract's answer arrives over a public RPC and is taken on its word. B: a URL-form convention forced by the URL Standard's IPv4 host rule | A: TRUSTED (never TRUSTLESS), lock closed on the chain proof for a content pointer or with a DANE pin for an address. B: as the Handshake chapter, for a name whose support is undecided |

| [11 — Native applications on a Handshake name](namespaces/apps/SPEC.md) (`AP`) | `hns` as an origin | `hns://` is a standard, secure scheme, so a name is a real origin with storage, cookies and service workers; a `wss://` upgrade to a Handshake name goes through a loopback CONNECT tunnel that resolves the name by chain proof and pins the TLS with DANE, and is fenced to loopback, Handshake hosts, public addresses and the anonymization gate; sign-in with a name from a page on another name goes through the browser as mediator | as Chapter 1 for the name; the tunnel adds no trust of its own and is never a proxy for anything but a Handshake host |

Chapter 11 is where this specification's pieces meet: a **native application**
— one that lives at a bare Handshake name, keeps state in that origin, holds a
WebSocket to it, and signs its users in with the names they hold — needs
Chapters 1, 2 and Part II to hold at once, and the chapter records what that
takes and what it cost.

**Experimental** (Chapter 10, and the sections so marked inside Chapters 3 and
7) means: shipped in the browser, reached only behind a record, a setting or a
name shape that opts into it, not yet a proposed standard, and liable to change
— and, for numeric Handshake TLDs, whether they are supported at all is
undecided. The non-experimental chapters describe behaviour this
implementation commits to interoperating on.
