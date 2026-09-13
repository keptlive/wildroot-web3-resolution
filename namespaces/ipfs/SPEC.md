# Chapter 3 — IPFS, IPNS and DNSLink

**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in this
directory and in the Wildroot browser it is extracted from. Not endorsed by any
standards body. Normative statements describe what an implementation must do
*to interoperate with this one*; where a rule is inherited from an existing
standard, that standard is cited and its text governs.
**Licence:** CC-BY-4.0 (`../../LICENSE-SPEC`). The reference implementation is
licensed separately.

This chapter is part of the integrated specification whose spine is
[`../../SPEC.md`](../../SPEC.md), where namespace selection — which identifier
belongs to which namespace, and the two routing laws that keep the boundary —
is specified. Where a Handshake name carries a content pointer, the spine gets
the name to the pointer and this chapter says what the pointer *is*; deviations
and open questions for this chapter live in
[`../../DEVIATIONS.md`](../../DEVIATIONS.md) under the `IP-` prefix, and its
references in `REFERENCES.md` beside this file. Both are part of the
specification, not appendices to it.

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are used
as in RFC 2119 / RFC 8174. **§8 is marked EXPERIMENTAL**: it ships in the
reference implementation, it is a local convention with no standing outside it,
and its behaviour may change. Everything else here describes what an
interoperating implementation must do.

---

## Contents

1. [What this specifies, and why it exists](#1-what-this-specifies-and-why-it-exists) — including [**scope**](#11-scope)
2. [Terminology](#2-terminology)
3. [Namespace membership](#3-namespace-membership)
4. [The identifiers](#4-the-identifiers)
5. [What a CID identifies](#5-what-a-cid-identifies)
6. [The pointer records a name carries](#6-the-pointer-records-a-name-carries)
7. [The resolution algorithm](#7-the-resolution-algorithm)
8. [**Experimental**: the `car=` stated origin and origin warming](#8-experimental-the-car-stated-origin-and-origin-warming)
9. [Verified by hash, and trusted](#9-verified-by-hash-and-trusted)
10. [Trust states](#10-trust-states)
11. [Failure modes](#11-failure-modes)
12. [Security considerations](#12-security-considerations)

---

## 1. What this specifies, and why it exists

IPFS is the one namespace in this stack where the *address is the proof*. A CID
is a hash; bytes that do not hash to it are not the content it names. That makes
the resolution question unusually sharp, and unusually easy to get subtly wrong:
everything interesting happens in the step **before** the hash check — deciding
*which* CID an identifier means.

This chapter specifies that step, in four places where it happens:

- a URL in one of the two IPFS schemes (§4),
- a `TXT` content pointer on a Handshake name (§6.1),
- an EIP-1577 `contenthash` read from a registry contract on the HIP-5 `_op`
  route (§6.4),
- and a **stated origin** (`car=`) that says where an archive of that CID can be
  fetched from — a hint about location that MUST NOT become a claim about
  content (§8.1, **EXPERIMENTAL**).

It also specifies the boundary that keeps the design honest: an IPNS name is
*not* a CID, and one of the two schemes in this namespace needs something other
than a hash before a hash can be checked.

### 1.1 Scope

**In scope: turning an identifier into a verified content address.** Precisely:
which identifiers belong to this namespace, what each one denotes, which of them
authenticate themselves and which rest on somebody's word, what a Handshake name
publishes to point into the namespace, and what an implementation is entitled to
tell a user about the result.

**Out of scope, explicitly.**

| Out of scope | Where it lives |
|---|---|
| **Retrieval** — bitswap, the DHT, the block exchange, HTTP trustless-gateway transport, the node's lifecycle | The Wildroot browser's `src/hns/ipfs.js` (the node) and `src/protocols/ipfs-protocol.js` (the `ipfs://`/`ipns://` adapter that reads it). Both are transport: they obtain and serve bytes for an address this chapter has already decided. |
| **Verification of retrieved bytes against the CID** | The IPFS node does it. This document says *that* it happens (§9) and what it is worth; it does not respecify multihash checking. |
| **Serving, pinning, announcing, cooperative delivery** | `docs/COOP-DELIVERY.md` in the Wildroot tree; pinthis's own decisions. |
| **Publishing** — how an `ipfs=` record is written, an IPNS key created, an archive uploaded | The write path is a different problem with a different threat model. `PUBLISHING-AND-DNS.md`, `STORAGE-PUBLISH-SHARE.md`. |
| **The Handshake half of a `hns://` resolution** — the chain proof, DNSSEC, DANE | The Handshake chapter, reached from the spine `../../SPEC.md`. |
| **The user interface** | §10 specifies the model a panel is given and the claims it must not make, never a rendering. |

A consequence worth stating: an implementation of this chapter answers *"which
bytes does this identifier name, and how sure are we that this is the right
question?"*. It does not fetch anything.

**One thing is in scope that looks like transport and is not.** Computing the
CID *of* a set of bytes (§5) is the definition of the address, and the reference
implementation includes it (`src/cid.js`) precisely so that "verified by hash"
can be tested without a daemon.

**Layout of the reference implementation.** `src/cid.js` computes the CID of a
set of bytes (§5), `src/origin-warm.js` is the stated origin and its byte
window (§8), and `src/block-presence.js` is how long a warmer may go on
believing a block is still on the node before it asks again (§8.3) — three
whole modules. Four smaller modules are factored out
of larger files whose remainder is transport or an unrelated subsystem, so that
the resolution half can be read and tested on its own: `src/ipfs-url.js` (a URL
in this namespace to its root CID, §4.1), `src/byte-range.js` (the `Range`
header a windowed read is derived from, §8.2), `src/car-roots.js` (the roots an
archive claims, and the minimal dag-cbor header reader that gets them, §12.2)
and `src/source-error.js` (the typed refusal `src/cid.js` raises). The pointer
grammar (`CID_RE`, `IPNS_RE`, `car=`), the EIP-1577 decoder and the scheme
table are shared with the rest of the specification and are used from
`../../src/pointers.js`, `../../src/contenthash.js` and `../../src/router.js`.

---

## 2. Terminology

IPFS and IPLD terms are used as their own specifications define them:
*multibase*, *multicodec*, *multihash*, *CID*, *UnixFS*, *DAG-PB*, *dag-cbor*,
*block*, *CAR*, *IPNS record*, *DNSLink*. Handshake and DNS terms are the
spine's (RFC 8499). Terms specific to this chapter:

- **Content address** — a CID: a self-describing hash that names exactly one
  DAG. Immutable by construction.
- **Mutable pointer** — an identifier that names a *sequence* of content
  addresses over time: an IPNS name, a DNSLink record. Resolving one is a
  lookup, not a hash check.
- **Content pointer** — a record on a Handshake name whose value is a content
  address or a mutable pointer (`ipfs=`, `ipns=`), as defined by the spine §10
  and `../../src/pointers.js`.
- **Stated origin** — a `car=` record naming an HTTPS location an archive of the
  pointed-at CID can be fetched from (§8.1). A hint about *where*, never about
  *what*.
- **Archive** — a CAR (Content Addressable aRchive) file: a header naming root
  CIDs, then a sequence of blocks.
- **Window** — a byte range of one file inside a DAG, requested from a trustless
  gateway with IPIP-402 `entity-bytes` (§8.2).
- **Root of trust** — for this namespace, the hash function. Nothing else in it
  is trusted, and everything that is not hash-checked is named as such.

---

## 3. Namespace membership

Two URL schemes belong to this namespace: **`ipfs` and `ipns`**. They share one
root of trust and are therefore one namespace, not two (`../../src/router.js`,
`SCHEME_TABLE`).

**One namespace, one node.** Both schemes are served by the same IPFS node a
Handshake name's `ipfs=` pointer is fetched through, so a block imported on one
path is on the node for the other, and an IPNS name published there is resolved
there (§12.5).

An implementation **MUST** apply the spine's two routing laws here without
exception:

- **An explicit scheme selects the namespace.** `ipfs://vitalik.eth/` is an IPFS
  request whose host happens to look like an ENS name; it **MUST NOT** be
  re-sniffed into another namespace.
- **A failure never crosses the boundary.** An `ipfs://` request that cannot be
  answered fails as an IPFS failure. It **MUST NOT** become a DNS lookup, a
  gateway redirect, or a search. This is RFC 9498 §9.10's rule, adopted
  verbatim by the spine.

Four further membership rules:

- The **gateway path forms** `/ipfs/<cid>[/path]` and `/ipns/<key>[/path]`,
  typed without a scheme, are IPFS identifiers and are rewritten to `ipfs://`
  and `ipns://` respectively. Nothing else scheme-less is.
- A Handshake name enters this namespace **only** by carrying a pointer record
  (§6). It is never *guessed* into it.
- **A bare CID typed on its own is in this namespace.** A single label that is
  a CID by shape is an address, not a name: it is classified to
  `ipfs://<cid>/` before the bare-label rule can take it. A **CIDv0** is
  base58btc and therefore case-sensitive, which a URL host does not survive
  (§4.2, IP-5), so it is written as **its CIDv1 base32 form** — the same
  multihash in another multibase, naming the same bytes.
- **An IPNS key typed on its own is not.** `Qm…` is both a legacy IPNS key and
  a CIDv0, and there is nothing in the string to decide between them. An
  implementation **MUST NOT** guess: sniffing between two address spaces is
  exactly what the routing laws above exist to prevent, and the cost of
  refusing is that an IPNS key is typed with its scheme or its gateway path.

---

## 4. The identifiers

### 4.1 `ipfs://<cid>[/<path>]`

The host is a **content address**; the path is a UnixFS path inside the DAG it
names.

- An implementation **MUST** validate the host against the CID shape it accepts
  before any retrieval is attempted, and **MUST** refuse a host that is not one.
  In the reference implementation the shape is a regular expression, `CID_RE`
  in `../../src/pointers.js`. It is **one definition, shared**: a per-module
  copy of an address shape drifts — an upper bound goes missing, a multibase
  prefix stops being required — and the modules then disagree about what an
  address is. Two private copies remain in the browser tree and are the subject
  of IP-2.
- A host that is not a CID **MUST NOT** be interpreted as a domain name and
  resolved through DNS or DNSLink. `ipfs://` names content, never a host.
- The path is opaque to resolution: it selects a node inside the DAG and is
  resolved by the retrieval layer, against blocks that are hash-checked as they
  arrive.
- **Resolution ends here.** The result is the pair `(root CID, path)`.

`rootCidOf` in `src/ipfs-url.js` is this function.

### 4.2 `ipns://<key>[/<path>]`

The host is a **mutable pointer**: an IPNS name, which is a public key. The
content it names changes; the address does not.

Four host forms are accepted (`IPNS_RE`, `../../src/pointers.js`):

| Form | Example prefix | What it is |
|---|---|---|
| base36 libp2p-key CIDv1 | `k51qzi5…` | what `ipfs name publish` prints |
| base32 libp2p-key CIDv1 | `bafzaajaiaejc…` | the same key, another multibase — what an EIP-1577 `ipns-ns` contenthash decodes to |
| modern peer ID | `12D3KooW…` | an Ed25519 peer identity |
| legacy peer ID | `Qm…` | a base58btc RSA peer identity |

- Resolving the key to a CID is an **IPNS record lookup**. It is a signature
  check over a record with a sequence number and a validity period — a different
  kind of proof from a hash, and one that can be *stale* rather than wrong.
- **The reference implementation does not perform that lookup itself.** It is
  delegated to the local IPFS node, which resolves the name over the DHT. This
  is stated as a limit, not claimed as a feature: we neither implement the IPNS
  record specification nor independently verify its signature, sequence number
  or validity window. See `../../DEVIATIONS.md` IP-3.
- **The lookup happens on the node, not at a gateway.** An implementation
  **MUST NOT** answer an `ipns://` name by asking a third-party gateway to
  resolve it and trusting what comes back: that replaces a signature check with
  a stranger's word about which CID the key names, and the reader has no way to
  tell the two apart. The reference implementation's `ipns://` adapter (the
  Wildroot tree's `src/protocols/ipfs-protocol.js`) asks the node, and the node
  is the same one the Handshake path uses (§3).
- An implementation **MUST NOT** describe an `ipns://` answer as immutable, and
  **MUST NOT** cache it as though it were a CID.
- Two of those four host forms carry uppercase characters, and a URL parser
  that canonicalises hosts lowercases them. An address that has an equivalent
  case-insensitive spelling **SHOULD** be re-spelled into it before it is
  written into a URL host — a CID into its base32 CIDv1 form (§3), an IPNS key
  into its base32 or base36 `libp2p-key` CIDv1 form. The reference
  implementation does this for a pasted CID and carries an IPNS key as it was
  given; see IP-5.

### 4.3 The scheme table answers for the scheme, not for the namespace

A table that records what each scheme verifies **MUST** fill a row in from the
*scheme*, not from the namespace the scheme belongs to. `ipfs`'s entry reads
`CID`; `ipns`'s reads `IPNS record + CID`, because an `ipns://` answer rests on
a signature check before any hash check applies and the extra hop is the part a
reader needs (§9). A table filled in from the namespace would read `CID` for
both and would be saying something untrue about the second.

---

## 5. What a CID identifies

A CID is **multibase(multicodec + multihash)** — a self-describing hash. What an
implementation of *this* document needs from that is narrow and worth stating
exactly, because it is the whole trust story:

1. **The bytes of a block are the block's identity.** A block whose bytes do not
   hash to its multihash is not that block. This is what "verified by hash"
   means and it is the only unconditional guarantee in this namespace.
2. **A file or folder is a DAG of blocks**, joined by CID. Checking every block
   therefore checks the whole tree, and a partial DAG is partial rather than
   wrong.
3. **The DAG's shape is part of the address.** Two implementations that chunk or
   fan out differently compute *different CIDs for the same bytes*. An
   implementation that records a CID for content it will later publish
   **MUST** produce the same DAG the node it publishes through would produce, or
   the address it recorded names nothing.

Point 3 is why `src/cid.js` exists. It computes a CID the way kubo 0.43 does
with `--cid-version=1 --raw-leaves`: a fixed-size 256 KiB chunker, raw leaves,
sha2-256, a balanced DAG at most 174 links wide, dag-pb internal nodes carrying
a UnixFS `File` message, and a UnixFS `Directory` node for a folder with links
sorted by name and each `Tsize` the cumulative size of the child's DAG. Those
parameters are normative for interoperating with this implementation and are
kubo's defaults, not ours.

HAMT-sharded directories are **not** implemented: a folder whose basic directory
node would exceed 256 KiB is refused with `NOT_SUPPORTED` rather than answered
with a CID kubo would disagree with. Refusing is the correct behaviour for a
function whose whole contract is agreement (IP-6).

**The blocks are available as they are built.** `fileCid` takes an optional
sink that is handed every block — leaves and internal nodes, children before
their parent, each exactly once — with its CID *and its exact bytes*, and
`directoryNode` returns a directory block's bytes beside its CID. An archive is
therefore written from the same bytes that were hashed, in the same pass, and
cannot disagree with the address computed here; without a sink nothing but the
CIDs is kept. The sink is awaited, so a slow disk slows the hashing rather than
being outrun by it. None of this changes a CID: the DAG, and therefore the
address, is the same whether or not anything is listening (`src/cid.js`,
`fileCid`, `directoryNode`).

**Shape versus decode.** `CID_RE` tests the *shape* of a CID string; it does not
decode one. It accepts a base58btc CIDv0 and a base32 CIDv1 and nothing else,
which is narrower than the multibase table allows — see IP-1.

---

## 6. The pointer records a name carries

The grammar of these records is specified by the spine (§10) and
implemented once, in `../../src/pointers.js`. This section says what the IPFS
members of it *mean*.

### 6.1 `ipfs=<cid>` and `ipns=<key>`

- `ipfs=<cid>` names content directly. It is the cheapest hop and the only one
  an implementation can verify outright, and it takes **precedence** over every
  other pointer kind.
- `ipns=<key>` names a mutable pointer (§4.2). It is second in precedence:
  same network, one extra resolution step, and the record survives a re-publish.
- A record's `<character-string>`s are **one** value, concatenated (RFC 1035
  §3.3.14). This rule **MUST** be applied identically on the authoritative-DNS
  path, the DoH path, the on-chain TXT path and the `_op` path, or the same
  record resolves differently depending on which path a user happens to be on.
- A pointer whose address fails its shape check is **not a pointer**. It
  **MUST NOT** be half-trusted, and it **MUST NOT** cause a fall-through to the
  name's address records: falling through is how a stripped `ipfs=` walks a
  browser from content-addressed bytes down to an attacker-chosen IP (spine
  §11.3, rung 3).
- On a DNSSEC-signed zone the pointer TXT **MUST** validate to the on-chain DS
  anchor, and its **absence MUST be proven** before an address record is
  consulted.

### 6.2 Precedence between namespaces

`ipfs` then `ipns` then `bittorrent` then `hyper` then `arweave`
(`POINTER_PRECEDENCE`). Record order in the DNS answer is irrelevant: only the
table decides, so every resolution path agrees regardless of how a server
happened to order them. An implementation **MUST** use a single precedence table
for every path.

### 6.3 DNSLink, the second pointer source

DNSLink (`_dnslink.<name> TXT dnslink=/ipfs/<cid>` or `/ipns/<key>`, either with
a trailing path) is the ecosystem's convention: kubo, Brave, IPFS Companion and
the public gateways all read it, and for most published IPFS sites it is the
*only* pointer record there is.

**It is read here, as a second pointer source of equal standing.** Both records
are asked for on every resolution that reads pointers at all — the name's own
`TXT` and `_dnslink.<name>` — on the authoritative-DNS route, where the DNSLink
query follows the pointer query, and on the DoH route, where the two are asked
in parallel. The full rules belong to Chapter 1 (`../handshake/SPEC.md` §6.5d–e
and §10.1); what matters in this chapter is:

- **The address space is the same.** A `dnslink=/ipfs/<cid>` value is parsed by
  the same `CID_RE` an `ipfs=` value is, and `dnslink=/ipns/<key>` by the same
  `IPNS_RE`, so the two carriers cannot disagree about what a valid address is
  (§6.1, §6.4). A value that fails its shape check is **not a pointer**, and it
  **MUST NOT** cause a fall-through to the name's address records.
- **Only `/ipfs/` and `/ipns/` are pointers.** Another DNSLink namespace
  (`/hyper/`, a nested `/dnslink/`) is not one here. A trailing path is carried
  with the pointer.
- **One value per name.** Where several `dnslink=` values parse, the first in
  record order wins, which is what every other DNSLink reader does.
- **The same proof obligations as `ipfs=`.** On a DNSSEC-signed zone the
  `_dnslink` RRset validates to the on-chain DS anchor or the resolution fails,
  and its **absence** is proven before an address record is consulted. Reading a
  second pointer source without the second denial proof would add a rung to the
  spine's §11.3 downgrade ladder — withhold `_dnslink.<name>` and a
  content-addressed site walks down to an address — instead of closing a hole.
- **Disagreement is surfaced, never resolved by precedence.** Either record
  alone is the pointer; the two agreeing (same kind, same address) is the normal
  case for a name this implementation published, and is recorded so an interface
  can say the pointer came from the DNSLink record; the two naming **different**
  content is a `pointer-conflict` (§11) and nothing is fetched. The precedence
  table of §6.2 ranks pointer *kinds* at one name; it is not a tie-breaker
  between two records that contradict each other, and using it as one would let
  whoever controls one of the two records decide the answer.

**What the read buys is interoperation in both directions.** A site published
the ordinary IPFS way — IPFS Companion, kubo, a gateway's publish flow, no
`ipfs=` anywhere — opens here unchanged. A site published by this
implementation, which writes both records, opens in every one of those clients.

When writing, `dnslink=/ipns/<key>` **SHOULD** be preferred over
`dnslink=/ipfs/<cid>`: an IPNS-valued DNSLink never has to be rewritten, while a
CID-valued one is a DNS write on every publish.

**What is still not settled is the other direction of the same convention:**
whether `ipns://<domain>` — a domain in an IPNS path, resolved as a DNSLink by
the *node* rather than by this stack — works at all when the daemon is
configured with `DNS.Resolvers: {}` (`../../DEVIATIONS.md`, Chapter 3 §2.4, and
IP-D8). That path is a second, node-side DNSLink reader whose behaviour under
this implementation's own privacy configuration is untested.

### 6.4 The EIP-1577 carrier

On the HIP-5 `_op` route a name's content pointer arrives as a `contenthash`
byte string rather than a TXT record. The two IPFS codecs are `ipfs-ns` `0xe3`
(the value is a CID) and `ipns-ns` `0xe5` (the value is a libp2p-key CID).
Decoding is specified by the spine; the requirement here is that the decoded
address **MUST** land in the same address space as §6.1, so that the two
carriers cannot disagree about what a name points at.

A codec that is recognised and cannot be fetched — `swarm-ns` `0xe4` — **MUST**
be refused **by name** ("this name points at Swarm content, which this client
cannot fetch"), never silently discarded and never fallen through.

---

## 7. The resolution algorithm

Given an identifier, produce a content address (or a mutable pointer, or a
refusal) and the trust facts that go with it.

### 7.1 A URL in this namespace

1. Take the scheme. It selects the namespace and is not second-guessed (§3).
2. **`ipfs://`** — parse the host. If it is not a CID by shape, **fail** (§11,
   `bad-address`). Otherwise the result is `(cid, path)`.
3. **`ipns://`** — parse the host. If it is not one of the four key forms,
   **fail**. Otherwise the result is `(key, path)`, a mutable pointer whose
   resolution to a CID is the node's (§4.2).

### 7.2 A Handshake name

The spine resolves the name and returns one of its resolution kinds. Two of
them are ours.

1. **Resolve the name** — chain proof, then the authoritative walk or the `_op`
   route, with DNSSEC validation anchored to the on-chain DS. Spine §6.
2. **Assemble the TXT strings** with the RFC 1035 §3.3.14 join rule, then take
   the winning pointer by precedence (§6.2) — from the name's own records.
3. **Read the DNSLink record** at `_dnslink.<name>` under the same rules
   (§6.3), and merge: either source alone is the pointer, agreement yields it,
   disagreement is a `pointer-conflict` and nothing is fetched.
4. If the winner is `ipfs`, and the same TXT set contains a valid `car=`, attach
   the **stated origin** to the resolution. It is carried, never resolved to.
5. **The result is `kind: 'ipfs'` with a CID (and possibly an origin), or
   `kind: 'ipns'` with a key.** In both cases the name's address records
   (`A`, `SYNTH4`, `GLUE4`) are **NOT** consulted: the name resolves into this
   namespace and stays there.

### 7.3 Fetching, which is where this chapter stops

For completeness, and to make the boundary unambiguous, this is what the
reference implementation does after §7.2 — none of it is specified here:

- optionally warms the local node from the stated origin (§8), which
  is a **cache fill and never a decision**: whatever it does or fails to do, the
  next step asks the node for the same CID;
- asks the node for `(cid, path)`, carrying the request's `Range` through, and
  returns what the node returns;
- gives the fetch a first-byte deadline (45 s in the reference implementation)
  and answers `504` honestly rather than hanging.

An implementation **MUST NOT** let a warm failure change the answer, and
**MUST NOT** let a warm success be reported as a stronger verification than an
ordinary fetch. Both would make a location hint into a trust input.

---

## 8. Experimental: the `car=` stated origin and origin warming

**What "experimental" means here.** Everything in this section ships in the
reference browser and is exercised by `tests/origin-warm.test.js`, and none of
it is a proposed standard anywhere. The record name, its grammar, the decision
that its value is a trustless-gateway URL, and every number in the windowing
policy are a **local convention with no standing outside this implementation**,
recorded in decision D-P2 of `STORAGE-PUBLISH-SHARE.md`. The behaviour may
change. An implementation **MAY** ignore this section entirely and lose
nothing but a cache fill: §7.3's rule is that a warm never changes an answer,
so a client that does not implement `car=` resolves every name in this
namespace to the same content address as one that does.

The two rules that are **not** experimental are the ones that make the section
safe to ignore and safe to implement: a stated origin is untrusted by
construction (§12.2), and a warm is a cache fill that cannot change what is
served (§7.3).

### 8.1 `car=<https url>` — the stated origin

**The problem.** A CID says what the content is and nothing at all about where
it is. A publisher who keeps their bytes with an ordinary storage provider has
no way to say "the archive is here" without either running an IPFS node or
handing a third party the list of everything anyone reads.

**The record.** Beside `ipfs=<cid>`, a name **MAY** carry `car=<url>`: an HTTPS
location from which an archive of *that* CID can be fetched.

- The value **MUST** be an absolute `https:` URL with a host. Plaintext is
  refused: a share URL is a bearer capability and handing it to the network
  defeats it.
- The value is bounded (480 bytes in the reference implementation) so it fits a
  TXT record without surprise.
- `car=` is **not a pointer kind**. It has no place in the precedence table, and
  the pointer parser returns nothing for it, so no code path that trusts a
  pointer can be handed a URL by mistake. A name that carries only `car=` points
  nowhere.
- The origin is attached to an `ipfs` pointer and to no other kind: an Arweave
  or torrent pointer with a `car=` beside it carries no origin.
- `car=` lives at the name whichever record the pointer came from, so an
  implementation **MUST** attach it to a pointer read from the name's DNSLink
  record too. The reference implementation does so on both routes (the
  authoritative path attaches the origin after the two sources are merged; the
  DoH path reads it from the name's strings after the merge), so a DNSLink-only
  site with a `car=` beside it warms from its origin exactly as an `ipfs=` site.
- A name that states no origin **MAY** fall back to a table mapping a TLD to a
  known gateway. The reference implementation carries one such entry, for
  `.pinthis` names, which is a transitional artefact of names published before
  `car=` existed (IP-10); a stated origin always wins over it. An
  implementation **SHOULD NOT** add entries, because each one names a company
  in a resolution path.

**A warm is remembered, and the memory expires.** Once an archive is on the
node the warmer skips the fetch for every later read of that CID. The node
garbage-collects unpinned blocks, and a warm is deliberately unpinned (§12.2),
so that memory **MUST** expire and be re-confirmed against the node rather than
held for the life of the process — §8.3.

**What it is worth: nothing, and that is the design.** The stated origin is a
*routing hint*. It changes where an implementation looks first; it **MUST NOT**
change the trust state, the lock, or what any interface claims. A hostile origin
can serve junk, serve nothing, or serve an unrelated archive; in every case the
CID check that follows means the wrong bytes are never rendered (§12.2).

**What we are unsure of.** The record name, the
bounding, and the decision that the URL is only ever a **trustless-gateway
form** — `https://<host>[/<prefix>]/ipfs/<cid>`, so that a byte window and a
path can be asked for (§8.2) — are all ours. The amended decision D-P2 in
`STORAGE-PUBLISH-SHARE.md` says gateway-form only; the reference implementation
*writes* only that form but *accepts* any HTTPS URL on read and has a
whole-archive branch for one that is not a gateway (IP-9). We would rather adopt
somebody else's convention for "here is a location for this CID" than defend
ours — IPIP-402's trustless gateway gives us the *shape* of the URL but nothing
says how a name announces one.

### 8.2 Windowed retrieval

When the stated origin is a trustless gateway, an implementation **MAY** fetch
part of a DAG rather than all of it, using the IPIP-402 parameters:

```
<gateway-base>/<path>?format=car&dag-scope=entity&entity-bytes=<from>:<to>
```

The reference implementation asks for an aligned **2 MiB slice** at the byte
position being read, imports it before answering, and then fetches the rest of
its aligned **16 MiB window** — and the next window, when the read is in the
last quarter of the current one — in the background. A whole-archive fetch is
used instead when the archive is small enough to hold (64 MiB in the reference
implementation) and is refused when the gateway states no length or a larger
one. These numbers are engineering, not protocol; what is normative is:

- The response **MUST** be treated as a CAR of *part* of the DAG, and the
  partial archive **MUST NOT** be pinned — pinning a partial DAG makes a node
  walk the network for the rest of it while the reader waits.
- A gateway that ignores `entity-bytes` and returns the whole archive **MUST**
  be refused by the same size bound, not accepted because it answered.
- Every block still arrives hash-checked, so a window is exactly as trustworthy
  as the whole archive: less content, identical guarantee.

`src/origin-warm.js` is this, complete.

### 8.3 What the warmer remembers, and for how long

A warmer that has imported an archive, or a slice of one, remembers it so the
next read of the same CID is free. That memory is a claim about the node's
blockstore, and the blockstore changes underneath it: the node runs a garbage
collector, and a collection removes every **unpinned** block — which is every
block a warm imports (§12.2). A memory held for the life of the process
therefore answers *"present"* for content the node no longer has, and the reader
gets nothing: the fetch that was skipped is the only one that would have brought
the bytes back, and under anonymisation the node is offline and cannot fetch
them itself (§12.4).

So, normatively:

- A remembered CID or slice **MUST NOT** be trusted indefinitely. An
  implementation **MUST** re-confirm it against the node once it is older than a
  bounded lifetime.
- The re-confirmation is **one local, offline block lookup of the root CID** —
  not a network fetch, and not a walk of the DAG.
- A root the node no longer has means the DAG went with it: the implementation
  **MUST** forget that CID **and every slice recorded under it**, and let the
  next read warm again.
- A node that cannot answer the question is **not** evidence of eviction. The
  memory is kept and the next read asks again; treating an API error as a
  missing block would re-fetch an archive that is still there.

The lifetime is engineering, not protocol. The reference implementation uses
**five minutes** (`PRESENCE_TTL_MS`, `src/block-presence.js`), chosen to be
short against the node's collection interval — kubo collects at most once an
hour, and only once the repo passes its high-water mark — so a collection is
noticed within minutes at a cost of one local lookup per CID per lifetime, and
repeated reads between them (a video being scrubbed) stay free. It is a
heuristic and is stated as one: a collection *inside* the window is not noticed
until the window ends (IP-12).

---

## 9. Verified by hash, and trusted

The claim this namespace lets an implementation make is narrow and strong.
Stated exactly:

> *The bytes rendered hash to the CID that was resolved.*

That holds whoever served them — a local daemon, a peer on the DHT, a public
gateway, the publisher's own storage provider. It is why an implementation
**MAY** treat a content pointer as closing the security question about
*content*, and why a `car=` origin needs no trust at all.

Everything else in this namespace is weaker, and an implementation **MUST NOT**
present these as equivalent:

| Step | What it rests on |
|---|---|
| bytes ↔ CID | the hash. Unconditional. |
| `ipfs=` on a name ↔ that name | the spine's chain proof, and the DNSSEC validation of the TXT record if the zone is signed |
| `ipns://<key>` ↔ a CID | an **IPNS record**: a signature by the key, with a sequence number and a validity window — resolved and checked by the node, not by this stack (IP-3) |
| a DNSLink ↔ a CID | ordinary DNS, with whatever DNSSEC the zone has. On a Handshake name that is the spine's chain proof plus the validation of the `_dnslink` RRset to the on-chain DS, and the proof of its absence where there is none (§6.3) — the same standing as an `ipfs=` record, because it is the same DNS answer |
| a `car=` origin ↔ the archive | **nothing, deliberately.** A hint; the CID check is what protects the reader |
| the CAR header's `roots` list ↔ the archive's contents | **nothing.** The header is written by whoever wrote the archive; see §12.2 |

---

## 10. Trust states

The spine's trust model applies unchanged. Three rules are specific to this
namespace:

- **A content pointer is self-verifying, so the chain proof of the pointer is
  the whole question.** A Handshake name resolving to `ipfs` or `ipns` closes the
  lock on the chain proof alone; unlike an address-record site it does not
  additionally need a DANE pin, because there is no TLS connection whose peer
  could be substituted.
- **An interface MUST distinguish `ipfs` from `ipns` when it says why.** "the
  bytes are verified against the CID" is true of the first. For the second the
  honest sentence is "an IPNS name is a signed pointer; the content it names is
  CID-verified once fetched" — the mutability is the part a reader needs.

- **Each of the two schemes gets its own step, in its own words.** `ipfs://`
  reports *"the bytes are verified against the CID"*; `ipns://` reports that an
  IPNS name is a signed pointer whose content is CID-verified once fetched.
  Neither falls to a default that claims no verification path exists, because
  under-claiming misleads a reader as surely as over-claiming (spine §11.4).
  The scheme table (§4.3) and the trust panel therefore say the same thing
  about the same scheme.

---

## 11. Failure modes

Every failure below is a refusal **inside this namespace**. None of them
**MUST** ever become a lookup somewhere else.

| Kind | Meaning | Reference behaviour |
|---|---|---|
| `bad-address` | the host is not a CID / not an IPNS key | refused before any retrieval |
| `unsupported-pointer` | the name's pointer is a codec this build cannot fetch (e.g. Swarm) | `501`, naming the protocol, with an explicit statement that the seller's nameservers were **not** then consulted |
| `pointer-conflict` | the name's own pointer record and its DNSLink record name **different** content (§6.3) | `502`, naming both pointers and saying the two records must agree; neither is fetched and neither is preferred |
| `no-node` | no IPFS node is available | `501` "this name points at IPFS content but no IPFS daemon is running" |
| `anonymized` | an anonymising proxy is on, and the local node's libp2p traffic — the CIDs it asks for **and the CIDs it announces having** — is outside what that proxy covers | `503`, refusing rather than leaking the real address (§12.4, spine §11.6) |
| `first-byte-timeout` | the blocks did not arrive | `504` after 45 s — a bounded, diagnosable answer instead of a hang |
| warm states | `not-ours`, `no-node`, `present`, `warmed`, `windowed`, `too-large`, `failed`, `disabled` | **never** an error: a warm that could not happen is logged and the ordinary fetch proceeds |

A note on the last row that is a security property rather than a nicety: the
warm path is the only part of this namespace that talks to a named third party,
and it is written so that it can fail in every one of those ways without
changing what the reader is served.

---

## 12. Security considerations

### 12.1 The address must be validated before anything is dialled

A host that is not a CID is a string an attacker chose. Handing it to a
retrieval layer means at best a wasted DHT walk and at worst a request to
whatever the string turns out to name. Validate first, refuse loudly, and keep
**one** copy of the shape: a private copy is how a bound goes missing and a
guard that used to refuse two hundred characters of junk starts accepting it
(IP-2).

### 12.2 A stated origin is an untrusted party, by construction

`car=` names a server chosen by whoever wrote the record. Everything that
follows assumes it is hostile:

- It is fetched over HTTPS only, so the capability in the URL is not handed to
  the network, and through the **injected** fetch, so it rides whatever proxied
  session the embedder configured rather than a platform default (§12.4).
- What comes back is imported into the node's blockstore, where **every block is
  hash-checked**. Blocks that are not what they claim do not enter.
- The archive is **not pinned**, so an unreferenced import is garbage-collected
  rather than kept.
- The import is bounded in size, whether or not the origin honours
  `entity-bytes`.
- The page is then served by asking the node for the resolved CID, exactly as it
  would have been with no origin at all. A lying origin therefore costs a wasted
  fetch and some disk, and cannot change a single byte the reader sees.

**The CAR header's root list is a claim, not a proof.** An implementation
**SHOULD** check that the archive names the CID it asked for — it catches a
misconfigured or confused origin cheaply — but **MUST NOT** treat that check as
security. The header is written by the same party as the rest of the file.

### 12.3 Mutability is a security property, not a convenience

An `ipns=` pointer and a DNSLink both mean "whatever the key holder says today". An implementation that caches such an answer as though it
were a CID, or renders it with the same words it uses for a CID, has quietly
converted a signed-and-revocable statement into an immutable one. Say which was
which.

### 12.4 The retrieval layer is a privacy surface even when it is not a trust surface

Asking the DHT for a CID tells peers which content is being read, from an
address no HTTP proxy covers. That is why the reference implementation refuses
an IPFS-served name outright while anonymisation is on rather than serving it
over a path that would leak.

**One part of this path is already private, and the refusal still stands. The
reason is worth stating exactly.** The `car=` warm (§8) is an HTTPS fetch made
through the fetch implementation the embedder injects, so it rides the proxied
session like any other HTTPS request: that leg leaks nothing under anonymisation
and needs no gate. What it does is **import blocks into the local node**, and a
node holding blocks *announces* them — it publishes provider records for what it
has, over the same libp2p connections no HTTP proxy covers. So a fetch that is
private on the way in creates an advertisement on the way out, from the real
address, naming exactly the content just read. Serving the page also means
asking the node for the CID, which is a second reason. The gate therefore stays
where it is — on the `ipfs=` branch, before the warm — and an implementation
**MUST NOT** conclude from "the warm fetch is proxied" that the name can be
served. Closing the gap means stopping the node from routing at all while
anonymisation is on (`IP-D9`), not moving the gate.

It is also why the local node is configured with
**no delegated routers and no delegated publishers**: a delegated router would
hand one company the list of every CID a person reads, and a delegated
publisher the list of everything a person publishes. The `car=` warm is the
deliberate exception and is scoped to make it a non-exception: the only server
asked is one that already knows this name is being opened, because it is the one
that serves it.

**A privacy policy is written once, as data.** The reference implementation
states it as a flat table of dotted keys — telemetry off, no delegated routers,
no delegated publishers, no DNS resolvers, no mDNS, an explicit bootstrap list —
and **derives** the nested object the node's JSON config takes by expanding each
key, so a policy line cannot be added to one form and not the other, and a test
can read the whole of it in one place. An implementation **MUST** be able to
point at that single definition. Where a second component sets a key *inside*
that policy it **MUST** merge into the derived value rather than replace it, or
it silently drops the sibling settings — an empty delegated-publisher list is
exactly the kind of thing lost that way.

### 12.5 One namespace, one node

The reference implementation runs **one** IPFS node. `ipfs://`, `ipns://` and
content behind a Handshake `ipfs=` pointer all read it: one blockstore, one
privacy policy, one lifecycle. That is a security property before it is a
tidiness one — every additional node is another place a privacy setting can be
missing, another blockstore that has to be told what the first one already
knows, and another resolver that may not have the IPNS key the publish flow
just wrote. Nothing in this specification requires exactly one, but an
implementation that runs more than one **MUST** be able to point at the single
policy definition every one of them is built from (§12.4), and **MUST NOT**
resolve an IPNS name on a node other than the one its own publishes reach.

---

## Appendix A — what an implementation of this chapter owes a reader

A one-paragraph summary, because it is the part that is easy to lose:

*A CID is a hash, so the content behind a resolved pointer cannot be tampered
with — by us, by a gateway, by the publisher's storage provider, or by anyone on
the path. What can be tampered with is **which** CID you were sent to, and that
question belongs to the name system that carried the pointer. An IPNS name and a
DNSLink are not hashes and do not carry that guarantee. A
`car=` origin is a shortcut to the bytes and carries no guarantee at all, which
is why it is safe to follow.*
