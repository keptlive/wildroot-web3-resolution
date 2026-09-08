# Chapter 3 — IPFS, IPNS and DNSLink

> **Review pending:** [REVIEW.md](../../REVIEW.md) records unresolved questions
> about Private-mode origin handling and pointer validation. The rewrite does not change runtime behaviour.

**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in this
directory and in the Wildroot browser it is extracted from. Not endorsed by any
standards body. Normative statements describe what an implementation must do
*to interoperate with this one*; where a rule is inherited from an existing
standard, that standard is cited and its text governs.
**Licence:** CC-BY-4.0 (`../../LICENSE-SPEC`). The reference implementation is
licensed separately.

The [routing specification](../../SPEC.md) defines namespace selection and
the Handshake name-to-pointer lookup. This chapter defines the IPFS-side
identifiers and their trust properties. See [deviations](DEVIATIONS.md) (`IP-`
entries) and [references](REFERENCES.md) for limits and supporting sources.

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

This chapter covers four entry points:

- URLs using `ipfs`, `ipns`, `ipld` or `pubsub` (§4);
- Handshake TXT content pointers (§6.1);
- EIP-1577 `contenthash` values returned through HIP-5 `_op` (§6.4);
- the experimental `car=` hint for locating a CAR archive (§8.1).

The rules distinguish content addresses from mutable IPNS names and pubsub
topics. A `car=` location **MUST NOT** be treated as evidence about content.

### 1.1 Scope

**In scope:** identifier membership and parsing, content-pointer records, CID
computation, and the trust claims attached to a resolution.

**Out of scope:**

| Out of scope | Where it lives |
|---|---|
| **Retrieval** — bitswap, the DHT, delegated routing, the block exchange, HTTP trustless-gateway transport, a local daemon's lifecycle | The Wildroot browser's `src/protocols/ipfs-protocol.js` (the `ipfs://` daemon) and `src/hns/ipfs.js` (the `hns://` node). Both are transport: they obtain and serve bytes for an address this chapter has already decided. |
| **Verification of retrieved bytes against the CID** | The IPFS node does it. This document says *that* it happens (§9) and what it is worth; it does not respecify multihash checking. |
| **Serving, pinning, announcing, cooperative delivery** | `docs/COOP-DELIVERY.md` in the Wildroot tree; pinthis's own decisions. |
| **Publishing** — how an `ipfs=` record is written, an IPNS key created, an archive uploaded | The write path is a different problem with a different threat model. `PUBLISHING-AND-DNS.md`, `STORAGE-PUBLISH-SHARE.md`. |
| **The Handshake half of a `hns://` resolution** — the chain proof, DNSSEC, DANE | The Handshake chapter, reached from the spine `../../SPEC.md`. |
| **The user interface** | §10 specifies the model a panel is given and the claims it must not make, never a rendering. |

The resolution result identifies a CID and path, a mutable pointer, a topic,
or a failure. Retrieval is handled separately.

`src/cid.js` computes CIDs from local bytes (§5), allowing the address
calculation to be tested without a daemon.

The reference implementation contains:

| Module | Responsibility |
|---|---|
| `src/cid.js` | CID computation (§5) |
| `src/origin-warm.js` | Origin hints and byte windows (§8) |
| `src/ipfs-url.js` | URL-to-root-CID parsing (§4.1) |
| `src/byte-range.js` | Range parsing (§8.2) |
| `src/car-roots.js` | CAR header roots and minimal dag-cbor decoding (§12.2) |
| `src/source-error.js` | Typed errors from CID computation |
| `../../src/pointers.js` | Pointer grammar |
| `../../src/contenthash.js` | EIP-1577 decoding |
| `../../src/router.js` | Scheme classification |

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
- **Root of trust** — the mechanism that authenticates a result: a content
  hash, an IPNS signature or the name system that supplied a pointer (§9).

---

## 3. Namespace membership

The router groups **`ipfs`, `ipns`, `ipld` and `pubsub`** under the IPFS
namespace (`../../src/router.js`, `SCHEME_TABLE`). Their verification rules
differ: CID checks apply to content, IPNS adds signed mutable records, and
pubsub topics are not content addresses (§4).

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
  and `ipns://` respectively. Bare CIDs are also recognized, as described below.
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
  The shared `CID_RE` is in `../../src/pointers.js`. IP-2 tracks two private
  copies that remain in the browser.
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
- **The reference implementation delegates the lookup to the local IPFS node.**
The node checks signatures, sequence numbers and validity windows. This package
does not independently repeat those checks or expose their results (IP-3).

### 4.3 `ipld://<cid>[/<path>]`

The host is a content address, as in §4.1; the path traverses **IPLD** links
rather than UnixFS entries, and the retrieval layer may re-encode the selected
node into dag-json or dag-cbor at the client's request. For resolution purposes
`ipld://` is `ipfs://` with a different traversal: same address space, same
verification, same rules as §4.1.

### 4.4 `pubsub://<topic>`

**This is not an address.** The host is a libp2p pubsub topic — a free-form
string chosen by whoever publishes to it. There is no CID, no hash check and no
content-addressing of any kind: a message's only authentication is the
publishing peer's signature over it, at the libp2p layer.

- An implementation **MUST NOT** present a `pubsub://` result as
  content-addressed or content-verified.
- A topic string is **case-sensitive** and **MUST** survive whatever URL
  canonicalisation the host environment applies, or the scheme is unusable for
  any topic containing an uppercase letter (IP-5).
- The scheme is in this namespace because it rides the same node, not because it
  shares its trust model. It is specified here so that it is not mistaken for
  the other three.

A scheme table **MUST** describe verification per scheme. The `pubsub`
entry is "libp2p publisher signature — a topic is not a content address";
the other three entries describe CID verification.

---

## 5. What a CID identifies

A CIDv1 string encodes a version, multicodec and multihash using a multibase.
CIDv0 uses its legacy base58btc representation. The relevant properties are:

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

`src/cid.js` reproduces kubo 0.43 with
`--cid-version=1 --raw-leaves`: 256 KiB fixed chunks, raw leaves, sha2-256,
a balanced DAG with at most 174 links per node, dag-pb internal nodes carrying
UnixFS `File` messages, and UnixFS `Directory` nodes with name-sorted links
and cumulative child-DAG `Tsize` values. These parameters are normative for
compatibility with this implementation.

HAMT-sharded directories are not implemented. `directoryCid` returns
`NOT_SUPPORTED` when a basic directory node would exceed 256 KiB, because
its CID would differ from kubo's sharded result (IP-6).

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

DNSLink uses `_dnslink.<name> TXT dnslink=/ipfs/<cid>` or `/ipns/<key>`,
optionally followed by a path.

Both the name's TXT records and `_dnslink.<name>` are read wherever this
resolver reads content pointers. The authoritative route queries DNSLink after
the name's TXT records; the DoH route queries both in parallel. Chapter 1
(`../handshake/SPEC.md` §6.5d–e and §10.1) defines the full rules:

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
2. **`ipfs://` / `ipld://`** — parse the host. If it is not a CID by shape,
   **fail** (§11, `bad-address`). Otherwise the result is `(cid, path)`.
3. **`ipns://`** — parse the host. If it is not one of the four key forms,
   **fail**. Otherwise the result is `(key, path)`, a mutable pointer whose
   resolution to a CID is the node's (§4.2).
4. **`pubsub://`** — the result is a topic. It is not an address and no further
   resolution applies (§4.4).

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

After §7.2, the browser performs these retrieval steps:

- optionally warms the local node from the stated origin (§8), which
  is a **cache fill and never a decision**: whatever it does or fails to do, the
  next step asks the node for the same CID;
- asks the node for `(cid, path)`, carrying the request's `Range` through, and
  returns what the node returns;
- gives the fetch a first-byte deadline (45 s in the reference implementation)
  and returns `504` if it expires.

An implementation **MUST NOT** let a warm failure change the answer, and
**MUST NOT** let a warm success be reported as a stronger verification than an
ordinary fetch. Both would make a location hint into a trust input.

---

## 8. Experimental: the `car=` stated origin and origin warming

This section describes a local convention implemented by the browser and
tested in `tests/origin-warm.test.js`. Its record name, grammar and window
sizes may change. Decision D-P2 in `STORAGE-PUBLISH-SHARE.md` records its
origin. An implementation **MAY** ignore `car=`: §7.3 requires the same
resolved content address whether warming runs, succeeds or fails.

Two requirements remain applicable outside this experiment: the origin is
untrusted (§12.2), and warming cannot change the content served (§7.3).

### 8.1 `car=<https url>` — the stated origin

`car=` lets a publisher announce an HTTPS location for the archive named by
an IPFS pointer.

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

The stated origin is a retrieval hint. It **MUST NOT** change the trust
state, lock or interface claims. An unrelated or malformed archive does not
change the CID requested from the local node (§12.2).

The writer emits gateway-form URLs,
`https://<host>[/<prefix>]/ipfs/<cid>`, as required by the amended D-P2
decision. The reader accepts any HTTPS URL and has a whole-archive branch for
non-gateway URLs. IP-9 records that unresolved mismatch. IPIP-402 defines the
gateway request parameters but does not define this TXT announcement record.

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

`src/origin-warm.js` implements this policy.

---

## 9. Verified by hash, and trusted

The content-integrity claim is:

> *The bytes rendered hash to the CID that was resolved.*

That holds whoever served them — a local daemon, a peer on the DHT, a public
gateway, the publisher's own storage provider. It is why an implementation
**MAY** treat a content pointer as closing the security question about
*content*, and why a `car=` origin needs no trust at all.

The remaining steps have separate trust requirements. An implementation
**MUST NOT** present them as equivalent:

| Step | What it rests on |
|---|---|
| bytes ↔ CID | the hash check |
| `ipfs=` on a name ↔ that name | the spine's chain proof, and the DNSSEC validation of the TXT record if the zone is signed |
| `ipns://<key>` ↔ a CID | an **IPNS record**: a signature by the key, with a sequence number and a validity window — resolved and checked by the node, not by this stack (IP-3) |
| a DNSLink ↔ a CID | ordinary DNS, with whatever DNSSEC the zone has. On a Handshake name that is the spine's chain proof plus the validation of the `_dnslink` RRset to the on-chain DS, and the proof of its absence where there is none (§6.3) — the same standing as an `ipfs=` record, because it is the same DNS answer |
| an `ipld://` path traversal | the hash, at every link |
| a `pubsub://` topic | **nothing.** A libp2p publisher signature at best; no content address exists |
| a `car=` origin ↔ the archive | no authentication. A hint; the CID check is what protects the reader |
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

- **Each of the four schemes gets its own step, in its own words.** `ipfs://`
  reports *"the bytes are verified against the CID"*; `ipld://` is
  CID-verified in the same way and says what that means for a traversal —
  *"each node on the path is verified against its CID"* — rather than falling
  to a default that claims no verification path exists, because under-claiming
  misleads a reader as surely as over-claiming (spine §11.4). `pubsub://`
  reports a step whose state is **none**, naming what a topic is: messages are
  signed by whichever peer published them, and anyone may publish to a topic.
  The scheme table (§4.4) and the trust panel therefore say the same thing
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

Warming may fail without changing the CID requested or the ordinary fetch
that follows.

---

## 12. Security considerations

### 12.1 The address must be validated before anything is dialled

Validate an address before passing it to retrieval. A shared shape check
prevents modules from accepting different address forms or bounds (IP-2).

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

IPNS and DNSLink answers can change. Pubsub topics identify message streams.
Caching or labelling any of these as an immutable CID misstates its semantics.

### 12.4 The retrieval layer is a privacy surface even when it is not a trust surface

Asking the DHT for a CID tells peers which content is being read, from an
address no HTTP proxy covers. That is why the reference implementation refuses
an IPFS-served name outright while anonymisation is on rather than serving it
over a path that would leak.

The `car=` HTTPS request uses the injected, proxied fetch, but its imported
blocks enter the local node. That node can announce provider records and issue
peer requests outside the HTTP proxy. The gate therefore remains on the
`ipfs=` branch before warming. An implementation **MUST NOT** infer from a
proxied warm request that the whole name can be served privately. IP-D9
proposes disabling node routing before allowing that case.

The local node disables delegated routers and delegated publishers to avoid
sending a single service the user's read and publish lists. The stated-origin
fetch contacts the server named for that content.

A privacy policy that has to reach more than one node **MUST** be written once.
The reference implementation states it as a flat table of dotted keys and
**derives** the nested object a JSON-configured daemon takes by expanding each
key, so a policy line cannot be added to one form and not the other; a daemon
that additionally sets a key inside that policy (the `ipfs://` daemon enables
the IPNS pubsub router) **MUST** merge into the derived value rather than
replace it, or it silently drops the sibling settings — here, the empty
delegated-publisher list. A test holds the two forms to the same leaves.

### 12.5 One namespace, two daemons

The browser runs two IPFS nodes: one for the four explicit schemes and one
for Handshake `ipfs=` content. They have separate blockstores, ports and
lifecycles, with privacy settings derived from one policy (§12.4). This
specification does not require two nodes. An implementation running more than
one **MUST** identify the shared policy definition used by all of them.

---

## Appendix A — what an implementation of this chapter owes a reader

Content integrity and pointer authenticity are separate checks.

A CID allows retrieved blocks to be checked against the selected content
address. The name system determines which CID is selected. IPNS and DNSLink
add mutable mappings; pubsub topics have no content address. `car=` changes
where retrieval starts, not which content is accepted.
