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

- a URL in one of the four IPFS schemes (§4),
- a `TXT` content pointer on a Handshake name (§6.1),
- an EIP-1577 `contenthash` read from a registry contract on the HIP-5 `_op`
  route (§6.4),
- and a **stated origin** (`car=`) that says where an archive of that CID can be
  fetched from — a hint about location that MUST NOT become a claim about
  content (§8.1, **EXPERIMENTAL**).

It also specifies the boundary that keeps the design honest: an IPNS name, an
IPLD path and a pubsub topic are *not* CIDs, and three of the four schemes in
this namespace need something other than a hash before a hash can be checked.

### 1.1 Scope

**In scope: turning an identifier into a verified content address.** Precisely:
which identifiers belong to this namespace, what each one denotes, which of them
authenticate themselves and which rest on somebody's word, what a Handshake name
publishes to point into the namespace, and what an implementation is entitled to
tell a user about the result.

**Out of scope, explicitly.**

| Out of scope | Where it lives |
|---|---|
| **Retrieval** — bitswap, the DHT, delegated routing, the block exchange, HTTP trustless-gateway transport, a local daemon's lifecycle | The Wildroot browser's `src/protocols/ipfs-protocol.js` (the `ipfs://` daemon) and `src/hns/ipfs.js` (the `hns://` node). Both are transport: they obtain and serve bytes for an address this chapter has already decided. |
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
set of bytes (§5) and `src/origin-warm.js` is the stated origin and its byte
window (§8), both whole modules. Four smaller modules are factored out
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

Four URL schemes belong to this namespace: **`ipfs`, `ipns`, `ipld` and
`pubsub`**. They share one root of trust and are therefore one namespace, not
four (`../../src/router.js`, `SCHEME_TABLE`).

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
  delegated to the local IPFS node, which resolves the name over the DHT (and,
  on one of the two daemons, over pubsub — §4.4). This is stated as a limit, not
  claimed as a feature: we neither implement the IPNS record specification nor
  independently verify its signature, sequence number or validity window.
  See `../../DEVIATIONS.md` IP-3.
- An implementation **MUST NOT** describe an `ipns://` answer as immutable, and
  **MUST NOT** cache it as though it were a CID.
- Two of those four host forms carry uppercase characters, and a URL parser
  that canonicalises hosts lowercases them. An address that has an equivalent
  case-insensitive spelling **SHOULD** be re-spelled into it before it is
  written into a URL host — a CID into its base32 CIDv1 form (§3), an IPNS key
  into its base32 or base36 `libp2p-key` CIDv1 form. The reference
  implementation does this for a pasted CID and carries an IPNS key as it was
  given; see IP-5.

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

A scheme table that records what each scheme verifies **MUST** answer for the
scheme and not for the namespace: `pubsub`'s entry reads *"libp2p publisher
signature — a topic is not a content address"*, where its three neighbours read
`CID`. A table filled in from the namespace would say `CID` for all four and
would be telling a reader something untrue about the fourth.

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

### 6.3 DNSLink

DNSLink (`_dnslink.<name> TXT dnslink=/ipfs/<cid>` or `/ipns/<key>`) is the
ecosystem's convention: kubo, Brave, IPFS Companion and the public gateways all
read it.

- An implementation **SHOULD** read `_dnslink.<name>` as a second pointer source
  when the name itself carries no `ipfs=`.
- The reference implementation **writes** DNSLink and **does not read it**
  (IP-4). A Handshake site published by someone else with only a DNSLink
  therefore resolves here as an address-record site, or as unregistered.
- When writing, `dnslink=/ipns/<key>` **SHOULD** be preferred over
  `dnslink=/ipfs/<cid>`: an IPNS-valued DNSLink never has to be rewritten, while
  a CID-valued one is a DNS write on every publish.

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
   the winning pointer by precedence (§6.2).
3. If the winner is `ipfs`, and the same TXT set contains a valid `car=`, attach
   the **stated origin** to the resolution. It is carried, never resolved to.
4. **The result is `kind: 'ipfs'` with a CID (and possibly an origin), or
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
- A name that states no origin **MAY** fall back to a table mapping a TLD to a
  known gateway. The reference implementation carries one such entry, for
  `.pinthis` names, which is a transitional artefact of names published before
  `car=` existed (IP-10); a stated origin always wins over it. An
  implementation **SHOULD NOT** add entries, because each one names a company
  in a resolution path.

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
| a DNSLink ↔ a CID | ordinary DNS, with whatever DNSSEC the zone has |
| an `ipld://` path traversal | the hash, at every link |
| a `pubsub://` topic | **nothing.** A libp2p publisher signature at best; no content address exists |
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
| `no-node` | no IPFS node is available | `501` "this name points at IPFS content but no IPFS daemon is running" |
| `anonymized` | an anonymising proxy is on, and the node dials peers over a path it cannot cover | `503`, refusing rather than leaking the real address (spine §11.6) |
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
  the network.
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

An `ipns=` pointer, a DNSLink and a `pubsub://` topic all mean "whatever the key
holder says today". An implementation that caches such an answer as though it
were a CID, or renders it with the same words it uses for a CID, has quietly
converted a signed-and-revocable statement into an immutable one. Say which was
which.

### 12.4 The retrieval layer is a privacy surface even when it is not a trust surface

Asking the DHT for a CID tells peers which content is being read, from an
address no HTTP proxy covers. That is why the reference implementation refuses
an IPFS-served name outright while anonymisation is on rather than serving it
over a path that would leak. It is also why the local node is configured with
**no delegated routers and no delegated publishers**: a delegated router would
hand one company the list of every CID a person reads, and a delegated
publisher the list of everything a person publishes. The `car=` warm is the
deliberate exception and is scoped to make it a non-exception: the only server
asked is one that already knows this name is being opened, because it is the one
that serves it.

A privacy policy that has to reach more than one node **MUST** be written once.
The reference implementation states it as a flat table of dotted keys and
**derives** the nested object a JSON-configured daemon takes by expanding each
key, so a policy line cannot be added to one form and not the other; a daemon
that additionally sets a key inside that policy (the `ipfs://` daemon enables
the IPNS pubsub router) **MUST** merge into the derived value rather than
replace it, or it silently drops the sibling settings — here, the empty
delegated-publisher list. A test holds the two forms to the same leaves.

### 12.5 One namespace, two daemons

The reference implementation runs **two** IPFS nodes: one for the `ipfs://`,
`ipns://`, `ipld://` and `pubsub://` schemes, and a separate one for content
behind a Handshake `ipfs=` pointer. They have separate blockstores, separate
ports and separate lifecycles, and they share one privacy policy by derivation
rather than by copy (§12.4). Nothing in this specification requires two, and a
second node is a second place for a privacy setting to be missing: an
implementation that runs more than one **MUST** be able to point at the single
definition every one of them is built from.

---

## Appendix A — what an implementation of this chapter owes a reader

A one-paragraph summary, because it is the part that is easy to lose:

*A CID is a hash, so the content behind a resolved pointer cannot be tampered
with — by us, by a gateway, by the publisher's storage provider, or by anyone on
the path. What can be tampered with is **which** CID you were sent to, and that
question belongs to the name system that carried the pointer. An IPNS name, a
DNSLink and a pubsub topic are not hashes and do not carry that guarantee. A
`car=` origin is a shortcut to the bytes and carries no guarantee at all, which
is why it is safe to follow.*
