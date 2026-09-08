# Chapter 3 — IPFS, IPNS and DNSLink: references

Specifications and implementation documents used by this chapter. Each row
identifies the relevant behaviour and source. Delegated checks and
unimplemented features are labelled explicitly.

`src/` and `tests/` paths are relative to this chapter; `../../src/` names
shared modules. Browser paths refer to the Wildroot source tree.

[Chapter specification](SPEC.md) · [Deviations and open questions](DEVIATIONS.md)

---

## Addressing: multiformats

| Identifier | Title | Used for |
|---|---|---|
| [multiformats/cid](https://github.com/multiformats/cid) | CID (Content IDentifier) Specification | SPEC §4.1, §4.3, §5 — what an `ipfs://` host, an `ipld://` host and an `ipfs=` value *are*: `multibase(version, multicodec, multihash)`. `../../src/pointers.js` (`CID_RE`), `src/ipfs-url.js`, `src/cid.js`, `src/car-roots.js`, and `../../src/router.js` for the bare-CID classification of SPEC §3 |
| [multiformats/multibase](https://github.com/multiformats/multibase) | Multibase | SPEC §5, §3 — the leading character saying which base a CID string is written in. Two are accepted (implicit base58btc for `Qm…`, `b` for base32), which is narrower than the table (IP-1), and the base32 form is the one a URL host survives. `../../src/pointers.js` |
| [multiformats/multicodec](https://github.com/multiformats/multicodec) ([table](https://github.com/multiformats/multicodec/blob/master/table.csv)) | Multicodec | SPEC §5, §6.4 — the codec byte inside a CID and inside a contenthash: `dag-pb` 0x70, `raw` 0x55, `libp2p-key` 0x72, `ipfs-ns` 0xe3, `ipns-ns` 0xe5, `swarm-ns` 0xe4. `src/cid.js`, `../../src/contenthash.js` |
| [multiformats/multihash](https://github.com/multiformats/multihash) | Multihash | SPEC §5 — the hash function and digest inside a CID. Only sha2-256 is produced; anything else is read as whatever the CID says it is. `src/cid.js` |
| [multiformats/unsigned-varint](https://github.com/multiformats/unsigned-varint) | Unsigned-varint | SPEC §5, §12.2 — the length and code prefixes throughout: the CAR header length, the multicodec code in a contenthash, protobuf field lengths. `src/car-roots.js`, `src/cid.js`, `../../src/contenthash.js` |
| [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180-4/final) | Secure Hash Standard (SHS) | SPEC §5, §9 — sha2-256, the hash every CID this stack produces is built on, and the root of trust of the whole namespace. `src/cid.js` via `multiformats/hashes/sha2` |
| [draft-msporny-base58](https://datatracker.ietf.org/doc/html/draft-msporny-base58) | The Base58 Encoding Scheme | SPEC §4.2, §3 — the base58btc alphabet, and that it is **case-sensitive**, which is the whole of IP-5. An Informational draft, not a ratified standard; cited because it is the only written definition. `../../src/pointers.js` |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) §6 | The Base16, Base32, and Base64 Data Encodings | SPEC §3, §4.2 — base32, lowercase and unpadded: the default CIDv1 text form, and the reason a CIDv1 survives host canonicalisation when a CIDv0 does not. `../../src/pointers.js` |

## The data model: what a CID names

| Identifier | Title | Used for |
|---|---|---|
| [UNIXFS.md](https://github.com/ipfs/specs/blob/main/UNIXFS.md) | UnixFS Data Format | SPEC §5 — the `Data` protobuf message a file or directory node carries (`Type`, `filesize`, `blocksizes`), and therefore the DAG shape that *is* the address. Written out by hand rather than imported, so the encoder cannot vanish with a transitive dependency. `src/cid.js` |
| [ipld/dag-pb](https://ipld.io/specs/codecs/dag-pb/spec/) | DAG-PB Specification | SPEC §5 — the wire form of an internal node: `Links` (Hash, Name, Tsize) then `Data`, with links sorted by name for a directory. `src/cid.js` |
| [ipld/dag-cbor](https://ipld.io/specs/codecs/dag-cbor/spec/) | DAG-CBOR Specification | SPEC §12.2 — the encoding of a CARv1 header and the tag-42 link form. Decoded by a minimal reader rather than by `@ipld/dag-cbor` (IP-7). `src/car-roots.js` |
| [ipld/car (CARv1)](https://ipld.io/specs/transport/car/carv1/) | Content Addressable aRchives (CAR / CARv1) | SPEC §8, §12.2 — the archive format a stated origin serves: a varint-prefixed dag-cbor header `{version: 1, roots: [CID…]}`, then blocks. Only the header is parsed here. `src/car-roots.js` |
| [go-unixfs balanced builder](https://github.com/ipfs/go-unixfs/blob/master/importer/balanced/builder.go) | Balanced DAG layout, and kubo's `Import.*` defaults | SPEC §5 — the chunker (`size-262144`), raw leaves, the 174-link fan-out (`UnixFSFileMaxLinks`) and the 256 KiB HAMT threshold (IP-6). Not a standard — an implementation's defaults — but normative for interoperating with it, which is the point of computing a CID before publishing. `src/cid.js`, `tests/cid.test.js` |

## Naming inside the namespace

| Identifier | Title | Used for |
|---|---|---|
| [ipns/ipns-record](https://specs.ipfs.tech/ipns/ipns-record/) | IPNS Record Specification | SPEC §4.2, §9 — what an `ipns://` host and an `ipns=` value resolve *through*: a signed record with a value, a sequence number and a validity window. **Delegated, not implemented** (IP-3): the local node performs the lookup and the signature check, and this stack validates the key's shape. `../../src/pointers.js` (`IPNS_RE`) |
| [ipns/ipns-pubsub-router](https://specs.ipfs.tech/ipns/ipns-pubsub-router/) | IPNS PubSub Router | SPEC §4.2, §12.4 — how an `ipns://` name updates without polling. Enabled on the `ipfs://` daemon (`Ipns.UsePubsub`), which merges into the derived privacy policy rather than replacing it. The Wildroot tree's `src/config.js` |
| [libp2p/peer-ids](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md) | libp2p Peer Ids | SPEC §4.2 — the four host forms an IPNS name takes: a base36 or base32 `libp2p-key` CIDv1, a modern `12D3Koo…` identity, a legacy `Qm…` one. `../../src/pointers.js` |
| [libp2p/pubsub](https://github.com/libp2p/specs/tree/master/pubsub) | libp2p PubSub | SPEC §4.4, §10 — what a `pubsub://` topic is, and that a message's authentication is a publisher signature at the libp2p layer, never a content address. That sentence is the scheme table's `verify` entry (`../../src/router.js`) and the trust panel's step (`../../src/trust-path.js`) |
| [DNSLink](https://dnslink.dev/) | DNSLink | SPEC §6.3 — `_dnslink.<name> TXT dnslink=/ipfs/<cid>` (or `/ipns/<key>`, either with a trailing path), the convention kubo, Brave, IPFS Companion and the public gateways read. **Read as a second pointer source and written at publish**, so a site published either way opens both ways: the `_dnslink` owner prefix, the value grammar, and the rule that a name carries one value. `../../src/pointers.js` (`parseDnslink`, `dnslinkPointerFrom`, `mergePointers`, `dnslinkValue`, `dnslinkOwner`), `../../src/resolver.js`, `../../src/doh.js`. The node-side reader kubo uses for `ipns://<domain>` is untested here (`../../DEVIATIONS.md` Chapter 3 §2.4) |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) §3.3.14 | Domain Names — Implementation and Specification | SPEC §6.1, §7.2 — a TXT record's `<character-string>`s are **one** value, concatenated; separate records are separate values. Applied identically on every resolution path. `../../src/pointers.js` (`txtStringsFrom`) |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) / [ENSIP-7](https://docs.ens.domains/ensip/7) | contenthash field | SPEC §6.4 — the second carrier: `ipfs-ns` 0xe3 and `ipns-ns` 0xe5 decode into this namespace, `swarm-ns` 0xe4 is recognised and refused by name. `../../src/contenthash.js` |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) §9.10 | The GNU Name System | SPEC §3 — resolve in the alternative namespace when its identifier matches, and do **not** continue into another namespace on failure. Inherited from the spine as the rule for these four schemes. `../../src/router.js` |

## Experimental: the `car=` stated origin and origin warming

These four are cited by SPEC §8, which is marked EXPERIMENTAL. They give the
*shape* of a gateway URL and the parameters for asking it for part of a DAG;
none of them says how a **name** announces such a location, which is why §8 is a
local convention (IP-9).

| Identifier | Title | Used for |
|---|---|---|
| [Trustless Gateway](https://specs.ipfs.tech/http-gateways/trustless-gateway/) | Trustless Gateway Specification | SPEC §8.1 — the URL form a `car=` origin takes to be windowable, `https://<host>[/<prefix>]/ipfs/<cid>`, plus `?format=car` and the `application/vnd.ipld.car` Accept header. `src/origin-warm.js` (`gatewayBase`) |
| [IPIP-0402](https://github.com/ipfs/specs/blob/main/ipips/ipip-0402.md) | Partial CAR support on Trustless Gateways (`dag-scope`, `entity-bytes`) | SPEC §8.2 — fetching a byte window of one file inside a large archive as a partial CAR: `dag-scope=entity&entity-bytes=<from>:<to>`, and `dag-scope=all` for a whole archive. The policy around it is ours (IP-11). `src/origin-warm.js` |
| [Path Gateway](https://specs.ipfs.tech/http-gateways/path-gateway/) | Path Gateway Specification | SPEC §8.2 — the `/ipfs/<cid>/<path>` URL shape those parameters are appended to, and the percent-encoding of each path segment. `src/origin-warm.js` |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) §14 | HTTP Semantics — Range Requests | SPEC §8.2 — the `Range` header a read carries, which decides *which* window is warmed. Single byte ranges and suffix ranges only; a multi-range request is treated as "the whole thing", because a correct 200 beats a wrong 206. `src/byte-range.js` |

## URLs and the host

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL](https://url.spec.whatwg.org/) ([host parsing](https://url.spec.whatwg.org/#host-parsing)) | URL Living Standard | SPEC §3, §4.2, §4.4 — an identifier in this namespace lives in a URL **host**, and a host is subject to whatever canonicalisation the parser applies. Node treats `ipfs:` as a non-special scheme and preserves case; a browser that registers it as a *standard* scheme does not. This split is IP-5, and it is why a pasted CIDv0 is re-spelled as base32 CIDv1. `src/ipfs-url.js`, `../../src/router.js`; the registration is in the Wildroot tree's `src/main.cjs` |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) §3.3 | Uniform Resource Identifier (URI): Generic Syntax | SPEC §8.2 — path segments, and percent-encoding each segment of a gateway path rather than the path as a whole. `src/origin-warm.js` |

<a id="not-a-standard-but-required"></a>

## Implementation dependencies

| Identifier | Title | Used for |
|---|---|---|
| [ipfs/kubo](https://github.com/ipfs/kubo) | kubo (go-ipfs) | SPEC §5, §7.3, §12.4, §12.5 — the node every retrieval goes through, and therefore the implementation whose IPNS record checking, block verification and DAG defaults this chapter relies on. Version 0.43 defaults are what `src/cid.js` reproduces and `tests/cid.test.js` pins; its privacy configuration is the subject of SPEC §12.4 |
| [RangerMauve/js-ipfs-fetch](https://github.com/RangerMauve/js-ipfs-fetch) | js-ipfs-fetch | SPEC §4.3, §4.4 — the handler behind `ipfs://`, `ipns://`, `ipld://` and `pubsub://` in the Wildroot tree, and therefore the definition of what `ipld://`'s `Accept` re-encoding and `pubsub://`'s event stream do. Not respecified here |
| `STORAGE-PUBLISH-SHARE.md` decision **D-P2** (as amended) | The stated origin: what `car=` is for | SPEC §8 — the provenance of the EXPERIMENTAL section, and the amendment that a stated origin is only ever a gateway-form HTTPS URL. Not a public document; cited because it governs IP-9 |
| [Routing](../router/SPEC.md), [Handshake resolution](../handshake/SPEC.md#6-the-resolution-algorithm), [Handshake content pointers](../handshake/SPEC.md#10-content-pointers), [shared trust states](../../SPEC.md#4-trust-states) | Shared resolution rules | Namespace selection, chain proofs, DNSSEC anchored to the on-chain DS, pointer grammar and trust-state aggregation. Applied in this chapter at SPEC §3, §6, §7.2 and §10. |

---

## Not used, and why the absence is deliberate

- **Bitswap, the Amino DHT, delegated routing (the Routing V1 HTTP API), IPNI** —
  retrieval and provider discovery. Out of scope (SPEC §1.1), and delegated
  routing is additionally switched **off**, because it would disclose every CID a
  person reads to a third party (SPEC §12.4).
- **CARv2** — indexed archives. Nothing here writes or reads one; a CARv2 header
  is refused as "not a CARv1 header" rather than partially understood.
- **HAMT-sharded directories** (UNIXFS.md, `HAMTDirectory`) — not implemented; a
  folder that would need one is refused rather than given a CID that would
  disagree with kubo's (IP-6).
- **Gateway response formats other than `car`** (`?format=raw`,
  `?format=dag-json`, a plain file body) — a stated origin is only ever asked for
  a CAR, because a CAR is the only response form whose blocks arrive individually
  hash-checkable.
