# Chapter 4 — Arweave: references

Specifications and implementation documents used by this chapter. Each row
identifies the relevant behaviour and source. Delegated checks and
unimplemented features are labelled explicitly.

`src/` and `tests/` paths are relative to this chapter; `../../src/` names
shared modules. Browser paths refer to the Wildroot source tree.

[Chapter specification](SPEC.md) · [Deviations and open questions](DEVIATIONS.md)

---

## Identifiers and transactions

| Identifier | Title | Used for |
|---|---|---|
| [ANS-104](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md) | The bundled data-item id is SHA-256 of its signature. `headerMatchesId` checks this relationship; it does not verify the signature over header fields. No bundle parser is implemented. SPEC §3 and §9; `src/ar.js`. | The identifier derivation, verbatim: *"The id of the DataItem, is the SHA256 digest of this signature."* The same rule a transaction id follows, which is why a 43-character identifier may name **either** a transaction or a bundled data item and this implementation cannot tell them apart (SPEC §3.1, §3.3), and — read the other way round — the rule the header check **computes**: `SHA-256(base64url-decode(signature))` must equal the identifier, or the transaction a gateway showed us is not the one the identifier names (SPEC §9.1.1 — `src/ar.js` `headerMatchesId`, `tests/arweave-header.test.js`). Nothing here parses a bundle. |
| [github.com/ArweaveTeam/arweave](https://github.com/ArweaveTeam/arweave) + [docs.arweave.org](https://docs.arweave.org/) | The transaction header, `/tx/<id>` endpoint, signature and `data_root`. `src/ar.js` checks the signature hash and conditionally compares bodies with the supplied root using `src/ar-merkle.js`. Header-field authentication and general chunk proofs remain open. SPEC §9; AR-1 and AR-D1. | Cited for both halves of §9. **Done:** `SHA-256(signature) == id` is recomputed against a header fetched from `GET <other gateway>/tx/<txid>` (SPEC §9.1.1). **Not done:** the bytes are never checked against the `data_root` that header carries, and no chunk proof is fetched or verified — which is why the row in `../../src/router.js` `SCHEME_TABLE` still says `status: 'partial'`. SPEC §9.2; `../../DEVIATIONS.md` AR-1, AR-D1. |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §5 (base64url, the URL and filename safe alphabet) is the identifier encoding: 32 bytes unpadded is 43 characters of `A-Z a-z 0-9 - _`. §3.5 (canonical encoding — non-alphabet bits must be zero) is the rule that makes exactly one of those 43-character strings the identifier. SPEC §3.2, §3.3 — `../../src/pointers.js` `isCanonicalTxid` and `ARTX_RE`, read by `src/ar.js`. The same encoding is decoded and re-encoded on both sides of the header check (the signature in, the digest out), so the comparison is between two canonical 43-character strings and not between two byte buffers — SPEC §9.1.1. §6 (base32, lowercase and unpadded) is the sandbox label a gateway redirects a transaction to (`sandboxLabel()`, SPEC §6.3) — accepted as the same gateway, with the identifier in the path as the required check. |
| [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | NIST, Secure Hash Standard (SHA-256) | The one cryptographic primitive this chapter computes. An Arweave identifier is the SHA-256 digest of the transaction's signature, so the header check is a single `node:crypto` `createHash('sha256')` and no Arweave library is involved. SPEC §9.1.1 — `src/ar.js` `headerMatchesId`. |

## Path manifests

| Identifier | Title | Used for |
|---|---|---|
| [path-manifest-schema.md](https://github.com/ArweaveTeam/arweave/blob/master/doc/path-manifest-schema.md) | Arweave path manifest schema (repository document, version 0.1.0) | The manifest format: `"manifest": "arweave/paths"`, Content-Type `application/x.arweave-manifest+json`, an optional `index` whose `path` must be a key of `paths`, and a required `paths` object whose *"object keys represent the subpaths, and the values tell us which content to resolve to"*. **Not implemented** — the client has no manifest reader. SPEC §7, which specifies the delegation to the gateway and what it costs; `../../DEVIATIONS.md` AR-U1. |
| Manifest version 0.2.0 | `index.id` and `fallback` — an ar.io-side extension, no retrievable specification document | Named as behaviour that is entirely the answering gateway's. Its clauses are **not verified** against a document we could obtain. SPEC §7; `../../DEVIATIONS.md` AR-U2 — no code. |

## Gateways, the `ar://` scheme, and names

| Identifier | Title | Used for |
|---|---|---|
| `ar://<txid>` | The `ar://` scheme as used by the ar.io gateway network and the Wander (formerly ArConnect) wallet — a de-facto convention, with **no RFC and no IANA registration** | The URL form of SPEC §4, adopted unchanged rather than replaced. `src/ar.js`; `../../src/contenthash.js` (`url: 'ar://' + txid`); `../../src/router.js` `SCHEME_TABLE`. `../../DEVIATIONS.md` AR-2. |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and Registration Procedures for URI Schemes | The registration procedure `ar` has not been through, and the provisional registration that would fit an established convention. SPEC §4.1; `../../DEVIATIONS.md` AR-2 — no code. |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | §3.1 (scheme syntax) and §3.3 (path segments, and the dot-segments a path must not smuggle) — the grammar SPEC §4.1 and §4.3 are written against. `src/ar.js` `isSafeSegment`. |
| [docs.ar.io](https://docs.ar.io/) | ar.io gateway and network documentation | The URL shape a gateway serves (`GET /<id>` and `GET /<id>/<path>` for transactions, data items and manifest subpaths), and `/ar-io/info` as the marker of a gateway-network member — which is the criterion `AR_GATEWAYS` states, and the observation that `arweave.net` does not answer it. SPEC §6.1 — `src/ar.js` `AR_GATEWAYS`. |
| ArNS / ANT / undername | The ar.io name system, its Arweave Name Token contract, and the `<undername>_<name>.<gateway-host>` wildcard convention ([docs.ar.io](https://docs.ar.io/)) | **Not implemented, anywhere.** Cited so SPEC §8 can state precisely what happens instead: `<label>_persist.ar.io` ends in the ICANN TLD `io`, so `classifyHost` routes it to ordinary DNS over ordinary CA-authenticated HTTPS. `../../src/router.js` `classifyHost`; `../../DEVIATIONS.md` AR-U3. |

## Content pointers into this chapter

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain Names — Implementation and Specification | §3.3.14: a TXT record's `<character-string>`s are **one** value and are concatenated; separate records are separate values. The rule that makes `ar=<txid>` read identically on the SPV, DoH and `_op` paths. SPEC §5.2 — `../../src/pointers.js` `txtStringsFrom`. |
| [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) | Clarifications to the DNS Specification | §5.2: the TTL is the authoritative server's statement of how long an RRset may be cached — the rule the flat 60-second positive cache does not follow. `../../src/resolver.js` `CACHEABLE`; `../../DEVIATIONS.md` AR-3. |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) / [ENSIP-7](https://docs.ens.domains/ensip/7) | `contenthash` field for ENS | The multicodec-prefixed byte string an ENS or HIP-5 `_op` resolver returns. `arweave-ns` is `0xb29910`, four bytes on the wire (`90 b2 ca 05`), and its value is the raw 32-byte transaction id — base64url-encoded here into the canonical 43-character form. SPEC §5.3 — `../../src/contenthash.js` (`CODEC.ARWEAVE`, `readVarint`), `../../src/hip5-op.js`. |
| [multicodec table.csv](https://github.com/multiformats/multicodec/blob/master/table.csv) | The multicodec code table | Where `arweave-ns` `0xb29910` and the neighbouring `ipfs-ns` `0xe3` / `ipns-ns` `0xe5` / `swarm-ns` `0xe4` codes come from. Only those four are recognised; everything else is reported as `unknown` and refused by name, never guessed at. SPEC §5.3 — `../../src/contenthash.js`. |
| [unsigned-varint](https://github.com/multiformats/unsigned-varint) | Unsigned variable-length integer (multiformats) | The LEB128 encoding of the multicodec code, hand-implemented with a 35-bit shift cap. SPEC §5.3 — `../../src/contenthash.js` `readVarint`. |

## HTTP and URLs

| Identifier | Title | Used for |
|---|---|---|
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §15.5 (a 4xx is an answer about the resource) and §15.6 (a 5xx is about the server) are what SPEC §6.2's failover rule turns on. §9.3.2 defines the forwarded `HEAD` method. §14 (Range requests), §13.1.2 (`If-None-Match`), §13.1.3 (`If-Modified-Since`), §8.8.2 (`Last-Modified`), §8.8.3 (`ETag`), §12.5.1 (`Accept`) and §12.5.5 (`Vary`) are the mechanisms SPEC §6.4's fixed safelists carry, and §15.5.6 (`405`) the refusal of §6.5. `src/ar.js` `FORWARDED`, `RETURNED`, `isReachFailure`, and the method check. |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | Three consequences. Its **path normalization** collapses dot segments — including percent-encoded ones — before a `Request` reaches the handler, which is why that half of the guard is defence for a raw string and the test asserts the *outcome* (SPEC §4.3). Its **percent-encoding** is already applied to the segments the handler receives, which is why they are forwarded as received (SPEC §4.3). Its **host parsing lowercases**, which would destroy a case-sensitive identifier — the reason parsing is done on the raw string and the reason `ar` is registered `standard: false` (SPEC §4.2, §10). `src/ar.js`; `src/main.cjs` in the browser tree. |

## Where this chapter hands off

| Identifier | Title | Used for |
|---|---|---|
| [Handshake §6](../handshake/SPEC.md#6-the-resolution-algorithm) | Handshake resolution | The chain resource, authoritative walk and DNSSEC validation of the name-to-Arweave pointer. This chapter uses that binding in SPEC §9.4. |
| [Experimental Part A](../experimental/SPEC.md#part-a--hip-5-_op-on-chain-resolution) | HIP-5 `_op` on-chain resolution | The contract route that returns an `arweave-ns` contenthash. This chapter starts at decoding that value (SPEC §5.3). |
| [Handshake §10](../handshake/SPEC.md#10-content-pointers) | Content pointers | The `ar=<txid>` grammar and precedence, implemented in `../../src/pointers.js`. Referenced by SPEC §5.2. |
| [Router §6](../router/SPEC.md#6-classification-of-bare-input), [shared trust states](../../SPEC.md#4-trust-states) | Namespace selection and trust states | Why an ar.io gateway name selects ICANN (SPEC §8), and how the trust model represents the result (SPEC §9.2; AR-U5). |
| [Handshake deviations](../handshake/DEVIATIONS.md), [Handshake §9.1](../handshake/SPEC.md#91-doh-fallback) | Shared cache and DoH limits | HS-1 tracks the fixed positive-cache lifetime; HS-8 describes resolver-trusted TLSA pins. The Handshake specification defines when DoH fallback is allowed. AR-3 and SPEC §9.4 refer to these limits. |
