# Chapter 4 — Arweave: references

Every specification this chapter's implementation actually reads, with what it
is used for and where. Nothing is listed that the code does not touch: a padded
bibliography is worse than none, because it makes the real dependencies
impossible to see. Where a row says *not implemented*, that is stated in the
row — it is here because a design decision turns on it, not because the
resolution path depends on it.

**Arweave has no RFCs.** Its formats are defined by the reference
implementation's repository documentation, by the Arweave Standards (ANS)
series, and — for the gateway and name-system conventions — by ar.io's
documentation. Where a citation is to a repository document rather than to a
standards body, the row says so. Where we could not retrieve a document to
check it, the row says that too, and `../../DEVIATIONS.md` §2 carries the
uncertainty.

---

## Identifiers and transactions

| Identifier | Title | Used for |
|---|---|---|
| [ANS-104](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md) | Bundled Data v2.0.0 (Arweave Standards) | The identifier derivation, verbatim: *"The id of the DataItem, is the SHA256 digest of this signature."* The same rule a transaction id follows, which is why a 43-character identifier may name **either** a transaction or a bundled data item and this implementation cannot tell them apart (SPEC §3.1, §3.3), and — read the other way round — half of what the header check **computes**: `SHA-256(base64url-decode(signature))` must equal the identifier, or the transaction a gateway showed us is not the one the identifier names (SPEC §9.1.1 — `src/ar-tx.js` `headerVerdict`, `tests/ar-tx.test.js`). The other half is verifying that signature over the fields. Nothing here parses a bundle, so a bundled data item's own id is never checked — `../../DEVIATIONS.md` AR-1. |
| [github.com/ArweaveTeam/arweave](https://github.com/ArweaveTeam/arweave) + [docs.arweave.org](https://docs.arweave.org/) | Arweave reference implementation and developer documentation — the transaction format, the `GET /tx/<id>` header endpoint, `data_root`, and the signature the id is a digest of and which signs the fields | Cited for both halves of §9. **Done:** against a header fetched from `GET <other gateway>/tx/<txid>`, `SHA-256(signature) == id` **and** the signature verified over the transaction's fields (SPEC §9.1.1), then the served body hashed against that header's `data_root` when the whole transaction is in hand and under 8 MiB (SPEC §9.2). **Not done:** chunk proofs, so a larger transaction, a `Range` and a bundled item are still gateway-trusted for their bytes — which is why the row in `../../src/router.js` `SCHEME_TABLE` still says `status: 'partial'`. `../../DEVIATIONS.md` AR-1, AR-D1. |
| [arweave-js](https://github.com/ArweaveTeam/arweave-js) (`lib/deepHash.ts`, `lib/transaction.ts` `getSignatureData()`, `lib/crypto/node-driver.ts` `verify()`) | The Arweave JS client library (repository source, v1.15.7) | The normative-by-practice statement of what a transaction signature is over: the deep hash (SHA-384, `"blob"`/`"list"` tags) of `["2", owner, target, quantity, reward, last_tx, tags, data_size, data_root]` for format 2 and the plain concatenation for format 1, verified as RSA-PSS/SHA-256 under `{ kty: 'RSA', e: 'AQAB', n: owner }` with the salt length left automatic. Re-implemented — **not imported** — in `src/ar-tx.js`, so this chapter adds no dependency; the deep hash is pinned against that library's own output in `tests/ar-tx.test.js`. SPEC §9.1.1. |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §5 (base64url, the URL and filename safe alphabet) is the identifier encoding: 32 bytes unpadded is 43 characters of `A-Z a-z 0-9 - _`. §3.5 (canonical encoding — non-alphabet bits must be zero) is the rule that makes exactly one of those 43-character strings the identifier. SPEC §3.2, §3.3 — `../../src/pointers.js` `isCanonicalTxid` and `ARTX_RE`, read by `src/ar.js`. The same encoding is decoded and re-encoded on both sides of the header check (the signature in, the digest out), so the comparison is between two canonical 43-character strings and not between two byte buffers — SPEC §9.1.1. §6 (base32, lowercase and unpadded) is the sandbox label a gateway redirects a transaction to (`sandboxLabel()`, SPEC §6.3) — accepted as the same gateway, with the identifier in the path as the load-bearing check. |
| [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | NIST, Secure Hash Standard (SHA-256, SHA-384) | Both hashes this chapter computes, out of `node:crypto` and no Arweave library: SHA-256 for the identifier (the digest of the signature), for the signature itself (RSA-PSS message digest) and for the chunk Merkle tree; SHA-384 for the deep hash the format-2 signature is over. SPEC §9.1.1, §9.2 — `src/ar-tx.js`, `src/ar-merkle.js`. |
| [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) | PKCS #1 v2.2: RSA Cryptography Specifications | §8.1 RSASSA-PSS, which is how an Arweave transaction is signed: SHA-256, MGF1-SHA-256, the salt length recovered from the signature on verification (`RSA_PSS_SALTLEN_AUTO`, which is what arweave-js's own verifier leaves Node to do), under the 4096-bit modulus the header carries as `owner` with exponent 65537. `src/ar-tx.js` `headerVerdict` — SPEC §9.1.1. |

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
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §15.5 (a 4xx is an answer about the resource) and §15.6 (a 5xx is about the server) are what SPEC §6.2's failover rule turns on. §9.3.2 (`HEAD`) is the rule the upstream `GET` departs from (`../../DEVIATIONS.md` AR-2). §14 (Range requests), §13.1.2 (`If-None-Match`), §13.1.3 (`If-Modified-Since`), §8.8.2 (`Last-Modified`), §8.8.3 (`ETag`), §12.5.1 (`Accept`) and §12.5.5 (`Vary`) are the mechanisms SPEC §6.4's fixed safelists carry, and §15.5.6 (`405`) the refusal of §6.5. `src/ar.js` `FORWARDED`, `RETURNED`, `isReachFailure`, and the method check. |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | Three consequences. Its **path normalization** collapses dot segments — including percent-encoded ones — before a `Request` reaches the handler, which is why that half of the guard is defence for a raw string and the test asserts the *outcome* (SPEC §4.3). Its **percent-encoding** is already applied to the segments the handler receives, which is why they are forwarded as received (SPEC §4.3). Its **host parsing lowercases**, which would destroy a case-sensitive identifier — the reason parsing is done on the raw string and the reason `ar` is registered `standard: false` (SPEC §4.2, §10). `src/ar.js`; `src/main.cjs` in the browser tree. |

## Where this chapter hands off

| Identifier | Title | Used for |
|---|---|---|
| `../../SPEC.md` §6 | The spine: the resolution algorithm | How a Handshake name's `ar=` record was proven — the chain proof, the authoritative walk, the DNSSEC validation anchored to the on-chain DS. SPEC §9.4 depends on it and does not repeat it. |
| `../../SPEC.md` §7 | The spine: HIP-5 `_op` on-chain resolution | The route that produces an `arweave-ns` contenthash. This chapter picks up at the decode, SPEC §5.3. |
| `../../SPEC.md` §10 | The spine: content pointers | The pointer grammar and precedence — `ar=<txid>`, last in `POINTER_PRECEDENCE`. Implemented in `../../src/pointers.js`, referenced by SPEC §5.2, not duplicated. |
| `../../SPEC.md` §3, §4 | The spine: namespace selection and trust states | Why `<label>_persist.ar.io` is an ICANN name (SPEC §8), and the four trust states the panel renders (SPEC §9.2, `../../DEVIATIONS.md` AR-U5). |
| `../../DEVIATIONS.md` D-1, D-9, D-10 | The spine's deviations | The flat positive cache this chapter inherits (AR-3), and the DoH-route trust weakenings that also apply to an `ar=` pointer resolved over DoH (SPEC §9.4). |
