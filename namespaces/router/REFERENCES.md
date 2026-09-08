# Part II — Namespace selection: references

Standards and implementation references used by this chapter. Each row states
its role; unsupported features are labelled explicitly. Paths below are relative
to the repository root unless a browser-only path is identified.

See [DEVIATIONS.md](DEVIATIONS.md) for limitations and
[REVIEW.md](../../REVIEW.md) for unresolved claims.

## Naming

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | Special-use treatment for localhost and its subtree, invalid, test, and example. `src/reserved-names.cjs`. |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | The `.local` multicast-DNS namespace. Excluded from Handshake classification. `src/reserved-names.cjs`. |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The ".onion" Special-Use Domain Name | Onion addresses remain in the Tor namespace, including malformed inputs. `src/classify-host.cjs`. |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-Use Domain 'home.arpa.' | The `home.arpa` special-use domain. It does not reserve `.home` or the other local-network conventions in this client’s list. |
| [RFC 3172](https://www.rfc-editor.org/rfc/rfc3172) | Management Guidelines for the ".arpa" Domain | Management and infrastructure role of `.arpa`; the reserved-name policy includes the subtree. |
| [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) | Reserved Top Level DNS Names | Provenance of the test, example, invalid, and localhost reservations. |
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS Terminology | DNS terminology used across these chapters. Superseded by RFC 9499; retained here for consistency with existing references. |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | Namespace precedence (§9.10), adopted from GNS as the router’s no-cross-namespace-fallback rule L2. |
| [SSAC SAC113](https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac-113-en.pdf) | SSAC Advisory on Private-Use TLDs | Private-use TLD advice. Use the relevant ICANN board resolution to establish the status of `internal`; the original citation did not verify it (RT-1). |
| [ICANN Name Collision](https://www.icann.org/resources/pages/name-collision-2013-12-06-en) | Name Collision Resources & Information | ICANN name-collision programme. Direct board decisions are needed for the `home`/`corp` status claims (RT-1). |
| [IANA root zone database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | Root Zone Database (TLD list) | The delegated-TLD list used for classification. The bundled snapshot contains 1,438 labels, version 2026090500. `src/icann-tlds.cjs`. |

## URI and URL syntax

| Identifier | Title | Used for |
|---|---|---|
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | Scheme grammar (§3.1), userinfo, host, and port syntax. The shorthand `host:port` distinction is a local input-classification rule. |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | URL syntax, host parsing, origins, and numeric-host handling. Electron’s custom `standard` flag is an implementation extension, not membership in WHATWG’s fixed special-scheme list. |
| [WHATWG Fetch](https://fetch.spec.whatwg.org/) | Fetch Living Standard | Request/Response interface used by dispatch. Request construction rejects unparseable URLs; runtime request-like objects can reach the 400 branch (RT-12). |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and Registration Procedures for URI Schemes | URI-scheme registration procedures, including provisional registration proposed for `hns` (RT-D4, HS-D2). |
| [IANA URI Schemes registry](https://www.iana.org/assignments/uri-schemes/) | Uniform Resource Identifier (URI) Schemes | Registration status for schemes in the router table. The inventory requires periodic verification (RT-6). |
| [HTML Standard — `registerProtocolHandler`](https://html.spec.whatwg.org/multipage/system-state.html#custom-handlers) | HTML Living Standard | The `web+` prefix applies to protocol handlers registered by web pages, rather than native browser schemes (RT-6). |

## Internationalized labels

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | IDNA2008: Definitions and Document Framework | A-label and U-label terminology for internationalized domain names. |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | IDNA2008: Protocol | IDNA2008 registration/lookup rules. The implementation instead uses WHATWG UTS #46; compatibility differences remain under review. |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | Compatibility processing required by the WHATWG host parser. Used for A-label conversion before ICANN classification. |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for Internet Hosts — Application and Support | Host label syntax and snapshot-entry validation. The numeric-TLD convention is a separate local extension. |

## Namespaces the router routes into

| Identifier | Title | Used for |
|---|---|---|
| [ERC-4804](https://eips.ethereum.org/EIPS/eip-4804) | Web3 URL to EVM Call Message Translation | The `web3://` scheme and the `w3://` alias this implementation declines to register (RT-9). |
| [Tor Rendezvous Specification v3](https://spec.torproject.org/rend-spec-v3) | Tor Rendezvous Specification — Version 3 | Onion v3 address encoding and SHA3-256 checksum. Validation is reported alongside classification and never selects a different namespace. |
| [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md) | bech32-encoded entities | Nostr bech32 identifier types and the bare-input recognition rule. The secret-key prefix is handled as a local refusal case. |
| [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) | Base32 address format for native v0-16 witness outputs (Bech32) | Bech32 checksum used when decoding public NIP-19 identifiers before routing them to Nostr. |
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | Schnorr signature verification reported by the Nostr trust step. |
| [BEP 46](https://www.bittorrent.org/beps/bep_0046.html) | Updating Torrents Via DHT Mutable Items | Key-addressed mutable torrent references, distinguished from immutable infohashes in the trust model. |
| [CID specification](https://github.com/multiformats/cid) | Self-describing content-addressed identifiers | CID parsing and conversion from CIDv0 to CIDv1 base32 before use as a URL host. |
| [DNSLink](https://dnslink.dev/) | DNSLink specification | The `_dnslink.<name>` TXT pointer convention. Supported namespaces are `/ipfs/` and `/ipns/`; Handshake SPEC §10.1 defines merging and conflict handling. `src/pointers.js`. |
| [W3C DID Core](https://www.w3.org/TR/did-core/) | Decentralized Identifiers (DIDs) v1.0 | DID identifiers and documents. The current trust model does not claim a locally verified PLC operation history. |
| [SearXNG](https://docs.searxng.org/) | SearXNG documentation | Search categories used by the `search://` URL grammar. |

## Browser integration

| Identifier | Title | Used for |
|---|---|---|
| [Electron `protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | Electron custom-scheme declarations and privileges before startup. `standard`, `secure`, and service-worker permissions are separate flags. |
| [Electron `protocol.handle`](https://www.electronjs.org/docs/latest/api/protocol#protocolhandlescheme-handler) | Electron `protocol` API | Binding scheme requests to the central dispatcher in the browser integration. |
| [Chromium URL / scheme registry](https://chromium.googlesource.com/chromium/src/+/main/url/) | Chromium `url` library | Chromium URL and custom-scheme parsing underlying Electron integration. |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs | Requirement keywords. RFC 8174 defines their uppercase interpretation. |
