# Part II — Namespace selection: references

Every standard the router and classifier actually read, with what it is used
for and where in the tree it is used. Nothing is listed that the code does not
touch: a padded bibliography is worse than none, because it makes the real
dependencies impossible to see.

This file is scoped to the routing spine. The standards the *resolution* of a
Handshake name rests on — DNSSEC, DANE, DoH, HIP-5 — are in the spine's
[`REFERENCES.md`](../../REFERENCES.md) and are not repeated. Where a row says
*not used* or *deliberately not followed*, that is the point of the row: it is
listed because [`../../DEVIATIONS.md`](../../DEVIATIONS.md) has to cite it.

Paths are relative to the repository root.

---

## Naming

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | `localhost` (§6.3, the **whole subtree**, which is why `app.localhost` is covered and not only the bare label), `invalid` (§6.4), `test` (§6.2) and `example` (§6.5) are never Handshake names; §5 defines what "special use" obliges a resolver to do. SPEC §7 · `src/reserved-names.cjs` |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | §3: `local` is mDNS. Without the carve-out every NAS and printer name on a home network reaches whoever registers the Handshake top-level name `local`. SPEC §7 · `src/reserved-names.cjs` |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The ".onion" Special-Use Domain Name | §2 rule 1 is the rule the classifier's first branch implements, and the reason a *malformed* onion is kept in the Tor namespace rather than validated and released to a resolver. SPEC §6.1, §11.3 · `src/classify-host.cjs` `isOnionHost`, `src/reserved-names.cjs` |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-Use Domain 'home.arpa.' | The IETF's designated home-network name. Note the scope: it reserves `home.arpa`, **not** the bare label `home` (RT-1). SPEC §7 · `src/reserved-names.cjs` |
| [RFC 3172](https://www.rfc-editor.org/rfc/rfc3172) | Management Guidelines for the ".arpa" Domain | The infrastructure domain `home.arpa` lives under. SPEC §7 · `src/reserved-names.cjs` |
| [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) | Reserved Top Level DNS Names | The predecessor of RFC 6761's `test`/`example`/`invalid`/`localhost` reservations, cited for provenance. SPEC §7 |
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS Terminology | The vocabulary this part uses for label, zone, delegation and authoritative. SPEC §2 |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | §9.10, namespace precedence: resolve in the alternative namespace when its suffix matches, and do not continue into DNS when that resolution fails. **Adopted as LAW L2** — the only place the rule is written down in an RFC. SPEC §3.2 · `src/router.js` `ProtocolRouter.dispatch` |
| [SSAC SAC113](https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac-113-en.pdf) | SSAC Advisory on Private-Use TLDs | The advice that led to a string being set aside for private use; ICANN's board reserved `internal` for that purpose in 2024. An **ICANN** reservation, not an IETF one (RT-1, and DEVIATIONS §2.7 on what we have not verified). SPEC §7 · `src/reserved-names.cjs` |
| [ICANN Name Collision](https://www.icann.org/resources/pages/name-collision-2013-12-06-en) | Name Collision Resources & Information | The programme under which `corp` and `home` were deferred indefinitely from delegation, and where the phrase for the failure this whole part prevents is defined — *a name intended to be resolved in one naming system is inadvertently resolved in a different one*. `lan`, `intranet` and `private` have no such standing. SPEC §7 · `src/reserved-names.cjs` |
| [IANA root zone database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | Root Zone Database (TLD list) | The ICANN/Handshake boundary. The bundled snapshot is 1,438 A-label entries and the classifier's whole ICANN rule is a set membership test against it. SPEC §6.2 · `src/icann-tlds.cjs` |

## URI and URL syntax

| Identifier | Title | Used for |
|---|---|---|
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | §3.1 is the scheme grammar the explicit-scheme test implements (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, case-insensitive) and why `https+raw` is a syntactically legal scheme name; §3.2.1 is the `userinfo@host` rule that makes a stray `@` in a scheme-less input a search rather than a name; §3.2.2/§3.2.3 are why `example.com:8080` has to be told apart from a scheme (RT-4) and why an IPv6 literal is bracketed in the URL built for it. SPEC §2, §3.1, §6.1 · `src/router.js` `hasExplicitScheme` |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | What a scheme *becomes* when it is registered as standard: [special schemes](https://url.spec.whatwg.org/#special-scheme), [host parsing](https://url.spec.whatwg.org/#host-parsing), a tuple [origin](https://url.spec.whatwg.org/#concept-url-origin). Registering `hns:` as standard and accepting the host parser's rules are one decision (RT-13); a non-standard scheme's opaque origin is never a secure context, which is the honest posture for `ar://` and `ens://`. Its ["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) are why a standard scheme cannot carry an all-numeric final label (`hns://14898/` canonicalises to `hns://0.0.58.50/`); the constraint that places on the classifier is SPEC §8.2 and the URL form that works around it is Chapter 10 Part B's. Its bracket rule for IPv6 authorities is why the web-namespace URL builder brackets an unbracketed literal. SPEC §4.4, §6.1, §8 · `src/router.js`, `src/hns-url.cjs` |
| [WHATWG Fetch](https://fetch.spec.whatwg.org/) | Fetch Living Standard | The dispatcher's interface: a `Request` in, a `Response` out, so it runs identically under `node --test` and under Electron. `Request` refuses to construct from an unparseable URL, which is why the 400 branch is reachable only from a non-`Request` caller (RT-12). SPEC §5 · `src/router.js` `ProtocolRouter.dispatch` |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and Registration Procedures for URI Schemes | The procedure a new scheme is expected to go through, and the low bar for a **Provisional** registration. **We have not gone through it** for any scheme we invented (RT-6, RT-D4). Listed so the deviation has a citation. SPEC §4.2 |
| [IANA URI Schemes registry](https://www.iana.org/assignments/uri-schemes/) | Uniform Resource Identifier (URI) Schemes | Checked, not assumed: the "IANA" column of SPEC §4.2 is this registry's own status field. Of the 32 schemes in the table, 2 are Permanent, 11 Provisional, 19 unregistered. SPEC §4.2, RT-6 |
| [HTML Standard — `registerProtocolHandler`](https://html.spec.whatwg.org/multipage/system-state.html#custom-handlers) | HTML Living Standard | Where the `web+` scheme prefix is defined: a web *page* may register a handler only for a safelisted scheme or one beginning `web+`. Inapplicable to a scheme a browser implements natively, which is the answer RT-6 gives. Cited for the deviation, not used. RT-6 |

## Internationalized labels

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | IDNA2008: Definitions and Document Framework | The A-label / U-label vocabulary SPEC §8.1 uses. SPEC §8.1 |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | IDNA2008: Protocol | A Unicode host is converted to A-labels **before** the ICANN comparison, so `пример.рф` reaches the punycode list as `xn--e1afmkfd.xn--p1ai` and an emoji label comes out the other way. Also the standard RT-11 departs from: a label that fails validation is to be rejected, not used unconverted. SPEC §8.1 · `src/classify-host.cjs` `asciiTld` |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | What the URL Standard actually requires, and therefore what the conversion actually is. It and IDNA2008 differ on the deviation characters and on transitional processing; the difference is unaudited (spine `D-17`, RT-11). SPEC §8.1 · `src/classify-host.cjs` `asciiTld` |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for Internet Hosts — Application and Support | §2.1, host label syntax: the reason a Handshake label can never contain `_`, which is what makes Chapter 10's experimental numeric-TLD marker unambiguous. SPEC §8.2 · `src/hns-url.cjs` |

## Namespaces the router routes into

| Identifier | Title | Used for |
|---|---|---|
| [ERC-4804](https://eips.ethereum.org/EIPS/eip-4804) | Web3 URL to EVM Call Message Translation | The scheme in the registry's `web3` row. Cited here for the part deliberately **not** implemented: the `w3://` short form, which would shadow the `.w3` Handshake namespace (RT-9). SPEC §4.2 |
| [Tor Rendezvous Specification v3](https://spec.torproject.org/rend-spec-v3) | Tor Rendezvous Specification — Version 3 | §6, the onion address encoding: `base32(PUBKEY[32] ‖ CHECKSUM[2] ‖ VERSION[1])`, `CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2]`. Both trailing fields are verified, and the verdict is reported alongside the routing decision, never used to make it. SPEC §6.1, §11.3 · `src/router.js` `isValidV3Onion` |
| [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md) | bech32-encoded entities | The prefixes the classifier claims as `nostr:` when a bare identifier is typed — `npub`, `note`, `nprofile`, `nevent`, `naddr`, `nsec` — and the reason it can do so safely: the human-readable part *is* the type. Chapter 6 §5 specifies the encoding; this part specifies only where it sits in the order and that it is decoded before it is claimed. SPEC §6.1 · `src/router.js` `classify`, `namespaces/nostr/src/nip19.js` |
| [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) | Base32 address format for native v0-16 witness outputs (Bech32) | The checksum that gates the NIP-19 branch: 30 bits over a fixed human-readable part, so a Handshake name that merely begins `npub` fails the decode and stays a name. Cited here for the *gate*; the encoding itself is Chapter 6's. SPEC §6.1 · `namespaces/nostr/src/nip19.js` |
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | The signature the `nostr` trust step reports as checked in this process. SPEC §10.2 · `src/trust-path.js` |
| [BEP 46](https://www.bittorrent.org/beps/bep_0046.html) | Updating Torrents Via DHT Mutable Items | The key-addressed torrent the `bittorrent` trust step distinguishes from an infohash. SPEC §10.2 · `src/trust-path.js` |
| [CID specification](https://github.com/multiformats/cid) | Self-describing content-addressed identifiers | The pasted-CID rule and the CIDv0→CIDv1 rewrite: v0 is case-sensitive base58 and cannot survive as a standard scheme's host. SPEC §6.5 · `src/router.js` `bareCid` |
| [DNSLink](https://dnslink.dev/) | DNSLink specification | The `hyper` dotted-host case: a name→key mapping read from a public DoH resolver, with no DNSSEC and no chain proof, reported as an `unverified` pointer step above a `verified` content step. SPEC §10.2 · `src/trust-path.js` |
| [W3C DID Core](https://www.w3.org/TR/did-core/) | Decentralized Identifiers (DIDs) v1.0 | The `did` row's object. The trust step says the document was fetched and checked to be about the identifier asked for, and that for `did:plc` the operation log that would prove it is not audited. SPEC §4.2, §10.2 |
| [SearXNG](https://docs.searxng.org/) | SearXNG documentation | The model the `search://` category grammar follows: a query runs against one category's engines, so the category is what a search URL is *on*. SPEC §9.1 · `src/search-url.js` |

## Browser integration

| Identifier | Title | Used for |
|---|---|---|
| [Electron `protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | The declaration that makes a custom scheme exist at all. It must run before application startup, and a dispatched-but-undeclared scheme is unknown to the URL parser. The `standard`, `secure`, `allowServiceWorkers`, `supportFetchAPI`, `corsEnabled`, `bypassCSP` and `stream` flags are the ones SPEC §4.4 tabulates. SPEC §4.4, RT-D1 |
| [Electron `protocol.handle`](https://www.electronjs.org/docs/latest/api/protocol#protocolhandlescheme-handler) | Electron `protocol` API | How a scheme is bound to a handler. Every scheme is bound to **one** dispatcher rather than to its own handler, which is what makes the dispatcher the enforcement point for L1/L2 rather than a convention each handler is trusted to keep. SPEC §5 |
| [Chromium URL / scheme registry](https://chromium.googlesource.com/chromium/src/+/main/url/) | Chromium `url` library | The implementation of the URL Standard behind all of the above. A registered standard scheme cannot opt out of IPv4 host parsing, which is what makes the numeric-label problem structural rather than a bug to be reported. SPEC §4.4, §8.2 |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs | The meaning of MUST, MUST NOT, SHOULD, SHOULD NOT and MAY throughout this part. SPEC, Contents |
