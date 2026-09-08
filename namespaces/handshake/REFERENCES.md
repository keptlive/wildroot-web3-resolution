# Chapter 1 — Handshake: references

Standards and implementation references used by this chapter. Each row states
its role; unsupported features are labelled explicitly. Paths below are relative
to the repository root unless a browser-only path is identified.

See [DEVIATIONS.md](DEVIATIONS.md) for limitations and
[REVIEW.md](../../REVIEW.md) for unresolved claims.

## DNS: messages, terminology, transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) | Domain names — concepts and facilities | Delegation and referral handling (§4.3.2), CNAME semantics (§3.6.2), and authoritative-server selection. `src/resolver.js`. |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain names — implementation and specification | DNS message and RR encoding. §3.3.14 permits one or more character-strings in a TXT RR; joining them is the pointer convention used by this implementation. `src/dns-query.js`, `src/pointers.js`. |
| [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) | Clarifications to the DNS specification | RRset TTL rules (§5.2), compared with the fixed positive cache (HS-1). |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | DNS case insensitivity clarification | Case-insensitive DNS owner comparison, including matching responses to questions. `src/classify-host.cjs`, `src/dns-query.js`. |
| [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891) | Extension mechanisms for DNS (EDNS(0)) | EDNS OPT and the DO bit. Extended RCODEs are not read by the shared DNS parser (HS-11). |
| [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) | DNS transport over TCP | Authoritative DNS transport uses TCP. `src/dns-query.js`. |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS protocol version 5 | SOCKS5 CONNECT for injected authoritative and site sockets. `src/socks-dial.js`, `src/dane-connect.js`; Handshake SPEC §6.11 and §8.1. |
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS terminology | DNS terminology used across these chapters. Superseded by RFC 9499; retained here for consistency with existing references. |
| [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596) | DNS extensions to support IPv6 (AAAA) | AAAA records and IPv6 resolution. The current IPv4-first selection policy is recorded in HS-2. |
| [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) | Extended DNS Errors | Extended DNS Errors, currently not parsed (HS-11). |
| [draft-ietf-dnsop-deleg](https://datatracker.ietf.org/doc/draft-ietf-dnsop-deleg/) | Extensible delegation for DNS | Delegation extensions considered but not implemented (HS-11). Draft and allocation status require a dated check. |

## DNSSEC

| Identifier | Title | Used for |
|---|---|---|
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS security introduction and requirements | DNSSEC security states and the distinction between secure, insecure, bogus, and indeterminate results. |
| [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) | Resource records for the DNS security extensions | DNSKEY, RRSIG, NSEC, DS, canonical signing input, label counts, and signature validity windows. `src/dnssec.js`, `src/nsec.js`. |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) | Protocol modifications for the DNS security extensions | DS/DNSKEY anchoring, RRset validation, CNAME and wildcard processing, authenticated denial, and validation failure. `src/dnssec.js`, `src/denial.js`, `src/resolver.js`. |
| [RFC 4592](https://www.rfc-editor.org/rfc/rfc4592) | The role of wildcards in the DNS | Wildcard source of synthesis and closest-encloser semantics. `src/nsec.js`, `src/nsec3.js`. |
| [RFC 5011](https://www.rfc-editor.org/rfc/rfc5011) | Automated updates of DNSSEC trust anchors | REVOKE-bit handling (§2.1). The rollover procedure is not used; Handshake anchors change through chain records (HS-11). |
| [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155) | DNSSEC hashed authenticated denial of existence (NSEC3) | NSEC3 closest-encloser, NXDOMAIN, NODATA, wildcard, and insecure-delegation proofs. `src/nsec3.js`, `src/denial.js`. |
| [RFC 9276](https://www.rfc-editor.org/rfc/rfc9276) | Guidance for NSEC3 parameter settings | NSEC3 parameter guidance. The validator caps iterations at 100. `src/nsec3.js`. |
| [RFC 8624](https://www.rfc-editor.org/rfc/rfc8624) | Algorithm implementation requirements for DNSSEC | The cited DNSSEC algorithm implementation requirements underlying the supported/refused lists in Handshake SPEC §6.7. |
| [RFC 3110](https://www.rfc-editor.org/rfc/rfc3110) | RSA/SHA-1 SIGs and RSA keys in the DNS | RSA DNSKEY wire format reused for RSASHA256. The SHA-1 signature algorithm is not supported. `src/dnssec.js`. |
| [RFC 5702](https://www.rfc-editor.org/rfc/rfc5702) | Use of SHA-2 algorithms with RSA in DNSKEY and RRSIG | RSASHA256 (algorithm 8), using the RSA key format from RFC 3110. `src/dnssec.js`. |
| [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605) | Elliptic curve digital signature algorithm (DSA) for DNSSEC | P-256/SHA-256, P-384/SHA-384, and DS digest type 4. `src/dnssec.js`. |
| [RFC 8080](https://www.rfc-editor.org/rfc/rfc8080) | Edwards-curve DSA for DNSSEC | Ed25519 DNSSEC (algorithm 15). Ed448 is not supported. `src/dnssec.js`. |
| [RFC 4509](https://www.rfc-editor.org/rfc/rfc4509) | Use of SHA-256 in DNSSEC delegation signer (DS) resource records | DS digest type 2, SHA-256. `src/dnssec.js`. |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32 and Base64 data encodings | Base32hex for NSEC3 names and base64url for DoH queries and transaction IDs. |

## TLS and certificates

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | The DNS-based authentication of named entities (DANE) transport layer security protocol: TLSA | TLSA records and port-derived owner names. Handshake supports the `3 1 1` profile; ICANN navigation does not use this DANE path. |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | The DANE protocol: updates and operational guidance | Unusable TLSA records (§4.1), DANE-EE certificate checks (§5.1), CNAME base domains (§7.2), and key rotation (§8.1). See HS-5, HS-9, and HS-12. |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | Internet X.509 public key infrastructure certificate and CRL profile | X.509 certificate structure. The DANE path extracts SPKI; the loopback bridge generates a certificate. Ordinary HTTPS uses the engine’s separate WebPKI validation. |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The transport layer security (TLS) protocol version 1.3 | TLS 1.3. The runtime provides the TLS implementation; this repository configures connections and applies DANE pins. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP semantics | HTTP semantics used by transport handlers and error responses. |

## Encrypted DNS transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS queries over HTTPS (DoH) | Wire-format DoH, HTTP templates, and media types. §4.1 recommends ID zero for cache compatibility; the client uses zero and separately matches the reply question. `src/doh.js`. |
| [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230) | Oblivious DNS over HTTPS | ODoH messages, configuration structures, and response key/nonce derivation (§6.3). `src/odoh.js`, `src/odoh-bridge.js`. |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) | Hybrid public key encryption | HPKE construction used by ODoH: X25519-HKDF-SHA256, HKDF-SHA256, AES-128-GCM. `src/odoh.js`. |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based extract-and-expand key derivation function (HKDF) | HKDF extract/expand used in ODoH key derivation. `src/odoh.js`. |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) | Discovery of designated resolvers | Discovery of Designated Resolvers. Not implemented; resolver templates are configured. |

## Service binding, ECH, and records read but not queried

| Identifier | Title | Used for |
|---|---|---|
| [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) | Service binding and parameter specification via the DNS (SVCB and HTTPS RRs) | SVCB/HTTPS RDATA and service parameters. The shared parser supports them; the Handshake resolution algorithm does not query type 65. |
| [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) | Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings | Obtaining ECH configuration through DNS service bindings. Handshake does not currently query the required HTTPS record; engine HTTPS capabilities are separate. |
| [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849) | TLS Encrypted Client Hello | ECH protocol itself; RFC 9848 specifies its DNS service-binding bootstrap. |
| [RFC 7929](https://www.rfc-editor.org/rfc/rfc7929) | DNS-based authentication of named entities (DANE) bindings for OpenPGP | OPENPGPKEY RR parsing for the browser’s mail functionality, outside this resolution algorithm. `src/dns-query.js`. |

## Special-use and reserved names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-use domain names | Special-use treatment for localhost and its subtree, invalid, test, and example. `src/reserved-names.cjs`. |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | The `.local` multicast-DNS namespace. Excluded from Handshake classification. `src/reserved-names.cjs`. |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The `.onion` special-use domain name | Onion addresses remain in the Tor namespace, including malformed inputs. `src/classify-host.cjs`. |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-use domain `home.arpa.` | The `home.arpa` special-use domain. It does not reserve `.home` or the other local-network conventions in this client’s list. |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) | IPv4 address blocks reserved for documentation | Documentation IPv4 ranges used by test fixtures. |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-purpose IP address registries | Special-purpose address registries consulted when defining the Handshake address guard. `src/safe-address.js`. |

## Internationalized names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | Internationalized domain names for applications (IDNA): definitions and document framework | A-label and U-label terminology for internationalized domain names. |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | Internationalized domain names in applications (IDNA): protocol | IDNA2008 registration/lookup rules. The implementation instead uses WHATWG UTS #46; compatibility differences remain under review. |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA compatibility processing | Compatibility processing required by the WHATWG host parser. Used for A-label conversion before ICANN classification. |

## Handshake

| Identifier | Title | Used for |
|---|---|---|
| [hsd](https://github.com/handshake-org/hsd) and [hsd-dev.org](https://hsd-dev.org/) | Handshake protocol implementation and documentation | SPV headers, resource proofs, and process configuration. `src/spv.js`, `src/hsd-spv-launcher.cjs`. |
| [Handshake resource format](https://hsd-dev.org/api-docs/) | The on-chain `Resource` | On-chain Resource records: NS, glue, synthetic addresses, DS, and TXT. `src/resolver.js`. |
| [Urkel tree](https://github.com/handshake-org/urkel) | The authenticated data structure | Authenticated tree used for Handshake name inclusion/exclusion proofs, via hsd. |
| [HIP-0005](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) | Pseudo-TLD delegation to alternative naming systems | Pseudo-TLD delegation. `_op` is specified in experimental Chapter 10; other pseudo-TLDs are excluded from ordinary nameserver queries. |

## URL and browser integration

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Standard | URL syntax, host parsing, origins, and numeric-host handling. Electron’s custom `standard` flag is an implementation extension, not membership in WHATWG’s fixed special-scheme list. |
| [Electron `protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron protocol API | Electron custom-scheme declarations and privileges before startup. `standard`, `secure`, and service-worker permissions are separate flags. |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and registration procedures for URI schemes | URI-scheme registration procedures, including provisional registration proposed for `hns` (RT-D4, HS-D2). |

## Implementation and interoperability references

| Identifier | Title | Used for |
|---|---|---|
| [DNSLink](https://dnslink.dev/) | The `_dnslink.<name> TXT dnslink=/ipfs/<cid>` convention | The `_dnslink.<name>` TXT pointer convention. Supported namespaces are `/ipfs/` and `/ipns/`; Handshake SPEC §10.1 defines merging and conflict handling. `src/pointers.js`. |
| [IANA root zone database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | Delegated top-level domains | The delegated-TLD list used for classification. The bundled snapshot contains 1,438 labels, version 2026090500. `src/icann-tlds.cjs`. |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | Namespace precedence (§9.10), adopted from GNS as the router’s no-cross-namespace-fallback rule L2. |
| [`../../SPEC.md` §4.2](../../SPEC.md) | The Fast / Private switch | Shared Fast/Private policy and trust model. `src/delivery-mode.js` and its tests define policy; browser composition applies it. |
