# Chapter 2 — ICANN names: references

Standards and implementation references used by this chapter. Each row states
its role; unsupported features are labelled explicitly. Paths below are relative
to the repository root unless a browser-only path is identified.

See [DEVIATIONS.md](DEVIATIONS.md) for limitations and
[REVIEW.md](../../REVIEW.md) for unresolved claims.

## The registry, and how it is vendored

| Identifier | Title | Used for |
|---|---|---|
| [`https://www.iana.org/domains/root/db`](https://www.iana.org/domains/root/db), machine-readable at [`https://data.iana.org/TLD/tlds-alpha-by-domain.txt`](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | IANA Root Zone Database | The delegated-TLD list used for classification. The bundled snapshot contains 1,438 labels, version 2026090500. `src/icann-tlds.cjs`. |
| ICANN New gTLD Program, next round (the programme's pages move; no stable URL is cited) | ICANN New gTLD Program | Future delegations make snapshot freshness relevant. The original application count had no cited source and is not used as evidence here. |

## Names that belong to neither root

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | Special-use treatment for localhost and its subtree, invalid, test, and example. `src/reserved-names.cjs`. |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | The `.local` multicast-DNS namespace. Excluded from Handshake classification. `src/reserved-names.cjs`. |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The `.onion` Special-Use Domain Name | Onion addresses remain in the Tor namespace, including malformed inputs. `src/classify-host.cjs`. |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-Use Domain `home.arpa.` | The `home.arpa` special-use domain. It does not reserve `.home` or the other local-network conventions in this client’s list. |

## DNS vocabulary, comparison and messages

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS Terminology (obsoleted by [RFC 9499](https://www.rfc-editor.org/rfc/rfc9499)) | DNS terminology used across these chapters. Superseded by RFC 9499; retained here for consistency with existing references. |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | DNS Case Insensitivity Clarification | Case-insensitive DNS owner comparison, including matching responses to questions. `src/classify-host.cjs`, `src/dns-query.js`. |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) §2.1 | Requirements for Internet Hosts — Application and Support | Host label syntax and snapshot-entry validation. The numeric-TLD convention is a separate local extension. |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) §4.1 | Domain Names — Implementation and Specification | DNS message and RR encoding. §3.3.14 permits one or more character-strings in a TXT RR; joining them is the pointer convention used by this implementation. `src/dns-query.js`, `src/pointers.js`. |

## Internationalized names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | IDNA: Definitions and Document Framework | A-label and U-label terminology for internationalized domain names. |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | IDNA: Protocol | IDNA2008 registration/lookup rules. The implementation instead uses WHATWG UTS #46; compatibility differences remain under review. |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | Compatibility processing required by the WHATWG host parser. Used for A-label conversion before ICANN classification. |

## URL parsing — the classifier's input

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL Standard §host parsing](https://url.spec.whatwg.org/#host-parsing) | URL Standard | URL syntax, host parsing, origins, and numeric-host handling. Electron’s custom `standard` flag is an implementation extension, not membership in WHATWG’s fixed special-scheme list. |
| [WHATWG URL Standard — ends-in-a-number checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) | URL Standard, IPv4 parsing | URL syntax, host parsing, origins, and numeric-host handling. Electron’s custom `standard` flag is an implementation extension, not membership in WHATWG’s fixed special-scheme list. |

## Encrypted DNS transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS Queries over HTTPS (DoH) | Wire-format DoH, HTTP templates, and media types. §4.1 recommends ID zero for cache compatibility; the client uses zero and separately matches the reply question. `src/doh.js`. |
| [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230) | Oblivious DNS over HTTPS | ODoH messages, configuration structures, and response key/nonce derivation (§6.3). `src/odoh.js`, `src/odoh-bridge.js`. |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) | Hybrid Public Key Encryption | HPKE construction used by ODoH: X25519-HKDF-SHA256, HKDF-SHA256, AES-128-GCM. `src/odoh.js`. |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | HKDF extract/expand used in ODoH key derivation. `src/odoh.js`. |
| [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) | Well-Known Uniform Resource Identifiers | Well-known URI registry framework. Verify the status of `odohconfigs` before assigning it a standards status (IC-8). |
| [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) | DNS over TLS (DoT) | DoT transport, which is not an accepted endpoint type for the engine API used here. |
| [RFC 8310](https://www.rfc-editor.org/rfc/rfc8310) | Usage Profiles for DNS over TLS and DTLS | Opportunistic and strict encrypted-DNS profiles, used as an analogy for `automatic` and `secure` policy. |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) | Discovery of Designated Resolvers | Discovery of Designated Resolvers. Not implemented; resolver templates are configured. |
| [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) | Service Binding and Parameter Specification via the DNS (SVCB and HTTPS RRs) | SVCB/HTTPS RDATA and service parameters. The shared parser supports them; the Handshake resolution algorithm does not query type 65. |
| [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) | Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings | Obtaining ECH configuration through DNS service bindings. Handshake does not currently query the required HTTPS record; engine HTTPS capabilities are separate. |
| [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849) | TLS Encrypted Client Hello | ECH protocol itself; RFC 9848 specifies its DNS service-binding bootstrap. |

## The loopback certificate

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | Internet X.509 PKI Certificate and CRL Profile | X.509 certificate structure. The DANE path extracts SPKI; the loopback bridge generates a certificate. Ordinary HTTPS uses the engine’s separate WebPKI validation. |
| [RFC 7469](https://www.rfc-editor.org/rfc/rfc7469) §2.4 | Public Key Pinning Extension for HTTP | SPKI pin construction: base64 of SHA-256 over SubjectPublicKeyInfo. This uses the hash format, not the HPKP deployment mechanism. |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The Transport Layer Security (TLS) Protocol Version 1.3 | TLS 1.3. The runtime provides the TLS implementation; this repository configures connections and applies DANE pins. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | HTTP semantics used by transport handlers and error responses. |

## Addresses and authentication — cited for what ICANN names do *not* get

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | Special-purpose address registries consulted when defining the Handshake address guard. `src/safe-address.js`. |
| [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) | Address Allocation for Private Internets | Private IPv4 ranges in `src/safe-address.js`. |
| [RFC 3927](https://www.rfc-editor.org/rfc/rfc3927) | Dynamic Configuration of IPv4 Link-Local Addresses | IPv4 link-local range in `src/safe-address.js`. |
| [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) | Unique Local IPv6 Unicast Addresses | IPv6 unique-local range in `src/safe-address.js`. |
| [RFC 6598](https://www.rfc-editor.org/rfc/rfc6598) | IANA-Reserved IPv4 Prefix for Shared Address Space | Shared-address CGNAT range in `src/safe-address.js`. |
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | DNS-Based Authentication of Named Entities (DANE) TLSA | TLSA records and port-derived owner names. Handshake supports the `3 1 1` profile; ICANN navigation does not use this DANE path. |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | DANE Protocol: Updates and Operational Guidance | Unusable TLSA records (§4.1), DANE-EE certificate checks (§5.1), CNAME base domains (§7.2), and key rotation (§8.1). See HS-5, HS-9, and HS-12. |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS Security Introduction and Requirements | DNSSEC security states and the distinction between secure, insecure, bogus, and indeterminate results. |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) | Protocol Modifications for the DNS Security Extensions | DS/DNSKEY anchoring, RRset validation, CNAME and wildcard processing, authenticated denial, and validation failure. `src/dnssec.js`, `src/denial.js`, `src/resolver.js`. |

## Requirement language

| Identifier | Title | Used for |
|---|---|---|
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Key words for use in RFCs to Indicate Requirement Levels | Requirement keywords. RFC 8174 defines their uppercase interpretation. |
| [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | Uppercase interpretation of normative requirement keywords. |

## Implementation and interoperability references

| Identifier | Title | Used for |
|---|---|---|
| [`app.configureHostResolver`](https://www.electronjs.org/docs/latest/api/app#appconfigurehostresolveroptions) | Electron API documentation | Engine DNS mode and DoH-template configuration. `src/dns-policy.js` computes the plan; browser composition applies and records it. |
| `--ignore-certificate-errors-spki-list` | Chromium command-line switch (documented in Chromium's own source; there is no specification) | The Chromium exception accepts the pinned key for any host. The bridge key is therefore generated per launch and kept in memory. |
| `odoh-relay.numa.rs`, `odoh-relay.edgecompute.app` | The deployed public ODoH relays | Relays named by the documented configuration. This list is not evidence of a worldwide relay count or operator independence. |
| [DNSCrypt public ODoH server list](https://github.com/DNSCrypt/dnscrypt-resolvers) | DNSCrypt resolver lists | Public resolver inventory relevant to target allowlisting. Current relay/target reachability requires a live check. |
| [`../../SPEC.md` §4.2](../../SPEC.md) | The Fast / Private switch | Shared Fast/Private policy and trust model. `src/delivery-mode.js` and its tests define policy; browser composition applies it. |
| [`../../namespaces/router/SPEC.md`](../router/SPEC.md) | The router chapter of this specification | Routing requirements L1/L2 and the response namespace marker. See REVIEW.md for the scope conflict between L1 and HTTP(S) rewrites. |
