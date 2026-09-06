# Chapter 1 — Handshake: references

Every standard this chapter's implementation actually reads, with what it is
used for and where. Nothing is listed that the code does not touch: a padded
bibliography is worse than none, because it makes the real dependencies
impossible to see. Where a row says *parsed, not queried* or *not implemented*,
that is the row's point.

Module paths are relative to this file: `../../src/` is this chapter's
reference implementation.

## DNS: messages, terminology, transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) | Domain names — concepts and facilities | §6.5c, the rule that tells a **referral** from a **NODATA** (§4.3.2: NS in AUTHORITY with no SOA is a referral), which is what makes the registry-TLD walk possible; §6.5f, §3.6.2 — a CNAME stands alone, so a validated CNAME needs no separate NSEC proving the `A` absent. §HS-15 cites it for the NS set. `../../src/resolver.js` (`referralIn`, the CNAME branch of `_fromZone`) |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain names — implementation and specification | The wire format used throughout §6: header, question, name compression, RR encoding. **§3.3.14** is the TXT rule of §10: a record's `<character-string>`s are **one** value, concatenated, and separate records are separate values — applied identically to the pointer TXT at the name, to the DNSLink TXT at `_dnslink.<name>` (§10.1), on the DoH route and on the `_op` route, so one record cannot mean different things on different paths. It is also why a pointer over 255 bytes is read at all. `../../src/dns-query.js`, `../../src/pointers.js` (`txtStringsFrom`) |
| [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) | Clarifications to the DNS specification | §5.2 TTL rules, cited by the caching deviation of §6.8. `../../src/resolver.js` — see HS-1 |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | DNS case insensitivity clarification | Owner names are compared case-insensitively and trailing-dot-stripped wherever a comparison happens, including the question-section check of §6.10. `../../src/resolver.js`, `../../src/dns-query.js`, `../../src/nsec.js`, `../../src/dnssec.js` |
| [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891) | Extension mechanisms for DNS (EDNS(0)) | The OPT pseudo-record of §6.5, emitted solely to carry the DO bit. **Partial**: not read back, no large-UDP advertisement (UDP is never used), no extended RCODEs. `../../src/dns-query.js` — see HS-11 |
| [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) | DNS transport over TCP | Queries in §6 go over **TCP always**, which is why the truncation (TC) rule is moot here by construction rather than unhandled. `../../src/dns-query.js` |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS protocol version 5 | §6.11: the `dial` seam. A CONNECT request (`no authentication` method only) to a device-local SOCKS port carries the authoritative TCP query of §6.5 while an anonymizing proxy is on, so the chain proof and the DNSSEC validation are kept rather than traded away. A dotted quad goes out as ATYP `0x01`; anything else as ATYP `0x03`, a domain name, resolved by the proxy and never locally. Which proxy, and what it is worth, is Chapter 8. `../../src/socks-dial.js`, `../../src/dns-query.js` (`query`'s `dial` option) |
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS terminology | The vocabulary of §2: *authoritative server*, *zone cut*, *delegation*, *referral*, *NODATA*, *validating resolver*, *insecure delegation*, *bailiwick*. §2 |
| [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596) | DNS extensions to support IPv6 (AAAA) | **Not implemented.** Listed because its absence is a documented gap: §6.5f reads only `A`. HS-2 |
| [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) | Extended DNS Errors | **Not implemented.** Would improve the failure reporting of §6.9 and §11.1. HS-11 |
| [draft-ietf-dnsop-deleg](https://datatracker.ietf.org/doc/draft-ietf-dnsop-deleg/) | Extensible delegation for DNS | **Watched, not implemented**; the RR type is not allocated at IANA, so nothing can interoperate. HS-11 |

## DNSSEC

| Identifier | Title | Used for |
|---|---|---|
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS security introduction and requirements | The security-state vocabulary (*Secure*, *Insecure*, *Bogus*, *Indeterminate*) that §2 maps the trust states onto, and the fail-closed requirement of §11.1. §2 |
| [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) | Resource records for the DNS security extensions | §6.7: DNSKEY (§2), RRSIG (§3) including the **Labels** rule of §3.1.3, DS (§5), NSEC (§4), canonical RR form (§6.2) and canonical NAME ordering (§6.1); §2.1.1 is the Zone Key flag; §3.1.5 the validity window (HS-10). `../../src/dnssec.js`, `../../src/nsec.js` |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) | Protocol modifications for the DNS security extensions | The validator's whole job in §6.5–§6.7: §5.2 DS→DNSKEY authentication including that a missing DS must be proven missing, §5.3 RRSIG validation, §5.3.1 CNAME handling (HS-9), §5.3.2 wildcard signature reconstruction, §5.3.4 the wildcard-answer proof, §5.4 authenticated denial, §5.5 "unvalidatable ⇒ Bogus", §3.1.3.4 wildcard NODATA. `../../src/dnssec.js`, `../../src/denial.js`, `../../src/resolver.js` |
| [RFC 4592](https://www.rfc-editor.org/rfc/rfc4592) | The role of wildcards in the DNS | §6.7: §3.3.1 source of synthesis, `*.<closest encloser>` — the name both wildcard proofs are built around. `../../src/nsec.js`, `../../src/nsec3.js` |
| [RFC 5011](https://www.rfc-editor.org/rfc/rfc5011) | Automated updates of DNSSEC trust anchors | §6.7, §2.1 only: the **REVOKE** bit; a revoked key anchors nothing. Anchor rollover is structurally inapplicable (HS-11). `../../src/dnssec.js` |
| [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155) | DNSSEC hashed authenticated denial of existence (NSEC3) | §6.7: hashing (§5), the closest-encloser proof (§8.3), NXDOMAIN (§8.4), NODATA (§8.5) and its wildcard form (§8.7), and §8.9 — Opt-Out proves an insecure delegation and nothing else (§6.6). `../../src/nsec3.js`, `../../src/denial.js` |
| [RFC 9276](https://www.rfc-editor.org/rfc/rfc9276) | Guidance for NSEC3 parameter settings | §6.7: iterations are the validator's cost to bear, so a hostile zone must not impose an unbounded one; capped at 100. `../../src/nsec3.js` |
| [RFC 8624](https://www.rfc-editor.org/rfc/rfc8624) | Algorithm implementation requirements for DNSSEC | §6.7: §3.1 signing algorithms and §3.3 DS digest algorithms, and which are MUST / RECOMMENDED / MUST NOT for a **validator** — the list supported and the list refused. `../../src/dnssec.js` |
| [RFC 3110](https://www.rfc-editor.org/rfc/rfc3110) | RSA/SHA-1 SIGs and RSA keys in the DNS | §6.7, §2 only: the **RSA public key wire format** reused by RSASHA256. The SHA-1 signature scheme itself is refused. `../../src/dnssec.js` |
| [RFC 5702](https://www.rfc-editor.org/rfc/rfc5702) | Use of SHA-2 algorithms with RSA in DNSKEY and RRSIG | §6.7: algorithm 8, RSASHA256, over the RFC 3110 key format. `../../src/dnssec.js` |
| [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605) | Elliptic curve digital signature algorithm (DSA) for DNSSEC | §6.7: §4 algorithms 13 (P-256/SHA-256) and 14 (P-384/SHA-384) — key X‖Y uncompressed, signature R‖S fixed-width — and §5 DS digest type 4 (SHA-384). `../../src/dnssec.js` |
| [RFC 8080](https://www.rfc-editor.org/rfc/rfc8080) | Edwards-curve DSA for DNSSEC | §6.7: algorithm 15, the 32-byte Ed25519 public key as-is. Algorithm 16 (Ed448) is refused. `../../src/dnssec.js` |
| [RFC 4509](https://www.rfc-editor.org/rfc/rfc4509) | Use of SHA-256 in DNSSEC delegation signer (DS) resource records | §6.7: DS digest type 2. `../../src/dnssec.js` |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32 and Base64 data encodings | §7 base32hex, uppercase and unpadded, is the NSEC3 hashed-owner encoding (§6.7); §5 base64url is the DoH GET parameter (§9.1) and the Arweave transaction id form (§10). `../../src/nsec3.js`, `../../src/doh.js`, `../../src/pointers.js` |

## TLS and certificates

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | The DNS-based authentication of named entities (DANE) transport layer security protocol: TLSA | §8: the TLSA record and its four parameters. One profile is implemented — usage 3 (DANE-EE), selector 1 (SPKI), matching type 1 (SHA-256). §3 gives the owner-name form `_<port>._tcp.<host>`; `_443._tcp` is always used (HS-6). `../../src/dane.js`, `../../src/resolver.js` |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | The DANE protocol: updates and operational guidance | §8: §4.1 unusable TLSA records (deviation, HS-5), §5.1 DANE-EE ignores PKIX expiry (followed deliberately), §7.2 the TLSA base domain across a CNAME, §8.1 operator key rotation and what a client does on a mismatch (HS-12). `../../src/dane.js`, `../../src/resolver.js` |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | Internet X.509 public key infrastructure certificate and CRL profile | §8, only to **parse** a certificate and extract its SubjectPublicKeyInfo for hashing. No chain is built and no CA is consulted on the `hns://` path — that is the point of DANE-EE. `../../src/dane.js` (Node `X509Certificate`) |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The transport layer security (TLS) protocol version 1.3 | §8: the transport an `hns://` fetch runs over, terminated by Node's TLS stack; the peer certificate it yields is what the pin is checked against. The composition layer (DEVIATIONS §4), not `../../src/` |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP semantics | §8: the application protocol carried over that connection, and the semantics of the status codes the resolution layer reports. The composition layer |

## Encrypted DNS transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS queries over HTTPS (DoH) | §9.1: wire-format DoH, GET with `?dns=<base64url>` and `application/dns-message`; §4.1 is why the message id is fixed at zero and the question section is the only binding (§6.10). Several Handshake DoH servers reject POST, which is why GET is used. `../../src/doh.js` |
| [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230) | Oblivious DNS over HTTPS | §9.2: §6 the message format and HPKE parameters, §6.3 the response AEAD key derivation from the HPKE exporter secret plus a target-chosen nonce, and the ODoH configuration record. `../../src/odoh.js`, `../../src/odoh-bridge.js` |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) | Hybrid public key encryption | §9.2: the construction ODoH is built on — X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM, over WebCrypto. `../../src/odoh.js` |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based extract-and-expand key derivation function (HKDF) | §9.2: §2.2/§2.3 extract-and-expand over WebCrypto HMAC-SHA256, for the ODoH response key and nonce. `../../src/odoh.js` |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) | Discovery of designated resolvers | **Not implemented**; an available upgrade not taken. HS-11 |

## Service binding, ECH, and records read but not queried

| Identifier | Title | Used for |
|---|---|---|
| [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) | Service binding and parameter specification via the DNS (SVCB and HTTPS RRs) | §2.2 the RDATA format. A complete parser exists — SvcPriority, TargetName, `alpn`, `port`, `ipv4hint`, and the `ech` SvcParam — tested against real Cloudflare rdata. **Type 65 is never queried during resolution.** `../../src/dns-query.js`, `../../tests/svcb.test.js` — HS-3 |
| [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) | TLS encrypted client hello | The reason the SVCB parser exists; blocked on the record not being queried *and* on Node exposing no ECH option. HS-3, §11.6 |
| [RFC 7929](https://www.rfc-editor.org/rfc/rfc7929) | DNS-based authentication of named entities (DANE) bindings for OpenPGP | RR type 61 is parsed (§2.3: the whole RDATA is the transferable public key). Used by the browser's mail client, not by resolution; it lives in the DNS client because that is the only one in the tree. `../../src/dns-query.js` |

## Special-use and reserved names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-use domain names | §3: `localhost` (the whole subtree), `invalid`, `test`, `example` are never Handshake names. `../../src/reserved-names.cjs`, consulted by `../../src/router.js` |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | §3: `local` is mDNS. Without this carve-out every NAS and printer name on a home network would be sent to whoever registers the Handshake TLD `local`. `../../src/reserved-names.cjs` |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The `.onion` special-use domain name | §3: `onion` is Tor's, never Handshake's, on every path. `../../src/reserved-names.cjs`, `../../src/router.js` (the Tor test runs first) |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-use domain `home.arpa.` | §3: together with `arpa`, `internal`, `home`, `lan`, `corp`, `intranet`, `private` — the labels home routers and corporate networks actually use. `../../src/reserved-names.cjs` |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) | IPv4 address blocks reserved for documentation | §11.2: the documentation addresses (`203.0.113.0/24`) used throughout the test fixtures. `../../tests/fixtures/resolver/` |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-purpose IP address registries | §11.2: the registry the SSRF guard rejects — loopback, private, link-local (including `169.254.169.254`), CGNAT, benchmarking, multicast, reserved, and the IPv6 equivalents. `../../src/safe-address.js` |

## Internationalized names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | Internationalized domain names for applications (IDNA): definitions and document framework | §3: a Unicode host is converted to A-labels before it reaches the resolver or the ICANN comparison, so a name is compared in one canonical form. `../../src/router.js` — see HS-14 |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | Internationalized domain names in applications (IDNA): protocol | §3: what IDNA2008 requires, and what is therefore *not* what this implementation performs. HS-14 |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA compatibility processing | §3: what the WHATWG URL Standard actually requires, and therefore what the conversion actually is. `../../src/router.js` — HS-14 |

## Handshake

| Identifier | Title | Used for |
|---|---|---|
| [hsd](https://github.com/handshake-org/hsd) and [hsd-dev.org](https://hsd-dev.org/) | Handshake protocol implementation and documentation | §6.1, §6.11, §11.5: the SPV node — header sync, `getnameresource`, and the Urkel tree proof verified against the committed tree root in a verified header; `--proxy` is how the node's own peer traffic is put through a SOCKS proxy, and `--memory` the backend used where no native LevelDB build is available, which is what makes the restart of HS-16 a full re-sync. hsd is an optional runtime dependency, spawned as a child process. `../../src/spv.js`, `../../src/hsd-spv-launcher.cjs` |
| [Handshake resource format](https://hsd-dev.org/api-docs/) | The on-chain `Resource` | §2, §6.1–§6.4: what a name's chain record can carry — `NS`, `GLUE4`/`GLUE6`, `SYNTH4`/`SYNTH6`, `DS`, `TXT`. The `DS` is the anchor this design substitutes for the ICANN root. `../../src/resolver.js` |
| [Urkel tree](https://github.com/handshake-org/urkel) | The authenticated data structure | §11.5: what the name proof is against. Via hsd |
| [HIP-0005](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) | Pseudo-TLD delegation to alternative naming systems | §6.3: why an `NS` target under a `_<chain>` pseudo-TLD is not a host and is removed from the nameserver list. The `_op` route itself is Chapter 10; `_eth` is not implemented (HS-13). `../../src/resolver.js` |

## URL and browser integration

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Standard | §5: a *standard* (special) scheme's host is parsed by the host parser, which is what makes `hns://` a real web origin and also what constrains the host form. The numeric-label consequence is Chapter 10, Part B. `../../src/router.js` |
| [Electron `protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron protocol API | §5: registering `hns:` as a **standard**, **secure** scheme is what buys origins, `fetch`, service workers and secure-context features — and is the same decision that subjects the host to the URL Standard's parsing. The browser's `main.cjs`, not in this tree |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and registration procedures for URI schemes | §3.8, the provisional registration `hns:` does not yet have. HS-D2 |

## Not standards, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [DNSLink](https://dnslink.dev/) | The `_dnslink.<name> TXT dnslink=/ipfs/<cid>` convention | §10.1: the **second pointer source**, and the reason a site published for kubo, IPFS Companion or Brave opens here unchanged. Defines the `_dnslink.` owner prefix, the `dnslink=/<namespace>/<address>[/path]` value grammar and the one-value-per-name rule this implementation reads it by; only `/ipfs/` and `/ipns/` are pointers here. Read on both routes, under the same DNSSEC and proven-absence rules as the pointer at the name (§6.5d–e), and written at publish beside `ipfs=`. `../../src/pointers.js` (`parseDnslink`, `dnslinkPointerFrom`, `mergePointers`, `dnslinkValue`, `dnslinkOwner`), `../../src/resolver.js` (`_fromZone`), `../../src/doh.js` |
| [IANA root zone database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | Delegated top-level domains | §3: the ICANN snapshot that decides ICANN-vs-Handshake for every name, checked against the live list by a network test in the browser tree. `../../src/icann-tlds.cjs` |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | §3, §9.10: namespace precedence — resolve in the alternative namespace when its suffix matches, and do not continue into DNS on failure. Adopted as a normative rule because it is the only place this is written down in an RFC. `../../src/router.js` |
