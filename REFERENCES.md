# References

Every standard this implementation actually reads, with what it is used for and
where in the tree it is used. Nothing is listed here that the code does not
touch: a padded bibliography is worse than none, because it makes the real
dependencies impossible to see.

Where a row says *parsed, not queried* or *watched*, that is stated in the row —
it is in the list because the code contains a reader for it, not because the
resolution algorithm depends on it.

---

## 1. DNS: messages, terminology, transport

| Reference | Used for | Where |
|---|---|---|
| [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) — Domain names, concepts and facilities | §4.3.2 is the rule that tells a **referral** from a **NODATA**: NS records in AUTHORITY with no SOA is a referral and is followed; an SOA present means the name exists and has no record of that type. This is what makes the registry-TLD walk possible. §3.6.2 — a CNAME stands alone, so a name that owns one owns no other data — is why a *validated* CNAME needs no separate NSEC proving the `A` absent (SPEC §6.5f). | `src/resolver.js` (`referralIn`, the CNAME branch of `_fromZone`) |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) — Domain names, implementation and specification | The wire format: header, question, name compression, RR encoding. §3.3.14 is the TXT rule — a record's `<character-string>`s are **one** value, concatenated; separate records are separate values. | `src/dns-query.js`, `src/pointers.js` (`txtStringsFrom`), `src/hip5-op.js` |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) §2.1 | Host label syntax; the reason a Handshake label can never contain `_`, which is what makes the numeric-TLD marker in §5 of the spec unambiguous. | `src/hns-url.cjs` |
| [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) — Clarifications to the DNS specification | §5.2 TTL rules. **We deviate** (flat 60 s positive cache); listed so the deviation has a citation. | `src/resolver.js` — see DEVIATIONS.md D-1 |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) — DNS case insensitivity clarification | Owner names are compared case-insensitively and trailing-dot-stripped everywhere a comparison happens. | `src/resolver.js`, `src/nsec.js`, `src/dnssec.js` |
| [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891) — EDNS(0) | The OPT pseudo-record, emitted solely to carry the DO bit. **Partial**: not read back, no large-UDP advertisement (we never use UDP), no extended RCODEs. | `src/dns-query.js` |
| [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) — DNS transport over TCP | Queries go over **TCP always**. This is why the truncation (TC) rule is moot here by construction rather than unhandled. | `src/dns-query.js` |
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) — DNS terminology | The vocabulary SPEC.md uses: *authoritative server*, *zone cut*, *delegation*, *referral*, *NODATA*, *validating resolver*, *insecure delegation*, *bailiwick*. | SPEC.md §2 |
| [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596) — AAAA | **Not implemented.** Listed because its absence is a documented gap, not an oversight. | DEVIATIONS.md D-2 |

## 2. DNSSEC

| Reference | Used for | Where |
|---|---|---|
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) — DNSSEC introduction and requirements | The security-state vocabulary (*Secure*, *Insecure*, *Bogus*, *Indeterminate*) that SPEC.md's trust states map onto, and the fail-closed requirement. | SPEC.md §4 |
| [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) — DNSSEC resource records | DNSKEY (§2), RRSIG (§3) including the **Labels** field rule of §3.1.3, DS (§5), NSEC (§4); canonical RR form (§6.2) and canonical NAME ordering (§6.1). §2.1.1 is the Zone Key flag. | `src/dnssec.js`, `src/nsec.js` |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) — DNSSEC protocol modifications | The validator's whole job: §5.2 DS→DNSKEY authentication (including that a **missing DS must be proven missing**), §5.3 RRSIG validation, §5.3.1 CNAME handling, §5.3.2 wildcard signature reconstruction, §5.3.4 the wildcard-answer proof, §5.4 authenticated denial with NSEC, §5.5 "unvalidatable ⇒ Bogus", §3.1.3.4 wildcard NODATA. | `src/dnssec.js`, `src/denial.js`, `src/resolver.js` |
| [RFC 4592](https://www.rfc-editor.org/rfc/rfc4592) — The role of wildcards in DNS | §3.3.1 source of synthesis, `*.<closest encloser>` — the name both wildcard proofs are built around. | `src/nsec.js`, `src/nsec3.js` |
| [RFC 5011](https://www.rfc-editor.org/rfc/rfc5011) — Automated updates of DNSSEC trust anchors | §2.1 only: the **REVOKE** bit. A revoked key anchors nothing and verifies nothing. We do **not** implement RFC 5011 anchor rollover — the anchor is the on-chain DS, which changes by a chain transaction, not by a timer. | `src/dnssec.js` |
| [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155) — DNSSEC hashed authenticated denial (NSEC3) | Hashing (§5), the closest-encloser proof (§8.3), NXDOMAIN (§8.4), NODATA (§8.5) and its wildcard form (§8.7), and §8.9 — **Opt-Out proves an insecure delegation and nothing else** (§6 for the general refusal). | `src/nsec3.js`, `src/denial.js` |
| [RFC 9276](https://www.rfc-editor.org/rfc/rfc9276) — NSEC3 parameter guidance | §3.1: iterations are the validator's cost to bear, so a hostile zone must not be able to impose an unbounded one. Capped at 100. | `src/nsec3.js` |
| [RFC 8624](https://www.rfc-editor.org/rfc/rfc8624) — Algorithm implementation requirements | §3.1 signing algorithms and §3.3 DS digest algorithms, and which are MUST / RECOMMENDED / MUST NOT for a **validator**. This is the list the implementation supports and the list it refuses. | `src/dnssec.js` |
| [RFC 3110](https://www.rfc-editor.org/rfc/rfc3110) — RSA/SHA-1 SIGs and RSA keys in the DNS | §2 only: the **RSA public key wire format** (exponent length, exponent, modulus) reused by RSASHA256. The SHA-1 signature scheme itself is refused. | `src/dnssec.js` |
| [RFC 5702](https://www.rfc-editor.org/rfc/rfc5702) — RSA/SHA-2 in DNSSEC | Algorithm 8, RSASHA256 — the signature scheme over the RFC 3110 key format. | `src/dnssec.js` |
| [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605) — ECDSA for DNSSEC | §4: algorithms 13 (P-256/SHA-256) and 14 (P-384/SHA-384); the key is X‖Y uncompressed, the signature is R‖S fixed-width. | `src/dnssec.js` |
| [RFC 8080](https://www.rfc-editor.org/rfc/rfc8080) — Ed25519/Ed448 for DNSSEC | §3: algorithm 15, the 32-byte Ed25519 public key as-is. Algorithm 16 (Ed448) is refused. | `src/dnssec.js` |
| [RFC 4509](https://www.rfc-editor.org/rfc/rfc4509) — SHA-256 in DS records | DS digest type 2. | `src/dnssec.js` |
| [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605) §5 | DS digest type 4 (SHA-384). | `src/dnssec.js` |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) — Base16/32/64 encodings | §7 base32hex, uppercase and unpadded: the NSEC3 hashed-owner encoding. §5 base64url: the DoH GET parameter and Arweave transaction ids. | `src/nsec3.js`, `src/doh.js`, `src/pointers.js` |

## 3. TLS and certificates

| Reference | Used for | Where |
|---|---|---|
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) — DANE TLSA | The TLSA record and its four parameters. We implement **one** profile: usage 3 (DANE-EE), selector 1 (SPKI), matching type 1 (SHA-256). §3 gives the owner-name form `_<port>._tcp.<host>`; we always use `_443._tcp`. | `src/dane.js`, `src/resolver.js` |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) — DANE operational guidance | §4.1 unusable TLSA records (**we deviate**, see D-6), §5.1 DANE-EE ignores PKIX expiry (**we follow this deliberately**), §7 / §7.2 the TLSA base domain across a CNAME, §8.1 operator key rotation and what a client should do on a mismatch. | `src/dane.js`, `src/resolver.js` |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — X.509 / PKIX certificate profile | Only to **parse** a certificate and extract its SubjectPublicKeyInfo for hashing. No chain is built and no CA is consulted on the `hns://` path — that is the point of DANE-EE. | `src/dane.js` (Node `X509Certificate`) |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3 | The transport an `hns://` fetch runs over, terminated by Node's TLS stack. The peer certificate this yields is what the TLSA pin is checked against. | the browser's `hns://` handler (not in this package — see README "What is not here") |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) — HTTP semantics | The application protocol carried over that connection, and the semantics of the status codes the resolution layer reports. | as above |

## 4. Encrypted DNS transport

| Reference | Used for | Where |
|---|---|---|
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) — DNS Queries over HTTPS (DoH) | Wire-format DoH, GET with `?dns=<base64url>` and `application/dns-message`. Note: several Handshake DoH servers reject POST, which is why GET is used. | `src/doh.js` |
| [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230) — Oblivious DNS over HTTPS | §6 the message format and the HPKE parameters; §6.3 the response AEAD key derivation from the HPKE exporter secret plus a target-chosen nonce; the ODoH configuration record. | `src/odoh.js`, `src/odoh-bridge.js` |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) — Hybrid Public Key Encryption (HPKE) | The construction ODoH is built on: X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM, implemented over WebCrypto. | `src/odoh.js` |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF | §2.2/§2.3 extract-and-expand, over WebCrypto HMAC-SHA256, for the ODoH response key and nonce. | `src/odoh.js` |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) — Discovery of Designated Resolvers (DDR) | **Not implemented.** Listed because it is an available upgrade we have not taken, not a gap we are unaware of. | DEVIATIONS.md D-13 |

## 5. Service binding, ECH and the records we can read but do not use

| Reference | Used for | Where |
|---|---|---|
| [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) — SVCB and HTTPS RRs (type 65) | §2.2 the RDATA format. A **complete parser** exists — SvcPriority, TargetName, `alpn`, `port`, `ipv4hint`, and the `ech` SvcParam carrying an ECHConfigList — tested against real Cloudflare rdata. **Type 65 is never queried during resolution.** | `src/dns-query.js`, `tests/svcb.test.js` — see D-3 |
| [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) — TLS Encrypted Client Hello | The reason the SVCB parser exists: ECH requires the client to fetch the ECHConfigList from the HTTPS RR. **Blocked** on the record not being queried *and* on Node exposing no ECH option at all. | D-3 |
| [RFC 7929](https://www.rfc-editor.org/rfc/rfc7929) — OPENPGPKEY | RR type 61 is parsed (§2.3: the whole RDATA is the transferable public key). Used by the browser's mail client, not by name resolution; it is in `dns-query.js` because that is the only DNS client in the tree. | `src/dns-query.js` |
| [draft-ietf-dnsop-deleg](https://datatracker.ietf.org/doc/draft-ietf-dnsop-deleg/) | **Watched, not implemented.** The RR type is not yet allocated at IANA, so nothing can interoperate yet. | D-13 |

## 6. Special-use and reserved names

| Reference | Used for | Where |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) — Special-use domain names | `localhost` (the whole subtree), `invalid`, `test`, `example` are never Handshake names. | `src/hns-host.js` |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) — Multicast DNS | `local` is mDNS. Without this carve-out, every NAS and printer name on a home network would be sent to whoever registers the Handshake TLD `local`. | `src/hns-host.js` |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) — The `.onion` special-use TLD | `onion` is Tor's, never Handshake's. | `src/hns-host.js` |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) — `home.arpa` | Together with `arpa`, `internal`, `home`, `lan`, `corp`, `intranet`, `private` — the labels home routers and corporate networks actually use. | `src/hns-host.js` |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) / [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | The special-purpose address registry the SSRF guard rejects: loopback, private, link-local (incl. `169.254.169.254`), CGNAT, benchmarking, multicast, reserved. Documentation addresses (`203.0.113.0/24`) are used throughout the test fixtures. | `src/safe-address.js`, `tests/fixtures/resolver/` |

## 7. Internationalized names

| Reference | Used for | Where |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) / [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) — IDNA2008 | A Unicode host is converted to A-labels **before** it reaches the resolver, so a name is compared against the chain and against the ICANN list in one canonical form. In practice the conversion is done by the WHATWG URL host parser (which specifies UTS-46, not strict IDNA2008 — see D-11), not by an IDNA implementation of our own. | `src/router.js` |
| [UTS #46](https://www.unicode.org/reports/tr46/) — Unicode IDNA Compatibility Processing | What the URL Standard actually requires, and therefore what we actually get. | as above |

## 8. Handshake

| Reference | Used for | Where |
|---|---|---|
| [Handshake protocol documentation](https://hsd-dev.org/) and [hsd](https://github.com/handshake-org/hsd) | The SPV node: header sync, `getnameresource`, and the Urkel tree proof verified against the committed tree root in a verified header. hsd is an optional runtime dependency, spawned as a child process. | `src/spv.js`, `src/hsd-spv-launcher.cjs` |
| [Handshake resource format](https://hsd-dev.org/api-docs/) — the on-chain `Resource` | What a name's chain record can carry: `NS`, `GLUE4`/`GLUE6`, `SYNTH4`/`SYNTH6`, `DS`, `TXT`. The `DS` is the DNSSEC anchor this whole design substitutes for the ICANN root. | `src/resolver.js` |
| [HIP-0005](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) — Pseudo-TLD delegation to alternative naming systems | The mechanism `_op` implements: an NS target under a `_<chain>` pseudo-TLD is not a host, it is a pointer into another naming system. **Status: permanent Draft.** The HIP process is not active; this is prior art with a number, not a ratified standard. | `src/hip5-op.js`, SPEC.md §7 |
| [Urkel tree](https://github.com/handshake-org/urkel) | The authenticated data structure the name proof is against. | via hsd |

## 9. Ethereum / Optimism (the HIP-5 `_op` route)

| Reference | Used for | Where |
|---|---|---|
| [EIP-137](https://eips.ethereum.org/EIPS/eip-137) — Ethereum Domain Name Service | `namehash`, and the registry interface `resolver(bytes32) returns (address)` (selector `0x0178b8bf`). Checked against the EIP's own published vectors. | `src/hip5-op.js` |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) / [ENSIP-7](https://docs.ens.domains/ensip/7) — contenthash | The multicodec-prefixed content pointer: `ipfs-ns` 0xe3, `ipns-ns` 0xe5, `swarm-ns` 0xe4, `arweave-ns` 0xb29910. | `src/contenthash.js` |
| [ENS DNSResolver interface](https://docs.ens.domains/resolvers/interfaces) | `hasDNSRecords(bytes32,bytes32)` (`0x4cbf6ba4`) and `dnsRecord(bytes32,bytes32,uint16)` (`0xa8fa5682`), where the second argument is `keccak256` of the lowercased, root-terminated, RFC 1035 wire-format owner name, and the returned bytes are wire-format RRsets. | `src/hip5-op.js` |
| [ENSIP-10](https://docs.ens.domains/ensip/10) — Wildcard resolution | Cited for what we **do not** do on the `_op` route: a sub-name whose own namehash has no resolver is not walked up to its parent's resolver. | D-8 |
| [Multiformats: multicodec / unsigned-varint / CID](https://github.com/multiformats/multicodec) | Reading a contenthash value. | `src/contenthash.js` |
| [Optimism JSON-RPC](https://docs.optimism.io/) — `eth_call`, chainId 10 | Hand-rolled `eth_call` over `fetch` (a 4-byte selector plus 32-byte words). No client library: this runs on every navigation. | `src/hip5-op.js` |

## 10. URL and browser-integration constraints

| Reference | Used for | Where |
|---|---|---|
| [WHATWG URL Standard](https://url.spec.whatwg.org/) — [§3.5 host parsing](https://url.spec.whatwg.org/#host-parsing), the ["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker), and the [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) | **The reason for the numeric-TLD convention.** A *special* or *standard* scheme's host is run through the host parser; if the ASCII domain "ends in a number" — its last label is non-empty and contains only ASCII digits — the host is parsed as an **IPv4 address**. So `hns://14898/` becomes `hns://0.0.58.50/`, and `hns://hello.14898/` is simply an invalid URL. The label is not reachable as written. | `src/hns-url.cjs`, SPEC.md §5, D-4 |
| [WHATWG URL Standard — forbidden host code points](https://url.spec.whatwg.org/#forbidden-host-code-point) | Why `_` is a usable marker: it is not a forbidden host code point, so `hello._14898` parses as an opaque-domain label in every browser (`_dmarc.example.com` is the everyday proof). | `src/hns-url.cjs` |
| [Electron `protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Registering `hns:` as a **standard** scheme is what buys origins, `fetch`, service workers and secure-context features — and is also what subjects the host to the URL Standard's parsing above. The two are the same decision. | the browser's `main.cjs` (not in this package) |
| [Chromium URL / scheme registry](https://chromium.googlesource.com/chromium/src/+/main/url/) | The implementation of the above. A registered standard scheme cannot opt out of IPv4 host parsing. | — |

## 10a. Not a standard, but load-bearing

| Reference | Used for |
|---|---|
| [DNSLink](https://dnslink.dev/) | The `_dnslink.<name> TXT dnslink=/ipfs/<cid>` convention used by kubo, Brave and the IPFS gateways. We **write** it and do **not read** it (D-5). |
| [IANA root zone database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | The ICANN TLD snapshot in `src/icann-tlds.cjs`, which decides ICANN-vs-Handshake for every name. Checked against the live list by a network test in the Wildroot tree. |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) — The GNU Name System | §9.10, namespace precedence: resolve in the alternative namespace first when its suffix matches, and do not continue into DNS on failure. Adopted as a normative rule here (SPEC.md §3) because it is the only place this rule is written down in an RFC. |
