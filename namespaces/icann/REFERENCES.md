# Chapter 2 — ICANN names: references

Every standard this chapter actually reads, with what it is used for and where
in the tree it is used. Nothing is listed that the code does not touch: a padded
bibliography is worse than none, because it makes the real dependencies
impossible to see.

Where a row says *not implemented* or *parsed, not queried*, that is stated in
the row — it is present because its absence is a recorded constraint, not
because the resolution depends on it.

Three path conventions are used. `../../src/…` is a module in this
repository's shared `src/`. A bare `src/dns-policy.js` or
`src/icann-tld-snapshot.js` is this chapter's own `namespaces/icann/src/`.
Every other `src/…` is in the Wildroot browser tree, which is not part of this
package; those are given with line numbers so a claim can be checked against
the code that makes it.

---

## The registry, and how it is vendored

| Identifier | Title | Used for |
|---|---|---|
| [`https://www.iana.org/domains/root/db`](https://www.iana.org/domains/root/db), machine-readable at [`https://data.iana.org/TLD/tlds-alpha-by-domain.txt`](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | IANA Root Zone Database | §2.1, §2.4 — the whole of the ICANN/Handshake boundary. Fetched at build time, parsed and rendered into a committed `Set` of A-labels carrying IANA's own `Version`/`Last Updated` line: `../../src/icann-tlds.cjs` (1,438 labels, version 2026090500), `src/icann-tld-snapshot.js`, `tests/icann-tld-snapshot.test.js`; the browser's `scripts/fetch-icann-tlds.mjs` and its drift alarm `tests/hns/icann-tlds-live.test.js`. |
| ICANN New gTLD Program, next round (the programme's pages move; no stable URL is cited) | ICANN New gTLD Program | §2.4, §9.1 — why the snapshot's staleness is a growing risk rather than a static one: roughly 1,600 applications in the 2026 round, each delegation converting a string that resolves as a Handshake name today into an ICANN TLD. `../../DEVIATIONS.md` IC-1. |

## Names that belong to neither root

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | §4 — `localhost` (§6.3: the **whole subtree**, so `app.localhost` too), `invalid`, `test` and `example` are never Handshake names, and none is in the IANA set. `../../src/reserved-names.cjs`, consulted at row 4 of `classifyHost` (`../../src/classify-host.cjs:87-116`). |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | §4 — `local` is mDNS's. Without the carve-out, every NAS, printer and Home Assistant name on a home network is sent to whoever registers the Handshake top-level name `local`. `../../src/reserved-names.cjs`. |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The `.onion` Special-Use Domain Name | §2.2 row 2 — `onion` is Tor's, never Handshake's and never ICANN's. Matched **before** the reserved list so a `.onion` host reaches the Tor namespace, and even a malformed one stays there: the query itself is the deanonymising event. `../../src/classify-host.cjs:87-116`. |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-Use Domain `home.arpa.` | §4 — together with `arpa`. The same list carries `internal`, `home`, `lan`, `corp`, `intranet` and `private`, which no RFC reserves and which home routers and corporate networks actually use: a deliberate over-reach, `../../DEVIATIONS.md` IC-5. `../../src/reserved-names.cjs`. |

## DNS vocabulary, comparison and messages

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS Terminology (obsoleted by [RFC 9499](https://www.rfc-editor.org/rfc/rfc9499)) | The vocabulary this chapter uses throughout. 8499 is cited to keep one vocabulary across the whole specification; nothing here depends on the differences. Its definition of a **cached answer** — one served without a new query — is what §6.2 and `../../DEVIATIONS.md` IC-17 mean when they say the engine may answer without the bridge seeing anything. |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | DNS Case Insensitivity Clarification | §2.3 — the final label is lowercased before it is compared against the snapshot, so `EXAMPLE.COM` and `example.com` land in the same namespace (`../../src/classify-host.cjs:68-76`). §5.3 — and the reason the bridge folds only ASCII `A`–`Z` when it compares a reply's question name to the query's, as label **bytes** rather than as decoded text: `dnsEnvelope()`, `../../src/odoh-bridge.js:278-282`. |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) §2.1 | Requirements for Internet Hosts — Application and Support | §2.4 — host label syntax, the shape every entry in the snapshot is asserted to have (a single label, `[a-z0-9-]`, optionally `xn--`-prefixed). `tests/icann-tld-snapshot.test.js`. |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) §4.1.1 (header), §4.1.2 (question), §4.1.4 (message compression), §3.2.1 (TTL) | Domain Names — Implementation and Specification | §5.3 — the envelope the loopback bridge parses on the way in and on the way back, so that a reply is **bound to its question** before it is treated as an answer: `dnsEnvelope()`, `../../src/odoh-bridge.js:253-306`, called from `_handle()` at `:135-156`. §4.1.1's ID, QR, TC and reserved bits; §4.1.2's single question with its QNAME, QTYPE and QCLASS; §4.1.4's pointers, which the parser follows but refuses to follow twice (a loop) and past the 255-octet name limit. §3.2.1's TTL is the quantity `recentEvidence()`'s fixed ten-minute window is **not** (`../../DEVIATIONS.md` IC-18, §2.5). Everything inside a record's RDATA is forwarded uninterpreted. §8 — the same question section that `assertAnswersTo` checks every answer against (`../../src/dns-query.js:342`), including the ICANN lookups a Handshake walk needs — a check the `dns.lookup()` library default has no counterpart for. |

## Internationalized names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | IDNA: Definitions and Document Framework | §2.3 — the A-label/U-label vocabulary the boundary comparison is stated in. |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | IDNA: Protocol | §2.3 — the lookup protocol we do **not** implement: a Unicode host must be an A-label before it is compared against the snapshot, and the conversion we use is the URL Standard's. `../../DEVIATIONS.md` IC-12. |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | §2.3 — what the WHATWG URL Standard actually requires, and therefore what we actually get. On this path the divergence from IDNA2008 can move a name **across the ICANN boundary**. `../../src/classify-host.cjs:68-76`, `../../DEVIATIONS.md` IC-12. |

## URL parsing — the classifier's input

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL Standard §host parsing](https://url.spec.whatwg.org/#host-parsing) | URL Standard | §2.3 — every host reaching the classifier is normalised by the URL parser: lowercased, punycoded, port and trailing dot stripped. `../../src/classify-host.cjs:55-76`, `../../src/hns-host.js:85-98`. |
| [WHATWG URL Standard — ends-in-a-number checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) | URL Standard, IPv4 parsing | §2.2 row 5, §2.3 — why a host whose last label is all ASCII digits cannot be written in a URL, so `classifyHost` falls back to the raw label for the numeric case and `rewriteToHns` gives up entirely; and how an IP literal is recognised before the label count. `../../src/classify-host.cjs:42-48`, `../../DEVIATIONS.md` IC-14. |

## Encrypted DNS transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS Queries over HTTPS (DoH) | §5.1, §5.3 — both ends of the bridge. The engine speaks **only** RFC 8484 over https templates, which is what the loopback bridge presents: §4.1's `application/dns-message` media type, on a GET with `?dns=<base64url>` and on a POST body, and the same type on every response (`_handle()`, `../../src/odoh-bridge.js:112-174`). It is also the protocol of the fallback resolver pool. §4.1 fixes the message id at zero for a DoH client's own queries, which is why the question section is the check that carries the weight (`../../src/doh.js:69-71`); the engine is the client here, and the bridge binds on whatever id the engine chose. `src/dns-policy.js`. |
| [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230) | Oblivious DNS over HTTPS | §5.3, §9.4 — what the bridge speaks upstream: §6 message format, §6.3 response AEAD key derivation from the HPKE exporter secret plus a target-chosen nonce, the `ODoHConfigs` structure. Cited as much for what it does **not** authenticate: the §6 encryption binds a response to the query's HPKE context — these bytes came from a holder of the target's key, for this exchange — and says nothing about whether the plaintext is a well-formed DNS message, or answers the question that was asked. That gap is closed here, not there, by `dnsEnvelope()` (`../../src/odoh-bridge.js:253-306`, SPEC §5.3). It also defines **no discovery mechanism** — `../../DEVIATIONS.md` IC-8. `../../src/odoh.js`. |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) | Hybrid Public Key Encryption | §5.3 — the construction ODoH is built on: X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM. `../../src/odoh.js`. |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | §5.3 — §2.2/§2.3 extract-and-expand for the ODoH key id, response key and nonce. `../../src/odoh.js:73-84`, `:117-120`. |
| [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) | Well-Known Uniform Resource Identifiers | §5.3 — the registry `/.well-known/odohconfigs` is, as far as we can establish, **not** in. `../../DEVIATIONS.md` IC-8 and §2. |
| [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) | DNS over TLS (DoT) | §5.1 — **not used, and not usable**: the engine accepts only RFC 8484 https templates, so DoT is not an option however configured. Listed because its absence is a constraint we inherited, not one we chose. `../../DEVIATIONS.md` IC-11. |
| [RFC 8310](https://www.rfc-editor.org/rfc/rfc8310) | Usage Profiles for DNS over TLS and DTLS | §5.2, §5.5, §5.7 — §8.2's opportunistic-versus-strict distinction is the vocabulary `automatic` and `secure` implement. `automatic` is the Fast-mode plan; Private is always the strict profile, with the oblivious bridge as its only server. §8.2 is also the citation behind §6.2's limit: a profile is a policy a client sets in advance, and nothing in the standard lets it establish afterwards which profile carried a given name. `../../DEVIATIONS.md` IC-6, IC-17. |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) | Discovery of Designated Resolvers | §5.1, §7.4 — **not implemented.** The resolver list is configuration and is never discovered. Listed because it is the standard's own answer to "the network's resolver may be the right one", and we have not taken it. `../../DEVIATIONS.md` IC-11. |
| [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) | Service Binding and Parameter Specification via the DNS (SVCB and HTTPS RRs) | §7.4 — type 65 is parsed by `../../src/dns-query.js` and never queried, here or anywhere. `../../DEVIATIONS.md` IC-11. |
| [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) | TLS Encrypted Client Hello | §9.4 — unreachable without a queried SVCB record, and blocked on the runtime exposing no ECH option. Relevant here because without it the server name is in the ClientHello, so an oblivious DNS lookup does not by itself hide which site was visited. |

## The loopback certificate

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | Internet X.509 PKI Certificate and CRL Profile | §5.3 — the certificate the bridge serves is built by hand, in DER, with no dependency on an `openssl` binary: v3, ECDSA-with-SHA-256, `basicConstraints` CA:FALSE (critical), `keyUsage` digitalSignature+keyEncipherment (critical), `extKeyUsage` serverAuth, and a `subjectAltName` (§4.2.1.6) naming only `DNS:localhost` and `IP:127.0.0.1`. `../../src/self-cert.js`. |
| [RFC 7469](https://www.rfc-editor.org/rfc/rfc7469) §2.4 | Public Key Pinning Extension for HTTP | §5.3, §9.3 — the pin construction the engine is given: base64 of SHA-256 over the certificate's SubjectPublicKeyInfo. HPKP itself is dead; the construction is what the engine's switch consumes, and citing it is how a reader knows exactly what bytes are hashed. `../../src/self-cert.js:134`, `src/index.js:265`. |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The Transport Layer Security (TLS) Protocol Version 1.3 | §1.1, §5.3 — the transport between the engine and the loopback bridge, and between the bridge and the relay. Terminated by the runtime's own TLS stack; nothing here implements it. `../../src/odoh-bridge.js`. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §1.1, §5.3 — the HTTP layer the DoH exchange rides, and the layer this chapter explicitly does not specify. `../../src/odoh-bridge.js`. |

## Addresses and authentication — cited for what ICANN names do *not* get

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | §7.3 — the registry the SSRF guard's ranges come from. The guard is applied to Handshake answers and to HIP-5 `_op` answers and is **not** applied to ICANN names, because the address never passes through our code. `../../src/safe-address.js`, `../../DEVIATIONS.md` IC-13. |
| [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) | Address Allocation for Private Internets | §7.3 — the private IPv4 ranges in that guard. `../../src/safe-address.js`. |
| [RFC 3927](https://www.rfc-editor.org/rfc/rfc3927) | Dynamic Configuration of IPv4 Link-Local Addresses | §7.3 — `169.254.0.0/16`, including the cloud metadata address `169.254.169.254`. `../../src/safe-address.js`. |
| [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) | Unique Local IPv6 Unicast Addresses | §7.3 — the IPv6 half of the same guard. `../../src/safe-address.js`. |
| [RFC 6598](https://www.rfc-editor.org/rfc/rfc6598) | IANA-Reserved IPv4 Prefix for Shared Address Space | §7.3 — the CGNAT range `100.64.0.0/10`. `../../src/safe-address.js`. |
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | DNS-Based Authentication of Named Entities (DANE) TLSA | §7.1 — implemented, used for Handshake names, and deliberately **not** applied to ICANN names: the certificate hook defers to the platform's WebPKI for every non-Handshake host. `../../src/dane.js`, `src/index.js:1330-1331`, `../../DEVIATIONS.md` IC-3. |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | DANE Protocol: Updates and Operational Guidance | §7.1 — §4's guidance that a client apply TLSA records wherever they are published is the standard we are departing from, and the reason IC-3 has to argue rather than assert. |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS Security Introduction and Requirements | §7.2 — cited for absence: nothing validates a signature on this path, and the ICANN root's trust anchor is not configured anywhere in this browser. `../../DEVIATIONS.md` IC-4. |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) | Protocol Modifications for the DNS Security Extensions | §7.2 — the validating-resolver behaviour we neither perform nor rely on. An ICANN address is the resolver's word, which is what the trust step says. |

## Requirement language

| Identifier | Title | Used for |
|---|---|---|
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Key words for use in RFCs to Indicate Requirement Levels | MUST / MUST NOT / SHOULD / SHOULD NOT / MAY, throughout `SPEC.md`. |
| [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | The capitalisation rule those key words are read under. |

## Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [`app.configureHostResolver`](https://www.electronjs.org/docs/latest/api/app#appconfigurehostresolveroptions) | Electron API documentation | §5.1, §5.4 — the one call that changes what an ICANN lookup does: `secureDnsMode` (`off` / `automatic` / `secure`) and `secureDnsServers` (RFC 8484 https templates only). Everything in §5 is a policy for choosing its two arguments. Called again on every mode switch (§5.7): Private gives it `secure` with the bridge's template alone, or `secure` with an empty list; a return to a plan that configures nothing sets `off` explicitly. It is a **one-way** call — a mode and a list go in, and there is no event, readback or per-navigation record to come back — which is why §6.2 and `../../DEVIATIONS.md` IC-17 can describe the configuration and not the lookup. `src/dns-policy.js` (`planDnsTransport`, `privateDns`), the browser's `applyDnsPlan`. |
| `--ignore-certificate-errors-spki-list` | Chromium command-line switch (documented in Chromium's own source; there is no specification) | §5.3, §9.3 — how the loopback bridge's certificate is trusted. It makes the engine accept that public key **for any host**, which is why the key is generated in memory per launch, never written to disk, and minted only when `wantsObliviousBridge()` is true. `src/index.js:259-265`, `../../src/self-cert.js`. |
| `odoh-relay.numa.rs`, `odoh-relay.edgecompute.app` | The deployed public ODoH relays | §9.4 — the reason RFC 9230's non-collusion assumption does not hold at current scale: two public relays exist worldwide and one is run by a target operator. The code stays; the privacy claim does not. `src/config.js:376-408`. |
| [DNSCrypt public ODoH server list](https://github.com/DNSCrypt/dnscrypt-resolvers) | DNSCrypt resolver lists | §5.3 — why the second relay is kept in the configuration although it does not currently carry our traffic: it allowlists targets, and will start working for `odoh.hns.one` once that target is on this list, so that day needs no release. `src/config.js:402-407`. |
| [`../../SPEC.md` §4.2](../../SPEC.md) | The Fast / Private switch | §5.7, §9.4 — the one control whose policy table (`policyFor`) decides `icannDns`: `secure` in Private, the configured `dns.mode` in Fast; and the controller (`DeliveryMode`) whose `change` event re-applies the plan. `../../src/delivery-mode.js`, `../../tests/delivery-mode.test.js`. |
| [`../../namespaces/router/SPEC.md`](../router/SPEC.md) | The router chapter of this specification | §2.1, §3 — laws **L1** (an explicit scheme selects the protocol, always) and **L2** (no silent cross-namespace fallback), which are what make "ICANN first" a *boundary* rather than a preference, and the `X-Resolution-Namespace` header that proves a failure stayed inside its namespace. `../../src/router.js`. |
