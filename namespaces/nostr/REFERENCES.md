# Chapter 6 — Nostr: references

Every standard this chapter's implementation actually reads, with what it is
used for and where in the tree it is used. Nothing is listed that the code does
not touch: a padded bibliography is worse than none, because it makes the real
dependencies impossible to see.

Paths are relative to `namespaces/nostr/`. Where a row points outside this
directory it is naming code in the Wildroot browser that is **not** extracted
here, and says so.

A note on what a "NIP" is, since this file cites nine of them. The
[NIPs repository](https://github.com/nostr-protocol/nips) is not a standards
body and has no process comparable to the IETF's. A NIP is a numbered document
in a git repository, merged by its maintainers, revisable in place, with no
errata mechanism and no versioning. **NIP-01 is stable and universally
implemented; the rest vary.** Every citation below is to the document as it
stands, and an implementer should read the current text rather than trusting
this summary of it.

---

## Naming

| Identifier | Title | Used for |
|---|---|---|
| [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md) | bech32-encoded entities | **§5**, the whole of it: the prefixes `npub`, `nsec`, `note`, `nprofile`, `nevent`, `naddr`; the TLV grammar and its four types (`0` special, `1` relay, `2` author, `3` kind as a big-endian uint32); the rule that these encodings are for display and transport, not for use inside NIP-01 events. Cited also for what it does not restate — BIP-173's 90-character limit, which Nostr identifiers routinely exceed (NO-4). `src/nip19.js` |
| [NIP-21](https://github.com/nostr-protocol/nips/blob/master/21.md) | The `nostr:` URI scheme | **§5.4**: the scheme token followed directly by a NIP-19 entity, with no authority component, and with `nsec` excluded. We additionally accept `nostr://` (NO-5). `src/nip19.js` (`parseNostrURI`), `src/nostr-protocol.js` |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Mapping Nostr keys to DNS-based internet identifiers | **§7**, the whole of it: the `<local>@<domain>` form; the `GET /.well-known/nostr.json?name=<local>` request; the `names` and optional `relays` objects; the local-part grammar `a-z0-9-_.`; the rule that a client must not follow redirects; the convention that a `_` local part is displayed as the bare domain. Cited also for its own honesty note — a NIP-05 answer is a mapping asserted by a domain, not an identity proof. `src/nip05.js` |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | **§5.4**: the `nostr:` URI's shape, and the reason `nostr://` is a different production (an authority component) rather than a spelling variant. `src/nip19.js` |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and Registration Procedures for URI Schemes | **§5.4**, cited for a negative: `nostr:` is not in the IANA URI Schemes registry. It is a de-facto scheme with wide implementation and no registration. |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | **§3**, §9.10 of it — namespace precedence: resolve in the alternative namespace when its suffix matches, and do not continue into DNS on failure. Adopted across this specification as rule L2; for Nostr it forbids a failed `nostr:` lookup from becoming a DNS or Handshake one. `../../src/router.js` |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for Internet Hosts — §2.1, host names | **§10.5**: LDH label syntax and length limits, which `verificationHost` enforces before a claim from a stranger's profile is allowed near a URL. `src/nip05.js` |
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework | **§10.5**, cited for what is refused: a Unicode host in a NIP-05 claim is rejected outright rather than IDNA-converted. `src/nip05.js` |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL | **§10.5**: the parser whose behaviour makes the SSRF vectors work — `\` is a path separator, `#` truncates, `:` starts a port, `@` ends userinfo. Every one of those characters ends the host, which is why appending a suffix to an unvalidated claim does not make it safe. `src/nip05.js`, and the adversarial vectors in `tests/nip05.test.js` |

## Protocol and transport

| Identifier | Title | Used for |
|---|---|---|
| [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic protocol flow description | **§6, §8 and §9.3**: the event object and its seven fields; the canonical serialisation `[0, pubkey, created_at, kind, tags, content]` whose SHA-256 is the event id; the BIP-340 signature over that id; the wire protocol `REQ` / `EVENT` / `EOSE` / `CLOSED` / `CLOSE` / `NOTICE`; the filter grammar (`ids`, `authors`, `kinds`, `#<letter>`, `since`, `until`, `limit`) that `matchesFilter` enforces against every returned event; kind 0 as profile metadata and kind 1 as a text note; replaceable and addressable events. `src/event.js`, `src/relay.js`, `src/nostr-protocol.js` |
| [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) | The WebSocket Protocol | **§8.1**: the relay transport, always over TLS. **§8.5**: on the Private route the client is the `ws` package — an RFC 6455 client that takes an agent, which is what lets its socket come out of a SOCKS tunnel — and anything but `wss://` is refused before a socket exists. **§10.4** is the rule that a relay *hint* must be `wss://` and nothing else. `src/relay.js`, `src/tor-websocket.js` |
| [WHATWG WebSockets](https://websockets.spec.whatwg.org/) | WebSockets Standard (the `WebSocket` interface) | **§8.1**: the API on the direct route, as distinct from RFC 6455's wire protocol — `onopen`/`onmessage`/`onerror`/`onclose`, `send`, `close` — taken from an injected `WebSocketImpl` or `globalThis.WebSocket`. The Private route's `ws` class presents the same surface, which is what lets `src/relay.js` drive both without knowing which it holds (§8.5, NO-16). A runtime without either is reported, never silently resolved as zero results. `src/relay.js` |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 | **§8.5**: the Private route. The Tor-dialling class is a SOCKS5 client of the device-local Tor, offering only the "no authentication" method (§3) and sending the relay's hostname as address type `0x03` `DOMAINNAME` (§4), so the name is resolved inside Tor and the operating system's resolver is never asked — the test asserts the address type on the wire. RFC 1929's username/password method is not used, so relays share the session's circuits (Chapter 8, TO-3). `src/tor-websocket.js` via `socksDialer`, `../../src/socks-dial.js` — shared with the Handshake resolver's authoritative hop, the WebSocket tunnel of Chapter 11 and `gemini://` of Chapter 9 |
| [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) | Transport Layer Security (TLS) Extensions: Extension Definitions — §3, Server Name Indication | **§8.5**: TLS on the Private route runs over a socket the client did not open, so the server name cannot be inferred from a hostname it resolved; `TorAgent` passes the relay's hostname as `servername` explicitly, and the test asserts the relay was offered it. `src/tor-websocket.js` |
| [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) | The JavaScript Object Notation (JSON) Data Interchange Format | **§6.1, §8.1, §9.2, §10.6**: three separate documents, each from a different source and each parsed defensively — the relay's wire frames, a kind:0's `content` (a nested JSON document chosen by a stranger), and the NIP-05 well-known document — plus the *serialisation* the event id is taken over, where reliance on the host's `JSON.stringify` matching NIP-01's escaping table is an assumption (NO-10). `src/relay.js`, `src/nostr-protocol.js`, `src/nip05.js`, `src/event.js` |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | **§7.1** for the NIP-05 `GET` and the redirect NIP-05 forbids following; **§9.4** for the status codes the handler emits, including 502 for "no relay was reached" as distinct from 404 for "a relay answered and had nothing". `src/nip05.js`, `src/nostr-protocol.js` |
| [Fetch Standard](https://fetch.spec.whatwg.org/) | Fetch — `redirect: "error"` | **§7.1**: the mechanism by which NIP-05's no-redirect rule is enforced rather than merely intended. `src/nip05.js` |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The Transport Layer Security (TLS) Protocol Version 1.3 | **§7.3**: the transport the NIP-05 well-known document arrives over, and half of what "NIP-05 verified" is worth. The host's TLS stack. **§8.5**: on the Private route, Node's TLS layered over the SOCKS socket, with verification unchanged from the direct route. `src/tor-websocket.js` |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | Internet X.509 Public Key Infrastructure Certificate and CRL Profile | **§7.3**: the trust model of that hop — a public CA vouched for the domain. This is what "NIP-05 verified" means and all it means; the DANE pinning of the Handshake chapter does not apply to it (NO-12). Also the trust model of a relay's certificate on both routes (§8.5): the Tor route changes who sees the address, not who vouches for the relay. |

## Cryptography

| Identifier | Title | Used for |
|---|---|---|
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | **§6.2**: the signature scheme NIP-01 specifies — a 64-byte signature over the 32-byte event id, verified against a 32-byte x-only public key using BIP-340's tagged-hash construction. This is not ECDSA; a generic secp256k1 verifier does not implement it. `src/event.js`, via [`@noble/curves`](https://github.com/paulmillr/noble-curves) `schnorr.verify` |
| [SEC 2](https://www.secg.org/sec2-v2.pdf) | Recommended Elliptic Curve Domain Parameters — §2.4.1, secp256k1 | **§6.2**: the curve. `src/event.js`, via `@noble/curves` |
| [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | Secure Hash Standard — SHA-256 | **§6.1**: the event id is the SHA-256 of the canonical serialisation. Taken from `node:crypto` rather than `@noble/hashes` deliberately — the latter is only a transitive dependency here, and importing a package we do not declare breaks the day that tree reshuffles. `src/event.js` |
| [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) | Base32 address format for native v0-16 witness outputs (Bech32) | **§5.1**: the encoding NIP-19 uses — the charset, the HRP expansion, the polymod checksum with the constant `1` (not bech32m's), the mixed-case prohibition, and the rejection of non-zero padding bits when regrouping 5-bit groups into bytes. One deviation: the 90-character limit is not enforced (NO-4). `src/nip19.js`, a local implementation |

## Cited for what is not done

Listed because each absence is a documented gap rather than an oversight.

| Identifier | Title | Used for |
|---|---|---|
| [NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md) | Relay list metadata (kind 10002, `r` tags) | **§8.2**, not read. This is the closest thing Nostr has to "where does this key live", and the resolver does not ask for it: it queries a bundled set plus the identifier's own checked hints. Wildroot publishes a NIP-65 list for every name it creates and its social client reads one; neither is in scope here. NO-3 |
| [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Authentication of clients to relays | **§8.2**, not implemented. A relay that demands `AUTH` is, to this code, a relay that returned nothing — and the condition is not yet named in the relay report. NO-7 |
| [NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event deletion request | **§10.1**, not implemented and unimplementable as a guarantee. Cited because it is why "this event exists on a relay" does not mean "its author still stands behind it". |
| [NIP-02](https://github.com/nostr-protocol/nips/blob/master/02.md) | Follow list (kind 3) | **§1.1**, out of scope. Read by Wildroot's social client, not by the resolver. Named so a reader does not go looking for it here. |
| [NIP-18](https://github.com/nostr-protocol/nips/blob/master/18.md) | Reposts (kinds 6 and 16) | **§1.1**, out of scope, as NIP-02. |
| [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) | HTTP Auth (kind 27235) | **§1.1**, out of scope. Wildroot uses it to authenticate panel requests with a name's control key; it is an authorization scheme, not a resolution mechanism, and no part of the `nostr:` path touches it. |

## Rendering and integration

| Identifier | Title | Used for |
|---|---|---|
| [CSP Level 3](https://www.w3.org/TR/CSP3/) | Content Security Policy Level 3 | **§10.6**: every response, error pages included, is served under `default-src 'none'; style-src 'unsafe-inline'; img-src https: data:`. No script source is granted at all, which is the second line of defence behind escaping a stranger's `content`. `src/nostr-protocol.js` |
| [Electron `registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | **§5.4** and `../../DEVIATIONS.md` §2.5: `nostr:` is registered with low privileges — not a standard scheme, so no origin, no `fetch`, no service workers, no secure-context features. A deliberate difference from `hns:`: a `nostr:` page is a document, not an application. The browser's `src/main.cjs`, not in this chapter |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) · [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs | The key words throughout `SPEC.md`. |

## Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Audited elliptic-curve implementations | **§6.2**: the BIP-340 implementation. Dependency-light and already in the browser's tree, which is the honest reason Nostr was cheap to add at all. `src/event.js`, and every test file, which mint their own key material rather than carrying fixtures |
| [nostr-tools `normalizeURL`](https://github.com/nbd-wtf/nostr-tools) | Relay-URL canonicalisation | **§9.1 step 3**: the canonicalisation everyone else follows — host lower-cased, a bare path collapsed, fragment dropped — so `wss://nos.lol` and `wss://nos.lol/` are one relay, one socket, and one row in the relay report. `normalizeRelayUrl` in `src/relay.js` |
| [The NIPs repository](https://github.com/nostr-protocol/nips) | Nostr Implementation Possibilities | Read for what is and is not settled. Its lack of a versioning or errata process is itself a fact an implementer needs — see the note at the top of this file. |
| [`ws`](https://github.com/websockets/ws) | WebSocket client and server for Node.js | **§8.5**: the client on the Private route, chosen because it takes an `agent` and the runtime's `WebSocket` does not. A declared dependency of this repository (`^8.18.2`); the browser carries 7.x, and the class is written for both — each hands a text frame to `onmessage` as a string. Only `src/tor-websocket.js` imports it; the direct route never touches it (NO-16). Also the relay server `tests/tor-websocket.test.js` stands up |
| `../../src/delivery-mode.js` | The one switch — Settings › Content delivery › Mode | **§8.5**: `policyFor()` is the policy table this handler's `nostrThroughTor` row comes from; `privateRefusal('relay')` is the wording of the 503 page and `SWITCH_HINT` its last sentence. `src/nostr-protocol.js` |
| `docs/MODES.md` (browser) | Wildroot, *Private mode and Fast mode* | **§8.5**: the design of the switch, and the table naming row 15 — Nostr relay queries — as one of the five divergences that need a mode at all. `../../DIVERGENCE.md` row 15 is the inventory entry. Not extracted |

---

## Running these tests

```sh
node --test namespaces/nostr/tests/*.test.js     # from the repository root
```

**73 tests, deterministic, no network.** Requirements: Node ≥ 20 (for the
global `Response` and `fetch` these modules use in place of dependencies),
`@noble/curves` and `ws`, installed at the repository root. `@noble/hashes` is
present at the root and is **not** used here: `src/event.js` takes SHA-256 from
`node:crypto` and says why in a comment.

`ws` is needed by `src/tor-websocket.js` and by the relay server
`tests/tor-websocket.test.js` stands up. Nothing else is: no Electron, no
bech32 library, no `nostr-tools`. The bech32 decoder is local (NO-4), the
direct-route relay client takes its WebSocket from the injected `WebSocketImpl`
seam or the global, and the NIP-05 client uses the platform `fetch` with the
implementation injectable for tests. Because the seam exists, no test replaces
a global — the whole handler is driven against scripted, misbehaving relays.
"No network" includes the Tor route: `tests/tor-websocket.test.js` runs a real
`wss://` relay behind a SOCKS5 server, both on loopback, with a certificate
from `../../src/self-cert.js`.

Four modules outside this directory are read, and one reads back the other
way. `tests/classification.test.js` imports `../../../src/router.js`, the same
classifier the Handshake chapter uses, shared rather than forked because a
divergent copy of a security-relevant classifier is the worse problem.
`src/relay.js` imports `../../../src/safe-address.js`, the address guard the
Handshake chapter applies to zone-supplied addresses, for the same reason a
relay hint needs it (§10.4). `src/tor-websocket.js` imports
`../../../src/socks-dial.js`, the SOCKS5 dialer the Handshake resolver's
authoritative hop, the WebSocket tunnel and Gemini share, so every raw-socket
path that goes through Tor speaks to it through one implementation.
`src/nostr-protocol.js` imports `privateRefusal` from
`../../../src/delivery-mode.js`, so its refusal page says what every other
Private-mode page says. In the other direction, `src/router.js` imports
`decodeNip19` from `src/nip19.js` in this directory: the classifier decodes a
bare identifier before claiming it (SPEC §3), so the routing decision depends
on this chapter's checksum. All of these modules are dependency-free of the
browser, so the edges are clean, but they are real — the namespace boundary is
decided with this chapter's decoder.
