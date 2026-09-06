# Chapter 7 — DID, AT Protocol and ActivityPub: references

Every standard this chapter's implementation reads, with what it is used for
and which module uses it — plus, in their own group, the standards a compliant
implementation would need for the namespaces this one refuses. Where a row says
*not implemented* or *cited for the deviation*, the row says so.

## Naming and identifiers

| Identifier | Title | Used for |
|---|---|---|
| [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) | Decentralized Identifiers (DIDs) v1.0, W3C Recommendation 19 July 2022 | §3.1 the syntax `did:<method-name>:<method-specific-id>` and the absence of an authority component, which is why the classifier accepts a slashless `scheme:`. §5.4 the `id` property is the DID subject and §7.1.3 a resolver answers with the document *for* the input DID — the equality check the handler makes. §5.4 also §7.1's resolution **result** envelope, which we do not return (`../../DEVIATIONS.md` DI-3). §6.2 `service` / `serviceEndpoint`, read to find a PDS. — `src/did-protocol.js`, `src/bsky.js` |
| [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/) | did:web Method Specification, W3C Credentials Community Group draft | §5.3 the read algorithm quoted and implemented in full — `:` → `/` before percent-decoding, the `%3A` port, `.well-known` only for a bare host, then `did.json` — and checked against the specification's published examples. A Community Group draft, not a W3C Recommendation: it is the only written definition of the method and it is not ratified. — `src/did-protocol.js` (`didWebUrl`), imported by `src/bsky.js` so the PDS lookup reads the method the same way (§6.2) |
| [did:plc Method Specification v0.1](https://web.plc.directory/spec/v0.1/did-plc) | did:plc — Public Ledger of Credentials, v0.1 ([source](https://github.com/did-method-plc/did-method-plc)) | §5.2 the directory endpoint `GET /<did>` that returns the current document — the whole of what is used. The parts *not* used are what make the method verifiable: the identifier is a truncated hash of the signed genesis operation, and `GET /<did>/log/audit` publishes the signed operation log (`../../DEVIATIONS.md` DI-2). One operator's specification, versioned v0.1. — `src/did-protocol.js`, `src/bsky.js` |
| [W3C DID Specification Registries](https://www.w3.org/TR/did-spec-registries/) | DID Specification Registries, W3C Group Note | §5.1 where a method name is looked up. Cited for what is refused: every method other than `plc` and `web` is a 400 before any network request. — `src/did-protocol.js` |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | §3 namespace precedence — resolve in the alternative namespace when its suffix matches, and do not continue into DNS on failure. §9.10 is the only place this rule is written down in an RFC; `../../SPEC.md` adopts it and this chapter inherits it. — `../../src/router.js` |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Standard — [host parsing](https://url.spec.whatwg.org/#host-parsing) | §3.1 the reason `did:` must not be a *standard* scheme: a standard scheme's authority is lowercased, IDNA-mapped and, when the last label is all digits, parsed as IPv4, while a method-specific identifier is byte-sensitive. Also why the canonical `at://did:plc:…` AT-URI does not parse and must be dispatched by scheme prefix. — `../../src/router.js`; the browser's `src/main.cjs` (not extracted) |

## AT Protocol

| Identifier | Title | Used for |
|---|---|---|
| [atproto.com/specs/handle](https://atproto.com/specs/handle) | AT Protocol — Handle Resolution | §6.1 the two authoritative handle→DID methods (`_atproto.<handle>` DNS `TXT` `did=…`, and `GET https://<handle>/.well-known/atproto-did`) and the bidirectional-verification requirement against `alsoKnownAs`. **Neither method is implemented**; the public AppView is asked instead (`../../DEVIATIONS.md` DI-5). Also the form of the `_atproto.<name>` record §9.3 signs an authorisation for. — `src/bsky.js` (`resolveHandle`) |
| [atproto.com/specs/did](https://atproto.com/specs/did) | AT Protocol — DID | §6.2 the two DID methods the network admits, and the document requirements a client reads: a `service` entry with id `#atproto_pds` and type `AtprotoPersonalDataServer` whose `serviceEndpoint` is the PDS. Both fields are checked, as is the document's own `id`. One deviation remains: where this specification makes an unresolvable DID a resolution failure, the implementation keeps a default PDS for the sign-in path and marks it `{ assumed: true, reason }` rather than failing (§6.2 rule 4). — `src/bsky.js` (`resolvePds`) |
| [atproto.com/specs/at-uri-scheme](https://atproto.com/specs/at-uri-scheme) | AT Protocol — AT-URI scheme | §6.3 `at://<did-or-handle>/<collection>/<rkey>`, the identifier form the `at` namespace owns. Recognised, fail-closed: parsed no further than its scheme, never resolved. The AT-URIs inside the adapter are opaque strings carried back to their origin. — `src/unimplemented-protocol.js`; strings in `src/bsky.js` |
| [atproto.com/specs/xrpc](https://atproto.com/specs/xrpc) | AT Protocol — XRPC | §6.1 the HTTP+JSON transport: `GET|POST /xrpc/<nsid>`, query parameters, `Bearer` auth, and the error body shape (`error`, `message`) mapped to a typed error. Hand-rolled — eight endpoints and an injectable `fetch` is fewer lines than an SDK integration. — `src/xrpc.js` |
| [atproto.com/specs/repository](https://atproto.com/specs/repository) | AT Protocol — Repository | §6.3 and §10.5 the signed commit over a Merkle Search Tree, verified with the `#atproto` key from the account's DID document, that would make an `at://` record *resolved* rather than *fetched*. **Not implemented**; cited as the bar. — no module |
| [public.api.bsky.app](https://docs.bsky.app/) | Bluesky public AppView | §6.1 the unauthenticated read service used for `com.atproto.identity.resolveHandle` and for profile and feed reads. A free service run for the whole network, which is why the transport caches briefly and retries a 429 once. As a *resolver* it is a trusted third party. Not a standard; listed because a load-bearing dependency belongs in the references. — `src/bsky.js`, `src/xrpc.js` |

## Transport, HTTP and the browser boundary

| Identifier | Title | Used for |
|---|---|---|
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §8 the 501 (§15.6.2) a recognised-but-unresolved namespace answers with; §10.4 the 503 (§15.6.4) the non-proxied gate answers with — a status the engine knows, deliberately; §5.1 the 400 (§15.5.1) for a malformed or unsupported DID; §5.4 the 502 (§15.6.3) for a transport error or a document about a different subject. — `src/unimplemented-protocol.js`, `src/gate.js`, `src/did-protocol.js` |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | §5.3 percent-encoding is case-insensitive (§2.1), so `%3a` and `%3A` are the same octet and a `did:web` port decodes from either spelling. — `src/did-protocol.js` (`didWebUrl`) |
| [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) | Well-Known Uniform Resource Identifiers | §5.3, §6.1, §7 the `/.well-known/` namespace shared by `did.json`, `atproto-did` and `webfinger`, and the registry that keeps them from colliding. — `src/did-protocol.js`, `src/bsky.js` |
| [WHATWG Fetch](https://fetch.spec.whatwg.org/) | Fetch Standard — [CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol) | §5.4 `Access-Control-Allow-Origin: *` on a resolved document (bounded by the scheme's privileges, not by the header — `../../DEVIATIONS.md` DI-1) and `null` on a fail-closed refusal; `redirect: 'error'` and `AbortSignal.timeout`, set on every request this chapter makes. — `src/did-protocol.js`, `src/unimplemented-protocol.js`, `src/bsky.js`, `src/xrpc.js` |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | §5.3, §10.2 the addresses a resolver reaching a host a stranger named must refuse, applied by `isSafeDidWebHost` before any request. — `src/did-protocol.js` via `../../src/safe-address.js` |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) | IPv4 Address Blocks Reserved for Documentation | §5.3, §10.2 the documentation blocks included in that refusal. — `../../src/safe-address.js` |
| [Electron `registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | §3.1, §8 how `did`, `at` and `activitypub` are declared to the engine: non-standard, non-secure, no service workers, no `fetch`, `corsEnabled`. Registration is mandatory even for a scheme that resolves nothing — an unregistered scheme loaded as a main-frame document has hard-crashed the application. — the browser's `src/main.cjs` (not extracted) |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Key words for use in RFCs to Indicate Requirement Levels | The requirement keywords, as amended by RFC 8174. — `SPEC.md` |
| [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | The same, restricted to the uppercase forms. — `SPEC.md` |

## Experimental: identity anchors under a Handshake name

The records and receipts of SPEC §9 are shipped and signed but are not a
proposed standard, and their formats may change. These are the standards they
are built from.

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain Names — Implementation and Specification | §9.1 §3.3.14: a TXT record's `<character-string>`s are one value, concatenated by the caller, and separate records are separate values, so a field is never merged across them; and the 255-byte maximum the parser enforces and the compact receipt encoding is shaped by. — `src/record.js` |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for Internet Hosts — Application and Support | §9.1 §2.1 host label syntax: a label may not contain `_`, which makes `_hns` an unambiguous prefix that can never collide with a Handshake label. — `src/record.js` (`recordName`), `src/keys.js` (`normalizeName`) |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS Security Introduction and Requirements | §9.2 the validation an `_hns` answer must have passed before its contents mean anything; an unvalidated answer is *unverified*, never *absent*. — `../../src/dnssec.js`, consumed by the browser's `src/folders/index.js` |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) | Protocol Modifications for the DNS Security Extensions | §9.2 the same, for the RRSIG and denial-of-existence machinery `../../SPEC.md` specifies in full. — `../../src/dnssec.js` |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §9.1 §5 base64url: the receipt field's 64 raw signature bytes after the decimal `created_at` and a `.`, chosen so the whole proof fits one TXT string. — `src/record.js` (`encodeReceipt` / `decodeReceipt`) |
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | §9.1 the signature scheme for every receipt, and the x-only 32-byte public key form the `pubkey=` field carries. — `src/keys.js`, `src/nostr-event.js` |
| [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Nostr — Basic protocol flow description | §9.1 the event object and its canonical serialisation — `sha256(JSON([0,pubkey,created_at,kind,tags,content]))` is the id, BIP-340 over that id is the signature. Deliberately not a new signature format: any Nostr library can verify a receipt. — `src/nostr-event.js` |
| [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) | Nostr — Arbitrary custom app data | §9.1, §9.3 kind 30078 and the `d` tag that makes an event parameterised-replaceable per name. Both receipts are kind-30078 events; the `v` tag exists precisely because 30078 is generic. — `src/receipt.js` |
| [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) | Nostr — HTTP Auth | Kind 27235, the `u` / `method` / `payload` tags, and `Authorization: Nostr <base64(event)>`, used to authenticate the *write* that publishes an anchor. Out of this chapter's scope, present because `receipt.js` is extracted whole. — `src/receipt.js` (`signAuth` / `verifyAuth`) |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Nostr — Mapping Nostr keys to DNS-based internet identifiers | Cited for the gap: NIP-05 verifies a Nostr identifier against a domain's `/.well-known/nostr.json`, which is the operator's word. The `_nostr.<name>` anchor described in `src/record.js` would attest the same binding with the control key instead — and is designed, not published (`../../DEVIATIONS.md` DI-11). — no module |

## Cited for what a compliant implementation must do — not read by this code

The `at` and `activitypub` namespaces are fail-closed (SPEC §7, §8). Their
refusal pages name what resolving them would require and §10.5 turns that into
a bar. These are the standards that bar is made of; no module in `src/`
imports, fetches or parses any of them.

| Identifier | Title | Used for |
|---|---|---|
| [RFC 7033](https://www.rfc-editor.org/rfc/rfc7033) | WebFinger | §7 `GET https://<host>/.well-known/webfinger?resource=acct:<user>@<host>` and the `self` link with type `application/activity+json` that names the actor URL — and what it is *not*: a redirection published by the host, never an authentication of the actor it points at. — no module |
| [W3C ActivityPub](https://www.w3.org/TR/activitypub/) | ActivityPub, W3C Recommendation 23 January 2018 | §7, §10.5 the actor object and the client's side of the protocol. ActivityPub specifies no client-side authentication of a fetched object; HTTP Signatures authenticate server-to-server delivery, and an implementation must not borrow the latter to imply the former. — no module |
| [W3C ActivityStreams 2.0](https://www.w3.org/TR/activitystreams-core/) | Activity Streams 2.0 Core | §7 the object vocabulary an actor document is written in. — no module |
| [W3C Controller Documents](https://www.w3.org/TR/controller-document/) | Controller Documents 1.0 (Multikey) | §10.5 the `verificationMethod` form (`#atproto`, type `Multikey`) an AT Protocol DID document carries, which a record-signature check would read the key from. The browser passes a multibase signing key through to the registry when binding a `did:web` account; nothing here parses one. — no module |

## Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | noble-curves — audited elliptic curve cryptography | §9.1 the secp256k1/BIP-340 implementation every receipt signature and verification goes through. The only runtime dependency this chapter adds beyond the shared modules and the platform. — `src/keys.js`, `src/nostr-event.js` |
| [`plc.directory`](https://plc.directory) | The did:plc directory service | §5.2 the default `did:plc` resolver, configurable via `plcDirectory` so a mirror or a self-hosted directory is a supported deployment and a test can drive every path with no network. — `src/did-protocol.js` |
| `../../src/delivery-mode.js` | The one switch — Settings › Content delivery › Mode | §10.4 `privateRefusal('p2p', …)`, the words the non-proxied gate answers with. `did:` itself reads nothing from it: it rides the proxied fetch and resolves in both modes. — `src/gate.js` |
| `docs/SOCIAL-MULTIPROTOCOL.md` | Wildroot design record — multi-protocol social identity | §9.4 the decision `did:web:<name>.hns.one`, its accepted cost, and the still-open question of whether `did:plc` should be the default instead (`../../DEVIATIONS.md` §2.5). — not extracted |
