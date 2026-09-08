# Chapter 9 — Key-addressed namespaces (hyper, SSB, Gemini, BitTorrent): references

Specifications and implementation documents used by this chapter. Each row
identifies the relevant behaviour and source. Delegated checks and
unimplemented features are labelled explicitly.

`src/` and `tests/` paths are relative to this chapter; `../../src/` names
shared modules. Browser paths refer to the Wildroot source tree.

[Chapter specification](SPEC.md) · [Deviations and open questions](DEVIATIONS.md)

---

## URI syntax

| Identifier | Title | Used for |
|---|---|---|
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | The generic grammar every identifier here is written in. §3.1 (scheme names are case-insensitive) is why the router lowercases before dispatch; §3.2.2 (host) is what a hypercore key or an info-hash *is* in the URL form; §4.2 (relative references) is what a Gemini redirect target may be; §3.3 (opaque path, no authority) is why `magnet:` is registered non-standard and is never an origin. SPEC §K.3.4, §K.6.1, §K.7.1 — `../../src/router.js`, `src/magnet-protocol.js`, `src/gemini-protocol.js`, `src/torrent-address.js` |
| [RFC 8141](https://www.rfc-editor.org/rfc/rfc8141) | Uniform Resource Names (URNs) | The `urn:btih:` / `urn:btpk:` / `urn:btmh:` forms a magnet's `xt`/`xs` carry. The two supported forms are matched with fixed regular expressions rather than by parsing URN syntax generally; the `q-component`/`r-component` grammar is not implemented and no BitTorrent magnet uses it. SPEC §K.7.1 — `src/magnet-protocol.js` |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | The parser Chromium and Node both use. §3.2 "special scheme" and the host-canonicalisation rules are why a *standard* custom scheme has its host lowercased — the property SPEC §K.3.4 reasons about, and the reason the legacy SSB sigil form cannot work as a URL host (SPEC §K.5.3). Reasoned about, not tested here (`DEVIATIONS.md` §2.2); the registration is `src/main.cjs` in the Wildroot tree |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | Domain Name System (DNS) Case Insensitivity Clarification | Why lowercasing a `gemini://` host is lossless, and why the same-host redirect predicate compares host names case-insensitively. SPEC §K.3.4, §K.6.3 — `src/gemini-protocol.js` (`sameHostGeminiRedirect`) |

## BitTorrent

The BEPs are indexed at
[bittorrent.org/beps/bep_0000.html](https://www.bittorrent.org/beps/bep_0000.html).

| Identifier | Title | Used for |
|---|---|---|
| [BEP 3](https://www.bittorrent.org/beps/bep_0003.html) | The BitTorrent Protocol Specification | The **v1 info-hash**: the SHA-1 of the bencoded `info` dictionary, 20 bytes, 40 hex characters — the identifier this namespace is built on. Also the metainfo format: the one-byte `d` check on a dropped `.torrent` is bencode's dictionary marker, and the piece-hash list in `info` is what makes received bytes self-authenticating. Piece verification is **via the engine**. SPEC §K.7.1, §K.7.6, §K.7.8 — `src/magnet-protocol.js` (`INFO_HASH_MATCH`), `src/torrent-input.js` (`validateTorrentFile`) |
| [BEP 9](https://www.bittorrent.org/beps/bep_0009.html) | Extension for Peers to Send Metadata Files | The **magnet URI format** (`xt=urn:btih:`, `dn=`, `tr=`) and the `ut_metadata` exchange that lets a client start from a magnet with no `.torrent`. BEP 9 permits the info-hash as 40 hex **or** 32 base32 characters; only hex is accepted and the base32 form is refused by name (`DEVIATIONS.md` KY-2). The metadata exchange is **via the engine**. SPEC §K.7.1, §K.7.4 — `src/magnet-protocol.js`, `src/torrent-input.js` |
| [BEP 5](https://www.bittorrent.org/beps/bep_0005.html) | DHT Protocol | Peer **discovery** from an info-hash with no tracker: `get_peers` / `announce_peer` over Kademlia. This is the step SPEC §K.7.8 classes as *trusted, not verified* — a DHT can withhold or stall, and cannot forge. **Via the engine** (`src/hns/torrent.js` in the Wildroot tree, not extracted) |
| [BEP 46](https://www.bittorrent.org/beps/bep_0046.html) | Updating Torrents Via DHT Mutable Items | The **64-hex `btpk`**: an Ed25519 public key whose DHT mutable item names a changing info-hash, and the `xs=urn:btpk:` magnet parameter. The one *key*-addressed form in the BitTorrent namespace, and the reason key shape is the whole dispatch. The signature check is **via the engine** (`bt-fetch`). SPEC §K.7.1, §K.7.2, §K.7.8, §K.9 — `src/magnet-protocol.js` (`PUBLIC_KEY_MATCH`), `src/torrent-address.js`, `src/torrent-input.js` |
| [BEP 44](https://www.bittorrent.org/beps/bep_0044.html) | Storing Arbitrary Data in the DHT | What BEP 46 is built on: the `seq` field is the freshness property nothing here pins. Cited because its absence is a stated gap (`DEVIATIONS.md` KY-11), not an oversight. SPEC §K.7.8, §K.11 |
| [BEP 52](https://www.bittorrent.org/beps/bep_0052.html) | The BitTorrent Protocol Specification v2 | The **v2 info-hash** (SHA-256, 32 bytes) and the `urn:btmh:` magnet form. **Not served** — recognised only so a v2 magnet can be refused by name. Cited also because a v2 info-hash is byte-for-byte the shape of a BEP-46 public key, which is a real ambiguity in the URL form (`DEVIATIONS.md` KY-3, §2.1). SPEC §K.7.1, §K.7.2 — `src/magnet-protocol.js` (`refusalFor`), `tests/magnet.test.js` |
| [BEP 53](https://www.bittorrent.org/beps/bep_0053.html) | Magnet URI extension — Select specific file indices | The `so=` parameter. **Not implemented** — it is ignored, along with every magnet parameter except `xt`, `xs` and `dn`. Its job (choose which files of a torrent to fetch) is done by the URL path instead. SPEC §K.7.7; `DEVIATIONS.md` KY-10 |
| [BEP 14](https://www.bittorrent.org/beps/bep_0014.html) | Local Service Discovery | **Deliberately disabled.** BEP 14 multicasts every info-hash a client is fetching to the whole LAN. Cited because turning it off is a decision this chapter defends, not a default. SPEC §K.11 — the engine's launch flags, `src/hns/torrent.js` in the Wildroot tree |

## Hypercore and Hyperdrive

| Identifier | Title | Used for |
|---|---|---|
| [Hypercore](https://docs.pears.com/building-blocks/hypercore) | Hypercore protocol (Holepunch / Pears documentation) | What a `hyper://` key **is**: the Ed25519 public key a signed, append-only log is authenticated under. Blocks are verified against a signed Merkle tree root, the guarantee SPEC §K.4.4 rests on. **Via the engine** (`hypercore`, through `hyper-sdk`) |
| [Hyperdrive](https://docs.pears.com/building-blocks/hyperdrive) | Hyperdrive (Holepunch / Pears documentation) | The filesystem abstraction over two hypercores that `hyper://<key>/<path>` addresses. SPEC §K.4 |
| [DEP-0002](https://github.com/datprotocol/DEPs/blob/master/proposals/0002-hypercore.md) | Hypercore (Dat Enhancement Proposal, historical) | The archived design document for the append-only log. Cited as **provenance, not as the implemented specification**. SPEC §K.4 |
| [DEP-0005](https://github.com/datprotocol/DEPs/blob/master/proposals/0005-dns.md) | DNS (Dat Enhancement Proposal, historical) | The Dat-era name→key mechanism, a `/.well-known/dat` fetch. Cited to say it is **not** what runs: `hyper-sdk` 6 resolves names with a DNSLink `TXT` record. SPEC §K.4.2 |
| [DNSLink](https://dnslink.dev/) | DNSLink specification | The name→key convention actually used: `TXT _dnslink.<host>` with a value of `dnslink=/hyper/<key>`. The same convention is read for IPFS by `../../src/pointers.js`; here it is read **via the engine**, over a public DoH JSON resolver with no DNSSEC. SPEC §K.4.2; `DEVIATIONS.md` KY-4 |
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS Queries over HTTPS (DoH) | The wire format the rest of this browser's DNS rides. Cited for what the engine does **not** use: `hyper-sdk` speaks the DoH *JSON* API (`?name=&type=TXT`, `accept: application/dns-json`), a vendor convention outside RFC 8484, so the DNSLink lookup cannot ride this browser's DoH or ODoH code even if the endpoint were configurable. SPEC §K.4.2; `DEVIATIONS.md` KY-4, KY-8 |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS Security Introduction and Requirements | Cited by its absence: the DNSLink `TXT` answer is not DNSSEC-validated, which is why a dotted `hyper://` host is reported as two trust steps with the mapping unverified. SPEC §K.4.2, §K.9; `DEVIATIONS.md` KY-4 — `../../src/trust-path.js` |
| [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) | Human-oriented base-32 encoding (Zooko O'Whielacronx) | The 52-character key encoding `hyper-sdk` builds `drive.url` from, alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`. Its being lower-case-only is what makes `hyper://` safe as a host-lowercasing standard scheme. SPEC §K.3.4, §K.4.1 — `../../src/pointers.js` (`HYPER_KEY_RE`) |

## Secure Scuttlebutt

| Identifier | Title | Used for |
|---|---|---|
| [ssb-uri-spec](https://github.com/ssb-ngi-pointer/ssb-uri-spec) | SSB URI Specification | The identifier grammar `ssb:<type>/<format>/<base64url-data>[/<extra>]`, the type/format pairs that are legal, and the mapping to and from the legacy sigil forms. Implemented **via the engine** (`ssb-uri2`); no SSB parsing is done in this package. SPEC §K.5.1, §K.5.3 |
| [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/) | Scuttlebutt Protocol Guide | What a **feed id** is — an Ed25519 public key — and the signed, hash-chained message format that makes a feed's history unforgeable, together with the completeness limit an eclipse imposes. **Via the engine.** SPEC §K.5.2 |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §5 (base64url) is the encoding SSB URI data is written in, and the `-`/`_` → `+`/`/` conversion performed before a sigil reaches the sbot. §6 (base32) is the magnet info-hash alphabet this implementation refuses (`DEVIATIONS.md` KY-2). SPEC §K.5.1, §K.7.1 |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Edwards-Curve Digital Signature Algorithm (EdDSA) | Ed25519: the signature scheme behind an SSB feed id, a hypercore key and a BEP-46 `btpk` — three of the four "verified by construction" claims in this chapter are this one primitive. Used **via the engines**; no Ed25519 code is in this package. SPEC §K.4.4, §K.5.2, §K.7.8 |

## Gemini

| Identifier | Title | Used for |
|---|---|---|
| [Gemini protocol specification](https://geminiprotocol.net/docs/specification.gmi) | Project Gemini — Protocol Specification (v0.24.x) | The URI form and default port **1965**; the TLS floor (servers use TLS 1.2+); the two-digit status codes and the `<META>` line, which become the HTTP status and the content type or error body; the `10`/`11` input requests rendered as a form; the `30`/`31` redirects and the guidance that a client bound them at five; and §4.2, the **TOFU** certificate model this implementation does not implement (`DEVIATIONS.md` KY-1). SPEC §K.6 — `src/gemini-protocol.js` |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The Transport Layer Security (TLS) Protocol Version 1.3 | The transport a Gemini request runs over, terminated by Node's TLS stack. SPEC §K.6.2 — `src/gemini-protocol.js` |
| [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) | The Transport Layer Security (TLS) Protocol Version 1.2 | The floor the client sets (`minVersion: 'TLSv1.2'`), which is the Gemini specification's own minimum. SPEC §K.6.2 |
| [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) | TLS Application-Layer Protocol Negotiation Extension | The `gemini` ALPN identifier the client offers. The negotiated identifier is not enforced (`verifyAlpnId: () => true`). SPEC §K.6.2; `DEVIATIONS.md` KY-1 |
| [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) | Representation and Verification of Domain-Based Application Service Identity in PKIX | Cited for what is **not** done: no identity check of any kind is performed on a Gemini server certificate, name or otherwise (`rejectUnauthorized: false`, no store, no comparison). `DEVIATIONS.md` KY-1 |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 | **§K.6.2** — how a Gemini request survives Private mode instead of being refused: the handler is a SOCKS5 client of the device-local Tor, offering only the "no authentication" method (§3) and sending the capsule's host as address type `0x03` `DOMAINNAME` (§4), so the name is resolved inside Tor and the operating system's resolver is never asked. `../../src/socks-dial.js` (`socksDialer`, shared with the Handshake resolver's authoritative hop, the WebSocket tunnel of Chapter 11 and the Nostr relays of Chapter 6), consumed in `src/gemini-protocol.js` where the socket is built. RFC 1929's username/password method is **not** used, so nothing isolates one capsule's circuit from another's (Chapter 8, TO-3). |

<a id="not-a-standard-but-required"></a>

## Implementation dependencies

| Identifier | Title | Used for |
|---|---|---|
| [`protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron — custom scheme privileges | What `standard: true, secure: true` buys and costs: a real tuple origin, service workers, `fetch`/CORS, streaming — and URL canonicalisation, including host lowercasing. The mechanism SPEC §K.3.4 reasons about, the reason `ar://` is deliberately low-privilege while `hyper://` is not, and the reason a Gemini cross-host redirect must move the address bar (SPEC §K.6.3). `src/main.cjs` in the Wildroot tree |
| `net::GetHttpReasonPhrase()` | Chromium — `ElectronURLLoaderFactory::StartLoading` status handling | Why a status a handler returns must be one Chromium defines: an unknown code `NOTREACHED`s in the loader. This is why the Private-mode refusal is **503** — both the gate's refusal of the three peer-to-peer namespaces and Gemini's refusal when there is no Tor port to dial — and why a Gemini status is passed through `safeStatus()`. SPEC §K.3.6, §K.6.2, §K.6.4 — `src/gate.js`, `../../src/safe-status.js` |
| `../../src/delivery-mode.js` | The one switch — Settings › Content delivery › Mode | `policyFor()`, whose `p2pDiscovery` row is what §K.3.6 enforces; `privateRefusal('p2p', { label })`, the words the gate answers with; `SWITCH_HINT`, its last sentence. `../../DIVERGENCE.md` row 19 is the inventory entry. SPEC §K.3.6 — `src/gate.js` |
| `docs/RESOLUTION-ROUTER.md`, `docs/TORRENT-DESIGN.md`, `docs/Protocols.md`, `docs/Fetch-Hyper.md`, `docs/Fetch-Gemini.md`, `docs/MODES.md` | Wildroot browser design documents | The design documents this chapter is checked against, and the place the retrieval behaviour it excludes (piece selection, `Range` handling, streaming) is specified. `docs/MODES.md` is the Private/Fast design that decides which namespaces here are refused and which are routed (SPEC §K.3.6). SPEC §K.1, §K.4, §K.6, §K.7 |
