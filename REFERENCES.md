# References

Every standard, specification and document the implementation reads, with what
each is used for. **Generated from the chapter files by `scripts/build-docs.mjs`;
edit those.**

The index lists each identifier once, with the chapters that cite it. Each
chapter's own table follows, because *what a standard is used for* differs by
chapter — RFC 9110 is the tunnel's CONNECT in one chapter and a redirect rule in
another — and that column is the point of the file.

## Index

276 identifiers.

| Identifier | Title | Cited in |
|---|---|---|
| `--ignore-certificate-errors-spki-list` | Chromium command-line switch (documented in Chromium's own source; there is no specification) | Chapter 2 |
| [`../../DEVIATIONS.md`](../../DEVIATIONS.md) | Deviations and open questions | Chapter 8 |
| `../../DEVIATIONS.md` D-1, D-9, D-10 | The spine's deviations | Chapter 4 |
| [`../../namespaces/router/SPEC.md`](../router/SPEC.md) | The router chapter of this specification | Chapter 2 |
| [`../../SPEC.md`](../../SPEC.md) | The integrated specification — the spine | Chapter 8 |
| `../../SPEC.md` §3, §4 | The spine: namespace selection and trust states | Chapter 4 |
| [`../../SPEC.md` §4.2](../../SPEC.md) | The Fast / Private switch | Chapter 1, Chapter 2, Chapter 8 |
| `../../SPEC.md` §6 | The spine: the resolution algorithm | Chapter 4 |
| `../../SPEC.md` §7 | The spine: HIP-5 `_op` on-chain resolution | Chapter 4 |
| `../../SPEC.md` §10 | The spine: content pointers | Chapter 4 |
| `../../src/delivery-mode.js` | The one switch — Settings › Content delivery › Mode | Chapter 6, Chapter 7, Chapter 9, Chapter 11 |
| [@adraffy/ens-normalize](https://github.com/adraffy/ens-normalize.js) | ens-normalize.js | Chapter 5 |
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Audited elliptic-curve implementations | Chapter 6, Chapter 7 |
| [ANS-104](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md) | Bundled Data v2.0.0 (Arweave Standards) | Chapter 4 |
| [`app.configureHostResolver`](https://www.electronjs.org/docs/latest/api/app#appconfigurehostresolveroptions) | Electron API documentation | Chapter 2 |
| `ar://<txid>` | The `ar://` scheme as used by the ar.io gateway network and the Wander (formerly ArConnect) wallet — a de-facto convention, with **no RFC and no IANA registration** | Chapter 4 |
| ArNS / ANT / undername | The ar.io name system, its Arweave Name Token contract, and the `<undername>_<name>.<gateway-host>` wildcard convention ([docs.ar.io](https://docs.ar.io/)) | Chapter 4 |
| [atproto.com/specs/at-uri-scheme](https://atproto.com/specs/at-uri-scheme) | AT Protocol — AT-URI scheme | Chapter 7 |
| [atproto.com/specs/did](https://atproto.com/specs/did) | AT Protocol — DID | Chapter 7 |
| [atproto.com/specs/handle](https://atproto.com/specs/handle) | AT Protocol — Handle Resolution | Chapter 7 |
| [atproto.com/specs/repository](https://atproto.com/specs/repository) | AT Protocol — Repository | Chapter 7 |
| [atproto.com/specs/xrpc](https://atproto.com/specs/xrpc) | AT Protocol — XRPC | Chapter 7 |
| [BEP 3](https://www.bittorrent.org/beps/bep_0003.html) | The BitTorrent Protocol Specification | Chapter 9 |
| [BEP 5](https://www.bittorrent.org/beps/bep_0005.html) | DHT Protocol | Chapter 9 |
| [BEP 9](https://www.bittorrent.org/beps/bep_0009.html) | Extension for Peers to Send Metadata Files | Chapter 9 |
| [BEP 14](https://www.bittorrent.org/beps/bep_0014.html) | Local Service Discovery | Chapter 9 |
| [BEP 44](https://www.bittorrent.org/beps/bep_0044.html) | Storing Arbitrary Data in the DHT | Chapter 9 |
| [BEP 46](https://www.bittorrent.org/beps/bep_0046.html) | Updating Torrents Via DHT Mutable Items | Part II, Chapter 9 |
| [BEP 52](https://www.bittorrent.org/beps/bep_0052.html) | The BitTorrent Protocol Specification v2 | Chapter 9 |
| [BEP 53](https://www.bittorrent.org/beps/bep_0053.html) | Magnet URI extension — Select specific file indices | Chapter 9 |
| [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) | Base32 address format for native v0-16 witness outputs (Bech32) | Part II, Chapter 6 |
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | Part II, Chapter 6, Chapter 7, Chapter 11 |
| `browser docs/HANDSHAKE-APPS-MEDIATOR.md` | Wildroot, the mediator as built | Chapter 11 |
| `browser docs/MODES.md` | Wildroot, *Private mode and Fast mode* | Chapter 11 |
| `browser docs/WEBSOCKETS.md` | Wildroot, *WebSockets for Handshake apps (`wss://<name>`)* — the tunnel as built | Chapter 11 |
| [Chromium proxy documentation](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md) | Chromium, `net/docs/proxy.md` — proxy resolution, PAC evaluation, proxy bypass rules | Chapter 11 |
| [Chromium URL / scheme registry](https://chromium.googlesource.com/chromium/src/+/main/url/) | Chromium `url` library | Part II, Chapter 10 |
| [CID specification](https://github.com/multiformats/cid) | Self-describing content-addressed identifiers | Part II |
| [Contract ABI Specification](https://docs.soliditylang.org/en/latest/abi-spec.html) | Solidity documentation — Contract ABI Specification | Chapter 5 |
| [control-spec](https://spec.torproject.org/control-spec/) | Tor control protocol specification | Chapter 8 |
| [CSP Level 3](https://www.w3.org/TR/CSP3/) | Content Security Policy Level 3 | Chapter 6, Chapter 8 |
| [DEP-0002](https://github.com/datprotocol/DEPs/blob/master/proposals/0002-hypercore.md) | Hypercore (Dat Enhancement Proposal, historical) | Chapter 9 |
| [DEP-0005](https://github.com/datprotocol/DEPs/blob/master/proposals/0005-dns.md) | DNS (Dat Enhancement Proposal, historical) | Chapter 9 |
| [did:plc Method Specification v0.1](https://web.plc.directory/spec/v0.1/did-plc) | did:plc — Public Ledger of Credentials, v0.1 ([source](https://github.com/did-method-plc/did-method-plc)) | Chapter 7 |
| [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/) | did:web Method Specification, W3C Credentials Community Group draft | Chapter 7 |
| [DNSCrypt public ODoH server list](https://github.com/DNSCrypt/dnscrypt-resolvers) | DNSCrypt resolver lists | Chapter 2 |
| [DNSLink](https://dnslink.dev/) | DNSLink specification | Part II, Chapter 1, Chapter 3, Chapter 9 |
| [docs.ar.io](https://docs.ar.io/) | ar.io gateway and network documentation | Chapter 4 |
| `docs/MODES.md` (browser) | Wildroot, *Private mode and Fast mode* | Chapter 6 |
| `docs/RESOLUTION-ROUTER.md`, `docs/TORRENT-DESIGN.md`, `docs/Protocols.md`, `docs/Fetch-Hyper.md`, `docs/Fetch-Gemini.md`, `docs/MODES.md` | Wildroot browser design documents | Chapter 9 |
| `docs/SOCIAL-MULTIPROTOCOL.md` | Wildroot design record — multi-protocol social identity | Chapter 7 |
| [draft-ietf-dnsop-deleg](https://datatracker.ietf.org/doc/draft-ietf-dnsop-deleg/) | Extensible delegation for DNS | Chapter 1 |
| [draft-msporny-base58](https://datatracker.ietf.org/doc/html/draft-msporny-base58) | The Base58 Encoding Scheme | Chapter 3 |
| [EIP-55](https://eips.ethereum.org/EIPS/eip-55) | Mixed-case checksum address encoding | Chapter 5 |
| [EIP-137](https://eips.ethereum.org/EIPS/eip-137) | Ethereum Domain Name Service — Specification | Chapter 5, Chapter 10 |
| [EIP-181](https://eips.ethereum.org/EIPS/eip-181) | ENS support for reverse resolution of Ethereum addresses | Chapter 5 |
| [EIP-1191](https://eips.ethereum.org/EIPS/eip-1191) | Add chain id to mixed-case checksum address encoding | Chapter 5 |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) | contenthash field for ENS | Chapter 5 |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) / [ENSIP-7](https://docs.ens.domains/ensip/7) | contenthash field | Chapter 3, Chapter 4, Chapter 10 |
| [Electron `protocol.handle`](https://www.electronjs.org/docs/latest/api/protocol#protocolhandlescheme-handler) | Electron `protocol` API | Part II |
| [Electron `protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | Part II, Chapter 1 |
| [Electron `registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | Chapter 6, Chapter 7 |
| [ENS DNSResolver interface](https://docs.ens.domains/resolvers/interfaces) | DNS records on an ENS-shaped resolver | Chapter 10 |
| [ENS DNSSEC gasless import](https://docs.ens.domains/dns/) | ENS documentation — DNS names in ENS | Chapter 5 |
| [ENS Universal Resolver](https://docs.ens.domains/resolution/universal) | ENS documentation — Universal Resolver | Chapter 5 |
| [ENSIP-1](https://docs.ens.domains/ensip/1) | ENS | Chapter 5 |
| [ENSIP-5](https://docs.ens.domains/ensip/5) | Text Records | Chapter 5 |
| [ENSIP-7](https://docs.ens.domains/ensip/7) | Contenthash Field | Chapter 5 |
| [ENSIP-9](https://docs.ens.domains/ensip/9) | Multichain Address Resolution | Chapter 5 |
| [ENSIP-10](https://docs.ens.domains/ensip/10) | Wildcard Resolution | Chapter 5, Chapter 10 |
| [ENSIP-15](https://docs.ens.domains/ensip/15) | ENS Name Normalization Standard | Chapter 5 |
| [ENSIP-21](https://docs.ens.domains/ensip/21) | Batch Gateway Offchain Lookup | Chapter 5 |
| [ERC-3668](https://eips.ethereum.org/EIPS/eip-3668) | CCIP Read: Secure offchain data retrieval | Chapter 5 |
| [ERC-4804](https://eips.ethereum.org/EIPS/eip-4804) | Web3 URL to EVM Call Message Translation | Part II, Chapter 5 |
| [ERC-5219](https://eips.ethereum.org/EIPS/eip-5219) | Contract Resource Request Mode | Chapter 5 |
| [ERC-6821](https://eips.ethereum.org/EIPS/eip-6821) | Support ENS Name for Web3 URL | Chapter 5 |
| [ERC-7617](https://eips.ethereum.org/EIPS/eip-7617) | Chunk support for ERC-5219 mode `web3://` | Chapter 5 |
| [`eth_call`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_call) | Ethereum JSON-RPC API — `eth_call` | Chapter 5 |
| [Fetch Standard](https://fetch.spec.whatwg.org/) | Fetch — `redirect: "error"` | Chapter 6, Chapter 8 |
| [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180-4/final) | Secure Hash Standard (SHS) | Chapter 3, Chapter 4, Chapter 6, Chapter 11 |
| [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions | Chapter 8 |
| [Gemini protocol specification](https://geminiprotocol.net/docs/specification.gmi) | Project Gemini — Protocol Specification (v0.24.x) | Chapter 9 |
| [github.com/ArweaveTeam/arweave](https://github.com/ArweaveTeam/arweave) + [docs.arweave.org](https://docs.arweave.org/) | Arweave reference implementation and developer documentation — the transaction format, the `GET /tx/<id>` header endpoint, `data_root`, and the signature the id is a digest of | Chapter 4 |
| [go-unixfs balanced builder](https://github.com/ipfs/go-unixfs/blob/master/importer/balanced/builder.go) | Balanced DAG layout, and kubo's `Import.*` defaults | Chapter 3 |
| [Handshake resource format](https://hsd-dev.org/api-docs/) | The on-chain `Resource` | Chapter 1, Chapter 10 |
| Handshake-Apps standard (`HANDSHAKE-APPS.md`, v0.1 + V0.2-DELTA) | The application-mediation standard the mediator implements: the capability surface, the manifest, and the consent model | Chapter 11 |
| [HIP-0005](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) | Pseudo-TLD delegation to alternative naming systems | Chapter 1, Chapter 10 |
| [hsd](https://github.com/handshake-org/hsd) and [hsd-dev.org](https://hsd-dev.org/) | Handshake protocol implementation and documentation | Chapter 1 |
| [HTML Standard — `registerProtocolHandler`](https://html.spec.whatwg.org/multipage/system-state.html#custom-handlers) | HTML Living Standard | Part II |
| [`https://www.iana.org/domains/root/db`](https://www.iana.org/domains/root/db), machine-readable at [`https://data.iana.org/TLD/tlds-alpha-by-domain.txt`](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | IANA Root Zone Database | Chapter 2 |
| [Hypercore](https://docs.pears.com/building-blocks/hypercore) | Hypercore protocol (Holepunch / Pears documentation) | Chapter 9 |
| [Hyperdrive](https://docs.pears.com/building-blocks/hyperdrive) | Hyperdrive (Holepunch / Pears documentation) | Chapter 9 |
| [IANA root zone database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | Root Zone Database (TLD list) | Part II, Chapter 1 |
| [IANA special-use domain names](https://www.iana.org/assignments/special-use-domain-names/) | Special-Use Domain Names registry | Chapter 8 |
| [IANA URI Schemes registry](https://www.iana.org/assignments/uri-schemes/) | Uniform Resource Identifier (URI) Schemes | Part II |
| [ICANN Name Collision](https://www.icann.org/resources/pages/name-collision-2013-12-06-en) | Name Collision Resources & Information | Part II |
| ICANN New gTLD Program, next round (the programme's pages move; no stable URL is cited) | ICANN New gTLD Program | Chapter 2 |
| [ipfs/kubo](https://github.com/ipfs/kubo) | kubo (go-ipfs) | Chapter 3 |
| [IPIP-0402](https://github.com/ipfs/specs/blob/main/ipips/ipip-0402.md) | Partial CAR support on Trustless Gateways (`dag-scope`, `entity-bytes`) | Chapter 3 |
| [ipld/car (CARv1)](https://ipld.io/specs/transport/car/carv1/) | Content Addressable aRchives (CAR / CARv1) | Chapter 3 |
| [ipld/dag-cbor](https://ipld.io/specs/codecs/dag-cbor/spec/) | DAG-CBOR Specification | Chapter 3 |
| [ipld/dag-pb](https://ipld.io/specs/codecs/dag-pb/spec/) | DAG-PB Specification | Chapter 3 |
| [ipns/ipns-pubsub-router](https://specs.ipfs.tech/ipns/ipns-pubsub-router/) | IPNS PubSub Router | Chapter 3 |
| [ipns/ipns-record](https://specs.ipfs.tech/ipns/ipns-record/) | IPNS Record Specification | Chapter 3 |
| [JSON-RPC 2.0](https://www.jsonrpc.org/specification) | JSON-RPC 2.0 Specification | Chapter 5 |
| [libp2p/peer-ids](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md) | libp2p Peer Ids | Chapter 3 |
| [libp2p/pubsub](https://github.com/libp2p/specs/tree/master/pubsub) | libp2p PubSub | Chapter 3 |
| Manifest version 0.2.0 | `index.id` and `fallback` — an ar.io-side extension, no retrievable specification document | Chapter 4 |
| [Mixed Content](https://www.w3.org/TR/mixed-content/) | W3C, Mixed Content | Chapter 11 |
| [multicodec](https://github.com/multiformats/multicodec) | Multiformats — multicodec table | Chapter 5 |
| [multicodec table.csv](https://github.com/multiformats/multicodec/blob/master/table.csv) | The multicodec code table | Chapter 4 |
| [Multiformats: multicodec, unsigned-varint, CID](https://github.com/multiformats/multicodec) | Self-describing value prefixes | Chapter 10 |
| [multiformats/cid](https://github.com/multiformats/cid) | CID (Content IDentifier) Specification | Chapter 3 |
| [multiformats/multibase](https://github.com/multiformats/multibase) | Multibase | Chapter 3 |
| [multiformats/multicodec](https://github.com/multiformats/multicodec) ([table](https://github.com/multiformats/multicodec/blob/master/table.csv)) | Multicodec | Chapter 3 |
| [multiformats/multihash](https://github.com/multiformats/multihash) | Multihash | Chapter 3 |
| [multiformats/unsigned-varint](https://github.com/multiformats/unsigned-varint) | Unsigned-varint | Chapter 3 |
| `net::GetHttpReasonPhrase()` | Chromium — `ElectronURLLoaderFactory::StartLoading` status handling | Chapter 9 |
| [net.fetch](https://www.electronjs.org/docs/latest/api/net#netfetchinput-init) | Electron API — `net.fetch` | Chapter 8 |
| [nginx `ngx_http_v2_module`](https://nginx.org/en/docs/http/ngx_http_v2_module.html) | nginx, HTTP/2 module — the `http2` directive and the `listen … http2` parameter | Chapter 11 |
| [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic protocol flow description | Chapter 6, Chapter 7, Chapter 11 |
| [NIP-02](https://github.com/nostr-protocol/nips/blob/master/02.md) | Follow list (kind 3) | Chapter 6 |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Mapping Nostr keys to DNS-based internet identifiers | Chapter 6, Chapter 7, Chapter 11 |
| [NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event deletion request | Chapter 6 |
| [NIP-18](https://github.com/nostr-protocol/nips/blob/master/18.md) | Reposts (kinds 6 and 16) | Chapter 6 |
| [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md) | bech32-encoded entities | Part II, Chapter 6 |
| [NIP-21](https://github.com/nostr-protocol/nips/blob/master/21.md) | The `nostr:` URI scheme | Chapter 6 |
| [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Authentication of clients to relays | Chapter 6 |
| [NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md) | Relay list metadata (kind 10002, `r` tags) | Chapter 6 |
| [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) | Nostr — Arbitrary custom app data | Chapter 7 |
| [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) | HTTP Auth (kind 27235) | Chapter 6, Chapter 7, Chapter 11 |
| [nostr-tools `normalizeURL`](https://github.com/nbd-wtf/nostr-tools) | Relay-URL canonicalisation | Chapter 6 |
| `odoh-relay.numa.rs`, `odoh-relay.edgecompute.app` | The deployed public ODoH relays | Chapter 2 |
| [Optimism JSON-RPC](https://docs.optimism.io/) | `eth_call`, chainId 10 | Chapter 10 |
| [PAC (MDN)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file) | Proxy Auto-Configuration (PAC) file — `FindProxyForURL(url, host)` and the `PROXY` / `SOCKS5` / `DIRECT` return grammar | Chapter 11 |
| [Path Gateway](https://specs.ipfs.tech/http-gateways/path-gateway/) | Path Gateway Specification | Chapter 3 |
| [path-manifest-schema.md](https://github.com/ArweaveTeam/arweave/blob/master/doc/path-manifest-schema.md) | Arweave path manifest schema (repository document, version 0.1.0) | Chapter 4 |
| [Permissions Policy](https://www.w3.org/TR/permissions-policy/) | Permissions Policy | Chapter 8 |
| [`plc.directory`](https://plc.directory) | The did:plc directory service | Chapter 7 |
| [proposal 224](https://spec.torproject.org/proposals/224-rend-spec-ng.html) | Next-Generation Hidden Services in Tor | Chapter 8 |
| [protocol.registerSchemesAsPrivileged](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron API — privileged scheme registration | Chapter 8, Chapter 9 |
| [public.api.bsky.app](https://docs.bsky.app/) | Bluesky public AppView | Chapter 7 |
| [RangerMauve/js-ipfs-fetch](https://github.com/RangerMauve/js-ipfs-fetch) | js-ipfs-fetch | Chapter 3 |
| [Referrer Policy](https://www.w3.org/TR/referrer-policy/) | Referrer Policy | Chapter 8 |
| [rend-spec-v3](https://spec.torproject.org/rend-spec/) | Tor Rendezvous Specification — Version 3 | Chapter 8 |
| [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) | Domain names — concepts and facilities | Chapter 1 |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain names — implementation and specification | Chapter 1, Chapter 4, Chapter 5, Chapter 7, Chapter 10 |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) §3.3.14 | Domain Names — Implementation and Specification | Chapter 3 |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) §4.1 | Domain Names — Implementation and Specification | Chapter 2 |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for Internet Hosts — Application and Support | Part II, Chapter 6, Chapter 7, Chapter 10 |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) §2.1 | Requirements for Internet Hosts — Application and Support | Chapter 2 |
| [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) | Address Allocation for Private Internets | Chapter 2 |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS protocol version 5 | Chapter 1, Chapter 6, Chapter 8, Chapter 9, Chapter 11 |
| [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) | Username/Password Authentication for SOCKS V5 | Chapter 8, Chapter 11 |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Key words for use in RFCs to Indicate Requirement Levels | Chapter 2, Chapter 7, Chapter 11 |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) · [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs | Chapter 6 |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs | Part II, Chapter 5 |
| [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) | Clarifications to the DNS specification | Chapter 1, Chapter 4 |
| [RFC 2397](https://www.rfc-editor.org/rfc/rfc2397) | The "data" URL scheme | Chapter 11 |
| [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) | Reserved Top Level DNS Names | Part II |
| [RFC 3110](https://www.rfc-editor.org/rfc/rfc3110) | RSA/SHA-1 SIGs and RSA keys in the DNS | Chapter 1 |
| [RFC 3172](https://www.rfc-editor.org/rfc/rfc3172) | Management Guidelines for the ".arpa" Domain | Part II |
| [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596) | DNS extensions to support IPv6 (AAAA) | Chapter 1 |
| [RFC 3927](https://www.rfc-editor.org/rfc/rfc3927) | Dynamic Configuration of IPv4 Link-Local Addresses | Chapter 2 |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | Part II, Chapter 4, Chapter 6, Chapter 7, Chapter 9, Chapter 11 |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) §3.3 | Uniform Resource Identifier (URI): Generic Syntax | Chapter 3 |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS security introduction and requirements | Chapter 1, Chapter 2, Chapter 7, Chapter 9 |
| [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) | Resource records for the DNS security extensions | Chapter 1 |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) | Protocol modifications for the DNS security extensions | Chapter 1, Chapter 2, Chapter 7 |
| [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) | Unique Local IPv6 Unicast Addresses | Chapter 2 |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | DNS case insensitivity clarification | Chapter 1, Chapter 2, Chapter 9 |
| [RFC 4509](https://www.rfc-editor.org/rfc/rfc4509) | Use of SHA-256 in DNSSEC delegation signer (DS) resource records | Chapter 1 |
| [RFC 4592](https://www.rfc-editor.org/rfc/rfc4592) | The role of wildcards in the DNS | Chapter 1 |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32 and Base64 data encodings | Chapter 1, Chapter 4, Chapter 7, Chapter 9 |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) §6 | The Base16, Base32, and Base64 Data Encodings | Chapter 3, Chapter 8 |
| [RFC 5011](https://www.rfc-editor.org/rfc/rfc5011) | Automated updates of DNSSEC trust anchors | Chapter 1 |
| [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155) | DNSSEC hashed authenticated denial of existence (NSEC3) | Chapter 1 |
| [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) | The Transport Layer Security (TLS) Protocol Version 1.2 | Chapter 9 |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | Internet X.509 public key infrastructure certificate and CRL profile | Chapter 1, Chapter 2, Chapter 6 |
| [RFC 5702](https://www.rfc-editor.org/rfc/rfc5702) | Use of SHA-2 algorithms with RSA in DNSKEY and RRSIG | Chapter 1 |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) | IPv4 address blocks reserved for documentation | Chapter 1, Chapter 5, Chapter 7 |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based extract-and-expand key derivation function (HKDF) | Chapter 1, Chapter 2 |
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | IDNA2008: Definitions and Document Framework | Part II, Chapter 1, Chapter 2, Chapter 6 |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | IDNA2008: Protocol | Part II, Chapter 1, Chapter 2 |
| [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) | Transport Layer Security (TLS) Extensions: Extension Definitions — §3, Server Name Indication | Chapter 6 |
| [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) | Representation and Verification of Domain-Based Application Service Identity in PKIX | Chapter 9 |
| [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265) | HTTP State Management Mechanism | Chapter 8 |
| [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454) | The Web Origin Concept | Chapter 11 |
| [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) | The WebSocket Protocol | Chapter 6, Chapter 11 |
| [RFC 6598](https://www.rfc-editor.org/rfc/rfc6598) | IANA-Reserved IPv4 Prefix for Shared Address Space | Chapter 2 |
| [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605) | Elliptic curve digital signature algorithm (DSA) for DNSSEC | Chapter 1 |
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | The DNS-based authentication of named entities (DANE) transport layer security protocol: TLSA | Chapter 1, Chapter 2, Chapter 11 |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | The OAuth 2.0 Authorization Framework: Bearer Token Usage | Chapter 11 |
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | Part II, Chapter 1, Chapter 2, Chapter 8, Chapter 11 |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | Part II, Chapter 1, Chapter 2, Chapter 11 |
| [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) | HTTP Strict Transport Security (HSTS) | Chapter 8 |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-purpose IP address registries | Chapter 1, Chapter 2, Chapter 5, Chapter 7, Chapter 11 |
| [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891) | Extension mechanisms for DNS (EDNS(0)) | Chapter 1 |
| [RFC 7033](https://www.rfc-editor.org/rfc/rfc7033) | WebFinger | Chapter 7 |
| [RFC 7034](https://www.rfc-editor.org/rfc/rfc7034) | HTTP Header Field X-Frame-Options | Chapter 8 |
| [RFC 7235](https://www.rfc-editor.org/rfc/rfc7235) | HTTP/1.1: Authentication | Chapter 11 |
| [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) | TLS Application-Layer Protocol Negotiation Extension | Chapter 9 |
| [RFC 7469](https://www.rfc-editor.org/rfc/rfc7469) §2.4 | Public Key Pinning Extension for HTTP | Chapter 2 |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and Registration Procedures for URI Schemes | Part II, Chapter 1, Chapter 4, Chapter 6 |
| [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617) | The 'Basic' HTTP Authentication Scheme | Chapter 11 |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | The DANE protocol: updates and operational guidance | Chapter 1, Chapter 2, Chapter 11 |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The ".onion" Special-Use Domain Name | Part II, Chapter 1, Chapter 2, Chapter 8, Chapter 11 |
| [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) | DNS transport over TCP | Chapter 1 |
| [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) | DNS over TLS (DoT) | Chapter 2 |
| [RFC 7929](https://www.rfc-editor.org/rfc/rfc7929) | DNS-based authentication of named entities (DANE) bindings for OpenPGP | Chapter 1 |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Edwards-Curve Digital Signature Algorithm (EdDSA) | Chapter 8, Chapter 9 |
| [RFC 8080](https://www.rfc-editor.org/rfc/rfc8080) | Edwards-curve DSA for DNSSEC | Chapter 1 |
| [RFC 8141](https://www.rfc-editor.org/rfc/rfc8141) | Uniform Resource Names (URNs) | Chapter 9 |
| [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | Chapter 2, Chapter 7, Chapter 11 |
| [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) | The JavaScript Object Notation (JSON) Data Interchange Format | Chapter 6 |
| [RFC 8310](https://www.rfc-editor.org/rfc/rfc8310) | Usage Profiles for DNS over TLS and DTLS | Chapter 2 |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-Use Domain 'home.arpa.' | Part II, Chapter 1, Chapter 2, Chapter 11 |
| [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441) | Bootstrapping WebSockets with HTTP/2 | Chapter 11 |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The transport layer security (TLS) protocol version 1.3 | Chapter 1, Chapter 2, Chapter 6, Chapter 9 |
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS queries over HTTPS (DoH) | Chapter 1, Chapter 2, Chapter 9 |
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS Terminology | Part II, Chapter 1, Chapter 2 |
| [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) | Well-Known Uniform Resource Identifiers | Chapter 2, Chapter 7 |
| [RFC 8624](https://www.rfc-editor.org/rfc/rfc8624) | Algorithm implementation requirements for DNSSEC | Chapter 1 |
| [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) | Extended DNS Errors | Chapter 1 |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP semantics | Chapter 1, Chapter 2, Chapter 4, Chapter 5, Chapter 6, Chapter 7, Chapter 8, Chapter 11 |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) §14 | HTTP Semantics — Range Requests | Chapter 3 |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) | HTTP/1.1 (message syntax and routing) | Chapter 11 |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) | HTTP/2 | Chapter 11 |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) | Hybrid public key encryption | Chapter 1, Chapter 2 |
| [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230) | Oblivious DNS over HTTPS | Chapter 1, Chapter 2 |
| [RFC 9276](https://www.rfc-editor.org/rfc/rfc9276) | Guidance for NSEC3 parameter settings | Chapter 1 |
| [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) | Service binding and parameter specification via the DNS (SVCB and HTTPS RRs) | Chapter 1, Chapter 2 |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) | Discovery of designated resolvers | Chapter 1, Chapter 2 |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | Part II, Chapter 1, Chapter 5, Chapter 6, Chapter 7 |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) §9.10 | The GNU Name System | Chapter 3, Chapter 8 |
| [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) | TLS encrypted client hello | Chapter 1, Chapter 2 |
| [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/) | Scuttlebutt Protocol Guide | Chapter 9 |
| [SearXNG](https://docs.searxng.org/) | SearXNG documentation | Part II |
| [SEC 2](https://www.secg.org/sec2-v2.pdf) | Recommended Elliptic Curve Domain Parameters — §2.4.1, secp256k1 | Chapter 6 |
| [Secure Contexts](https://www.w3.org/TR/secure-contexts/) | W3C, Secure Contexts | Chapter 11 |
| [Service Workers](https://www.w3.org/TR/service-workers/) | W3C, Service Workers | Chapter 11 |
| [session.setProxy](https://www.electronjs.org/docs/latest/api/session#sessetproxyconfig) | Electron API — session proxy configuration, `proxyBypassRules` | Chapter 8 |
| [SSAC SAC113](https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac-113-en.pdf) | SSAC Advisory on Private-Use TLDs | Part II |
| [ssb-uri-spec](https://github.com/ssb-ngi-pointer/ssb-uri-spec) | SSB URI Specification | Chapter 9 |
| `STORAGE-PUBLISH-SHARE.md` decision **D-P2** (as amended) | The stated origin: what `car=` is for | Chapter 3 |
| The bundled mainnet chain entry | `web3protocol/chains`, `chainId` 1 | Chapter 5 |
| [The NIPs repository](https://github.com/nostr-protocol/nips) | Nostr Implementation Possibilities | Chapter 6 |
| The spine: [`../../SPEC.md`](../../SPEC.md), [`../../DEVIATIONS.md`](../../DEVIATIONS.md), [`../../REFERENCES.md`](../../REFERENCES.md) | The integrated specification | Chapter 3 |
| [Tor Browser design](https://2019.www.torproject.org/projects/torbrowser/design/) | The Design and Implementation of the Tor Browser | Chapter 8 |
| [Tor Expert Bundle](https://www.torproject.org/download/tor/) | Tor Project download page — the expert bundle | Chapter 8 |
| [Tor Rendezvous Specification v3](https://spec.torproject.org/rend-spec-v3) | Tor Rendezvous Specification — Version 3 | Part II |
| [tor-man](https://spec.torproject.org/tor-man/) | Tor manual — `SocksPort`, `ClientOnly`, `AvoidDiskWrites`, `IsolateSOCKSAuth`, `ClientOnionAuthDir` | Chapter 8 |
| [Trustless Gateway](https://specs.ipfs.tech/http-gateways/trustless-gateway/) | Trustless Gateway Specification | Chapter 3 |
| [UNIXFS.md](https://github.com/ipfs/specs/blob/main/UNIXFS.md) | UnixFS Data Format | Chapter 3 |
| [unsigned-varint](https://github.com/multiformats/unsigned-varint) | Unsigned variable-length integer (multiformats) | Chapter 4 |
| [Urkel tree](https://github.com/handshake-org/urkel) | The authenticated data structure | Chapter 1 |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | Part II, Chapter 1, Chapter 2, Chapter 5 |
| [v2 deprecation timeline](https://blog.torproject.org/v2-deprecation-timeline) | Tor Project, "Onion Service version 2 deprecation timeline" | Chapter 8 |
| [viem](https://viem.sh/) | viem — TypeScript interface for Ethereum | Chapter 5 |
| [W3C ActivityPub](https://www.w3.org/TR/activitypub/) | ActivityPub, W3C Recommendation 23 January 2018 | Chapter 7 |
| [W3C ActivityStreams 2.0](https://www.w3.org/TR/activitystreams-core/) | Activity Streams 2.0 Core | Chapter 7 |
| [W3C Controller Documents](https://www.w3.org/TR/controller-document/) | Controller Documents 1.0 (Multikey) | Chapter 7 |
| [W3C DID Core](https://www.w3.org/TR/did-core/) | Decentralized Identifiers (DIDs) v1.0 | Part II |
| [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) | Decentralized Identifiers (DIDs) v1.0, W3C Recommendation 19 July 2022 | Chapter 7 |
| [W3C DID Specification Registries](https://www.w3.org/TR/did-spec-registries/) | DID Specification Registries, W3C Group Note | Chapter 7 |
| [web3protocol](https://github.com/web3-protocol/web3protocol-js) | web3protocol-js | Chapter 5 |
| [WHATWG Fetch](https://fetch.spec.whatwg.org/) | Fetch Living Standard | Part II, Chapter 7, Chapter 11 |
| [WHATWG HTML](https://html.spec.whatwg.org/multipage/) | HTML Standard | Chapter 11 |
| [WHATWG URL](https://url.spec.whatwg.org/) | URL Standard | Chapter 8, Chapter 11 |
| [WHATWG URL](https://url.spec.whatwg.org/) ([host parsing](https://url.spec.whatwg.org/#host-parsing)) | URL Living Standard | Chapter 3 |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | Part II, Chapter 1, Chapter 4, Chapter 5, Chapter 6, Chapter 7, Chapter 9, Chapter 10 |
| [WHATWG URL Standard — ends-in-a-number checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) | URL Standard, IPv4 parsing | Chapter 2 |
| [WHATWG URL Standard §host parsing](https://url.spec.whatwg.org/#host-parsing) | URL Standard | Chapter 2 |
| [WHATWG WebSockets](https://websockets.spec.whatwg.org/) | WebSockets Standard (the `WebSocket` interface) | Chapter 6 |
| [`ws`](https://github.com/websockets/ws) | WebSocket client and server for Node.js | Chapter 6 |
| [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) | Human-oriented base-32 encoding (Zooko O'Whielacronx) | Chapter 9 |

---

## Part II — Namespace selection

_Source: [`namespaces/router/REFERENCES.md`](namespaces/router/REFERENCES.md)._

Every standard the router and classifier actually read, with what it is used
for and where in the tree it is used. Nothing is listed that the code does not
touch: a padded bibliography is worse than none, because it makes the real
dependencies impossible to see.

This file is scoped to the routing spine. The standards the *resolution* of a
Handshake name rests on — DNSSEC, DANE, DoH, HIP-5 — are in the spine's
[`REFERENCES.md`](REFERENCES.md) and are not repeated. Where a row says
*not used* or *deliberately not followed*, that is the point of the row: it is
listed because [`DEVIATIONS.md`](DEVIATIONS.md) has to cite it.

Paths are relative to the repository root.

---

### Naming

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

### URI and URL syntax

| Identifier | Title | Used for |
|---|---|---|
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | §3.1 is the scheme grammar the explicit-scheme test implements (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, case-insensitive) and why `https+raw` is a syntactically legal scheme name; §3.2.1 is the `userinfo@host` rule that makes a stray `@` in a scheme-less input a search rather than a name; §3.2.2/§3.2.3 are why `example.com:8080` has to be told apart from a scheme (RT-4) and why an IPv6 literal is bracketed in the URL built for it. SPEC §2, §3.1, §6.1 · `src/router.js` `hasExplicitScheme` |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | What a scheme *becomes* when it is registered as standard: [special schemes](https://url.spec.whatwg.org/#special-scheme), [host parsing](https://url.spec.whatwg.org/#host-parsing), a tuple [origin](https://url.spec.whatwg.org/#concept-url-origin). Registering `hns:` as standard and accepting the host parser's rules are one decision (RT-13); a non-standard scheme's opaque origin is never a secure context, which is the honest posture for `ar://` and `ens://`. Its ["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) are why a standard scheme cannot carry an all-numeric final label (`hns://14898/` canonicalises to `hns://0.0.58.50/`); the constraint that places on the classifier is SPEC §8.2 and the URL form that works around it is Chapter 10 Part B's. Its bracket rule for IPv6 authorities is why the web-namespace URL builder brackets an unbracketed literal. SPEC §4.4, §6.1, §8 · `src/router.js`, `src/hns-url.cjs` |
| [WHATWG Fetch](https://fetch.spec.whatwg.org/) | Fetch Living Standard | The dispatcher's interface: a `Request` in, a `Response` out, so it runs identically under `node --test` and under Electron. `Request` refuses to construct from an unparseable URL, which is why the 400 branch is reachable only from a non-`Request` caller (RT-12). SPEC §5 · `src/router.js` `ProtocolRouter.dispatch` |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and Registration Procedures for URI Schemes | The procedure a new scheme is expected to go through, and the low bar for a **Provisional** registration. **We have not gone through it** for any scheme we invented (RT-6, RT-D4). Listed so the deviation has a citation. SPEC §4.2 |
| [IANA URI Schemes registry](https://www.iana.org/assignments/uri-schemes/) | Uniform Resource Identifier (URI) Schemes | Checked, not assumed: the "IANA" column of SPEC §4.2 is this registry's own status field. Of the 32 schemes in the table, 2 are Permanent, 11 Provisional, 19 unregistered. SPEC §4.2, RT-6 |
| [HTML Standard — `registerProtocolHandler`](https://html.spec.whatwg.org/multipage/system-state.html#custom-handlers) | HTML Living Standard | Where the `web+` scheme prefix is defined: a web *page* may register a handler only for a safelisted scheme or one beginning `web+`. Inapplicable to a scheme a browser implements natively, which is the answer RT-6 gives. Cited for the deviation, not used. RT-6 |

### Internationalized labels

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | IDNA2008: Definitions and Document Framework | The A-label / U-label vocabulary SPEC §8.1 uses. SPEC §8.1 |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | IDNA2008: Protocol | A Unicode host is converted to A-labels **before** the ICANN comparison, so `пример.рф` reaches the punycode list as `xn--e1afmkfd.xn--p1ai` and an emoji label comes out the other way. Also the standard RT-11 departs from: a label that fails validation is to be rejected, not used unconverted. SPEC §8.1 · `src/classify-host.cjs` `asciiTld` |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | What the URL Standard actually requires, and therefore what the conversion actually is. It and IDNA2008 differ on the deviation characters and on transitional processing; the difference is unaudited (spine `D-17`, RT-11). SPEC §8.1 · `src/classify-host.cjs` `asciiTld` |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for Internet Hosts — Application and Support | §2.1, host label syntax: the reason a Handshake label can never contain `_`, which is what makes Chapter 10's experimental numeric-TLD marker unambiguous. SPEC §8.2 · `src/hns-url.cjs` |

### Namespaces the router routes into

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

### Browser integration

| Identifier | Title | Used for |
|---|---|---|
| [Electron `protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | The declaration that makes a custom scheme exist at all. It must run before application startup, and a dispatched-but-undeclared scheme is unknown to the URL parser. The `standard`, `secure`, `allowServiceWorkers`, `supportFetchAPI`, `corsEnabled`, `bypassCSP` and `stream` flags are the ones SPEC §4.4 tabulates. SPEC §4.4, RT-D1 |
| [Electron `protocol.handle`](https://www.electronjs.org/docs/latest/api/protocol#protocolhandlescheme-handler) | Electron `protocol` API | How a scheme is bound to a handler. Every scheme is bound to **one** dispatcher rather than to its own handler, which is what makes the dispatcher the enforcement point for L1/L2 rather than a convention each handler is trusted to keep. SPEC §5 |
| [Chromium URL / scheme registry](https://chromium.googlesource.com/chromium/src/+/main/url/) | Chromium `url` library | The implementation of the URL Standard behind all of the above. A registered standard scheme cannot opt out of IPv4 host parsing, which is what makes the numeric-label problem structural rather than a bug to be reported. SPEC §4.4, §8.2 |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs | The meaning of MUST, MUST NOT, SHOULD, SHOULD NOT and MAY throughout this part. SPEC, Contents |


---

## Chapter 1 — Handshake

_Source: [`namespaces/handshake/REFERENCES.md`](namespaces/handshake/REFERENCES.md)._

Every standard this chapter's implementation actually reads, with what it is
used for and where. Nothing is listed that the code does not touch: a padded
bibliography is worse than none, because it makes the real dependencies
impossible to see. Where a row says *parsed, not queried* or *not implemented*,
that is the row's point.

Module paths are relative to this file: `../../src/` is this chapter's
reference implementation.

### DNS: messages, terminology, transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) | Domain names — concepts and facilities | §6.5c, the rule that tells a **referral** from a **NODATA** (§4.3.2: NS in AUTHORITY with no SOA is a referral), which is what makes the registry-TLD walk possible; §6.5f, §3.6.2 — a CNAME stands alone, so a validated CNAME needs no separate NSEC proving the `A` absent. §HS-15 cites it for the NS set. `../../src/resolver.js` (`referralIn`, the CNAME branch of `_fromZone`) |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain names — implementation and specification | The wire format used throughout §6: header, question, name compression, RR encoding. **§3.3.14** is the TXT rule of §10: a record's `<character-string>`s are **one** value, concatenated, and separate records are separate values — applied identically to the pointer TXT at the name, to the DNSLink TXT at `_dnslink.<name>` (§10.1), on the DoH route and on the `_op` route, so one record cannot mean different things on different paths. It is also why a pointer over 255 bytes is read at all. `../../src/dns-query.js`, `../../src/pointers.js` (`txtStringsFrom`) |
| [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) | Clarifications to the DNS specification | §5.2 TTL rules, cited by the caching deviation of §6.8. `../../src/resolver.js` — see HS-1 |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | DNS case insensitivity clarification | Owner names are compared case-insensitively and trailing-dot-stripped wherever a comparison happens, including the question-section check of §6.10. `../../src/resolver.js`, `../../src/dns-query.js`, `../../src/nsec.js`, `../../src/dnssec.js` |
| [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891) | Extension mechanisms for DNS (EDNS(0)) | The OPT pseudo-record of §6.5, emitted solely to carry the DO bit. **Partial**: not read back, no large-UDP advertisement (UDP is never used), no extended RCODEs. `../../src/dns-query.js` — see HS-11 |
| [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) | DNS transport over TCP | Queries in §6 go over **TCP always**, which is why the truncation (TC) rule is moot here by construction rather than unhandled. `../../src/dns-query.js` |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS protocol version 5 | §6.11: the `dial` seam. A CONNECT request (`no authentication` method only) to a device-local SOCKS port carries the authoritative TCP query of §6.5 while an anonymizing proxy is on, so the chain proof and the DNSSEC validation are kept rather than traded away. A dotted quad goes out as ATYP `0x01`; anything else as ATYP `0x03`, a domain name, resolved by the proxy and never locally. §8.1: in Private mode the same dialler carries the A-record site's TLS socket, **by address** (ATYP `0x01`), so Tor learns an IP and no name while the DANE pin is checked on that handshake. Which proxy, and what it is worth, is Chapter 8. `../../src/socks-dial.js`, `../../src/dns-query.js` (`query`'s `dial` option), `../../src/dane-connect.js` (`connectDane`'s and `connectPlain`'s `dial`) |
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS terminology | The vocabulary of §2: *authoritative server*, *zone cut*, *delegation*, *referral*, *NODATA*, *validating resolver*, *insecure delegation*, *bailiwick*. §2 |
| [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596) | DNS extensions to support IPv6 (AAAA) | **Not implemented.** Listed because its absence is a documented gap: §6.5f reads only `A`. HS-2 |
| [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) | Extended DNS Errors | **Not implemented.** Would improve the failure reporting of §6.9 and §11.1. HS-11 |
| [draft-ietf-dnsop-deleg](https://datatracker.ietf.org/doc/draft-ietf-dnsop-deleg/) | Extensible delegation for DNS | **Watched, not implemented**; the RR type is not allocated at IANA, so nothing can interoperate. HS-11 |

### DNSSEC

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

### TLS and certificates

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | The DNS-based authentication of named entities (DANE) transport layer security protocol: TLSA | §8: the TLSA record and its four parameters. One profile is implemented — usage 3 (DANE-EE), selector 1 (SPKI), matching type 1 (SHA-256). §3 gives the owner-name form `_<port>._tcp.<host>`; `_443._tcp` is always used (HS-6). The check is the same on both routes of §8.1 — direct, or through the device-local Tor by address — because `connectDane` hands `verifyDane` the peer certificate of whichever socket carried the handshake. `../../src/dane.js`, `../../src/resolver.js`, `../../src/dane-connect.js` |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | The DANE protocol: updates and operational guidance | §8: §4.1 unusable TLSA records (deviation, HS-5), §5.1 DANE-EE ignores PKIX expiry (followed deliberately), §7.2 the TLSA base domain across a CNAME, §8.1 operator key rotation and what a client does on a mismatch (HS-12). The pin is applied on the one handshake the request rides, whichever route carried it (this chapter's §8.1), and the socket is never pooled. `../../src/dane.js`, `../../src/resolver.js`, `../../src/dane-connect.js` |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | Internet X.509 public key infrastructure certificate and CRL profile | §8, only to **parse** a certificate and extract its SubjectPublicKeyInfo for hashing. No chain is built and no CA is consulted on the `hns://` path — that is the point of DANE-EE. `../../src/dane.js` (Node `X509Certificate`) |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The transport layer security (TLS) protocol version 1.3 | §8, §8.1: the transport an `hns://` fetch runs over, terminated by Node's TLS stack; the peer certificate it yields is what the pin is checked against. `connectDane` sets `servername` to the Handshake name, turns PKIX verification off, and layers the handshake over a direct socket or the SOCKS tunnel alike. `../../src/dane-connect.js`; the request written over it is the composition layer's (DEVIATIONS §4) |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP semantics | §8: the application protocol carried over that connection, and the semantics of the status codes the resolution layer reports. The composition layer |

### Encrypted DNS transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS queries over HTTPS (DoH) | §9.1: wire-format DoH, GET with `?dns=<base64url>` and `application/dns-message`; §4.1 is why the message id is fixed at zero and the question section is the only binding (§6.10). Several Handshake DoH servers reject POST, which is why GET is used. §9.3: the plain transport is used in Fast mode only; in Private it is never taken (`DoHResolver`'s `strictOblivious`). `../../src/doh.js` |
| [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230) | Oblivious DNS over HTTPS | §9.2: §6 the message format and HPKE parameters, §6.3 the response AEAD key derivation from the HPKE exporter secret plus a target-chosen nonce, and the ODoH configuration record. §9.3: in Private mode the only transport a Handshake name may take over DoH. `../../src/odoh.js`, `../../src/odoh-bridge.js` |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) | Hybrid public key encryption | §9.2: the construction ODoH is built on — X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM, over WebCrypto. `../../src/odoh.js` |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based extract-and-expand key derivation function (HKDF) | §9.2: §2.2/§2.3 extract-and-expand over WebCrypto HMAC-SHA256, for the ODoH response key and nonce. `../../src/odoh.js` |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) | Discovery of designated resolvers | **Not implemented**; an available upgrade not taken. HS-11 |

### Service binding, ECH, and records read but not queried

| Identifier | Title | Used for |
|---|---|---|
| [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) | Service binding and parameter specification via the DNS (SVCB and HTTPS RRs) | §2.2 the RDATA format. A complete parser exists — SvcPriority, TargetName, `alpn`, `port`, `ipv4hint`, and the `ech` SvcParam — tested against real Cloudflare rdata. **Type 65 is never queried during resolution.** `../../src/dns-query.js`, `../../tests/svcb.test.js` — HS-3 |
| [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) | TLS encrypted client hello | The reason the SVCB parser exists; blocked on the record not being queried *and* on Node exposing no ECH option. HS-3, §11.6 |
| [RFC 7929](https://www.rfc-editor.org/rfc/rfc7929) | DNS-based authentication of named entities (DANE) bindings for OpenPGP | RR type 61 is parsed (§2.3: the whole RDATA is the transferable public key). Used by the browser's mail client, not by resolution; it lives in the DNS client because that is the only one in the tree. `../../src/dns-query.js` |

### Special-use and reserved names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-use domain names | §3: `localhost` (the whole subtree), `invalid`, `test`, `example` are never Handshake names. `../../src/reserved-names.cjs`, consulted by `../../src/router.js` |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | §3: `local` is mDNS. Without this carve-out every NAS and printer name on a home network would be sent to whoever registers the Handshake TLD `local`. `../../src/reserved-names.cjs` |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The `.onion` special-use domain name | §3: `onion` is Tor's, never Handshake's, on every path. `../../src/reserved-names.cjs`, `../../src/router.js` (the Tor test runs first) |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-use domain `home.arpa.` | §3: together with `arpa`, `internal`, `home`, `lan`, `corp`, `intranet`, `private` — the labels home routers and corporate networks actually use. `../../src/reserved-names.cjs` |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) | IPv4 address blocks reserved for documentation | §11.2: the documentation addresses (`203.0.113.0/24`) used throughout the test fixtures. `../../tests/fixtures/resolver/` |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-purpose IP address registries | §11.2: the registry the SSRF guard rejects — loopback, private, link-local (including `169.254.169.254`), CGNAT, benchmarking, multicast, reserved, and the IPv6 equivalents. `../../src/safe-address.js` |

### Internationalized names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | Internationalized domain names for applications (IDNA): definitions and document framework | §3: a Unicode host is converted to A-labels before it reaches the resolver or the ICANN comparison, so a name is compared in one canonical form. `../../src/router.js` — see HS-14 |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | Internationalized domain names in applications (IDNA): protocol | §3: what IDNA2008 requires, and what is therefore *not* what this implementation performs. HS-14 |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA compatibility processing | §3: what the WHATWG URL Standard actually requires, and therefore what the conversion actually is. `../../src/router.js` — HS-14 |

### Handshake

| Identifier | Title | Used for |
|---|---|---|
| [hsd](https://github.com/handshake-org/hsd) and [hsd-dev.org](https://hsd-dev.org/) | Handshake protocol implementation and documentation | §6.1, §6.11, §11.5: the SPV node — header sync, `getnameresource`, and the Urkel tree proof verified against the committed tree root in a verified header; `--proxy` is how the node's own peer traffic is put through a SOCKS proxy, and `--memory` the backend used where no native LevelDB build is available, which is what makes the restart of HS-16 a full re-sync. hsd is an optional runtime dependency, spawned as a child process. `../../src/spv.js`, `../../src/hsd-spv-launcher.cjs` |
| [Handshake resource format](https://hsd-dev.org/api-docs/) | The on-chain `Resource` | §2, §6.1–§6.4: what a name's chain record can carry — `NS`, `GLUE4`/`GLUE6`, `SYNTH4`/`SYNTH6`, `DS`, `TXT`. The `DS` is the anchor this design substitutes for the ICANN root. `../../src/resolver.js` |
| [Urkel tree](https://github.com/handshake-org/urkel) | The authenticated data structure | §11.5: what the name proof is against. Via hsd |
| [HIP-0005](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) | Pseudo-TLD delegation to alternative naming systems | §6.3: why an `NS` target under a `_<chain>` pseudo-TLD is not a host and is removed from the nameserver list. The `_op` route itself is Chapter 10; `_eth` is not implemented (HS-13). `../../src/resolver.js` |

### URL and browser integration

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Standard | §5: a *standard* (special) scheme's host is parsed by the host parser, which is what makes `hns://` a real web origin and also what constrains the host form. The numeric-label consequence is Chapter 10, Part B. `../../src/router.js` |
| [Electron `protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron protocol API | §5: registering `hns:` as a **standard**, **secure** scheme is what buys origins, `fetch`, service workers and secure-context features — and is the same decision that subjects the host to the URL Standard's parsing. The browser's `main.cjs`, not in this tree |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and registration procedures for URI schemes | §3.8, the provisional registration `hns:` does not yet have. HS-D2 |

### Not standards, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [DNSLink](https://dnslink.dev/) | The `_dnslink.<name> TXT dnslink=/ipfs/<cid>` convention | §10.1: the **second pointer source**, and the reason a site published for kubo, IPFS Companion or Brave opens here unchanged. Defines the `_dnslink.` owner prefix, the `dnslink=/<namespace>/<address>[/path]` value grammar and the one-value-per-name rule this implementation reads it by; only `/ipfs/` and `/ipns/` are pointers here. Read on both routes, under the same DNSSEC and proven-absence rules as the pointer at the name (§6.5d–e), and written at publish beside `ipfs=`. `../../src/pointers.js` (`parseDnslink`, `dnslinkPointerFrom`, `mergePointers`, `dnslinkValue`, `dnslinkOwner`), `../../src/resolver.js` (`_fromZone`), `../../src/doh.js` |
| [IANA root zone database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | Delegated top-level domains | §3: the ICANN snapshot that decides ICANN-vs-Handshake for every name, checked against the live list by a network test in the browser tree. `../../src/icann-tlds.cjs` |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | §3, §9.10: namespace precedence — resolve in the alternative namespace when its suffix matches, and do not continue into DNS on failure. Adopted as a normative rule because it is the only place this is written down in an RFC. `../../src/router.js` |
| [`SPEC.md` §4.2](SPEC.md) | The Fast / Private switch | §4.1, §8.1, §9.3, §10.2, §11.6: the one control whose policy table (`policyFor`) this chapter's consumers read — `strictOblivious` for the DoH resolver, the route for the site socket and the pointer decisions — and the one builder of every mode-caused page, `privateRefusal('lookup' \| 'site' \| 'ipfs' \| 'p2p')`. The disclosure the control carries is `DISCLOSURE`, in full. `../../src/delivery-mode.js`, `../../tests/delivery-mode.test.js` |


---

## Chapter 2 — ICANN names

_Source: [`namespaces/icann/REFERENCES.md`](namespaces/icann/REFERENCES.md)._

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

### The registry, and how it is vendored

| Identifier | Title | Used for |
|---|---|---|
| [`https://www.iana.org/domains/root/db`](https://www.iana.org/domains/root/db), machine-readable at [`https://data.iana.org/TLD/tlds-alpha-by-domain.txt`](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | IANA Root Zone Database | §2.1, §2.4 — the whole of the ICANN/Handshake boundary. Fetched at build time, parsed and rendered into a committed `Set` of A-labels carrying IANA's own `Version`/`Last Updated` line: `../../src/icann-tlds.cjs` (1,438 labels, version 2026090500), `src/icann-tld-snapshot.js`, `tests/icann-tld-snapshot.test.js`; the browser's `scripts/fetch-icann-tlds.mjs` and its drift alarm `tests/hns/icann-tlds-live.test.js`. |
| ICANN New gTLD Program, next round (the programme's pages move; no stable URL is cited) | ICANN New gTLD Program | §2.4, §9.1 — why the snapshot's staleness is a growing risk rather than a static one: roughly 1,600 applications in the 2026 round, each delegation converting a string that resolves as a Handshake name today into an ICANN TLD. `DEVIATIONS.md` IC-1. |

### Names that belong to neither root

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | §4 — `localhost` (§6.3: the **whole subtree**, so `app.localhost` too), `invalid`, `test` and `example` are never Handshake names, and none is in the IANA set. `../../src/reserved-names.cjs`, consulted at row 4 of `classifyHost` (`../../src/classify-host.cjs:87-116`). |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | §4 — `local` is mDNS's. Without the carve-out, every NAS, printer and Home Assistant name on a home network is sent to whoever registers the Handshake top-level name `local`. `../../src/reserved-names.cjs`. |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The `.onion` Special-Use Domain Name | §2.2 row 2 — `onion` is Tor's, never Handshake's and never ICANN's. Matched **before** the reserved list so a `.onion` host reaches the Tor namespace, and even a malformed one stays there: the query itself is the deanonymising event. `../../src/classify-host.cjs:87-116`. |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-Use Domain `home.arpa.` | §4 — together with `arpa`. The same list carries `internal`, `home`, `lan`, `corp`, `intranet` and `private`, which no RFC reserves and which home routers and corporate networks actually use: a deliberate over-reach, `DEVIATIONS.md` IC-5. `../../src/reserved-names.cjs`. |

### DNS vocabulary, comparison and messages

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8499](https://www.rfc-editor.org/rfc/rfc8499) | DNS Terminology (obsoleted by [RFC 9499](https://www.rfc-editor.org/rfc/rfc9499)) | The vocabulary this chapter uses throughout. 8499 is cited to keep one vocabulary across the whole specification; nothing here depends on the differences. |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | DNS Case Insensitivity Clarification | §2.3 — the final label is lowercased before it is compared against the snapshot, so `EXAMPLE.COM` and `example.com` land in the same namespace. `../../src/classify-host.cjs:68-76`. |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) §2.1 | Requirements for Internet Hosts — Application and Support | §2.4 — host label syntax, the shape every entry in the snapshot is asserted to have (a single label, `[a-z0-9-]`, optionally `xn--`-prefixed). `tests/icann-tld-snapshot.test.js`. |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) §4.1 | Domain Names — Implementation and Specification | §5.3, §8 — the wire format of the query the loopback bridge forwards without interpreting, beyond reading the QNAME so the interface can be told which name was answered obliviously (`../../src/odoh-bridge.js`); and the question section that `assertAnswersTo` checks every answer against (`../../src/dns-query.js:342`), including the ICANN lookups a Handshake walk needs, which go through the DoH/ODoH client (§8) — a check the `dns.lookup()` library default has no counterpart for. |

### Internationalized names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5890](https://www.rfc-editor.org/rfc/rfc5890) | IDNA: Definitions and Document Framework | §2.3 — the A-label/U-label vocabulary the boundary comparison is stated in. |
| [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891) | IDNA: Protocol | §2.3 — the lookup protocol we do **not** implement: a Unicode host must be an A-label before it is compared against the snapshot, and the conversion we use is the URL Standard's. `DEVIATIONS.md` IC-12. |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | §2.3 — what the WHATWG URL Standard actually requires, and therefore what we actually get. On this path the divergence from IDNA2008 can move a name **across the ICANN boundary**. `../../src/classify-host.cjs:68-76`, `DEVIATIONS.md` IC-12. |

### URL parsing — the classifier's input

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL Standard §host parsing](https://url.spec.whatwg.org/#host-parsing) | URL Standard | §2.3 — every host reaching the classifier is normalised by the URL parser: lowercased, punycoded, port and trailing dot stripped. `../../src/classify-host.cjs:55-76`, `../../src/hns-host.js:85-98`. |
| [WHATWG URL Standard — ends-in-a-number checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) | URL Standard, IPv4 parsing | §2.2 row 5, §2.3 — why a host whose last label is all ASCII digits cannot be written in a URL, so `classifyHost` falls back to the raw label for the numeric case and `rewriteToHns` gives up entirely; and how an IP literal is recognised before the label count. `../../src/classify-host.cjs:42-48`, `DEVIATIONS.md` IC-14. |

### Encrypted DNS transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS Queries over HTTPS (DoH) | §5.1, §5.3 — both ends of the bridge. The engine speaks **only** RFC 8484 over https templates, which is what the loopback bridge presents (GET with `?dns=<base64url>` and POST, `application/dns-message`), and it is the protocol of the fallback resolver pool. §4.1 fixes the message id at zero, which is why the question section is the only check left. `../../src/odoh-bridge.js`, `../../src/doh.js:69-71`, `src/dns-policy.js`. |
| [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230) | Oblivious DNS over HTTPS | §5.3, §9.4 — what the bridge speaks upstream: §6 message format, §6.3 response AEAD key derivation from the HPKE exporter secret plus a target-chosen nonce, the `ODoHConfigs` structure. It defines **no discovery mechanism** — `DEVIATIONS.md` IC-8. `../../src/odoh.js`. |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) | Hybrid Public Key Encryption | §5.3 — the construction ODoH is built on: X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM. `../../src/odoh.js`. |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | §5.3 — §2.2/§2.3 extract-and-expand for the ODoH key id, response key and nonce. `../../src/odoh.js:73-84`, `:117-120`. |
| [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) | Well-Known Uniform Resource Identifiers | §5.3 — the registry `/.well-known/odohconfigs` is, as far as we can establish, **not** in. `DEVIATIONS.md` IC-8 and §2. |
| [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) | DNS over TLS (DoT) | §5.1 — **not used, and not usable**: the engine accepts only RFC 8484 https templates, so DoT is not an option however configured. Listed because its absence is a constraint we inherited, not one we chose. `DEVIATIONS.md` IC-11. |
| [RFC 8310](https://www.rfc-editor.org/rfc/rfc8310) | Usage Profiles for DNS over TLS and DTLS | §5.2, §5.5, §5.7 — §8.2's opportunistic-versus-strict distinction is the vocabulary `automatic` and `secure` implement. `automatic` is the Fast-mode plan; Private is always the strict profile, with the oblivious bridge as its only server. `DEVIATIONS.md` IC-6. |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) | Discovery of Designated Resolvers | §5.1, §7.4 — **not implemented.** The resolver list is configuration and is never discovered. Listed because it is the standard's own answer to "the network's resolver may be the right one", and we have not taken it. `DEVIATIONS.md` IC-11. |
| [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460) | Service Binding and Parameter Specification via the DNS (SVCB and HTTPS RRs) | §7.4 — type 65 is parsed by `../../src/dns-query.js` and never queried, here or anywhere. `DEVIATIONS.md` IC-11. |
| [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) | TLS Encrypted Client Hello | §9.4 — unreachable without a queried SVCB record, and blocked on the runtime exposing no ECH option. Relevant here because without it the server name is in the ClientHello, so an oblivious DNS lookup does not by itself hide which site was visited. |

### The loopback certificate

| Identifier | Title | Used for |
|---|---|---|
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | Internet X.509 PKI Certificate and CRL Profile | §5.3 — the certificate the bridge serves is built by hand, in DER, with no dependency on an `openssl` binary: v3, ECDSA-with-SHA-256, `basicConstraints` CA:FALSE (critical), `keyUsage` digitalSignature+keyEncipherment (critical), `extKeyUsage` serverAuth, and a `subjectAltName` (§4.2.1.6) naming only `DNS:localhost` and `IP:127.0.0.1`. `../../src/self-cert.js`. |
| [RFC 7469](https://www.rfc-editor.org/rfc/rfc7469) §2.4 | Public Key Pinning Extension for HTTP | §5.3, §9.3 — the pin construction the engine is given: base64 of SHA-256 over the certificate's SubjectPublicKeyInfo. HPKP itself is dead; the construction is what the engine's switch consumes, and citing it is how a reader knows exactly what bytes are hashed. `../../src/self-cert.js:134`, `src/index.js:265`. |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The Transport Layer Security (TLS) Protocol Version 1.3 | §1.1, §5.3 — the transport between the engine and the loopback bridge, and between the bridge and the relay. Terminated by the runtime's own TLS stack; nothing here implements it. `../../src/odoh-bridge.js`. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §1.1, §5.3 — the HTTP layer the DoH exchange rides, and the layer this chapter explicitly does not specify. `../../src/odoh-bridge.js`. |

### Addresses and authentication — cited for what ICANN names do *not* get

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | §7.3 — the registry the SSRF guard's ranges come from. The guard is applied to Handshake answers and to HIP-5 `_op` answers and is **not** applied to ICANN names, because the address never passes through our code. `../../src/safe-address.js`, `DEVIATIONS.md` IC-13. |
| [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) | Address Allocation for Private Internets | §7.3 — the private IPv4 ranges in that guard. `../../src/safe-address.js`. |
| [RFC 3927](https://www.rfc-editor.org/rfc/rfc3927) | Dynamic Configuration of IPv4 Link-Local Addresses | §7.3 — `169.254.0.0/16`, including the cloud metadata address `169.254.169.254`. `../../src/safe-address.js`. |
| [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) | Unique Local IPv6 Unicast Addresses | §7.3 — the IPv6 half of the same guard. `../../src/safe-address.js`. |
| [RFC 6598](https://www.rfc-editor.org/rfc/rfc6598) | IANA-Reserved IPv4 Prefix for Shared Address Space | §7.3 — the CGNAT range `100.64.0.0/10`. `../../src/safe-address.js`. |
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | DNS-Based Authentication of Named Entities (DANE) TLSA | §7.1 — implemented, used for Handshake names, and deliberately **not** applied to ICANN names: the certificate hook defers to the platform's WebPKI for every non-Handshake host. `../../src/dane.js`, `src/index.js:1330-1331`, `DEVIATIONS.md` IC-3. |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | DANE Protocol: Updates and Operational Guidance | §7.1 — §4's guidance that a client apply TLSA records wherever they are published is the standard we are departing from, and the reason IC-3 has to argue rather than assert. |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS Security Introduction and Requirements | §7.2 — cited for absence: nothing validates a signature on this path, and the ICANN root's trust anchor is not configured anywhere in this browser. `DEVIATIONS.md` IC-4. |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) | Protocol Modifications for the DNS Security Extensions | §7.2 — the validating-resolver behaviour we neither perform nor rely on. An ICANN address is the resolver's word, which is what the trust step says. |

### Requirement language

| Identifier | Title | Used for |
|---|---|---|
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Key words for use in RFCs to Indicate Requirement Levels | MUST / MUST NOT / SHOULD / SHOULD NOT / MAY, throughout `SPEC.md`. |
| [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | The capitalisation rule those key words are read under. |

### Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [`app.configureHostResolver`](https://www.electronjs.org/docs/latest/api/app#appconfigurehostresolveroptions) | Electron API documentation | §5.1, §5.4 — the one call that changes what an ICANN lookup does: `secureDnsMode` (`off` / `automatic` / `secure`) and `secureDnsServers` (RFC 8484 https templates only). Everything in §5 is a policy for choosing its two arguments. Called again on every mode switch (§5.7): Private gives it `secure` with the bridge's template alone, or `secure` with an empty list; a return to a plan that configures nothing sets `off` explicitly. `src/dns-policy.js` (`planDnsTransport`, `privateDns`), the browser's `applyDnsPlan`. |
| `--ignore-certificate-errors-spki-list` | Chromium command-line switch (documented in Chromium's own source; there is no specification) | §5.3, §9.3 — how the loopback bridge's certificate is trusted. It makes the engine accept that public key **for any host**, which is why the key is generated in memory per launch, never written to disk, and minted only when `wantsObliviousBridge()` is true. `src/index.js:259-265`, `../../src/self-cert.js`. |
| `odoh-relay.numa.rs`, `odoh-relay.edgecompute.app` | The deployed public ODoH relays | §9.4 — the reason RFC 9230's non-collusion assumption does not hold at current scale: two public relays exist worldwide and one is run by a target operator. The code stays; the privacy claim does not. `src/config.js:376-408`. |
| [DNSCrypt public ODoH server list](https://github.com/DNSCrypt/dnscrypt-resolvers) | DNSCrypt resolver lists | §5.3 — why the second relay is kept in the configuration although it does not currently carry our traffic: it allowlists targets, and will start working for `odoh.hns.one` once that target is on this list, so that day needs no release. `src/config.js:402-407`. |
| [`SPEC.md` §4.2](SPEC.md) | The Fast / Private switch | §5.7, §9.4 — the one control whose policy table (`policyFor`) decides `icannDns`: `secure` in Private, the configured `dns.mode` in Fast; and the controller (`DeliveryMode`) whose `change` event re-applies the plan. `../../src/delivery-mode.js`, `../../tests/delivery-mode.test.js`. |
| [`../../namespaces/router/SPEC.md`](namespaces/router/SPEC.md) | The router chapter of this specification | §2.1, §3 — laws **L1** (an explicit scheme selects the protocol, always) and **L2** (no silent cross-namespace fallback), which are what make "ICANN first" a *boundary* rather than a preference, and the `X-Resolution-Namespace` header that proves a failure stayed inside its namespace. `../../src/router.js`. |


---

## Chapter 3 — IPFS, IPNS and DNSLink

_Source: [`namespaces/ipfs/REFERENCES.md`](namespaces/ipfs/REFERENCES.md)._

Every specification this chapter's implementation reads, with what it is used
for and where. Nothing is listed that the code does not touch: a padded
bibliography is worse than none, because it makes the real dependencies
impossible to see. Where a row says *delegated*, *written not read* or *not
implemented*, that is stated in the row — it is here because the behaviour
depends on the document, not because we implement it.

Paths beginning `src/` or `tests/` are in this chapter's directory. Paths
beginning `../../src/` are the package's shared modules. Paths named as *the
Wildroot tree* are in the browser this package is extracted from and are out of
scope here (SPEC §1.1).

---

### Addressing: multiformats

| Identifier | Title | Used for |
|---|---|---|
| [multiformats/cid](https://github.com/multiformats/cid) | CID (Content IDentifier) Specification | SPEC §4.1, §4.3, §5 — what an `ipfs://` host, an `ipld://` host and an `ipfs=` value *are*: `multibase(version, multicodec, multihash)`. `../../src/pointers.js` (`CID_RE`), `src/ipfs-url.js`, `src/cid.js`, `src/car-roots.js`, and `../../src/router.js` for the bare-CID classification of SPEC §3 |
| [multiformats/multibase](https://github.com/multiformats/multibase) | Multibase | SPEC §5, §3 — the leading character saying which base a CID string is written in. Two are accepted (implicit base58btc for `Qm…`, `b` for base32), which is narrower than the table (IP-1), and the base32 form is the one a URL host survives. `../../src/pointers.js` |
| [multiformats/multicodec](https://github.com/multiformats/multicodec) ([table](https://github.com/multiformats/multicodec/blob/master/table.csv)) | Multicodec | SPEC §5, §6.4 — the codec byte inside a CID and inside a contenthash: `dag-pb` 0x70, `raw` 0x55, `libp2p-key` 0x72, `ipfs-ns` 0xe3, `ipns-ns` 0xe5, `swarm-ns` 0xe4. `src/cid.js`, `../../src/contenthash.js` |
| [multiformats/multihash](https://github.com/multiformats/multihash) | Multihash | SPEC §5 — the hash function and digest inside a CID. Only sha2-256 is produced; anything else is read as whatever the CID says it is. `src/cid.js` |
| [multiformats/unsigned-varint](https://github.com/multiformats/unsigned-varint) | Unsigned-varint | SPEC §5, §12.2 — the length and code prefixes throughout: the CAR header length, the multicodec code in a contenthash, protobuf field lengths. `src/car-roots.js`, `src/cid.js`, `../../src/contenthash.js` |
| [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180-4/final) | Secure Hash Standard (SHS) | SPEC §5, §9 — sha2-256, the hash every CID this stack produces is built on, and the root of trust of the whole namespace. `src/cid.js` via `multiformats/hashes/sha2` |
| [draft-msporny-base58](https://datatracker.ietf.org/doc/html/draft-msporny-base58) | The Base58 Encoding Scheme | SPEC §4.2, §3 — the base58btc alphabet, and that it is **case-sensitive**, which is the whole of IP-5. An Informational draft, not a ratified standard; cited because it is the only written definition. `../../src/pointers.js` |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) §6 | The Base16, Base32, and Base64 Data Encodings | SPEC §3, §4.2 — base32, lowercase and unpadded: the default CIDv1 text form, and the reason a CIDv1 survives host canonicalisation when a CIDv0 does not. `../../src/pointers.js` |

### The data model: what a CID names

| Identifier | Title | Used for |
|---|---|---|
| [UNIXFS.md](https://github.com/ipfs/specs/blob/main/UNIXFS.md) | UnixFS Data Format | SPEC §5 — the `Data` protobuf message a file or directory node carries (`Type`, `filesize`, `blocksizes`), and therefore the DAG shape that *is* the address. Written out by hand rather than imported, so the encoder cannot vanish with a transitive dependency. `src/cid.js` |
| [ipld/dag-pb](https://ipld.io/specs/codecs/dag-pb/spec/) | DAG-PB Specification | SPEC §5 — the wire form of an internal node: `Links` (Hash, Name, Tsize) then `Data`, with links sorted by name for a directory. `src/cid.js` |
| [ipld/dag-cbor](https://ipld.io/specs/codecs/dag-cbor/spec/) | DAG-CBOR Specification | SPEC §12.2 — the encoding of a CARv1 header and the tag-42 link form. Decoded by a minimal reader rather than by `@ipld/dag-cbor` (IP-7). `src/car-roots.js` |
| [ipld/car (CARv1)](https://ipld.io/specs/transport/car/carv1/) | Content Addressable aRchives (CAR / CARv1) | SPEC §8, §12.2 — the archive format a stated origin serves: a varint-prefixed dag-cbor header `{version: 1, roots: [CID…]}`, then blocks. Only the header is parsed here. `src/car-roots.js` |
| [go-unixfs balanced builder](https://github.com/ipfs/go-unixfs/blob/master/importer/balanced/builder.go) | Balanced DAG layout, and kubo's `Import.*` defaults | SPEC §5 — the chunker (`size-262144`), raw leaves, the 174-link fan-out (`UnixFSFileMaxLinks`) and the 256 KiB HAMT threshold (IP-6). Not a standard — an implementation's defaults — but normative for interoperating with it, which is the point of computing a CID before publishing. `src/cid.js`, `tests/cid.test.js` |

### Naming inside the namespace

| Identifier | Title | Used for |
|---|---|---|
| [ipns/ipns-record](https://specs.ipfs.tech/ipns/ipns-record/) | IPNS Record Specification | SPEC §4.2, §9 — what an `ipns://` host and an `ipns=` value resolve *through*: a signed record with a value, a sequence number and a validity window. **Delegated, not implemented** (IP-3): the local node performs the lookup and the signature check, and this stack validates the key's shape. `../../src/pointers.js` (`IPNS_RE`) |
| [ipns/ipns-pubsub-router](https://specs.ipfs.tech/ipns/ipns-pubsub-router/) | IPNS PubSub Router | SPEC §4.2, §12.4 — how an `ipns://` name updates without polling. Enabled on the `ipfs://` daemon (`Ipns.UsePubsub`), which merges into the derived privacy policy rather than replacing it. The Wildroot tree's `src/config.js` |
| [libp2p/peer-ids](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md) | libp2p Peer Ids | SPEC §4.2 — the four host forms an IPNS name takes: a base36 or base32 `libp2p-key` CIDv1, a modern `12D3Koo…` identity, a legacy `Qm…` one. `../../src/pointers.js` |
| [libp2p/pubsub](https://github.com/libp2p/specs/tree/master/pubsub) | libp2p PubSub | SPEC §4.4, §10 — what a `pubsub://` topic is, and that a message's authentication is a publisher signature at the libp2p layer, never a content address. That sentence is the scheme table's `verify` entry (`../../src/router.js`) and the trust panel's step (`../../src/trust-path.js`) |
| [DNSLink](https://dnslink.dev/) | DNSLink | SPEC §6.3 — `_dnslink.<name> TXT dnslink=/ipfs/<cid>` (or `/ipns/<key>`, either with a trailing path), the convention kubo, Brave, IPFS Companion and the public gateways read. **Read as a second pointer source and written at publish**, so a site published either way opens both ways: the `_dnslink` owner prefix, the value grammar, and the rule that a name carries one value. `../../src/pointers.js` (`parseDnslink`, `dnslinkPointerFrom`, `mergePointers`, `dnslinkValue`, `dnslinkOwner`), `../../src/resolver.js`, `../../src/doh.js`. The node-side reader kubo uses for `ipns://<domain>` is untested here (`DEVIATIONS.md` Chapter 3 §2.4) |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) §3.3.14 | Domain Names — Implementation and Specification | SPEC §6.1, §7.2 — a TXT record's `<character-string>`s are **one** value, concatenated; separate records are separate values. Applied identically on every resolution path. `../../src/pointers.js` (`txtStringsFrom`) |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) / [ENSIP-7](https://docs.ens.domains/ensip/7) | contenthash field | SPEC §6.4 — the second carrier: `ipfs-ns` 0xe3 and `ipns-ns` 0xe5 decode into this namespace, `swarm-ns` 0xe4 is recognised and refused by name. `../../src/contenthash.js` |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) §9.10 | The GNU Name System | SPEC §3 — resolve in the alternative namespace when its identifier matches, and do **not** continue into another namespace on failure. Inherited from the spine as the rule for these four schemes. `../../src/router.js` |

### Experimental: the `car=` stated origin and origin warming

These four are cited by SPEC §8, which is marked EXPERIMENTAL. They give the
*shape* of a gateway URL and the parameters for asking it for part of a DAG;
none of them says how a **name** announces such a location, which is why §8 is a
local convention (IP-9).

| Identifier | Title | Used for |
|---|---|---|
| [Trustless Gateway](https://specs.ipfs.tech/http-gateways/trustless-gateway/) | Trustless Gateway Specification | SPEC §8.1 — the URL form a `car=` origin takes to be windowable, `https://<host>[/<prefix>]/ipfs/<cid>`, plus `?format=car` and the `application/vnd.ipld.car` Accept header. `src/origin-warm.js` (`gatewayBase`) |
| [IPIP-0402](https://github.com/ipfs/specs/blob/main/ipips/ipip-0402.md) | Partial CAR support on Trustless Gateways (`dag-scope`, `entity-bytes`) | SPEC §8.2 — fetching a byte window of one file inside a large archive as a partial CAR: `dag-scope=entity&entity-bytes=<from>:<to>`, and `dag-scope=all` for a whole archive. The policy around it is ours (IP-11). `src/origin-warm.js` |
| [Path Gateway](https://specs.ipfs.tech/http-gateways/path-gateway/) | Path Gateway Specification | SPEC §8.2 — the `/ipfs/<cid>/<path>` URL shape those parameters are appended to, and the percent-encoding of each path segment. `src/origin-warm.js` |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) §14 | HTTP Semantics — Range Requests | SPEC §8.2 — the `Range` header a read carries, which decides *which* window is warmed. Single byte ranges and suffix ranges only; a multi-range request is treated as "the whole thing", because a correct 200 beats a wrong 206. `src/byte-range.js` |

### URLs and the host

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL](https://url.spec.whatwg.org/) ([host parsing](https://url.spec.whatwg.org/#host-parsing)) | URL Living Standard | SPEC §3, §4.2, §4.4 — an identifier in this namespace lives in a URL **host**, and a host is subject to whatever canonicalisation the parser applies. Node treats `ipfs:` as a non-special scheme and preserves case; a browser that registers it as a *standard* scheme does not. This split is IP-5, and it is why a pasted CIDv0 is re-spelled as base32 CIDv1. `src/ipfs-url.js`, `../../src/router.js`; the registration is in the Wildroot tree's `src/main.cjs` |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) §3.3 | Uniform Resource Identifier (URI): Generic Syntax | SPEC §8.2 — path segments, and percent-encoding each segment of a gateway path rather than the path as a whole. `src/origin-warm.js` |

### Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [ipfs/kubo](https://github.com/ipfs/kubo) | kubo (go-ipfs) | SPEC §5, §7.3, §12.4, §12.5 — the node every retrieval goes through, and therefore the implementation whose IPNS record checking, block verification and DAG defaults this chapter relies on. Version 0.43 defaults are what `src/cid.js` reproduces and `tests/cid.test.js` pins; its privacy configuration is the subject of SPEC §12.4 |
| [RangerMauve/js-ipfs-fetch](https://github.com/RangerMauve/js-ipfs-fetch) | js-ipfs-fetch | SPEC §4.3, §4.4 — the handler behind `ipfs://`, `ipns://`, `ipld://` and `pubsub://` in the Wildroot tree, and therefore the definition of what `ipld://`'s `Accept` re-encoding and `pubsub://`'s event stream do. Not respecified here |
| `STORAGE-PUBLISH-SHARE.md` decision **D-P2** (as amended) | The stated origin: what `car=` is for | SPEC §8 — the provenance of the EXPERIMENTAL section, and the amendment that a stated origin is only ever a gateway-form HTTPS URL. Not a public document; cited because it governs IP-9 |
| The spine: [`SPEC.md`](SPEC.md), [`DEVIATIONS.md`](DEVIATIONS.md), [`REFERENCES.md`](REFERENCES.md) | The integrated specification | SPEC §3, §6, §7.2, §10 — namespace selection and the two routing laws, the chain proof and DNSSEC anchored to the on-chain DS, the pointer-record grammar (spine §10), and the trust-state model this chapter maps onto |

---

### Not used, and why the absence is deliberate

- **Bitswap, the Amino DHT, delegated routing (the Routing V1 HTTP API), IPNI** —
  retrieval and provider discovery. Out of scope (SPEC §1.1), and delegated
  routing is additionally switched **off**, because it would disclose every CID a
  person reads to a third party (SPEC §12.4).
- **CARv2** — indexed archives. Nothing here writes or reads one; a CARv2 header
  is refused as "not a CARv1 header" rather than partially understood.
- **HAMT-sharded directories** (UNIXFS.md, `HAMTDirectory`) — not implemented; a
  folder that would need one is refused rather than given a CID that would
  disagree with kubo's (IP-6).
- **Gateway response formats other than `car`** (`?format=raw`,
  `?format=dag-json`, a plain file body) — a stated origin is only ever asked for
  a CAR, because a CAR is the only response form whose blocks arrive individually
  hash-checkable.


---

## Chapter 4 — Arweave

_Source: [`namespaces/arweave/REFERENCES.md`](namespaces/arweave/REFERENCES.md)._

Every specification this chapter's implementation actually reads, with what it
is used for and where. Nothing is listed that the code does not touch: a padded
bibliography is worse than none, because it makes the real dependencies
impossible to see. Where a row says *not implemented*, that is stated in the
row — it is here because a design decision turns on it, not because the
resolution path depends on it.

**Arweave has no RFCs.** Its formats are defined by the reference
implementation's repository documentation, by the Arweave Standards (ANS)
series, and — for the gateway and name-system conventions — by ar.io's
documentation. Where a citation is to a repository document rather than to a
standards body, the row says so. Where we could not retrieve a document to
check it, the row says that too, and `DEVIATIONS.md` §2 carries the
uncertainty.

---

### Identifiers and transactions

| Identifier | Title | Used for |
|---|---|---|
| [ANS-104](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md) | Bundled Data v2.0.0 (Arweave Standards) | The identifier derivation, verbatim: *"The id of the DataItem, is the SHA256 digest of this signature."* The same rule a transaction id follows, which is why a 43-character identifier may name **either** a transaction or a bundled data item and this implementation cannot tell them apart (SPEC §3.1, §3.3), and — read the other way round — the rule the header check **computes**: `SHA-256(base64url-decode(signature))` must equal the identifier, or the transaction a gateway showed us is not the one the identifier names (SPEC §9.1.1 — `src/ar.js` `headerMatchesId`, `tests/arweave-header.test.js`). Nothing here parses a bundle. |
| [github.com/ArweaveTeam/arweave](https://github.com/ArweaveTeam/arweave) + [docs.arweave.org](https://docs.arweave.org/) | Arweave reference implementation and developer documentation — the transaction format, the `GET /tx/<id>` header endpoint, `data_root`, and the signature the id is a digest of | Cited for both halves of §9. **Done:** `SHA-256(signature) == id` is recomputed against a header fetched from `GET <other gateway>/tx/<txid>` (SPEC §9.1.1). **Not done:** the bytes are never checked against the `data_root` that header carries, and no chunk proof is fetched or verified — which is why the row in `../../src/router.js` `SCHEME_TABLE` still says `status: 'partial'`. SPEC §9.2; `DEVIATIONS.md` AR-1, AR-D1. |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §5 (base64url, the URL and filename safe alphabet) is the identifier encoding: 32 bytes unpadded is 43 characters of `A-Z a-z 0-9 - _`. §3.5 (canonical encoding — non-alphabet bits must be zero) is the rule that makes exactly one of those 43-character strings the identifier. SPEC §3.2, §3.3 — `../../src/pointers.js` `isCanonicalTxid` and `ARTX_RE`, read by `src/ar.js`. The same encoding is decoded and re-encoded on both sides of the header check (the signature in, the digest out), so the comparison is between two canonical 43-character strings and not between two byte buffers — SPEC §9.1.1. §6 (base32, lowercase and unpadded) is the sandbox label a gateway redirects a transaction to (`sandboxLabel()`, SPEC §6.3) — accepted as the same gateway, with the identifier in the path as the load-bearing check. |
| [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | NIST, Secure Hash Standard (SHA-256) | The one cryptographic primitive this chapter computes. An Arweave identifier is the SHA-256 digest of the transaction's signature, so the header check is a single `node:crypto` `createHash('sha256')` and no Arweave library is involved. SPEC §9.1.1 — `src/ar.js` `headerMatchesId`. |

### Path manifests

| Identifier | Title | Used for |
|---|---|---|
| [path-manifest-schema.md](https://github.com/ArweaveTeam/arweave/blob/master/doc/path-manifest-schema.md) | Arweave path manifest schema (repository document, version 0.1.0) | The manifest format: `"manifest": "arweave/paths"`, Content-Type `application/x.arweave-manifest+json`, an optional `index` whose `path` must be a key of `paths`, and a required `paths` object whose *"object keys represent the subpaths, and the values tell us which content to resolve to"*. **Not implemented** — the client has no manifest reader. SPEC §7, which specifies the delegation to the gateway and what it costs; `DEVIATIONS.md` AR-U1. |
| Manifest version 0.2.0 | `index.id` and `fallback` — an ar.io-side extension, no retrievable specification document | Named as behaviour that is entirely the answering gateway's. Its clauses are **not verified** against a document we could obtain. SPEC §7; `DEVIATIONS.md` AR-U2 — no code. |

### Gateways, the `ar://` scheme, and names

| Identifier | Title | Used for |
|---|---|---|
| `ar://<txid>` | The `ar://` scheme as used by the ar.io gateway network and the Wander (formerly ArConnect) wallet — a de-facto convention, with **no RFC and no IANA registration** | The URL form of SPEC §4, adopted unchanged rather than replaced. `src/ar.js`; `../../src/contenthash.js` (`url: 'ar://' + txid`); `../../src/router.js` `SCHEME_TABLE`. `DEVIATIONS.md` AR-2. |
| [RFC 7595](https://www.rfc-editor.org/rfc/rfc7595) | Guidelines and Registration Procedures for URI Schemes | The registration procedure `ar` has not been through, and the provisional registration that would fit an established convention. SPEC §4.1; `DEVIATIONS.md` AR-2 — no code. |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | §3.1 (scheme syntax) and §3.3 (path segments, and the dot-segments a path must not smuggle) — the grammar SPEC §4.1 and §4.3 are written against. `src/ar.js` `isSafeSegment`. |
| [docs.ar.io](https://docs.ar.io/) | ar.io gateway and network documentation | The URL shape a gateway serves (`GET /<id>` and `GET /<id>/<path>` for transactions, data items and manifest subpaths), and `/ar-io/info` as the marker of a gateway-network member — which is the criterion `AR_GATEWAYS` states, and the observation that `arweave.net` does not answer it. SPEC §6.1 — `src/ar.js` `AR_GATEWAYS`. |
| ArNS / ANT / undername | The ar.io name system, its Arweave Name Token contract, and the `<undername>_<name>.<gateway-host>` wildcard convention ([docs.ar.io](https://docs.ar.io/)) | **Not implemented, anywhere.** Cited so SPEC §8 can state precisely what happens instead: `<label>_persist.ar.io` ends in the ICANN TLD `io`, so `classifyHost` routes it to ordinary DNS over ordinary CA-authenticated HTTPS. `../../src/router.js` `classifyHost`; `DEVIATIONS.md` AR-U3. |

### Content pointers into this chapter

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain Names — Implementation and Specification | §3.3.14: a TXT record's `<character-string>`s are **one** value and are concatenated; separate records are separate values. The rule that makes `ar=<txid>` read identically on the SPV, DoH and `_op` paths. SPEC §5.2 — `../../src/pointers.js` `txtStringsFrom`. |
| [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) | Clarifications to the DNS Specification | §5.2: the TTL is the authoritative server's statement of how long an RRset may be cached — the rule the flat 60-second positive cache does not follow. `../../src/resolver.js` `CACHEABLE`; `DEVIATIONS.md` AR-3. |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) / [ENSIP-7](https://docs.ens.domains/ensip/7) | `contenthash` field for ENS | The multicodec-prefixed byte string an ENS or HIP-5 `_op` resolver returns. `arweave-ns` is `0xb29910`, four bytes on the wire (`90 b2 ca 05`), and its value is the raw 32-byte transaction id — base64url-encoded here into the canonical 43-character form. SPEC §5.3 — `../../src/contenthash.js` (`CODEC.ARWEAVE`, `readVarint`), `../../src/hip5-op.js`. |
| [multicodec table.csv](https://github.com/multiformats/multicodec/blob/master/table.csv) | The multicodec code table | Where `arweave-ns` `0xb29910` and the neighbouring `ipfs-ns` `0xe3` / `ipns-ns` `0xe5` / `swarm-ns` `0xe4` codes come from. Only those four are recognised; everything else is reported as `unknown` and refused by name, never guessed at. SPEC §5.3 — `../../src/contenthash.js`. |
| [unsigned-varint](https://github.com/multiformats/unsigned-varint) | Unsigned variable-length integer (multiformats) | The LEB128 encoding of the multicodec code, hand-implemented with a 35-bit shift cap. SPEC §5.3 — `../../src/contenthash.js` `readVarint`. |

### HTTP and URLs

| Identifier | Title | Used for |
|---|---|---|
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §15.5 (a 4xx is an answer about the resource) and §15.6 (a 5xx is about the server) are what SPEC §6.2's failover rule turns on. §9.3.2 (`HEAD`) is the rule the upstream `GET` departs from (`DEVIATIONS.md` AR-2). §14 (Range requests), §13.1.2 (`If-None-Match`), §13.1.3 (`If-Modified-Since`), §8.8.2 (`Last-Modified`), §8.8.3 (`ETag`), §12.5.1 (`Accept`) and §12.5.5 (`Vary`) are the mechanisms SPEC §6.4's fixed safelists carry, and §15.5.6 (`405`) the refusal of §6.5. `src/ar.js` `FORWARDED`, `RETURNED`, `isReachFailure`, and the method check. |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | Three consequences. Its **path normalization** collapses dot segments — including percent-encoded ones — before a `Request` reaches the handler, which is why that half of the guard is defence for a raw string and the test asserts the *outcome* (SPEC §4.3). Its **percent-encoding** is already applied to the segments the handler receives, which is why they are forwarded as received (SPEC §4.3). Its **host parsing lowercases**, which would destroy a case-sensitive identifier — the reason parsing is done on the raw string and the reason `ar` is registered `standard: false` (SPEC §4.2, §10). `src/ar.js`; `src/main.cjs` in the browser tree. |

### Where this chapter hands off

| Identifier | Title | Used for |
|---|---|---|
| `SPEC.md` §6 | The spine: the resolution algorithm | How a Handshake name's `ar=` record was proven — the chain proof, the authoritative walk, the DNSSEC validation anchored to the on-chain DS. SPEC §9.4 depends on it and does not repeat it. |
| `SPEC.md` §7 | The spine: HIP-5 `_op` on-chain resolution | The route that produces an `arweave-ns` contenthash. This chapter picks up at the decode, SPEC §5.3. |
| `SPEC.md` §10 | The spine: content pointers | The pointer grammar and precedence — `ar=<txid>`, last in `POINTER_PRECEDENCE`. Implemented in `../../src/pointers.js`, referenced by SPEC §5.2, not duplicated. |
| `SPEC.md` §3, §4 | The spine: namespace selection and trust states | Why `<label>_persist.ar.io` is an ICANN name (SPEC §8), and the four trust states the panel renders (SPEC §9.2, `DEVIATIONS.md` AR-U5). |
| `DEVIATIONS.md` D-1, D-9, D-10 | The spine's deviations | The flat positive cache this chapter inherits (AR-3), and the DoH-route trust weakenings that also apply to an `ar=` pointer resolved over DoH (SPEC §9.4). |


---

## Chapter 5 — ENS and `web3://`

_Source: [`namespaces/ens/REFERENCES.md`](namespaces/ens/REFERENCES.md)._

Every standard this chapter's implementation reads, with what it is used for
and where. The rule is the spine's: **nothing is listed here that the code does
not touch**, because a padded bibliography makes the real dependencies
impossible to see. A row that says *not implemented* or *via the library* says
so in the row — it is present because its absence, or its indirection, is a
documented fact rather than an oversight.

Rows that point at `../../src/` are dependencies this chapter **shares with the
rest of the specification** and does not re-implement.

---

### Naming and records

| Identifier | Title | Used for |
|---|---|---|
| [EIP-137](https://eips.ethereum.org/EIPS/eip-137) | Ethereum Domain Name Service — Specification | `namehash`, the recursive keccak256 over labels that turns a name into the `bytes32` node every ENS read is keyed by; and the registry interface `resolver(bytes32)`, which this chapter does **not** call. Its own normalisation text (nameprep / UTS-46) is superseded by ENSIP-15. SPEC §5.1, §5.2; `src/ens-protocol.js` via `viem/ens` `namehash`. |
| [ENSIP-1](https://docs.ens.domains/ensip/1) | ENS | EIP-137 republished under the ENS numbering — the document an ENS reader is pointed at first, and the source of the "Name Syntax" clause ENSIP-15 replaced. No separate behaviour. SPEC §5.1. |
| [ENSIP-15](https://docs.ens.domains/ensip/15) | ENS Name Normalization Standard | The normalisation actually performed, before hashing and before any network request, so that this client computes the node the registration was validated under. It is also the thing that refuses a malformed name after §4's guarded percent-decode. SPEC §4, §5.1; `src/ens-protocol.js` `resolve()`. |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | The processing ENSIP-15 derives from and the one EIP-137 originally specified. Bare UTS-46 is **not** applied; the row exists so a reader can see which of the two is meant. SPEC §5.1. |
| [ENSIP-10](https://docs.ens.domains/ensip/10) | Wildcard Resolution | `resolve(bytes name, bytes data)` on the Universal Resolver: the on-chain walk up to the nearest ancestor **with** a resolver, which is why `jesse.base.eth` resolves at all. SPEC §5.2; `src/ens-protocol.js` `UNIVERSAL_RESOLVER_ABI`. |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) | contenthash field for ENS | The record read: the multicodec-prefixed value that names a website. SPEC §5.5; `../../src/contenthash.js`. |
| [ENSIP-7](https://docs.ens.domains/ensip/7) | Contenthash Field | EIP-1577 under the ENS numbering, and the codec assignments the decoder recognises: `ipfs-ns` 0xe3, `ipns-ns` 0xe5, `swarm-ns` 0xe4, `arweave-ns` 0xb29910. SPEC §5.5; `../../src/contenthash.js`. |
| [ENSIP-21](https://docs.ens.domains/ensip/21) | Batch Gateway Offchain Lookup | The sentinel URL `x-batch-gateway:true`, the `query((address,string[],bytes)[])` selector `0xa780bab6`, and the `(bool[],bytes[])` return. Implemented locally, so `ccip-v3.ens.xyz` is never contacted. SPEC §6; `src/ccip-read.js` `batchLocally`. |
| [EIP-181](https://eips.ethereum.org/EIPS/eip-181) | ENS support for reverse resolution of Ethereum addresses | **Not implemented** (EN-3). Listed because a reader expects it in an ENS chapter and its absence is deliberate: nothing on a browsing path has an address to reverse. |
| [ENSIP-5](https://docs.ens.domains/ensip/5) | Text Records | **Not read** (EN-1, EN-7). The record profile a "name info" panel would use, and the reason this chapter's single call is a `contenthash` call and nothing else. |
| [ENSIP-9](https://docs.ens.domains/ensip/9) | Multichain Address Resolution | **Not read** (EN-1, EN-7). A wallet's record profile, cited so that the boundary of "resolves a name to a website" is explicit. |
| [ENS Universal Resolver](https://docs.ens.domains/resolution/universal) | ENS documentation — Universal Resolver | The contract this chapter calls, `0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe` on mainnet: a DAO-owned upgradable proxy, pinned deliberately rather than read from the bundled chain registry. SPEC §5.2; `src/ens-protocol.js` `UNIVERSAL_RESOLVER`. |

### CCIP-Read

| Identifier | Title | Used for |
|---|---|---|
| [ERC-3668](https://eips.ethereum.org/EIPS/eip-3668) | CCIP Read: Secure offchain data retrieval | The whole of `src/ccip-read.js`: the `OffchainLookup(address,string[],bytes,bytes4,bytes)` error (selector `0x556f1830`); the Client Lookup Protocol — `sender` MUST equal the reverting contract, `{sender}`/`{data}` are lowercase 0x-hex, GET when the template carries `{data}` and POST otherwise, 4xx returns an error and stops while 5xx tries the next URL; and the MUST-cap on lookups. SPEC §6. |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) | IPv4 Address Blocks Reserved for Documentation | Part of the address set a gateway IP literal is checked against. SPEC §6 rule 3; `../../src/safe-address.js`. |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | The SSRF guard proper: loopback, private, link-local (including `169.254.169.254`), CGNAT, benchmarking, multicast, reserved. SPEC §6 rule 3, §9.1, EN-5; `../../src/safe-address.js`. |

### Ethereum transport

| Identifier | Title | Used for |
|---|---|---|
| [JSON-RPC 2.0](https://www.jsonrpc.org/specification) | JSON-RPC 2.0 Specification | The request envelope, and critically the `error` object: a member carrying revert bytes is the chain answering, not a failure to reach it. §5.1's freedom over `error.data` is why three shapes must be accepted. SPEC §5.3, §5.6; `src/ens-protocol.js` `ethCall`, `revertDataOf`. |
| [`eth_call`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_call) | Ethereum JSON-RPC API — `eth_call` | The one method used: always `{to, data}` at block tag `latest`; no `from`, no gas parameters, no state override. SPEC §5.3; `src/ens-protocol.js`. |
| [EIP-55](https://eips.ethereum.org/EIPS/eip-55) | Mixed-case checksum address encoding | **Deliberately not relied on.** Addresses are compared and templated lowercased (ERC-3668 requires the lowercase form for `{sender}`), so a checksum mismatch can never change a decision. `src/ccip-read.js` `fillTemplate`, the sender check. |
| [EIP-1191](https://eips.ethereum.org/EIPS/eip-1191) | Add chain id to mixed-case checksum address encoding | Named only to separate it from name normalisation, which it is adjacent to in most reading lists and has nothing to do with. Not used. |
| [Contract ABI Specification](https://docs.soliditylang.org/en/latest/abi-spec.html) | Solidity documentation — Contract ABI Specification | Function selectors (`contenthash(bytes32)` → `0xbc1c58d1`) and the encode/decode of every argument and return value, including the decode whose failure is `unreachable`. SPEC §5.2, §5.4, §6; `src/ens-protocol.js`, `src/ccip-read.js`, performed by `viem`. |

### `web3://`

| Identifier | Title | Used for |
|---|---|---|
| [ERC-4804](https://eips.ethereum.org/EIPS/eip-4804) | Web3 URL to EVM Call Message Translation | The scheme itself, implemented by the third-party `web3protocol` package; the module here is a lazy loader, a `GET`-only gate and a constrained response. Its short form `w3://` is deliberately not offered. SPEC §8; `src/web3-protocol.js`. |
| [ERC-5219](https://eips.ethereum.org/EIPS/eip-5219) | Contract Resource Request Mode | Where `web3://`'s HTTP status code and response headers come from: the contract returns `(uint16, bytes, (string,string)[])`. The citation SPEC §8.3's two constraints rest on. Via `web3protocol`; clamped and filtered in `src/web3-protocol.js` `web3Response`. |
| [ERC-6821](https://eips.ethereum.org/EIPS/eip-6821) | Support ENS Name for Web3 URL | The library resolves a `.eth` host in a `web3://` URL through its **own** ENS implementation, with its own RPC list and its own normalisation. Neither implemented nor gated here — which means the browser contains two ENS clients. Via `web3protocol`. |
| [ERC-7617](https://eips.ethereum.org/EIPS/eip-7617) | Chunk support for ERC-5219 mode `web3://` | Reached the same way. The library streams further chunks by re-entering `web3://`, so one navigation can become a long chain of contract calls with no deadline of ours (EN-D1). Via `web3protocol`. |

### URLs, HTTP and namespace selection

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain Names — Implementation and Specification | §3.1's wire-format name encoding — length-prefixed labels, root-terminated, no compression — which ENSIP-10's `resolve()` takes as its first argument. SPEC §5.1; `viem/ens` `packetToBytes`. |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL — Living Standard | Two ways: `new URL()` is the parser the gateway guard refuses with (and `protocol` must be exactly `https:`), and `ens:` is a non-special scheme whose content is an opaque path, which is why the name arrives percent-encoded and must be decoded before normalisation. SPEC §4, §6 rule 3; `src/ens-protocol.js` `parseEnsUrl`, `src/ccip-read.js` `isSafeGatewayUrl`. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | The status-code classes ERC-3668's 4xx/5xx rule is written in, the `content-length` header the gateway response cap reads, and the statuses this chapter serves (400 / 404 / 405 / 500 / 501 / 502). SPEC §5.7, §6, §8.3. |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | §9.10's namespace precedence: resolve in the alternative namespace when its suffix matches, and do **not** continue into DNS on failure. Applied to `.eth` — no failure kind may become a lookup in another namespace. SPEC §1, §3, §5.7; `../../src/router.js` `classifyHost`. |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs to Indicate Requirement Levels | The requirement keywords used throughout this chapter. |
| [multicodec](https://github.com/multiformats/multicodec) | Multiformats — multicodec table | The codec prefixes a contenthash value is read by, with unsigned-varint and CID. Shared with the rest of the specification. SPEC §5.5; `../../src/contenthash.js`. |

### Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [viem](https://viem.sh/) | viem — TypeScript interface for Ethereum | ABI encode/decode, `namehash`, `packetToBytes` and `normalize`. The only third-party dependency on the `ens://` resolution path, and it is on the critical path of a security decision (normalisation), so its version is worth pinning exactly rather than by range. |
| [@adraffy/ens-normalize](https://github.com/adraffy/ens-normalize.js) | ens-normalize.js | What viem's `normalize` actually is: ENSIP-15's reference implementation, reached through [ox](https://oxlib.sh/). Named because "we normalise with viem" hides which specification is being applied. |
| [web3protocol](https://github.com/web3-protocol/web3protocol-js) | web3protocol-js | The entire ERC-4804 implementation, **and** the bundled chain registry that supplies the Ethereum RPC endpoints `ens://` itself trusts. Both schemes depend on this package, one of them for a list of trusted third parties. |
| The bundled mainnet chain entry | `web3protocol/chains`, `chainId` 1 | `https://ethereum.publicnode.com` and `https://cloudflare-eth.com`: the endpoints trusted for every ENS mapping and the ones the trust output must name. Its `ensUniversalResolver` and `ensRegistry` addresses are **not** used (SPEC §5.2). |
| [ENS DNSSEC gasless import](https://docs.ens.domains/dns/) | ENS documentation — DNS names in ENS | Not a document implemented here, but the reason CCIP-Read is mandatory rather than optional: every ICANN domain imported into ENS answers through an offchain lookup, so a client without SPEC §6 cannot resolve any of them. |


---

## Chapter 6 — Nostr

_Source: [`namespaces/nostr/REFERENCES.md`](namespaces/nostr/REFERENCES.md)._

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

### Naming

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

### Protocol and transport

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

### Cryptography

| Identifier | Title | Used for |
|---|---|---|
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | **§6.2**: the signature scheme NIP-01 specifies — a 64-byte signature over the 32-byte event id, verified against a 32-byte x-only public key using BIP-340's tagged-hash construction. This is not ECDSA; a generic secp256k1 verifier does not implement it. `src/event.js`, via [`@noble/curves`](https://github.com/paulmillr/noble-curves) `schnorr.verify` |
| [SEC 2](https://www.secg.org/sec2-v2.pdf) | Recommended Elliptic Curve Domain Parameters — §2.4.1, secp256k1 | **§6.2**: the curve. `src/event.js`, via `@noble/curves` |
| [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | Secure Hash Standard — SHA-256 | **§6.1**: the event id is the SHA-256 of the canonical serialisation. Taken from `node:crypto` rather than `@noble/hashes` deliberately — the latter is only a transitive dependency here, and importing a package we do not declare breaks the day that tree reshuffles. `src/event.js` |
| [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) | Base32 address format for native v0-16 witness outputs (Bech32) | **§5.1**: the encoding NIP-19 uses — the charset, the HRP expansion, the polymod checksum with the constant `1` (not bech32m's), the mixed-case prohibition, and the rejection of non-zero padding bits when regrouping 5-bit groups into bytes. One deviation: the 90-character limit is not enforced (NO-4). `src/nip19.js`, a local implementation |

### Cited for what is not done

Listed because each absence is a documented gap rather than an oversight.

| Identifier | Title | Used for |
|---|---|---|
| [NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md) | Relay list metadata (kind 10002, `r` tags) | **§8.2**, not read. This is the closest thing Nostr has to "where does this key live", and the resolver does not ask for it: it queries a bundled set plus the identifier's own checked hints. Wildroot publishes a NIP-65 list for every name it creates and its social client reads one; neither is in scope here. NO-3 |
| [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Authentication of clients to relays | **§8.2**, not implemented. A relay that demands `AUTH` is, to this code, a relay that returned nothing — and the condition is not yet named in the relay report. NO-7 |
| [NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event deletion request | **§10.1**, not implemented and unimplementable as a guarantee. Cited because it is why "this event exists on a relay" does not mean "its author still stands behind it". |
| [NIP-02](https://github.com/nostr-protocol/nips/blob/master/02.md) | Follow list (kind 3) | **§1.1**, out of scope. Read by Wildroot's social client, not by the resolver. Named so a reader does not go looking for it here. |
| [NIP-18](https://github.com/nostr-protocol/nips/blob/master/18.md) | Reposts (kinds 6 and 16) | **§1.1**, out of scope, as NIP-02. |
| [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) | HTTP Auth (kind 27235) | **§1.1**, out of scope. Wildroot uses it to authenticate panel requests with a name's control key; it is an authorization scheme, not a resolution mechanism, and no part of the `nostr:` path touches it. |

### Rendering and integration

| Identifier | Title | Used for |
|---|---|---|
| [CSP Level 3](https://www.w3.org/TR/CSP3/) | Content Security Policy Level 3 | **§10.6**: every response, error pages included, is served under `default-src 'none'; style-src 'unsafe-inline'; img-src https: data:`. No script source is granted at all, which is the second line of defence behind escaping a stranger's `content`. `src/nostr-protocol.js` |
| [Electron `registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | **§5.4** and `DEVIATIONS.md` §2.5: `nostr:` is registered with low privileges — not a standard scheme, so no origin, no `fetch`, no service workers, no secure-context features. A deliberate difference from `hns:`: a `nostr:` page is a document, not an application. The browser's `src/main.cjs`, not in this chapter |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) · [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs | The key words throughout `SPEC.md`. |

### Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Audited elliptic-curve implementations | **§6.2**: the BIP-340 implementation. Dependency-light and already in the browser's tree, which is the honest reason Nostr was cheap to add at all. `src/event.js`, and every test file, which mint their own key material rather than carrying fixtures |
| [nostr-tools `normalizeURL`](https://github.com/nbd-wtf/nostr-tools) | Relay-URL canonicalisation | **§9.1 step 3**: the canonicalisation everyone else follows — host lower-cased, a bare path collapsed, fragment dropped — so `wss://nos.lol` and `wss://nos.lol/` are one relay, one socket, and one row in the relay report. `normalizeRelayUrl` in `src/relay.js` |
| [The NIPs repository](https://github.com/nostr-protocol/nips) | Nostr Implementation Possibilities | Read for what is and is not settled. Its lack of a versioning or errata process is itself a fact an implementer needs — see the note at the top of this file. |
| [`ws`](https://github.com/websockets/ws) | WebSocket client and server for Node.js | **§8.5**: the client on the Private route, chosen because it takes an `agent` and the runtime's `WebSocket` does not. A declared dependency of this repository (`^8.18.2`); the browser carries 7.x, and the class is written for both — each hands a text frame to `onmessage` as a string. Only `src/tor-websocket.js` imports it; the direct route never touches it (NO-16). Also the relay server `tests/tor-websocket.test.js` stands up |
| `../../src/delivery-mode.js` | The one switch — Settings › Content delivery › Mode | **§8.5**: `policyFor()` is the policy table this handler's `nostrThroughTor` row comes from; `privateRefusal('relay')` is the wording of the 503 page and `SWITCH_HINT` its last sentence. `src/nostr-protocol.js` |
| `docs/MODES.md` (browser) | Wildroot, *Private mode and Fast mode* | **§8.5**: the design of the switch, and the table naming row 15 — Nostr relay queries — as one of the five divergences that need a mode at all. `../../DIVERGENCE.md` row 15 is the inventory entry. Not extracted |

---

### Running these tests

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


---

## Chapter 7 — DID, AT Protocol and ActivityPub

_Source: [`namespaces/did/REFERENCES.md`](namespaces/did/REFERENCES.md)._

Every standard this chapter's implementation reads, with what it is used for
and which module uses it — plus, in their own group, the standards a compliant
implementation would need for the namespaces this one refuses. Where a row says
*not implemented* or *cited for the deviation*, the row says so.

### Naming and identifiers

| Identifier | Title | Used for |
|---|---|---|
| [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) | Decentralized Identifiers (DIDs) v1.0, W3C Recommendation 19 July 2022 | §3.1 the syntax `did:<method-name>:<method-specific-id>` and the absence of an authority component, which is why the classifier accepts a slashless `scheme:`. §5.4 the `id` property is the DID subject and §7.1.3 a resolver answers with the document *for* the input DID — the equality check the handler makes. §5.4 also §7.1's resolution **result** envelope, which we do not return (`DEVIATIONS.md` DI-3). §6.2 `service` / `serviceEndpoint`, read to find a PDS. — `src/did-protocol.js`, `src/bsky.js` |
| [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/) | did:web Method Specification, W3C Credentials Community Group draft | §5.3 the read algorithm quoted and implemented in full — `:` → `/` before percent-decoding, the `%3A` port, `.well-known` only for a bare host, then `did.json` — and checked against the specification's published examples. A Community Group draft, not a W3C Recommendation: it is the only written definition of the method and it is not ratified. — `src/did-protocol.js` (`didWebUrl`), imported by `src/bsky.js` so the PDS lookup reads the method the same way (§6.2) |
| [did:plc Method Specification v0.1](https://web.plc.directory/spec/v0.1/did-plc) | did:plc — Public Ledger of Credentials, v0.1 ([source](https://github.com/did-method-plc/did-method-plc)) | §5.2 the directory endpoint `GET /<did>` that returns the current document — the whole of what is used. The parts *not* used are what make the method verifiable: the identifier is a truncated hash of the signed genesis operation, and `GET /<did>/log/audit` publishes the signed operation log (`DEVIATIONS.md` DI-2). One operator's specification, versioned v0.1. — `src/did-protocol.js`, `src/bsky.js` |
| [W3C DID Specification Registries](https://www.w3.org/TR/did-spec-registries/) | DID Specification Registries, W3C Group Note | §5.1 where a method name is looked up. Cited for what is refused: every method other than `plc` and `web` is a 400 before any network request. — `src/did-protocol.js` |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | §3 namespace precedence — resolve in the alternative namespace when its suffix matches, and do not continue into DNS on failure. §9.10 is the only place this rule is written down in an RFC; `SPEC.md` adopts it and this chapter inherits it. — `../../src/router.js` |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Standard — [host parsing](https://url.spec.whatwg.org/#host-parsing) | §3.1 the reason `did:` must not be a *standard* scheme: a standard scheme's authority is lowercased, IDNA-mapped and, when the last label is all digits, parsed as IPv4, while a method-specific identifier is byte-sensitive. Also why the canonical `at://did:plc:…` AT-URI does not parse and must be dispatched by scheme prefix. — `../../src/router.js`; the browser's `src/main.cjs` (not extracted) |

### AT Protocol

| Identifier | Title | Used for |
|---|---|---|
| [atproto.com/specs/handle](https://atproto.com/specs/handle) | AT Protocol — Handle Resolution | §6.1 the two authoritative handle→DID methods (`_atproto.<handle>` DNS `TXT` `did=…`, and `GET https://<handle>/.well-known/atproto-did`) and the bidirectional-verification requirement against `alsoKnownAs`. **Neither method is implemented**; the public AppView is asked instead (`DEVIATIONS.md` DI-5). Also the form of the `_atproto.<name>` record §9.3 signs an authorisation for. — `src/bsky.js` (`resolveHandle`) |
| [atproto.com/specs/did](https://atproto.com/specs/did) | AT Protocol — DID | §6.2 the two DID methods the network admits, and the document requirements a client reads: a `service` entry with id `#atproto_pds` and type `AtprotoPersonalDataServer` whose `serviceEndpoint` is the PDS. Both fields are checked, as is the document's own `id`. One deviation remains: where this specification makes an unresolvable DID a resolution failure, the implementation keeps a default PDS for the sign-in path and marks it `{ assumed: true, reason }` rather than failing (§6.2 rule 4). — `src/bsky.js` (`resolvePds`) |
| [atproto.com/specs/at-uri-scheme](https://atproto.com/specs/at-uri-scheme) | AT Protocol — AT-URI scheme | §6.3 `at://<did-or-handle>/<collection>/<rkey>`, the identifier form the `at` namespace owns. Recognised, fail-closed: parsed no further than its scheme, never resolved. The AT-URIs inside the adapter are opaque strings carried back to their origin. — `src/unimplemented-protocol.js`; strings in `src/bsky.js` |
| [atproto.com/specs/xrpc](https://atproto.com/specs/xrpc) | AT Protocol — XRPC | §6.1 the HTTP+JSON transport: `GET|POST /xrpc/<nsid>`, query parameters, `Bearer` auth, and the error body shape (`error`, `message`) mapped to a typed error. Hand-rolled — eight endpoints and an injectable `fetch` is fewer lines than an SDK integration. — `src/xrpc.js` |
| [atproto.com/specs/repository](https://atproto.com/specs/repository) | AT Protocol — Repository | §6.3 and §10.5 the signed commit over a Merkle Search Tree, verified with the `#atproto` key from the account's DID document, that would make an `at://` record *resolved* rather than *fetched*. **Not implemented**; cited as the bar. — no module |
| [public.api.bsky.app](https://docs.bsky.app/) | Bluesky public AppView | §6.1 the unauthenticated read service used for `com.atproto.identity.resolveHandle` and for profile and feed reads. A free service run for the whole network, which is why the transport caches briefly and retries a 429 once. As a *resolver* it is a trusted third party. Not a standard; listed because a load-bearing dependency belongs in the references. — `src/bsky.js`, `src/xrpc.js` |

### Transport, HTTP and the browser boundary

| Identifier | Title | Used for |
|---|---|---|
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §8 the 501 (§15.6.2) a recognised-but-unresolved namespace answers with; §10.4 the 503 (§15.6.4) the non-proxied gate answers with — a status the engine knows, deliberately; §5.1 the 400 (§15.5.1) for a malformed or unsupported DID; §5.4 the 502 (§15.6.3) for a transport error or a document about a different subject. — `src/unimplemented-protocol.js`, `src/gate.js`, `src/did-protocol.js` |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | §5.3 percent-encoding is case-insensitive (§2.1), so `%3a` and `%3A` are the same octet and a `did:web` port decodes from either spelling. — `src/did-protocol.js` (`didWebUrl`) |
| [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) | Well-Known Uniform Resource Identifiers | §5.3, §6.1, §7 the `/.well-known/` namespace shared by `did.json`, `atproto-did` and `webfinger`, and the registry that keeps them from colliding. — `src/did-protocol.js`, `src/bsky.js` |
| [WHATWG Fetch](https://fetch.spec.whatwg.org/) | Fetch Standard — [CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol) | §5.4 `Access-Control-Allow-Origin: *` on a resolved document (bounded by the scheme's privileges, not by the header — `DEVIATIONS.md` DI-1) and `null` on a fail-closed refusal; `redirect: 'error'` and `AbortSignal.timeout`, set on every request this chapter makes. — `src/did-protocol.js`, `src/unimplemented-protocol.js`, `src/bsky.js`, `src/xrpc.js` |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | §5.3, §10.2 the addresses a resolver reaching a host a stranger named must refuse, applied by `isSafeDidWebHost` before any request. — `src/did-protocol.js` via `../../src/safe-address.js` |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) | IPv4 Address Blocks Reserved for Documentation | §5.3, §10.2 the documentation blocks included in that refusal. — `../../src/safe-address.js` |
| [Electron `registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron `protocol` API | §3.1, §8 how `did`, `at` and `activitypub` are declared to the engine: non-standard, non-secure, no service workers, no `fetch`, `corsEnabled`. Registration is mandatory even for a scheme that resolves nothing — an unregistered scheme loaded as a main-frame document has hard-crashed the application. — the browser's `src/main.cjs` (not extracted) |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Key words for use in RFCs to Indicate Requirement Levels | The requirement keywords, as amended by RFC 8174. — `SPEC.md` |
| [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | The same, restricted to the uppercase forms. — `SPEC.md` |

### Experimental: identity anchors under a Handshake name

The records and receipts of SPEC §9 are shipped and signed but are not a
proposed standard, and their formats may change. These are the standards they
are built from.

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain Names — Implementation and Specification | §9.1 §3.3.14: a TXT record's `<character-string>`s are one value, concatenated by the caller, and separate records are separate values, so a field is never merged across them; and the 255-byte maximum the parser enforces and the compact receipt encoding is shaped by. — `src/record.js` |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for Internet Hosts — Application and Support | §9.1 §2.1 host label syntax: a label may not contain `_`, which makes `_hns` an unambiguous prefix that can never collide with a Handshake label. — `src/record.js` (`recordName`), `src/keys.js` (`normalizeName`) |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) | DNS Security Introduction and Requirements | §9.2 the validation an `_hns` answer must have passed before its contents mean anything; an unvalidated answer is *unverified*, never *absent*. — `../../src/dnssec.js`, consumed by the browser's `src/folders/index.js` |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) | Protocol Modifications for the DNS Security Extensions | §9.2 the same, for the RRSIG and denial-of-existence machinery `SPEC.md` specifies in full. — `../../src/dnssec.js` |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §9.1 §5 base64url: the receipt field's 64 raw signature bytes after the decimal `created_at` and a `.`, chosen so the whole proof fits one TXT string. — `src/record.js` (`encodeReceipt` / `decodeReceipt`) |
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | §9.1 the signature scheme for every receipt, and the x-only 32-byte public key form the `pubkey=` field carries. — `src/keys.js`, `src/nostr-event.js` |
| [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Nostr — Basic protocol flow description | §9.1 the event object and its canonical serialisation — `sha256(JSON([0,pubkey,created_at,kind,tags,content]))` is the id, BIP-340 over that id is the signature. Deliberately not a new signature format: any Nostr library can verify a receipt. — `src/nostr-event.js` |
| [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) | Nostr — Arbitrary custom app data | §9.1, §9.3 kind 30078 and the `d` tag that makes an event parameterised-replaceable per name. Both receipts are kind-30078 events; the `v` tag exists precisely because 30078 is generic. — `src/receipt.js` |
| [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) | Nostr — HTTP Auth | Kind 27235, the `u` / `method` / `payload` tags, and `Authorization: Nostr <base64(event)>`, used to authenticate the *write* that publishes an anchor. Out of this chapter's scope, present because `receipt.js` is extracted whole. — `src/receipt.js` (`signAuth` / `verifyAuth`) |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Nostr — Mapping Nostr keys to DNS-based internet identifiers | Cited for the gap: NIP-05 verifies a Nostr identifier against a domain's `/.well-known/nostr.json`, which is the operator's word. The `_nostr.<name>` anchor described in `src/record.js` would attest the same binding with the control key instead — and is designed, not published (`DEVIATIONS.md` DI-11). — no module |

### Cited for what a compliant implementation must do — not read by this code

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

### Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | noble-curves — audited elliptic curve cryptography | §9.1 the secp256k1/BIP-340 implementation every receipt signature and verification goes through. The only runtime dependency this chapter adds beyond the shared modules and the platform. — `src/keys.js`, `src/nostr-event.js` |
| [`plc.directory`](https://plc.directory) | The did:plc directory service | §5.2 the default `did:plc` resolver, configurable via `plcDirectory` so a mirror or a self-hosted directory is a supported deployment and a test can drive every path with no network. — `src/did-protocol.js` |
| `../../src/delivery-mode.js` | The one switch — Settings › Content delivery › Mode | §10.4 `privateRefusal('p2p', …)`, the words the non-proxied gate answers with. `did:` itself reads nothing from it: it rides the proxied fetch and resolves in both modes. — `src/gate.js` |
| `docs/SOCIAL-MULTIPROTOCOL.md` | Wildroot design record — multi-protocol social identity | §9.4 the decision `did:web:<name>.hns.one`, its accepted cost, and the still-open question of whether `did:plc` should be the default instead (`DEVIATIONS.md` §2.5). — not extracted |


---

## Chapter 8 — Tor

_Source: [`namespaces/tor/REFERENCES.md`](namespaces/tor/REFERENCES.md)._

Every standard this chapter's implementation actually reads, with what it is
used for and where in the tree it is used. Nothing is listed that the code does
not touch: a padded bibliography is worse than none, because it makes the real
dependencies impossible to see.

Where a row says *cited for what we do not do*, that is stated in the row. Those
rows are here because a reader deciding whether to copy this design needs to
know which available mechanism was declined, and why.

Paths written `../../src/…` are the shared modules of the top-level package;
paths written `src/…` and `tests/…` are this chapter's, under `namespaces/tor/`.

---

### Tor

| Identifier | Title | Used for |
|---|---|---|
| [rend-spec-v3](https://spec.torproject.org/rend-spec/) | Tor Rendezvous Specification — Version 3 | **§6, "Encoding onion addresses"** is §4 of this chapter: `base32(PUBKEY ‖ CHECKSUM ‖ VERSION)`, PUBKEY the 32-byte Ed25519 master public key, VERSION `0x03`, CHECKSUM `SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2]`; 35 bytes → 56 unpadded base32 characters. Implemented in full by `isValidV3Onion`, `../../src/router.js:232-252`, and consumed by the handler at `src/onion-protocol.js:119-124`. **The rendezvous protocol** is §9.1: the client's proof that the far end holds the private key is obtained by *establishing the circuit*, not by checking anything afterwards — **not implemented here**, it is performed by the `tor` process (`src/tor.js`). **Client authorization** is specified here too, and we do not implement it (DEVIATIONS TO-5). |
| [proposal 224](https://spec.torproject.org/proposals/224-rend-spec-ng.html) | Next-Generation Hidden Services in Tor | §4, provenance for the v2 refusal: the design rend-spec-v3 came from, and the reason a v3 address is 56 characters where a v2 address was 16. |
| [v2 deprecation timeline](https://blog.torproject.org/v2-deprecation-timeline) | Tor Project, "Onion Service version 2 deprecation timeline" | §4, why 16-character addresses are refused rather than supported: deprecation was announced in 2020 and support removed from Tor during 2021, so they are unreachable and not merely discouraged. `../../src/router.js:232-252`. |
| [control-spec](https://spec.torproject.org/control-spec/) | Tor control protocol specification | §7.1, **cited for what we do not do**: the bundled client is started with no `ControlPort` and readiness is parsed from tor's own `Bootstrapped 100%` notice on stdout, so there is no local control socket to authenticate and nothing for another process on the machine to talk to. `src/tor.js:197-208`; pinned by `tests/tor-circuit.test.js`. |
| [tor-man](https://spec.torproject.org/tor-man/) | Tor manual — `SocksPort`, `ClientOnly`, `AvoidDiskWrites`, `IsolateSOCKSAuth`, `ClientOnionAuthDir` | §7.1, the generated `torrc` (`src/tor.js:197-208`). `IsolateSOCKSAuth` and `ClientOnionAuthDir` are **cited for what we do not do**: per-origin SOCKS credentials would buy stream isolation we do not take (DEVIATIONS TO-3), and no client-authorization directory is configured (DEVIATIONS TO-5). |
| [Tor Browser design](https://2019.www.torproject.org/projects/torbrowser/design/) | The Design and Implementation of the Tor Browser | §9.3 and §1, the threat model this browser explicitly does **not** meet. It is why every user-facing string on this path pairs "hides your IP" with "not full anonymity", why `Accept-Language` is pinned to the value Tor Browser sends (`src/onion-protocol.js:209-219`), and the reference point DEVIATIONS TO-6 is measured against. |
| [Tor Expert Bundle](https://www.torproject.org/download/tor/) | Tor Project download page — the expert bundle | §7.1, where the bundled binary comes from. The vendoring step verifies a pinned GPG signature and then a pinned SHA-256; no binary is vendored in this package (DEVIATIONS §4). |

### Naming

| Identifier | Title | Used for |
|---|---|---|
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The ".onion" Special-Use Domain Name | §3, the rule this whole chapter is built around. The application requirements of §2: software that does not implement the Tor protocol should not perform a DNS lookup for a `.onion` name, and name-resolution APIs must either refuse it or hand it to Tor. Implemented in the stronger form R1/R2 — `.onion` is classified first and unconditionally, valid or malformed, at every entry point: `../../src/router.js:310-313`, `../../src/reserved-names.cjs:31`, `../../src/hns-host.js:50`, `src/subresource-guard.js:35-53`. Cited again in DEVIATIONS TO-1 and TO-2. |
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | §3, the registry and the process RFC 7686 used, and the reason `onion` sits in the same never-Handshake list as `localhost`, `invalid`, `test` and `example` rather than being a special case of its own. `../../src/reserved-names.cjs`. |
| [IANA special-use domain names](https://www.iana.org/assignments/special-use-domain-names/) | Special-Use Domain Names registry | §3, where `onion` is recorded. The bundled ICANN root snapshot does **not** contain it, which is why the carve-out has to be explicit: without it, "not in the ICANN root" would make `.onion` a Handshake name. `../../src/reserved-names.cjs`, `../../src/icann-tlds.cjs`. |
| [RFC 9498 §9.10](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System — namespace precedence | §3, namespace precedence: resolve in the alternative namespace when its suffix matches, and do not continue into DNS on failure. Adopted as a normative rule in the spine and applied here in its strictest form, R2 — a *failed* onion address still must not continue into DNS. It is the only place we know of where this rule is written down in an RFC. |

### Encoding

| Identifier | Title | Used for |
|---|---|---|
| [RFC 4648 §6](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §4.1, base 32 (alphabet `A`–`Z`, `2`–`7`), lower-cased and unpadded: 56 characters × 5 bits = 280 bits = exactly 35 bytes, which is why a v3 label needs no padding and always decodes cleanly. §6 is the plain base32 alphabet — **not** §7 base32hex, which is what DNSSEC's NSEC3 owner names use. `../../src/router.js:214`, and the reference decoder in `tests/onion-address.test.js`. |
| [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions | §4.2, `SHA3-256` is the checksum function in the v3 address encoding, computed with `node:crypto` in `../../src/router.js:248-251` and independently in the test oracle. |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Edwards-Curve Digital Signature Algorithm (EdDSA) | §4.1 and §9.1, the signature scheme whose public key an onion address encodes. Cited because it is what "the address *is* the key" means concretely; no Ed25519 operation is performed by this code. |

### Transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 | §6.4 and R6, the transport the whole design rests on, and specifically §4: address type `0x03` (`DOMAINNAME`). Sending the `.onion` *hostname* to the proxy — rather than resolving it and sending an address — is the mechanism by which RFC 7686's no-DNS rule is satisfied at the wire level. `src/anonymize.js:243-258` (the `socks5://` proxy rule), `src/onion-protocol.js:136-176`. §7.5 cites it a second time for the five main-process paths that dial this controller's port for themselves rather than through the session: the protocol is spoken directly by `../../src/socks-dial.js` — the greeting with the "no authentication" method of §3, a CONNECT command, and `ATYP` IPv4 for a resolved address (the Handshake authoritative hop, an A-record `hns://` site's DANE-pinned socket, the `wss://` tunnel) or `0x03` for a host that must be resolved inside Tor (a Gemini capsule, a Nostr relay). §5 (the reply, whose own address type the client must parse to know where the framing ends) is implemented there too. |
| [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) | Username/Password Authentication for SOCKS V5 | **Cited for what we do not do.** Tor overloads SOCKS username/password for stream isolation, so distinct credentials per origin put each site on its own circuit. We send none — not on the session proxy, which has no hook for it, and not on the five direct dialers of §7.5, which could pass one and do not — so everything shares circuits within the session. DEVIATIONS TO-3 and TO-D1. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §6.4–§6.7, the protocol spoken **inside** the tunnel, in plain HTTP. §13 conditional requests and §14 `Range` are among the forwarded request headers; §15 is the status codes the handler returns and passes through; §15.4 is the redirect semantics of §6.5, including §15.4.4: a same-service 301/302/303 after a request with a body is followed with a GET and no body, 307/308 keep the method. There is no TLS in this path, which is why the lock is open (§8). `src/onion-protocol.js:136-205`. |
| [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265) | HTTP State Management Mechanism | §6.4 and §6.6, cited for a negative that matters: neither `Cookie` (request) nor `Set-Cookie` (response) crosses this handler's allow-lists. Whether the underlying session-bound fetch attaches the session cookie jar of its own accord is **not established** — DEVIATIONS TO-4. `src/onion-protocol.js:182-190`, `:209-219`. |
| [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) | HTTP Strict Transport Security (HSTS) | §6.6, cited for a deliberate exclusion: `Strict-Transport-Security` is the one service header **not** passed through, because there is no TLS inside the tunnel and forwarding it would poison HSTS state for the `onion://` origin. `src/onion-protocol.js:182-190`. |

### Content the service controls

| Identifier | Title | Used for |
|---|---|---|
| [CSP Level 3](https://www.w3.org/TR/CSP3/) | Content Security Policy Level 3 | §6.6 and R9, `content-security-policy` and `content-security-policy-report-only` are passed through unchanged: they are the service's instruction about its own content, and dropping them would leave an onion page less defended here than in a browser that does nothing. `src/onion-protocol.js:182-190`. |
| [Fetch Standard](https://fetch.spec.whatwg.org/) | WHATWG Fetch — `X-Content-Type-Options: nosniff`, redirect modes | §6.5 and §6.6, `redirect: 'manual'` is the mode the redirect decision rests on, and `x-content-type-options` is passed through with the other service headers. `src/onion-protocol.js:142-176`, `:182-190`. |
| [RFC 7034](https://www.rfc-editor.org/rfc/rfc7034) | HTTP Header Field X-Frame-Options | §6.6, passed through with the other headers the service uses to defend its own content. `src/onion-protocol.js:182-190`. |
| [Referrer Policy](https://www.w3.org/TR/referrer-policy/) | Referrer Policy | §6.6, `referrer-policy` is passed through. `src/onion-protocol.js:182-190`. |
| [Permissions Policy](https://www.w3.org/TR/permissions-policy/) | Permissions Policy | §6.6, `permissions-policy` is passed through. `src/onion-protocol.js:182-190`. |

### URL and browser integration

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL](https://url.spec.whatwg.org/) | URL Standard | §5, what a *standard* scheme means — a real origin, host parsing, same-origin policy — and the parser `parseOnionUrl` uses to split host, port and path and to drop the fragment. `onion:` is not one of the *special* schemes, which is why a query-only URL has an empty path. `src/onion-protocol.js:54-79`; the scheme registration is in the browser's `main.cjs`, not in this package. |
| [protocol.registerSchemesAsPrivileged](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron API — privileged scheme registration | §5 and §8, the `standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, allowServiceWorkers: false` registration that gives `onion://` a real, persistent, per-host origin so real web applications do not crash on an opaque one. `secure: true` is a **capability** decision, not a trust claim. The browser's `src/main.cjs` — **not extracted**, see DEVIATIONS §4. |
| [session.setProxy](https://www.electronjs.org/docs/latest/api/session#sessetproxyconfig) | Electron API — session proxy configuration, `proxyBypassRules` | §7.5, how the Tor SOCKS endpoint becomes the session's proxy for *everything*, with proxy-side name resolution. `<-loopback>` **subtracts** the implicit loopback bypass, so even `127.0.0.1` rides the tunnel rather than going around it. While BLOCKED (§7.6) the same call points every session at `BLACKHOLE_RULES`, `socks5://127.0.0.1:9` — a loopback port nothing listens on — so a Tor that cannot be had never becomes a direct connection. `src/anonymize.js:243-258`, `_cannotRoute`. |
| [net.fetch](https://www.electronjs.org/docs/latest/api/net#netfetchinput-init) | Electron API — `net.fetch` | §6.4, the session-bound fetch the handler is given, which rides the session proxy. Injected as `fetchImpl`, so every test in this package drives the handler with a stub and no Electron is imported anywhere. `src/onion-protocol.js:100-107`; wired in the browser's `src/protocols/index.js`. |

### Cross-references into the spine

| Identifier | Title | Used for |
|---|---|---|
| [`SPEC.md`](SPEC.md) | The integrated specification — the spine | §3, the classifier contract this chapter specialises, and the two laws: an explicit scheme selects the protocol, and a failure never crosses a namespace boundary. §8, the trust-state model the open onion lock maps onto. |
| [`SPEC.md` §4.2](SPEC.md) | The Fast / Private switch | §2, §7.3, §7.6 — the one control that drives this controller: `DeliveryMode.set('private')` flips the mode and then calls `setMode('tor')`; `set('fast')` calls `setMode('off')` and then flips; `policyFor(mode).ipProtection` is the value passed. The browser constructs the controller with `failClosed`, which is what makes BLOCKED reachable. `../../src/delivery-mode.js`, `../../tests/delivery-mode.test.js`. |
| [`DEVIATIONS.md`](DEVIATIONS.md) | Deviations and open questions | The `TO-` entries this chapter cites, and the Handshake chapter's numeric-TLD convention referred to in §2.6. |


---

## Chapter 9 — Key-addressed namespaces

_Source: [`namespaces/keys/REFERENCES.md`](namespaces/keys/REFERENCES.md)._

Every standard, specification or protocol document this chapter's code actually
reads, with what it is used for and where. Nothing is listed that the code does
not touch: a padded bibliography is worse than none, because it makes the real
dependencies impossible to see.

A row that says **via the engine** means the rule is implemented by a
third-party library this implementation depends on, not by code in this
package. That distinction is kept deliberately — see `DEVIATIONS.md` **KY-7** —
and it is the honest answer to "did you implement this?" for much of this
chapter.

The spine's `REFERENCES.md` covers DNS, DNSSEC, DANE, DoH/ODoH, Handshake and
the URL constraints; those rows are not repeated. RFC 3986 is restated because
it is the shared grammar every identifier here is written in.

Paths beginning `src/` are in this directory; `../../src/` is a shared module of
this package; anything named *the Wildroot tree* is the browser this is
extracted from.

---

### URI syntax

| Identifier | Title | Used for |
|---|---|---|
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | The generic grammar every identifier here is written in. §3.1 (scheme names are case-insensitive) is why the router lowercases before dispatch; §3.2.2 (host) is what a hypercore key or an info-hash *is* in the URL form; §4.2 (relative references) is what a Gemini redirect target may be; §3.3 (opaque path, no authority) is why `magnet:` is registered non-standard and is never an origin. SPEC §K.3.4, §K.6.1, §K.7.1 — `../../src/router.js`, `src/magnet-protocol.js`, `src/gemini-protocol.js`, `src/torrent-address.js` |
| [RFC 8141](https://www.rfc-editor.org/rfc/rfc8141) | Uniform Resource Names (URNs) | The `urn:btih:` / `urn:btpk:` / `urn:btmh:` forms a magnet's `xt`/`xs` carry. The two supported forms are matched with fixed regular expressions rather than by parsing URN syntax generally; the `q-component`/`r-component` grammar is not implemented and no BitTorrent magnet uses it. SPEC §K.7.1 — `src/magnet-protocol.js` |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Living Standard | The parser Chromium and Node both use. §3.2 "special scheme" and the host-canonicalisation rules are why a *standard* custom scheme has its host lowercased — the property SPEC §K.3.4 reasons about, and the reason the legacy SSB sigil form cannot work as a URL host (SPEC §K.5.3). Reasoned about, not tested here (`DEVIATIONS.md` §2.2); the registration is `src/main.cjs` in the Wildroot tree |
| [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343) | Domain Name System (DNS) Case Insensitivity Clarification | Why lowercasing a `gemini://` host is lossless, and why the same-host redirect predicate compares host names case-insensitively. SPEC §K.3.4, §K.6.3 — `src/gemini-protocol.js` (`sameHostGeminiRedirect`) |

### BitTorrent

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

### Hypercore and Hyperdrive

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

### Secure Scuttlebutt

| Identifier | Title | Used for |
|---|---|---|
| [ssb-uri-spec](https://github.com/ssb-ngi-pointer/ssb-uri-spec) | SSB URI Specification | The identifier grammar `ssb:<type>/<format>/<base64url-data>[/<extra>]`, the type/format pairs that are legal, and the mapping to and from the legacy sigil forms. Implemented **via the engine** (`ssb-uri2`); no SSB parsing is done in this package. SPEC §K.5.1, §K.5.3 |
| [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/) | Scuttlebutt Protocol Guide | What a **feed id** is — an Ed25519 public key — and the signed, hash-chained message format that makes a feed's history unforgeable, together with the completeness limit an eclipse imposes. **Via the engine.** SPEC §K.5.2 |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §5 (base64url) is the encoding SSB URI data is written in, and the `-`/`_` → `+`/`/` conversion performed before a sigil reaches the sbot. §6 (base32) is the magnet info-hash alphabet this implementation refuses (`DEVIATIONS.md` KY-2). SPEC §K.5.1, §K.7.1 |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Edwards-Curve Digital Signature Algorithm (EdDSA) | Ed25519: the signature scheme behind an SSB feed id, a hypercore key and a BEP-46 `btpk` — three of the four "verified by construction" claims in this chapter are this one primitive. Used **via the engines**; no Ed25519 code is in this package. SPEC §K.4.4, §K.5.2, §K.7.8 |

### Gemini

| Identifier | Title | Used for |
|---|---|---|
| [Gemini protocol specification](https://geminiprotocol.net/docs/specification.gmi) | Project Gemini — Protocol Specification (v0.24.x) | The URI form and default port **1965**; the TLS floor (servers use TLS 1.2+); the two-digit status codes and the `<META>` line, which become the HTTP status and the content type or error body; the `10`/`11` input requests rendered as a form; the `30`/`31` redirects and the guidance that a client bound them at five; and §4.2, the **TOFU** certificate model this implementation does not implement (`DEVIATIONS.md` KY-1). SPEC §K.6 — `src/gemini-protocol.js` |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The Transport Layer Security (TLS) Protocol Version 1.3 | The transport a Gemini request runs over, terminated by Node's TLS stack. SPEC §K.6.2 — `src/gemini-protocol.js` |
| [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) | The Transport Layer Security (TLS) Protocol Version 1.2 | The floor the client sets (`minVersion: 'TLSv1.2'`), which is the Gemini specification's own minimum. SPEC §K.6.2 |
| [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) | TLS Application-Layer Protocol Negotiation Extension | The `gemini` ALPN identifier the client offers. The negotiated identifier is not enforced (`verifyAlpnId: () => true`). SPEC §K.6.2; `DEVIATIONS.md` KY-1 |
| [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) | Representation and Verification of Domain-Based Application Service Identity in PKIX | Cited for what is **not** done: no identity check of any kind is performed on a Gemini server certificate, name or otherwise (`rejectUnauthorized: false`, no store, no comparison). `DEVIATIONS.md` KY-1 |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 | **§K.6.2** — how a Gemini request survives Private mode instead of being refused: the handler is a SOCKS5 client of the device-local Tor, offering only the "no authentication" method (§3) and sending the capsule's host as address type `0x03` `DOMAINNAME` (§4), so the name is resolved inside Tor and the operating system's resolver is never asked. `../../src/socks-dial.js` (`socksDialer`, shared with the Handshake resolver's authoritative hop, the WebSocket tunnel of Chapter 11 and the Nostr relays of Chapter 6), consumed in `src/gemini-protocol.js` where the socket is built. RFC 1929's username/password method is **not** used, so nothing isolates one capsule's circuit from another's (Chapter 8, TO-3). |

### Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [`protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron — custom scheme privileges | What `standard: true, secure: true` buys and costs: a real tuple origin, service workers, `fetch`/CORS, streaming — and URL canonicalisation, including host lowercasing. The mechanism SPEC §K.3.4 reasons about, the reason `ar://` is deliberately low-privilege while `hyper://` is not, and the reason a Gemini cross-host redirect must move the address bar (SPEC §K.6.3). `src/main.cjs` in the Wildroot tree |
| `net::GetHttpReasonPhrase()` | Chromium — `ElectronURLLoaderFactory::StartLoading` status handling | Why a status a handler returns must be one Chromium defines: an unknown code `NOTREACHED`s in the loader. This is why the Private-mode refusal is **503** — both the gate's refusal of the three peer-to-peer namespaces and Gemini's refusal when there is no Tor port to dial — and why a Gemini status is passed through `safeStatus()`. SPEC §K.3.6, §K.6.2, §K.6.4 — `src/gate.js`, `../../src/safe-status.js` |
| `../../src/delivery-mode.js` | The one switch — Settings › Content delivery › Mode | `policyFor()`, whose `p2pDiscovery` row is what §K.3.6 enforces; `privateRefusal('p2p', { label })`, the words the gate answers with; `SWITCH_HINT`, its last sentence. `../../DIVERGENCE.md` row 19 is the inventory entry. SPEC §K.3.6 — `src/gate.js` |
| `docs/RESOLUTION-ROUTER.md`, `docs/TORRENT-DESIGN.md`, `docs/Protocols.md`, `docs/Fetch-Hyper.md`, `docs/Fetch-Gemini.md`, `docs/MODES.md` | Wildroot browser design documents | The design documents this chapter is checked against, and the place the retrieval behaviour it excludes (piece selection, `Range` handling, streaming) is specified. `docs/MODES.md` is the Private/Fast design that decides which namespaces here are refused and which are routed (SPEC §K.3.6). SPEC §K.1, §K.4, §K.6, §K.7 |


---

## Chapter 10 — Experimental: HIP-5 `_op` and numeric Handshake TLDs

_Source: [`namespaces/experimental/REFERENCES.md`](namespaces/experimental/REFERENCES.md)._

Every standard, draft or interface this chapter's implementation actually
reads, with what it is used for and where. Module paths are relative to this
file; the code lives at the repository root because it is entered from
Chapter 1.

### Handshake and pseudo-TLD delegation (Part A)

| Identifier | Title | Used for |
|---|---|---|
| [HIP-0005](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) | Pseudo-TLD delegation to alternative naming systems | §A.1, §A.7: the mechanism `_op` extends — an NS target under a `_<chain>` pseudo-TLD is not a host but a pointer into another naming system. **Status: permanent Draft**; the HIP process is not active, which is part of why this chapter is experimental. `../../src/resolver.js`, `../../src/hip5-op.js` |
| [Handshake resource format](https://hsd-dev.org/api-docs/) | The on-chain `Resource` | §A.1: the `NS` record carrying `<address>._op.` is read from the chain resource Chapter 1 §6.1 proves. `../../src/resolver.js` |

### Ethereum and Optimism (Part A)

| Identifier | Title | Used for |
|---|---|---|
| [EIP-137](https://eips.ethereum.org/EIPS/eip-137) | Ethereum domain name service — specification | §A.2: `namehash`, and the registry interface `resolver(bytes32) returns (address)` (selector `0x0178b8bf`). Checked against the EIP's own published vectors. `../../src/hip5-op.js` |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) / [ENSIP-7](https://docs.ens.domains/ensip/7) | contenthash field | §A.2: the multicodec-prefixed content pointer read first on this route — `ipfs-ns` 0xe3, `ipns-ns` 0xe5, `swarm-ns` 0xe4, `arweave-ns` 0xb29910. `../../src/contenthash.js` |
| [ENS DNSResolver interface](https://docs.ens.domains/resolvers/interfaces) | DNS records on an ENS-shaped resolver | §A.2, §A.3: `hasDNSRecords(bytes32,bytes32)` (`0x4cbf6ba4`) and `dnsRecord(bytes32,bytes32,uint16)` (`0xa8fa5682`), where the second argument is `keccak256` of the lowercased, root-terminated, RFC 1035 wire-format owner name and the returned bytes are wire-format RRsets. `../../src/hip5-op.js` |
| [ENSIP-10](https://docs.ens.domains/ensip/10) | Wildcard resolution | §A.4: cited for what this route does **not** do — a sub-name whose own namehash has no resolver is not walked up to its parent's resolver. `OP-1` |
| [Optimism JSON-RPC](https://docs.optimism.io/) | `eth_call`, chainId 10 | §A.2, §A.6: a hand-rolled `eth_call` over the injected `fetch` — a 4-byte selector plus 32-byte words, no client library, because this runs on every navigation. Being an ordinary HTTPS request through that injected fetch is also what lets the route run unchanged while the user is anonymized. `../../src/hip5-op.js` |
| [Multiformats: multicodec, unsigned-varint, CID](https://github.com/multiformats/multicodec) | Self-describing value prefixes | §A.2: reading a contenthash value. `../../src/contenthash.js` |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain names — implementation and specification | §A.2, §A.3: the wire format stored records are in, and the owner-name encoding hashed into `nameKey`. Compression pointers are refused rather than followed. `../../src/hip5-op.js` |

### URL and host syntax (Part B)

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Standard — [host parsing](https://url.spec.whatwg.org/#host-parsing), the ["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker), the [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) and [forbidden host code points](https://url.spec.whatwg.org/#forbidden-host-code-point) | §B.1, §B.2: **the reason the convention exists.** A standard scheme's host whose last label is all ASCII digits is parsed as an IPv4 address, so `hns://14898/` becomes `hns://0.0.58.50/` and `hns://hello.14898/` is not a URL; and `_` is usable as the marker because it is not a forbidden host code point. `../../src/hns-url.cjs`, `NT-2` |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for internet hosts — application and support | §B.2, §2.1 host label syntax: why a Handshake label can never contain `_`, which is what makes the marker unambiguous. `../../src/hns-url.cjs` |
| [Chromium URL / scheme registry](https://chromium.googlesource.com/chromium/src/+/main/url/) | The implementation of the above | §B.1: a registered standard scheme cannot opt out of IPv4 host parsing, which is why this is not fixable in the embedder. — |


---

## Chapter 11 — Native applications on a Handshake name

_Source: [`namespaces/apps/REFERENCES.md`](namespaces/apps/REFERENCES.md)._

Every standard this chapter's implementation actually reads, with what it is
used for and where in the tree it is used. Nothing is listed that the code does
not touch: a padded bibliography is worse than none, because it makes the real
dependencies impossible to see.

Where a row says *cited for what we do not do*, that is stated in the row. Those
rows are here because a reader deciding whether to copy this design needs to
know which available mechanism was declined, and why — and they are among the
most useful rows in the file.

Paths written `../../src/…` are shared modules of the top-level package; paths
written `src/…` and `tests/…` are this chapter's, under `namespaces/apps/`.
Paths written `browser src/…` are in the Wildroot browser tree and are not
extracted into this repository (SPEC.md, "Paths").

---

### Origins, schemes and secure contexts

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL](https://url.spec.whatwg.org/) | URL Standard | **§4.6** — the parser a PAC sandbox does **not** have, which is why the PAC's host rule is an ASCII-only copy of the one classifier rather than a call into it. **§3.1** — what registering `hns` as a *standard* scheme means: a [special scheme](https://url.spec.whatwg.org/#special-scheme) whose URLs get an [origin](https://url.spec.whatwg.org/#concept-url-origin) and whose host is run through [host parsing](https://url.spec.whatwg.org/#host-parsing). **§3.3** — the cost: the [ends-in-a-number checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and the [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) make an all-digit final label an IP address, which is the numeric-TLD casualty Chapter 10 Part B addresses. Registration at `browser src/main.cjs:110-120`; the marker is decoded at `src/ws-proxy.js:295` via `../../src/hns-url.cjs`. |
| [WHATWG HTML](https://html.spec.whatwg.org/multipage/) | HTML Standard | **§3.2** — [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin) as a tuple, and the [storage model](https://html.spec.whatwg.org/multipage/webstorage.html) keyed by it: what a Handshake page gains when the scheme becomes standard, and why an opaque origin makes an ordinary web application throw on its first line. Also **DEVIATIONS §2.5**, storage partitioning, which we have not measured. |
| [Secure Contexts](https://www.w3.org/TR/secure-contexts/) | W3C, Secure Contexts | **§3.1, §3.2** — what `secure: true` makes an `hns://` document: `isSecureContext`, `crypto.subtle`, and eligibility to open `wss://`. Note the chapter's own qualification: a secure *context* is not a padlock, and this implementation keeps the indicator scheme- and proof-driven (spine Part I §4). |
| [Mixed Content](https://www.w3.org/TR/mixed-content/) | W3C, Mixed Content | **§4.1** — the rule that makes this chapter's whole transport design necessary: a secure context may not open a plaintext `ws://`, and the reference engine enforces it in the renderer, before any proxy or handler could route it. |
| [Service Workers](https://www.w3.org/TR/service-workers/) | W3C, Service Workers | **§3.3**, *cited for what we do not do*: the `hns` registration sets `allowServiceWorkers: false` (`browser src/main.cjs:114`), so a native application cannot be offline-capable or installable at its Handshake name. DEVIATIONS AP-3, AP-D4. |
| [WHATWG Fetch](https://fetch.spec.whatwg.org/) | Fetch Standard | **§3.3** — the CORS model that a custom-scheme response is *not* protected by in the reference engine, because such a request arrives with no `Origin` and no initiator. It is why the origin gate of §5.1 is built on the engine's record of the sender rather than on headers. |
| [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454) | The Web Origin Concept | **§5.1** — the origin an operation is attributed to, reconstructed as `<scheme>//<host>` for a scheme a URL parser treats as opaque (`appOrigin`, `browser src/protocols/app-manifest.js:82-88`). **§8 / DEVIATIONS AP-4** — the `Origin` request header, which is the defence a Handshake application's own socket endpoint must apply. |

### Transport: the tunnel and the WebSocket

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) | The WebSocket Protocol | **§4** throughout: the `101` upgrade the tunnel carries but never parses. **§4.1 of the RFC** (the client's `Sec-WebSocket-Accept` check) is performed by the user agent, not by this implementation — DEVIATIONS §2.1 is explicit that we have not pinned it, and SPEC §6 therefore scores the upgrade step `none`. **§10.2 of the RFC**, that WebSockets are deliberately not subject to the same-origin policy, is the standards basis for DEVIATIONS AP-4. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | **§4.2** — [§9.3.6 CONNECT](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6): the method the tunnel implements, its `<host>:<port>` request target, and the rule that after a 2xx the connection becomes a tunnel (`parseAuthority` and the splice, `src/ws-proxy.js:166-172`, `:341-344`). **§4.3** — [§11 authentication](https://www.rfc-editor.org/rfc/rfc9110#section-11), the `407` / `Proxy-Authenticate` / `Proxy-Authorization` exchange, *cited for what we do not do*: it is implemented (`:283-286`) and unreachable, because the engine never surfaces the challenge for a `wss://` handshake. **§4.5** — the status codes the refusals use. |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) | HTTP/1.1 (message syntax and routing) | **§4.2** — the request-line and field-line grammar the head parser accepts, the CRLF CRLF terminator it reads to, and the `Connection: close` framing of a refusal (`readHead`, `parseConnectHead`, `_refuse`; `src/ws-proxy.js:115-159`, `:247-257`). The 8 KiB bound on a head is this implementation's, not the RFC's. |
| [RFC 7235](https://www.rfc-editor.org/rfc/rfc7235) | HTTP/1.1: Authentication | **§4.3** — the challenge/credentials framework RFC 9110 §11 now carries, cited because the implementation's retained credential path speaks it verbatim (`Proxy-Authenticate: Basic realm="…"`, `src/ws-proxy.js:284-285`). *Cited for what we do not do.* |
| [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617) | The 'Basic' HTTP Authentication Scheme | **§4.3** — the `Basic <base64(user:pass)>` encoding the retained gate parses and compares in constant time (`basicCredential`, `src/ws-proxy.js:175-179`; `safeEqual`, `:88-97`). |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 | Cited twice, for opposite reasons. **§4.3**, *for what we do not do*: the first implementation of this tunnel was a SOCKS5 CONNECT *server*. Chromium's SOCKS5 client offers only the "no authentication" method, so a proxy demanding anything else fails in the greeting — the reason the tunnel speaks HTTP CONNECT instead, and a stray SOCKS greeting arriving at it is answered as a malformed head (`tests/ws-proxy.test.js`). **§4.4 fence 4**, *for what we do*: the tunnel is a SOCKS5 *client* of the device-local Tor in Private mode. The greeting offers only "no authentication", the command is CONNECT, and the resolved address is sent as one of §4's address types (`ATYP` IPv4 or IPv6) so no name reaches the proxy — `socksDialer`, `../../src/socks-dial.js`, shared with the resolver's authoritative hop (Chapter 1) and with `gemini://` (Chapter 9). Chapter 8 §7.5 owns the circuit it dials into. |
| [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) | Username/Password Authentication for SOCKS V5 | **§4.3**, *cited for what we do not do*: the authentication method the first implementation required and Chromium does not implement at all. Named in the module header (`src/ws-proxy.js:25-30`). |
| [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441) | Bootstrapping WebSockets with HTTP/2 | **§7**, *cited for what we do not do*: extended CONNECT is the mechanism by which a WebSocket could survive an HTTP/2 hop. It is not deployed on the reference path, which is why an h2 front end turns a WebSocket handshake into a plain `GET` and a `404`. |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) | HTTP/2 | **§7** — the fact behind that trap: HTTP/2 does not use the `Upgrade` mechanism, so an `Upgrade: websocket` request cannot exist on an h2 connection. Diagnosis in §7 is `curl --http1.1` versus the default, and ALPN inspection per SNI. |
| [nginx `ngx_http_v2_module`](https://nginx.org/en/docs/http/ngx_http_v2_module.html) | nginx, HTTP/2 module — the `http2` directive and the `listen … http2` parameter | **§7** — the operational half of the same trap: before nginx 1.25.1 HTTP/2 is enabled per listening socket by the `listen` parameter, so one `listen 443 ssl http2` anywhere enables h2 (via ALPN) for every SNI on that socket; the per-server `http2 off;` directive requires ≥ 1.25.1. |

### Proxy selection

| Identifier | Title | Used for |
|---|---|---|
| [PAC (MDN)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file) | Proxy Auto-Configuration (PAC) file — `FindProxyForURL(url, host)` and the `PROXY` / `SOCKS5` / `DIRECT` return grammar | **§4.6** — the format `src/ws-proxy-pac.js` generates. There is no RFC for PAC; the Netscape original is documented only in vendor documentation, and this is the reference implementers actually use. `tests/native-origin.test.js` evaluates the generated script the way an engine does. |
| [Chromium proxy documentation](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md) | Chromium, `net/docs/proxy.md` — proxy resolution, PAC evaluation, proxy bypass rules | **§4.6** — the engine-specific behaviour this design depends on: PAC scripts are evaluated per request; a PAC directive's embedded `user:pass@` is ignored; a proxy configuration must be supplied as a PAC *URL*. Also **DEVIATIONS §2.3**, the question of whether an implicit loopback bypass applies under a PAC configuration, which this document did not settle for us. |
| [RFC 2397](https://www.rfc-editor.org/rfc/rfc2397) | The "data" URL scheme | **§4.6** — how the generated script is delivered: `data:application/x-ns-proxy-autoconfig;base64,<script>` (`browser src/index.js:1142-1144`). Passing the script as text is rejected and the whole proxy configuration is silently dropped. |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | **§4.6** — the syntax that `data:` URL sits inside. **§4.2** — the authority form (`host:port`) the CONNECT target is, which is why `parseAuthority` accepts a bracketed IPv6 literal and nothing else with a colon. |

### Naming, pinning and the network's reserved names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | DANE: TLSA records | **§4.7** — the record the WebSocket's certificate is pinned to, resolved through Chapter 1 and checked in the session's certificate-verification procedure (`browser src/index.js:1330-1351`, `../../src/dane.js`). Its owner name `_443._tcp.<name>` is also the reason for **§4.4 fence 1**: 443 is the only port the pin covers, so it is the only port the tunnel accepts. Proven end to end through a real spliced connection by `tests/ws-proxy.test.js`. |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | DANE: Operational Guidance | **§4.7, §4.8** — the `3 1 1` (DANE-EE / SPKI / SHA-256) usage this implementation accepts, and the operational rules a publisher must follow for the pin to be usable. Chapter 1 §8 specifies the check itself; this chapter specifies that a WebSocket to a Handshake host is subject to it and fails closed without it. |
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | **§4.6** — `localhost`, `invalid`, `test` and `example` in the reserved list the PAC embeds from `../../src/reserved-names.cjs`, so they are never routed to the tunnel. Pinned by `tests/native-origin.test.js`. |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | **§4.6** — `.local`: the user's own NAS, printer or hub is never a Handshake name. |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The ".onion" Special-Use Domain Name | **§4.6** — `.onion` is excluded by the PAC explicitly as well as by the reserved list, so an onion address can never be sent to a component that would resolve it. Chapter 8 owns the rule; this is the copy that holds in the PAC. |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-Use Domain 'home.arpa.' | **§4.6** — `arpa` and the informal home-network labels in the same list. |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | **§4.4 fence 3** — the registry the SSRF guard's ranges come from: loopback, private, link-local (including `169.254.169.254`), CGNAT, benchmarking, multicast and reserved, and the IPv6 equivalents. The guard is the shared `../../src/safe-address.js`; Chapter 1's references enumerate the individual range registrations. |

### Identity and authentication

| Identifier | Title | Used for |
|---|---|---|
| [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) | Nostr, HTTP Auth (kind 27235) | **§5.3, §5.4** — the token the mediator mints and the application's server verifies: kind 27235, empty content, `u` / `method` / `payload` tags, a freshness window, and single use. `browser src/identity/receipt.js:174-218`, `browser src/identity/app-attest.js`. **DEVIATIONS AP-5** — the one place we depart from it: at a native origin the `u` tag is the application's canonical gateway origin, not the URL the request is sent to. |
| [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Nostr, Basic protocol flow description | **§5.3** — the event shape and id/signature rules NIP-98 builds on: the serialised id, the `pubkey` field, and the signature the application's server checks. |
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | **§5.3, §5.4** — the signature algorithm over that event. The verifying server implements it independently (and vendors one implementation rather than two), which is the correct posture: the browser's signature is worth nothing until something the browser does not control has checked it. |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Nostr, Mapping Nostr keys to DNS-based internet identifiers | **§5.1** — one of the public facts the identity capability may return about the user's main name (`_@<name>.<base>`), and nothing more: it is a discoverable address, not a credential. `browser src/identity/app-identity.js`. |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | The OAuth 2.0 Authorization Framework: Bearer Token Usage | **§5.4** — the shape of the credential that carries a session after the one signed request: `Authorization: Bearer <token>`, treated as a bearer credential (high-entropy, constant-time compared, expiring, revocable, never in a URL). Cited for the pattern; no OAuth flow is involved. |
| [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | NIST, Secure Hash Standard (SHA-256) | **§5.3, §5.2** — the body hash in a NIP-98 `payload` tag, and the hash that pins an installed manifest's bytes. |
| Handshake-Apps standard (`HANDSHAKE-APPS.md`, v0.1 + V0.2-DELTA) | The application-mediation standard the mediator implements: the capability surface, the manifest, and the consent model | **§5** — the document this chapter's §5 is a host for. It is not published in this repository, and it is the standard that had **no verb for an application to authenticate a user to its own server** — the gap the reference application found, declared as the extension `one.hns.auth.nip98`, and proposed as `identity.authenticate`. The other three findings recorded against it are: no notion of a *primary* name; no statement that a provider's answer is not proof (SPEC §5.4 states it normatively here); and an unspecified `names.request({})` with no TLD. |

### Reference-implementation documents

| Identifier | Title | Used for |
|---|---|---|
| `browser docs/WEBSOCKETS.md` | Wildroot, *WebSockets for Handshake apps (`wss://<name>`)* — the tunnel as built | **§4** in full: the constraint, the CONNECT mechanism, why not SOCKS5, the five fences with the port rule and the Tor route, the certificate gate, and the postmortem of the release that shipped and never connected once. It is the document this chapter's §4 is the specification of, and where the file-by-file map of the reference wiring lives. |
| `browser docs/MODES.md` | Wildroot, *Private mode and Fast mode* | **§4.4 fence 4** — the design of the one control, Settings › Content delivery › Mode, whose Private side routes the tunnel's upstream dial through Tor and whose fail-closed anonymizer produces the blocked state fence 4 refuses. Chapter 8 owns the circuit itself. |
| `../../src/delivery-mode.js` | The one switch — Settings › Content delivery › Mode | **§4.4 fence 4** — `policyFor()`, the policy table whose `ipProtection` row (`tor` or `off`) the anonymizer is driven to by `DeliveryMode`; the tunnel reads the anonymizer's `isOn()` and `torSocks()`, never a flag of its own. `namespaces/tor/src/anonymize.js` is where `BLACKHOLE_RULES` and the blocked state live. |
| `browser docs/HANDSHAKE-APPS-MEDIATOR.md` | Wildroot, the mediator as built | **§5** — the capability surface, the manifest store and the consent copy this chapter's §5 specifies the behaviour of (`browser src/apps/app-store.js`). |

### Specification conventions

| Identifier | Title | Used for |
|---|---|---|
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Key words for use in RFCs to Indicate Requirement Levels | The requirement keywords throughout this chapter. |
| [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | The same, in its uppercase-only reading. |

