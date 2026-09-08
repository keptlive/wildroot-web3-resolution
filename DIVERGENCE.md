# Privacy and transport

This table compares the routes described for Fast and Private delivery. It
records what a service can learn, which paths are implemented, and which
claims still need verification. Row numbers are retained for existing links
and references.

Private mode uses the device-local Tor client where supported and refuses
some protocols. A Tor route hides the client's IP address from the destination;
it does not hide the requested name, CID, or relay filter from the service
answering it. ODoH separates the client's address from the DNS question across
a relay and target, subject to their non-collusion assumption.

The policy is defined by `policyFor()` in
[`src/delivery-mode.js`](src/delivery-mode.js). The browser supplies session
and content-engine integration. Its current deployment is not established by
this repository.

The table reflects the repository's current policy and separates extracted
modules from browser integration. Remaining questions are listed in
[REVIEW.md](REVIEW.md).

| # | Operation | Fast route and disclosure | Private route | Status and remaining question |
|---|---|---|---|---|
| 1 | Handshake authoritative DNS (§6, Chapter 1) | Local chain proof, then TCP/53 to the authoritative server. The server and network path can see the name and client address. | Keep the chain proof; send authoritative TCP through Tor. | Implemented through `src/socks-dial.js`. Tor adds latency. The documented transition while restarting the SPV node uses DoH and reports its weaker trust state. |
| 2 | SPV peer traffic (§11.5, Chapter 1) | Direct hsd peer connections expose the client address. | Start hsd with its SOCKS proxy option. | Implemented. Changing the proxy restarts the spawned node; sync and availability costs remain. |
| 3 | Handshake DoH/ODoH (§9, Chapter 1) | Try ODoH; plain DoH may answer if relays fail. That endpoint receives the query without the oblivious separation. | Require ODoH; report failure rather than use plain DoH. | Implemented by `strictOblivious`. More independent relays could improve availability. |
| 4 | ICANN NS/CNAME targets during a Handshake walk | Browser integration injects `DoHResolver.addressOf` in both modes. The library default uses the OS resolver. | Use the injected encrypted/oblivious lookup. | Integration requirement. Library embedders must supply the lookup explicitly to avoid the OS default. |
| 5 | ODoH configuration fetch (IC-9) | Fetch `/.well-known/odohconfigs` from the target. It can associate the client with use of the service. | Proposed: bundle a configuration and refresh it through Tor. | Open. The ODoH relay does not provide a general GET proxy for this resource. |
| 6 | ICANN browsing DNS (§5, Chapter 2) | Chromium secure DNS uses the configured pool. | Use the local ODoH bridge in secure mode. | `policyFor('private')` requires secure mode. Plaintext fallback belongs to the configurable automatic policy, not the Private preset. |
| 7 | ICANN page fetches (Chapter 2) | Direct connection; the site sees the client address. | Session fetches through Tor; blocked proxy when Tor is unavailable. | Implemented. Tor latency and sites that reject Tor exits remain limitations. |
| 8 | IPFS DHT and Bitswap (§7, Chapter 3) | Kubo connects to peers, exposing the client address and requested CIDs. | Offline local node plus a proxied, verified content source for named sites. | The repository policy selects `contentNode: offline`. Browser integration implements the Kubo restart and content import; it is not included in this package. Peer discovery remains unavailable in Private. |
| 9 | Stated-origin CAR fetch (§8, Chapter 3) | Fetch a CAR from the published origin; it sees the CID and client address. | Fetch through the proxied session and verify imported blocks. | The origin-fetch module is implemented. Private delivery of named sites requires the offline-node integration in row 8. Bare CIDs without a stated origin need a separate source. |
| 10 | Cooperative delivery | Proposed peer delivery exposes addresses and CIDs to other users' nodes. | Proposed onion-service peers, or refusal. | Not shipped in either mode. Peer identity and performance remain design questions. |
| 11 | Arweave gateways (§6, Chapter 4) | Gateway receives the transaction ID and client address. | Use the same injected fetch through Tor. | Proxied transport is implemented. Header and byte verification are separate trust questions; see REVIEW.md. |
| 12 | ENS resolution (§5, Chapter 5) | Ethereum RPC receives the lookup and client address; CCIP-Read may contact gateways. | Send RPC and CCIP-Read through the proxied fetch. | Implemented. A cache reduces repeated queries; Tor does not conceal the query from the endpoint. |
| 13 | `web3://` RPC (§8, Chapter 5) | The library creates RPC clients using its own fetch. | Refuse with 503 while anonymized. | A proxied path needs an injectable transport in the dependency or a fork. |
| 14 | HIP-5 `_op` RPC (Chapter 10 Part A) | Optimism RPC through the injected fetch. | Use the proxied fetch while the chain path is available. | Implemented by injection. The library's global-fetch default is a separate risk (OP-D1). |
| 15 | Nostr relays (§8, Chapter 6) | Direct WebSockets expose the client address and filter. | Dial relay names through Tor; refuse if no Tor port is available. | Implemented in `namespaces/nostr/src/tor-websocket.js`. Relays still see filters. The handler exposes the injected WebSocket transport required for this route. |
| 16 | DID documents (Chapter 7) | Directory or `did:web` host receives the identifier and client address. | Use the injected proxied fetch. | Implemented for remote DID methods. Locally derived methods do not need this lookup. AT Protocol navigation and ActivityPub remain refused. |
| 17 | Onion services (Chapter 8) | No direct route is defined for this namespace. | Device-local Tor only. | The handler requires IP Protection and otherwise displays an interstitial. Circuit isolation remains open (TO-3). |
| 18 | Gemini (§K.6, Chapter 9) | Direct TLS; the OS resolver sees the hostname. | Dial by name through Tor; refuse without a Tor port. | Tor transport is implemented. Using the browser's resolver in Fast mode remains open. Certificate authentication is a separate issue. |
| 19 | Hyper, SSB, and BitTorrent discovery (Chapter 9) | DHT, swarm, or gossip exposes addresses and discovery requests. | Refuse with 503 and explain the mode restriction. | Refusal is implemented. Stated-origin delivery for a named site is the separate path in rows 8–9. |
| 20 | Hyper DNSLink (KY-4) | The dependency queries a DoH JSON resolver, Cloudflare by default. | The engine is refused in Private mode. | Using the browser's bridge would require a compatible JSON endpoint and certificate handling. |
| 21 | Handshake WebSockets (§4, Chapter 11) | Local CONNECT proxy dials the resolved public address. | The tunnel dials that address through Tor, or refuses without Tor. | Implemented. The same address restrictions and certificate checks apply to either route. |
| 22 | Search | Metasearch receives the query and client address through the configured fetch. | Use the proxied fetch. | Proxied transport is described. The backend still receives the query. |
| 23 | Bootstrap and configuration | Kubo bootstrap features are disabled by policy; the ICANN TLD list is bundled. | Same policy; ODoH configuration is covered by row 5. | The disabled and bundled paths avoid their corresponding startup requests. |
| 24 | Address-based `hns://` document fetch (§8, Chapter 1) | Raw TLS socket to the resolved address, with DANE checking. | Dial the address through Tor and check the pin on that connection. | Implemented in `src/dane-connect.js`. Refuse when Private mode has no Tor route. |

## Reading the comparison

Transport privacy, verification, latency, and availability are separate
properties. A route can preserve its cryptographic checks and still take
longer through Tor. A cache can remove repeated queries without protecting
the first one. A refused request prevents that disclosure but also prevents
the requested operation.

The earlier totals for “no-trade-off” and completed rows were inconsistent
and mixed proposed work with shipped behavior. This table reports status per
operation instead. It makes no general claim that Private is as fast as Fast.

Browser integration details are recorded in the browser's `docs/MODES.md`.
The user-facing disclosure string is `DISCLOSURE` in `src/delivery-mode.js`.
