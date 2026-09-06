# Chapter 11 — Native applications on a Handshake name: references

Every standard this chapter's implementation actually reads, with what it is
used for and where in the tree it is used. Nothing is listed that the code does
not touch: a padded bibliography is worse than none, because it makes the real
dependencies impossible to see.

Where a row says *cited for what we do not do*, that is stated in the row. Those
rows are here because a reader deciding whether to copy this design needs to
know which available mechanism was declined, and why — this chapter has three of
them, and they are the most useful rows in the file.

Paths written `../../src/…` are shared modules of the top-level package; paths
written `src/…` and `tests/…` are this chapter's, under `namespaces/apps/`.
Paths written `browser src/…` are in the Wildroot browser tree and are not
extracted into this repository (SPEC.md, "Paths").

---

## Origins, schemes and secure contexts

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL](https://url.spec.whatwg.org/) | URL Standard | **§3.1** — what registering `hns` as a *standard* scheme means: a [special scheme](https://url.spec.whatwg.org/#special-scheme) whose URLs get an [origin](https://url.spec.whatwg.org/#concept-url-origin) and whose host is run through [host parsing](https://url.spec.whatwg.org/#host-parsing). **§3.3** — the cost: the [ends-in-a-number checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and the [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) make an all-digit final label an IP address, which is the numeric-TLD casualty Chapter 10 Part B addresses. Registration at `browser src/main.cjs:110-120`; the marker is decoded at `src/ws-proxy.js:287` via `../../src/hns-url.cjs`. |
| [WHATWG HTML](https://html.spec.whatwg.org/multipage/) | HTML Standard | **§3.2** — [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin) as a tuple, and the [storage model](https://html.spec.whatwg.org/multipage/webstorage.html) keyed by it: what a Handshake page gains when the scheme becomes standard, and why an opaque origin makes an ordinary web application throw on its first line. Also **DEVIATIONS §2.5**, storage partitioning, which we have not measured. |
| [Secure Contexts](https://www.w3.org/TR/secure-contexts/) | W3C, Secure Contexts | **§3.1, §3.2** — what `secure: true` makes an `hns://` document: `isSecureContext`, `crypto.subtle`, and eligibility to open `wss://`. Note the chapter's own qualification: a secure *context* is not a padlock, and this implementation keeps the indicator scheme- and proof-driven (spine Part I §4). |
| [Mixed Content](https://www.w3.org/TR/mixed-content/) | W3C, Mixed Content | **§4.1** — the rule that makes this chapter's whole transport design necessary: a secure context may not open a plaintext `ws://`, and the reference engine enforces it in the renderer, before any proxy or handler could route it. |
| [Service Workers](https://www.w3.org/TR/service-workers/) | W3C, Service Workers | **§3.3**, *cited for what we do not do*: the `hns` registration sets `allowServiceWorkers: false` (`browser src/main.cjs:114`), so a native application cannot be offline-capable or installable at its Handshake name. DEVIATIONS AP-3, AP-D4. |
| [WHATWG Fetch](https://fetch.spec.whatwg.org/) | Fetch Standard | **§3.3** — the CORS model that a custom-scheme response is *not* protected by in the reference engine, because such a request arrives with no `Origin` and no initiator. It is why the origin gate of §5.1 is built on the engine's record of the sender rather than on headers. |
| [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454) | The Web Origin Concept | **§5.1** — the origin an operation is attributed to, reconstructed as `<scheme>//<host>` for a scheme a URL parser treats as opaque (`appOrigin`, `browser src/protocols/app-manifest.js:82-88`). **§8 / DEVIATIONS AP-4** — the `Origin` request header, which is the defence a Handshake application's own socket endpoint must apply. |

## Transport: the tunnel and the WebSocket

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) | The WebSocket Protocol | **§4** throughout: the `101` upgrade the tunnel carries but never parses. **§4.1 of the RFC** (the client's `Sec-WebSocket-Accept` check) is performed by the user agent, not by this implementation — DEVIATIONS §2.1 is explicit that we have not pinned it, and SPEC §6 therefore scores the upgrade step `none`. **§10.2 of the RFC**, that WebSockets are deliberately not subject to the same-origin policy, is the standards basis for DEVIATIONS AP-4. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | **§4.2** — [§9.3.6 CONNECT](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6): the method the tunnel implements, its `<host>:<port>` request target, and the rule that after a 2xx the connection becomes a tunnel (`parseAuthority` and the splice, `src/ws-proxy.js:158-164`, `:333-336`). **§4.3** — [§11 authentication](https://www.rfc-editor.org/rfc/rfc9110#section-11), the `407` / `Proxy-Authenticate` / `Proxy-Authorization` exchange, *cited for what we do not do*: it is implemented (`:275-278`) and unreachable, because the engine never surfaces the challenge for a `wss://` handshake. **§4.5** — the status codes the refusals use. |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) | HTTP/1.1 (message syntax and routing) | **§4.2** — the request-line and field-line grammar the head parser accepts, the CRLF CRLF terminator it reads to, and the `Connection: close` framing of a refusal (`readHead`, `parseConnectHead`, `_refuse`; `src/ws-proxy.js:107-151`, `:239-249`). The 8 KiB bound on a head is this implementation's, not the RFC's. |
| [RFC 7235](https://www.rfc-editor.org/rfc/rfc7235) | HTTP/1.1: Authentication | **§4.3** — the challenge/credentials framework RFC 9110 §11 now carries, cited because the implementation's retained credential path speaks it verbatim (`Proxy-Authenticate: Basic realm="…"`, `src/ws-proxy.js:276-277`). *Cited for what we do not do.* |
| [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617) | The 'Basic' HTTP Authentication Scheme | **§4.3** — the `Basic <base64(user:pass)>` encoding the retained gate parses and compares in constant time (`basicCredential`, `src/ws-proxy.js:167-171`; `safeEqual`, `:80-89`). |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 | **§4.3**, *cited for what we do not do*: the first implementation of this tunnel was a SOCKS5 CONNECT server. Chromium's SOCKS5 client offers only the "no authentication" method, so a proxy demanding anything else fails in the greeting — the reason the tunnel speaks HTTP CONNECT instead. A stray SOCKS greeting arriving at the HTTP tunnel is answered as a malformed head, pinned by `tests/ws-proxy.test.js`. |
| [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) | Username/Password Authentication for SOCKS V5 | **§4.3**, *cited for what we do not do*: the authentication method the first implementation required and Chromium does not implement at all. Named in the module header (`src/ws-proxy.js:25-30`). |
| [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441) | Bootstrapping WebSockets with HTTP/2 | **§7**, *cited for what we do not do*: extended CONNECT is the mechanism by which a WebSocket could survive an HTTP/2 hop. It is not deployed on the reference path, which is why an h2 front end turns a WebSocket handshake into a plain `GET` and a `404`. |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) | HTTP/2 | **§7** — the fact behind that trap: HTTP/2 does not use the `Upgrade` mechanism, so an `Upgrade: websocket` request cannot exist on an h2 connection. Diagnosis in §7 is `curl --http1.1` versus the default, and ALPN inspection per SNI. |
| [nginx `ngx_http_v2_module`](https://nginx.org/en/docs/http/ngx_http_v2_module.html) | nginx, HTTP/2 module — the `http2` directive and the `listen … http2` parameter | **§7** — the operational half of the same trap: before nginx 1.25.1 HTTP/2 is enabled per listening socket by the `listen` parameter, so one `listen 443 ssl http2` anywhere enables h2 (via ALPN) for every SNI on that socket; the per-server `http2 off;` directive requires ≥ 1.25.1. |

## Proxy selection

| Identifier | Title | Used for |
|---|---|---|
| [PAC (MDN)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file) | Proxy Auto-Configuration (PAC) file — `FindProxyForURL(url, host)` and the `PROXY` / `SOCKS5` / `DIRECT` return grammar | **§4.6** — the format `src/ws-proxy-pac.js` generates. There is no RFC for PAC; the Netscape original is documented only in vendor documentation, and this is the reference implementers actually use. `tests/native-origin.test.js` evaluates the generated script the way an engine does. |
| [Chromium proxy documentation](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md) | Chromium, `net/docs/proxy.md` — proxy resolution, PAC evaluation, proxy bypass rules | **§4.6** — the engine-specific behaviour this design depends on: PAC scripts are evaluated per request; a PAC directive's embedded `user:pass@` is ignored; a proxy configuration must be supplied as a PAC *URL*. Also **DEVIATIONS §2.3**, the question of whether an implicit loopback bypass applies under a PAC configuration, which this document did not settle for us. |
| [RFC 2397](https://www.rfc-editor.org/rfc/rfc2397) | The "data" URL scheme | **§4.6** — how the generated script is delivered: `data:application/x-ns-proxy-autoconfig;base64,<script>` (`browser src/index.js:1142-1144`). Passing the script as text is rejected and the whole proxy configuration is silently dropped. |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) | Uniform Resource Identifier (URI): Generic Syntax | **§4.6** — the syntax that `data:` URL sits inside. **§4.2** — the authority form (`host:port`) the CONNECT target is, which is why `parseAuthority` accepts a bracketed IPv6 literal and nothing else with a colon. |

## Naming, pinning and the network's reserved names

| Identifier | Title | Used for |
|---|---|---|
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | DANE: TLSA records | **§4.7** — the record the WebSocket's certificate is pinned to, resolved through Chapter 1 and checked in the session's certificate-verification procedure (`browser src/index.js:1330-1351`, `../../src/dane.js`). Proven end to end through a real spliced connection by `tests/ws-proxy.test.js`. |
| [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) | DANE: Operational Guidance | **§4.7, §4.8** — the `3 1 1` (DANE-EE / SPKI / SHA-256) usage this implementation accepts, and the operational rules a publisher must follow for the pin to be usable. Chapter 1 §8 specifies the check itself; this chapter specifies that a WebSocket to a Handshake host is subject to it and fails closed without it. |
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | **§4.6** — `localhost`, `invalid`, `test` and `example` in the reserved list the PAC embeds from `../../src/reserved-names.cjs`, so they are never routed to the tunnel. Pinned by `tests/native-origin.test.js`. |
| [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) | Multicast DNS | **§4.6** — `.local`: the user's own NAS, printer or hub is never a Handshake name. |
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The ".onion" Special-Use Domain Name | **§4.6** — `.onion` is excluded by the PAC explicitly as well as by the reserved list, so an onion address can never be sent to a component that would resolve it. Chapter 8 owns the rule; this is the copy that holds in the PAC. |
| [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375) | Special-Use Domain 'home.arpa.' | **§4.6** — `arpa` and the informal home-network labels in the same list. |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | **§4.4 fence 2** — the registry the SSRF guard's ranges come from: loopback, private, link-local (including `169.254.169.254`), CGNAT, benchmarking, multicast and reserved, and the IPv6 equivalents. The guard is the shared `../../src/safe-address.js`; Chapter 1's references enumerate the individual range registrations. |

## Identity and authentication

| Identifier | Title | Used for |
|---|---|---|
| [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) | Nostr, HTTP Auth (kind 27235) | **§5.3, §5.4** — the token the mediator mints and the application's server verifies: kind 27235, empty content, `u` / `method` / `payload` tags, a freshness window, and single use. `browser src/identity/receipt.js:174-218`, `browser src/identity/app-attest.js`. **DEVIATIONS AP-5** — the one place we depart from it: at a native origin the `u` tag is the application's canonical gateway origin, not the URL the request is sent to. |
| [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Nostr, Basic protocol flow description | **§5.3** — the event shape and id/signature rules NIP-98 builds on: the serialised id, the `pubkey` field, and the signature the application's server checks. |
| [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) | Schnorr Signatures for secp256k1 | **§5.3, §5.4** — the signature algorithm over that event. The verifying server implements it independently (and vendors one implementation rather than two), which is the correct posture: the browser's signature is worth nothing until something the browser does not control has checked it. |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Nostr, Mapping Nostr keys to DNS-based internet identifiers | **§5.1** — one of the public facts the identity capability may return about the user's main name (`_@<name>.<base>`), and nothing more: it is a discoverable address, not a credential. `browser src/identity/app-identity.js`. |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | The OAuth 2.0 Authorization Framework: Bearer Token Usage | **§5.4** — the shape of the credential that carries a session after the one signed request: `Authorization: Bearer <token>`, treated as a bearer credential (high-entropy, constant-time compared, expiring, revocable, never in a URL). Cited for the pattern; no OAuth flow is involved. |
| [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | NIST, Secure Hash Standard (SHA-256) | **§5.3, §5.2** — the body hash in a NIP-98 `payload` tag, and the hash that pins an installed manifest's bytes. |
| Handshake-Apps standard (`HANDSHAKE-APPS.md`, v0.1 + V0.2-DELTA) | The application-mediation standard the mediator implements: the capability surface, the manifest, and the consent model | **§5** — the document this chapter's §5 is a host for. It is not published in this repository, and it is the standard that had **no verb for an application to authenticate a user to its own server** — the gap the reference application found, declared as the extension `one.hns.auth.nip98`, and proposed as `identity.authenticate`. The other three findings recorded against it are: no notion of a *primary* name; no statement that a provider's answer is not proof (SPEC §5.4 states it normatively here); and an unspecified `names.request({})` with no TLD. |

## Specification conventions

| Identifier | Title | Used for |
|---|---|---|
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Key words for use in RFCs to Indicate Requirement Levels | The requirement keywords throughout this chapter. |
| [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words | The same, in its uppercase-only reading. |
