# Chapter 8 — Tor: references

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

## Tor

| Identifier | Title | Used for |
|---|---|---|
| [rend-spec-v3](https://spec.torproject.org/rend-spec/) | Tor Rendezvous Specification — Version 3 | **§6, "Encoding onion addresses"** is §4 of this chapter: `base32(PUBKEY ‖ CHECKSUM ‖ VERSION)`, PUBKEY the 32-byte Ed25519 master public key, VERSION `0x03`, CHECKSUM `SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2]`; 35 bytes → 56 unpadded base32 characters. Implemented in full by `isValidV3Onion`, `../../src/router.js:240-262`, and consumed by the handler at `src/onion-protocol.js:123-127`. **The rendezvous protocol** is §9.1: the client's proof that the far end holds the private key is obtained by *establishing the circuit*, not by checking anything afterwards — **not implemented here**, it is performed by the `tor` process (`src/tor.js`). **Client authorization** is specified here too, and we do not implement it (DEVIATIONS TO-5). |
| [proposal 224](https://spec.torproject.org/proposals/224-rend-spec-ng.html) | Next-Generation Hidden Services in Tor | §4, provenance for the v2 refusal: the design rend-spec-v3 came from, and the reason a v3 address is 56 characters where a v2 address was 16. |
| [v2 deprecation timeline](https://blog.torproject.org/v2-deprecation-timeline) | Tor Project, "Onion Service version 2 deprecation timeline" | §4, why 16-character addresses are refused rather than supported: deprecation was announced in 2020 and support removed from Tor during 2021, so they are unreachable and not merely discouraged. `../../src/router.js:240-262`. |
| [control-spec](https://spec.torproject.org/control-spec/) | Tor control protocol specification | §7.1, **cited for what we do not do**: the bundled client is started with no `ControlPort` and readiness is parsed from tor's own `Bootstrapped 100%` notice on stdout, so there is no local control socket to authenticate and nothing for another process on the machine to talk to. `src/tor.js:199-208`; pinned by `tests/tor-circuit.test.js`. |
| [tor-man](https://spec.torproject.org/tor-man/) | Tor manual — `SocksPort`, `ClientOnly`, `AvoidDiskWrites`, `IsolateSOCKSAuth`, `ClientOnionAuthDir` | §7.1, the generated `torrc` (`src/tor.js:199-208`). `IsolateSOCKSAuth` and `ClientOnionAuthDir` are **cited for what we do not do**: per-origin SOCKS credentials would buy stream isolation we do not take (DEVIATIONS TO-3), and no client-authorization directory is configured (DEVIATIONS TO-5). |
| [Tor Browser design](https://2019.www.torproject.org/projects/torbrowser/design/) | The Design and Implementation of the Tor Browser | §9.3 and §1, the threat model this browser explicitly does **not** meet. It is why every user-facing string on this path pairs "hides your IP" with "not full anonymity", why `Accept-Language` is pinned to the value Tor Browser sends (`src/onion-protocol.js:228-241`), and the reference point DEVIATIONS TO-6 is measured against. |
| [Tor Expert Bundle](https://www.torproject.org/download/tor/) | Tor Project download page — the expert bundle | §7.1, where the bundled binary comes from. The vendoring step verifies a pinned GPG signature and then a pinned SHA-256; no binary is vendored in this package (DEVIATIONS §4). |

## Naming

| Identifier | Title | Used for |
|---|---|---|
| [RFC 7686](https://www.rfc-editor.org/rfc/rfc7686) | The ".onion" Special-Use Domain Name | §3, the rule this whole chapter is built around. The application requirements of §2: software that does not implement the Tor protocol should not perform a DNS lookup for a `.onion` name, and name-resolution APIs must either refuse it or hand it to Tor. Implemented in the stronger form R1/R2 — `.onion` is classified first and unconditionally, valid or malformed, at every entry point: `../../src/classify-host.cjs:116-119`, `../../src/reserved-names.cjs:31`, `../../src/hns-host.js:50`, `src/subresource-guard.js:35-54`. Cited again in DEVIATIONS TO-1 and TO-2. |
| [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) | Special-Use Domain Names | §3, the registry and the process RFC 7686 used, and the reason `onion` sits in the same never-Handshake list as `localhost`, `invalid`, `test` and `example` rather than being a special case of its own. `../../src/reserved-names.cjs`. |
| [IANA special-use domain names](https://www.iana.org/assignments/special-use-domain-names/) | Special-Use Domain Names registry | §3, where `onion` is recorded. The bundled ICANN root snapshot does **not** contain it, which is why the carve-out has to be explicit: without it, "not in the ICANN root" would make `.onion` a Handshake name. `../../src/reserved-names.cjs`, `../../src/icann-tlds.cjs`. |
| [RFC 9498 §9.10](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System — namespace precedence | §3, namespace precedence: resolve in the alternative namespace when its suffix matches, and do not continue into DNS on failure. Adopted as a normative rule in the spine and applied here in its strictest form, R2 — a *failed* onion address still must not continue into DNS. It is the only place we know of where this rule is written down in an RFC. |

## Encoding

| Identifier | Title | Used for |
|---|---|---|
| [RFC 4648 §6](https://www.rfc-editor.org/rfc/rfc4648) | The Base16, Base32, and Base64 Data Encodings | §4.1, base 32 (alphabet `A`–`Z`, `2`–`7`), lower-cased and unpadded: 56 characters × 5 bits = 280 bits = exactly 35 bytes, which is why a v3 label needs no padding and always decodes cleanly. §6 is the plain base32 alphabet — **not** §7 base32hex, which is what DNSSEC's NSEC3 owner names use. `../../src/router.js:226`, and the reference decoder in `tests/onion-address.test.js`. |
| [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions | §4.2, `SHA3-256` is the checksum function in the v3 address encoding, computed with `node:crypto` in `../../src/router.js:256-259` and independently in the test oracle. |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Edwards-Curve Digital Signature Algorithm (EdDSA) | §4.1 and §9.1, the signature scheme whose public key an onion address encodes. Cited because it is what "the address *is* the key" means concretely; no Ed25519 operation is performed by this code. |

## Transport

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 | §6.4 and R6, the transport the whole design rests on, and specifically §4: address type `0x03` (`DOMAINNAME`). Sending the `.onion` *hostname* to the proxy — rather than resolving it and sending an address — is the mechanism by which RFC 7686's no-DNS rule is satisfied at the wire level. `src/anonymize.js:300-315` (the `socks5://` proxy rule), `src/onion-protocol.js:140-195`. §7.5 cites it a second time for the five main-process paths that dial this controller's port for themselves rather than through the session: the protocol is spoken directly by `../../src/socks-dial.js` — the greeting with the "no authentication" method of §3, a CONNECT command, and `ATYP` IPv4 for a resolved address (the Handshake authoritative hop, an A-record `hns://` site's DANE-pinned socket, the `wss://` tunnel) or `0x03` for a host that must be resolved inside Tor (a Gemini capsule, a Nostr relay). §5 (the reply, whose own address type the client must parse to know where the framing ends) is implemented there too. |
| [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) | Username/Password Authentication for SOCKS V5 | **Cited for what we do not do.** Tor overloads SOCKS username/password for stream isolation, so distinct credentials per origin put each site on its own circuit. We send none — not on the session proxy, which has no hook for it, and not on the five direct dialers of §7.5, which could pass one and do not — so everything shares circuits within the session. DEVIATIONS TO-3 and TO-D1. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | §6.4–§6.7, the protocol spoken **inside** the tunnel, in plain HTTP. §13 conditional requests and §14 `Range` are among the forwarded request headers; §15 is the status codes the handler returns and passes through; §15.4 is the redirect semantics of §6.5, including §15.4.4: a same-service 301/302/303 after a request with a body is followed with a GET and no body, 307/308 keep the method. **§15.6.2 (`501 Not Implemented`)** — *"the server does not support the functionality required to fulfill the request"* — is the status for the one redirect class this handler refuses rather than follows: an `https:` target on an onion host, which the HTTP-only carrier cannot express (§5 R16, §6.5 R17, DEVIATIONS TO-8). The functionality that is missing is this browser's, which is why 501 is the accurate code rather than a 4xx blaming the service. There is no TLS in this path, which is why the lock is open (§8). `src/onion-protocol.js:140-217`, `:161-168`. |
| [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265) | HTTP State Management Mechanism | §6.4 and §6.6, cited for a negative that matters: neither `Cookie` (request) nor `Set-Cookie` (response) crosses this handler's allow-lists. Whether the underlying session-bound fetch attaches the session cookie jar of its own accord is **not established** — DEVIATIONS TO-4. `src/onion-protocol.js:200-214`, `:209-219`. |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | The Transport Layer Security (TLS) Protocol Version 1.3 | **Cited for what we do not do.** No TLS is spoken inside the tunnel and the `onion://` carrier has no way to express it (§5, R16), so a service's `https:` redirect is refused rather than downgraded (§6.5, R17) and the lock stays open (§8). What a certificate would even *mean* on a host name that is already a public key is the open question in DEVIATIONS TO-D6. `src/onion-protocol.js:86-101`, `:161-168`. |
| [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) | HTTP Strict Transport Security (HSTS) | §6.6, cited for a deliberate exclusion: `Strict-Transport-Security` is the one service header **not** passed through, because there is no TLS inside the tunnel and forwarding it would poison HSTS state for the `onion://` origin. `src/onion-protocol.js:200-214`. |

## Content the service controls

| Identifier | Title | Used for |
|---|---|---|
| [CSP Level 3](https://www.w3.org/TR/CSP3/) | Content Security Policy Level 3 | §6.6 and R9, `content-security-policy` and `content-security-policy-report-only` are passed through unchanged: they are the service's instruction about its own content, and dropping them would leave an onion page less defended here than in a browser that does nothing. `src/onion-protocol.js:200-214`. |
| [Fetch Standard](https://fetch.spec.whatwg.org/) | WHATWG Fetch — `X-Content-Type-Options: nosniff`, redirect modes | §6.5 and §6.6, `redirect: 'manual'` is the mode the redirect decision rests on, and `x-content-type-options` is passed through with the other service headers. `src/onion-protocol.js:141-195`, `:182-190`. |
| [RFC 7034](https://www.rfc-editor.org/rfc/rfc7034) | HTTP Header Field X-Frame-Options | §6.6, passed through with the other headers the service uses to defend its own content. `src/onion-protocol.js:200-214`. |
| [Referrer Policy](https://www.w3.org/TR/referrer-policy/) | Referrer Policy | §6.6, `referrer-policy` is passed through. `src/onion-protocol.js:200-214`. |
| [Permissions Policy](https://www.w3.org/TR/permissions-policy/) | Permissions Policy | §6.6, `permissions-policy` is passed through. `src/onion-protocol.js:200-214`. |

## URL and browser integration

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL](https://url.spec.whatwg.org/) | URL Standard | §5, what a *standard* scheme means — a real origin, host parsing, same-origin policy — and the parser `parseOnionUrl` uses to split host, port and path and to drop the fragment. `onion:` is not one of the *special* schemes, which is why a query-only URL has an empty path. `src/onion-protocol.js:54-74`; the scheme registration is in the browser's `main.cjs`, not in this package. |
| [protocol.registerSchemesAsPrivileged](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes) | Electron API — privileged scheme registration | §5 and §8, the `standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, allowServiceWorkers: false` registration that gives `onion://` a real, persistent, per-host origin so real web applications do not crash on an opaque one. `secure: true` is a **capability** decision, not a trust claim. The browser's `src/main.cjs` — **not extracted**, see DEVIATIONS §4. |
| [session.setProxy](https://www.electronjs.org/docs/latest/api/session#sessetproxyconfig) | Electron API — session proxy configuration, `proxyBypassRules` | §7.5, how the Tor SOCKS endpoint becomes the session's proxy for *everything*, with proxy-side name resolution. `<-loopback>` **subtracts** the implicit loopback bypass, so even `127.0.0.1` rides the tunnel rather than going around it. While BLOCKED (§7.6) the same call points every session at `BLACKHOLE_RULES`, `socks5://127.0.0.1:9` — a loopback port nothing listens on — so a Tor that cannot be had never becomes a direct connection. `src/anonymize.js:300-315`, `_cannotRoute`. |
| [webRequest.onBeforeRequest](https://www.electronjs.org/docs/latest/api/web-request#webrequestonbeforerequestfilter-listener) | Electron API — `webRequest.onBeforeRequest` | §3.1, the constraint the whole leak guard is shaped by: **one listener per session**, and a second registration silently replaces the first. That is why the onion/ENS leak guard, the Wildroot API gate and the WebSocket policy are composed into one function (`installSubresourceGuard`, `src/subresource-guard.js:74-110`) with a five-pattern filter, and why R18 requires an injected privacy policy to fail closed on its own fault (`:83-85`). The WebSocket policy itself is Chapter 11's (`../apps/SPEC.md` §4). Driven with a duck-typed session in `tests/onion-leak-guard.test.js`; Electron is not imported. |
| [net.fetch](https://www.electronjs.org/docs/latest/api/net#netfetchinput-init) | Electron API — `net.fetch` | §6.4, the session-bound fetch the handler is given, which rides the session proxy. Injected as `fetchImpl`, so every test in this package drives the handler with a stub and no Electron is imported anywhere. `src/onion-protocol.js:103-111`; wired in the browser's `src/protocols/index.js`. |

## Cross-references into the spine

| Identifier | Title | Used for |
|---|---|---|
| [`../../SPEC.md`](../../SPEC.md) | The integrated specification — the spine | §3, the classifier contract this chapter specialises, and the two laws: an explicit scheme selects the protocol, and a failure never crosses a namespace boundary. §8, the trust-state model the open onion lock maps onto. |
| [`../../SPEC.md` §4.2](../../SPEC.md) | The Fast / Private switch | §2, §7.3, §7.6 — the one control that drives this controller: `DeliveryMode.set('private')` flips the mode and then calls `setMode('tor')`; `set('fast')` calls `setMode('off')` and then flips; `policyFor(mode).ipProtection` is the value passed. The browser constructs the controller with `failClosed`, which is what makes BLOCKED reachable. `../../src/delivery-mode.js`, `../../tests/delivery-mode.test.js`. |
| [`../apps/SPEC.md`](../apps/SPEC.md) §4 | Chapter 11 — Handshake applications and the `wss://` tunnel | §3.1, the owner of the `websocketPolicy` this chapter's single `onBeforeRequest` listener dispatches `ws:`/`wss:` to. What the policy decides is specified there; what is specified here is that it is consulted before anything else, that no WebSocket enters the ad blocker or the HTTP namespace rewrite, and that a policy fault cancels (R18). §7.5 also names the tunnel as one of the five main-process paths that dial this controller's SOCKS port for themselves. |
| [`../../DEVIATIONS.md`](../../DEVIATIONS.md) | Deviations and open questions | The `TO-` entries this chapter cites, and the Handshake chapter's numeric-TLD convention referred to in §2.6. |
