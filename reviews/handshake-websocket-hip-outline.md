# Candidate HIP outline: Authenticated WebSocket connections for Handshake names

Prepared 2026-09-08 for discussion. This is a proposed scope, not a submitted HIP or an adopted standard. No HIP number has been assigned. The requirements below are recommendations for a draft, not claims that the current browser implements them.

## Recommendation

A HIP is reasonable if it specifies behavior that independent Handshake clients and servers need to share. The present application chapter mixes endpoint authentication, Electron configuration, storage, application installation, and identity. Extract a small transport profile first.

The [HIP repository](https://github.com/handshake-org/HIPs#what-is-a-hip) explicitly seeks implementation-agnostic proposals. Use `HIP-xxxx` during discussion and follow the [HIP template](https://github.com/handshake-org/HIPs/blob/master/HIP-0000.md); maintainers assign numbers. A HIP does not imply a consensus change or endorsement.

Suggested title: **Authenticated WebSocket connections for Handshake names**.

Suggested type for discussion: Standards Track. If the final text contains only a description of Wildroot's Electron workaround, keep it as an implementation guide instead.

## Abstract

Define how a client authenticates a secure WebSocket endpoint identified by a Handshake name using authenticated DNS TLSA records. Reuse existing WebSocket framing, TLS, and DNSSEC/DANE. Specify the mapping between the requested name, service port, TLSA owner, and connection result. Support clients with different resolver and networking implementations.

## Motivation

An application should be able to publish one endpoint and know which name and key a compatible client will authenticate. Today, the application chapter leaves several questions to the browser: whether an unverified resolver answer is enough, how URL host spelling maps to DNS, and which failures can fall back. These are the interoperability questions worth standardizing.

## Proposed scope

| Include in the transport profile | Keep in separate guidance |
|---|---|
| Explicit `wss://` endpoint and authority mapping | Electron custom-scheme privilege flags |
| Authentication of the TLSA RRset to a Handshake trust anchor | Local HTTP CONNECT proxy and PAC implementation |
| Supported TLSA usages, selectors, and matching types | Proxy authentication limitations in particular engine versions |
| Port handling, aliases, key rotation, and evidence freshness | Tor installation and proxy configuration |
| Failure behavior and precise authentication result | Application manifests, grants, NIP-98, and sign-in |
| Browser handshake and origin compatibility requirements | Storage, cookies, service workers, and application installation |
| Interoperability examples and negative test vectors | Nginx deployment recipes and Wildroot trust-label wording |

## Proposed technical decisions

1. **Existing WebSocket protocol.** Use secure WebSockets. Do not introduce new frames, a custom JavaScript constructor, or a new URI scheme. Retain browser handshake protections, including redirect refusal and subprotocol validation. A browser integration annex can explain a page at `hns://` opening an explicitly constructed `wss://` URL. The standard constructor does not automatically convert an `hns:` base to `wss:`. [WebSockets Standard](https://websockets.spec.whatwg.org/#dom-websocket-websocket).

2. **Name and port mapping.** Define the canonical DNS name and `_<port>._tcp.<name>` lookup. Make 443 the initial interoperable baseline; implementations may refuse other ports before network activity. Additional ports require a port-aware certificate check. Define alias handling rather than silently mixing URL authority, CNAME target, and TLSA owner. Keep the numeric-name escape convention provisional or explicitly out of the first profile until its wire behavior is tested.

3. **Authentication evidence.** Require authenticated TLSA data for the Handshake-authenticated result. Specify accepted Handshake trust anchors and DNSSEC validation, including delegation, authenticated denial, stale evidence, and unsupported algorithms. An untrusted address may act as a locator if the endpoint key is independently authenticated and address policy permits it; address provenance and key authentication are distinct. Resolver-asserted pins must not receive the same result as locally validated evidence.

4. **DANE profile.** Start discussion with DANE-EE `3 1 1` as the common baseline and explicitly define treatment of mixed or unsupported TLSA records. Do not accidentally require WebPKI hostname or certificate-expiry checks for DANE-EE: its authenticated key association comes from TLSA. Define freshness, rollover overlap, caching, and resumed TLS sessions. [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671.html#section-5.1), [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698.html).

5. **Failure behavior.** A missing, bogus, expired, or mismatched required authentication proof fails the authenticated connection. No silent switch to plaintext, a gateway origin, or resolver-asserted trust. Optional compatibility behavior, if desired, needs a separately named result and explicit policy. Do not make Wildroot's current `TRUSTLESS`/`TRUSTED` labels the interoperable contract.

6. **Origin and application identity.** Preserve the initiating browser origin; it is not necessarily the target's origin. Servers can allow exact native and gateway origins according to their application policy. Origin checking does not authenticate a non-browser client or prove control of a Handshake name. Keep account authentication separate. [RFC 6455 §10](https://www.rfc-editor.org/rfc/rfc6455.html#section-10).

7. **Transport independence.** A local tunnel is one implementation option. It must not terminate TLS while claiming authentication of the remote endpoint's key. Ordinary HTTP/1.1 WebSockets provide a first compatibility target; HTTP/2 support can follow RFC 8441 where negotiated and supported. The client-to-local-proxy CONNECT and the server-side WebSocket opening handshake are different layers. [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html).

8. **Privacy and diagnostics.** An optional privacy section should state observable guarantees rather than require Tor everywhere: preserve the selected route, refuse unavailable required proxies, and specify behavior during mode changes. Report authentication and routing separately. Keep detailed failure reasons in privileged diagnostics instead of changing the web platform's generic error surface.

## Relationship to HIP-0017

[HIP-0017, Stateless DANE clients](https://github.com/handshake-org/HIPs/blob/master/HIP-0017.md), is a Standards Track draft describing certificate-carried Handshake/DNSSEC evidence. This profile should reference it and explain the distinction: HIP-0017 concerns obtaining and validating evidence without ordinary client DNS lookups; this proposal concerns applying authenticated endpoint identity to WebSocket connections.

Avoid requiring HIP-0017 as the only proof transport. A validating resolver and a future compatible certificate-proof implementation could satisfy the same authentication contract. If review shows that no interoperability decision remains beyond existing DANE and HIP-0017, publish an implementation note instead of duplicating those specifications.

## Evidence needed before submission

- A complete browser connection on a named, frozen build, with observed CONNECT authority, SNI, TLSA lookup name, HTTP authority, and initiating Origin.
- A valid connection plus failures for wrong key, absent TLSA, invalid DNSSEC, unsupported TLSA profiles, stale evidence, and unavailable resolver.
- Tests for mixed TLSA records, key rotation, cached certificate decisions, TLS resumption, aliases, and port handling.
- Negative handshake tests: wrong `Sec-WebSocket-Accept`, rejected subprotocol, HTTP redirect, and forbidden plaintext request.
- Fast/Private/blocked routing tests for Handshake, ICANN, onion, and local targets, including mode changes while resolving and established sockets.
- A second independent client or server interpretation of the draft and shared test vectors. This is a recommendation for quality, not a formal HIP submission requirement.

The current PAC defect, privacy transition case, trust-result contradiction, request-head limit, and stale DNS deployment guidance should be addressed or clearly bounded before presenting Wildroot as a conforming reference implementation.
