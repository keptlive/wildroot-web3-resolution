# Findings reassessment and WebSocket specification review

Reviewed 2026-09-08. Scope: `keptlive/wildroot-web3-resolution`, package 0.7.2. Runtime findings refer to code baseline `bd720c19019b08b6b68f856962deb0956e381961`; the documentation rewrite was merged as `5eec37c4bdc8249dfc050fbfd683929407c0d812`. Selected browser files were inspected read-only to clarify integration. The browser has concurrent work, so these observations do not identify a released build. No browser, service, or runtime source was changed during this reassessment.

## Handoff after release

The owner plans to assign implementation work after Wildroot is released. This publication records findings and proposed decisions only. The fixing agent should compare these cases with the post-release source before changing behavior; the current browser has concurrent work. R1–R14 retain the original review identifiers; W1–W9 are the focused WebSocket follow-up.

## Main assessment

The highest-priority correction candidates are the TXT/DNSSEC validation gap, the WebSocket PAC's direct route in Private mode, and Arweave's unauthenticated header fields. The Arweave response-size check also needs a real consumption bound.

Several other findings are misleading descriptions or unresolved design choices. They should not all be presented as demonstrated security vulnerabilities. In particular, the gateway sign-in mapping is deliberate, the ENS content-label problem does not establish a green-lock bypass, and the engine DNS/privacy observations still need browser evidence.

The WebSocket work could make a useful HIP after narrowing it to an interoperable endpoint-authentication profile. The [candidate outline](handshake-websocket-hip-outline.md) separates that profile from Wildroot's implementation choices.

## Review of every numbered finding

### R1 — Arweave header authentication: confirmed; high priority when verification is enabled

`headerMatchesId()` checks the hash of the signature against the transaction ID. It does not verify that signature over the fields used to verify content. The stronger reproduction generated a real signed format-2 transaction header, changed its root and tags, and showed that the owner signature then failed while the module still returned `200` with `X-Arweave-Verified: bytes` for matching substituted content. The honest header rejected a same-length substituted body, which demonstrates exactly where the trust gap is.

The library defaults `verifyHeader` to false. The browser source inspected during this review explicitly enabled it. Neither fact establishes the configuration of a deployed release. The issue is the authenticity promised by the enabled path, not a claim that every request is locally verified.

**Recommendation:** verify the transaction signature using the supported transaction/account format before trusting its root, tags, or size. Keep gateway consistency and authenticated transaction content distinct in results. An RSA-only implementation must not claim support for every current transaction type. Test altered fields, unsupported formats, invalid signatures, and body/root mismatches.

Evidence: [ar.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/arweave/src/ar.js#L38), [Arweave transaction verification](https://github.com/ArweaveTeam/arweave-js/blob/master/src/common/transactions.ts).

### R2 — WebSocket PAC selects DIRECT: confirmed generator defect; high priority

With a Tor base directive, the generated PAC returns Tor for an ordinary HTTPS request but `DIRECT` for non-Handshake WebSockets. Reassessment also produced `DIRECT` for an onion WebSocket target. This contradicts the intended Private-mode route. It does not by itself prove what an installed browser does with onion names or whether an affected PAC is active in a released build.

**Recommendation:** preserve the base privacy directive for non-Handshake WebSockets. Define local-network exceptions separately. Test actual browser routing for ICANN, Handshake, onion, IPv4/IPv6, blocked Tor, disabled features, and every relevant session. No silent direct fallback when the required privacy route fails.

Evidence: [ws-proxy-pac.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/apps/src/ws-proxy-pac.js#L58).

### R3 — Non-pointer TXT bypasses validation: confirmed with signed fixtures; high priority

This was initially a static concern. A local fixture now establishes the narrower, concrete failure: replacing either content-pointer TXT source with unsigned non-pointer TXT, or an unsigned CNAME in its TXT response, changes resolution from IPFS content to the zone's valid signed address. With genuine authenticated no-TLSA evidence, the result includes `dnssecValidated: true` and `allowInsecure: true`. Empty responses and altered signed pointer data correctly fail, making the exception specific.

A second case allows unsigned `car=` metadata to set an origin on an otherwise valid DNSLink result. These tests show route downgrade and unauthenticated fetch metadata. They do not show acceptance of a forged A record or CID, an external attack, or the behavior of the concurrently modified browser.

**Recommendation:** validate complete TXT/CNAME evidence that determines pointer presence, absence, or origin metadata before using it. Require authenticated denial where appropriate. Add the substitution cases as resolver regression tests and review every metadata field influencing the subsequent fetch.

Evidence: [resolver TXT processing](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/src/resolver.js#L895).

### R4 — Arweave size threshold: confirmed; resource bound and policy both need attention

With an honest signed header declaring 13 bytes, the handler consumed a 9 MiB response and served it with the weaker `header` label. The declared-size threshold does not constrain `arrayBuffer()` consumption. The length mismatch also skips body verification. Gateway-rendered bundle/index responses explain the fallback's purpose, but do not make it safe to call the body verified.

**Recommendation:** enforce actual byte limits during consumption. Give raw transaction data and gateway-rendered responses different contracts. Decide whether a raw-data size mismatch fails; retain rendered content only with an explicit weaker assurance. Test false content lengths, chunked/oversized responses, interrupted streams, and the intended rendered-content case.

Evidence: [ar.js response verification](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/arweave/src/ar.js#L282).

### R5 — Trust output: confirmed inconsistencies; narrow the consequence

There are three distinct problems: locally derived DID documents are described as remote fetches; ENS content is described generically as verified without knowing the pointer's assurance; and the WebSocket table includes `none` steps while claiming an aggregate the shared aggregator does not produce. The ENS result remains partial overall in the reproduced case, so this is an inaccurate content step, not evidence of a green-lock bypass.

**Recommendation:** build output from actual completed checks, including method, pointer type, TLSA provenance, and fetch result. Separate “not applicable” from a missing verification check before aggregating. Local DID derivation establishes an identifier/document relationship, not user key possession. Transport encryption, server authentication, and application sign-in should remain separate facts.

Evidence: [trust-path.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/src/trust-path.js), [WebSocket trust table](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/apps/SPEC.md#6-trust-states).

### R6 — Explicit schemes versus browser rewrites: specification boundary, not a demonstrated routing bug

The classifier's “explicit scheme wins” rule and the browser adapter's host-based rewriting describe different stages. Treating them as one global invariant creates the contradiction.

**Recommendation:** specify input adaptation, classification, and dispatch in order. State which explicit URLs the browser adapts and apply the classifier rule to its actual input. Preserve intentional routing until a product decision changes it. Table-test explicit HTTP(S), native schemes, ENS, onion, and reserved hosts.

Evidence: [router specification](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/router/SPEC.md), [hns-host.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/src/hns-host.js).

### R7 — Lowercased DID receipt subjects: confirmed identifier-collision problem

Lowercasing the entire DID makes differently cased method-specific identifiers produce the same signed subject. A `did:web` path can contain case-sensitive characters. This does not establish a forged user session, but it breaks the receipt's intended exact-identifier binding.

**Recommendation:** define supported methods and method-specific canonicalization. Version or otherwise distinguish the corrected signing format so existing receipts cannot silently change meaning. Include pairs differing only in method-specific case and malformed identifiers.

Evidence: [receipt.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/did/src/receipt.js), [did:web method](https://w3c-ccg.github.io/did-method-web/).

### R8 — Onion HTTPS redirect loses its scheme: confirmed; Tor-contained correctness issue

The redirect classifier accepts an HTTPS location for the same service, then constructs an HTTP fetch URL. Default-port handling can also change the intended endpoint. Tor still authenticates the onion service; this finding does not establish a direct-network/IP leak. It changes application transport semantics.

**Recommendation:** preserve and implement HTTPS semantics, or reject unsupported HTTPS transitions. If the handler intentionally supports HTTP only, make that explicit and refuse contradictory redirects. Test default and explicit ports and same/different service identities.

Evidence: [onion-protocol.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/tor/src/onion-protocol.js#L90).

### R9 — ENS “not registered” error: confirmed factual wording error

A mocked no-resolver response produces “is not registered” without an ownership lookup. Registration and resolver configuration are separate facts.

**Recommendation:** say “has no resolver configured.” Only claim nonregistration after a suitable ownership/registration check. Review unrelated resolver errors separately instead of mapping all failures to missing content.

Evidence: [ens-protocol.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/ens/src/ens-protocol.js#L403).

### R10 — Private stated-origin promises: confirmed documentation scope error

The inspected browser permits IPFS CAR-origin warming in its relevant Private path but refuses named IPNS, BitTorrent, and Hyper there. Generic refusal text promises more than that implementation provides. This is not an observed Private-mode peer leak.

**Recommendation:** document a delivery matrix by protocol and mode. Promise origin delivery only for paths with an implementation and integration evidence. Keep planned torrent/Hyper origin support marked as planned.

Evidence: [delivery-mode.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/src/delivery-mode.js#L172), [IPFS specification](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/ipfs/SPEC.md).

### R11 — Magnet consent exception: confirmed; decide intended scope

Both mutable `btpk` links and mixed `btih`/`btpk` links bypass the confirmation rewrite. The inspected browser follows the mutable path in Fast mode and retains its Private gate. The blanket “clicked magnets never start peers before consent” requirement is therefore too broad.

**Recommendation:** either extend consent to mutable magnets or narrow the requirement to managed v1 infohash torrents. Test pure and mixed links, not just the common v1 form.

Evidence: [key-addressed specification](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/keys/SPEC.md).

### R12 — Recent ODoH activity: confirmed heuristic, not per-navigation evidence

A recent lookup for a parent name makes `servedRecently()` pass for an unqueried child name. Time proximity also does not correlate a result with one navigation. The bridge also discards the actual relay/target returned by the ODoH operation while the status helper names the first configured pair, so fallback can produce inaccurate attribution.

**Recommendation:** label this as recent resolver activity, or attach evidence to the actual lookup and navigation, retaining the relay and target that answered. Test parent/child names, concurrent tabs, cache reuse, expired entries, and relay/target fallback. Do not infer a network leak from the heuristic alone.

Evidence: [odoh-bridge.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/src/odoh-bridge.js#L170).

### R13 — DNSLink path lost during merge: confirmed behavior; precedence needs a decision

A direct `ipfs=CID` pointer and `dnslink=/ipfs/CID/subdir` merge to the direct pointer and lose the DNSLink path. Matching content identifiers do not imply matching resources.

**Recommendation:** include path in equality or specify explicit precedence. I favor reporting a disagreement rather than silently changing the requested content root. Test empty/nonempty paths, equal paths, and different paths for IPFS and other supported pointer kinds.

Evidence: [pointers.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/src/pointers.js#L324).

### R14 — Engine DNS/privacy claims: evidence gap; no demonstrated plaintext DNS leak

Policy tests show configured inputs, not the actual resolver path. Electron documents secure mode as DoH-only, but an empty `secureDnsServers` list can still allow provider auto-upgrade. Thus an empty list does not prove that every lookup is blocked or travels through this ODoH bridge. An injected fetch also does not establish one universal bootstrap route.

**Recommendation:** use the tested engine version and capture failed DNS, cache reuse, provider selection, relay/target bootstrap, and proxy failure. Describe intended policy separately from observed traffic. [Electron configureHostResolver](https://www.electronjs.org/docs/latest/api/app#appconfigurehostresolveroptions).

The separate `w3://` omission remains a product choice. A URI scheme and a `.w3` DNS label are syntactically distinct; a collision claim is not a sound rationale for omitting the alias.

## WebSocket findings and recommended specification changes

### W1 — Private-mode transitions need an explicit connection policy

**New, reproduced at module level.** The tunnel chooses a dial function before awaiting resolution. In a local test, changing Fast to Private while resolution was pending still invoked the previously selected direct dial after Private became true. The dial was injected and made no external connection. Browser cancellation or tunnel replacement could mitigate it; that lifecycle has not been verified.

**Recommendation:** use a policy generation/cancellation mechanism and check it before dialing. Specify what happens to pending and established sockets when the user enters Private mode or Tor fails. Rechecking a Boolean alone is not a complete lifecycle policy. Evidence: [ws-proxy.js](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/apps/src/ws-proxy.js#L327).

### W2 — The request-head bound has a bypass

**New, reproduced locally.** `readHead()` accepts a terminator before applying the size limit. A 10,052-byte complete request head reached resolution despite the stated 8,192-byte limit. Packet segmentation can affect this behavior.

**Recommendation:** compare the head-end offset with the limit even when the terminator is present. Add fragmented and single-chunk over-limit tests, a header deadline, bounded pending resolutions/dials, and a concurrency cap. Keep tunnel payload bytes distinct from header bytes. Evidence: [readHead()](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/namespaces/apps/src/ws-proxy.js#L126).

### W3 — Specify who authenticates TLS

**Confirmed wording problem, reproduced locally.** A CONNECT to port 443 carried arbitrary plaintext through the raw proxy to a local test upstream. That is expected for an opaque TCP tunnel. The browser's TLS/certificate gate supplies endpoint authentication; the proxy's port restriction does not.

Require end-to-end TLS for conforming browser WebSockets, and distinguish that requirement from the behavior available to arbitrary local CONNECT clients. Do not claim every socket is pinned to the document's current key: cross-origin sockets and key rotation require independent endpoint identity decisions.

### W4 — Require proof provenance, not merely a matching pin

The chapter's certificate procedure says to obtain TLSA and match it, while its trust table requires a validated zone and also describes a DoH fallback. Those are different assurance levels. The inspected browser hook passes returned TLSA records to the certificate matcher without an explicit provenance check at that call site. Whether a particular result was authenticated depends on the resolver path; this is not a reproduced certificate bypass.

Define the authenticated profile's evidence requirements. Keep address selection, authenticated name-to-key binding, encryption, and application identity separate. Resolve the R5 aggregation conflict. Define TLSA freshness, alias handling, rotation overlap, and cached/resumed connections. [DANE guidance](https://www.rfc-editor.org/rfc/rfc7671.html).

### W5 — Fix URL and handshake examples

The chapter permits a protocol-relative URL on the assumption that a secure custom scheme upgrades it to `wss:`. Standard constructor processing maps HTTP(S), not arbitrary secure custom schemes. `//pxls/ws` against `hns://pxls/` resolves to `hns://pxls/ws` in the URL check. Use an explicit `wss://` example; confirm the target browser before claiming an extension.

Retain server Origin checking and browser CSP behavior. Do not treat Origin as proof of user identity or as a guarantee that the initiator equals the destination. Keep browser redirects refused and generic JavaScript errors intact. Add negative handshake tests and privileged diagnostic records. [WebSockets Standard](https://websockets.spec.whatwg.org/), [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html#section-10.2).

### W6 — Fix privacy explanations and local-network policy

- **Loopback:** AP-D1's rationale reverses Chromium's `<-loopback>` meaning. That token removes implicit bypass rules. Do not automatically make private ranges direct; first define which local services are intentionally reachable and test IPv4/IPv6, mapped addresses, and PAC behavior. [Chromium proxy documentation](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md#overriding-the-implicit-bypass-rules).
- **Name exposure:** SOCKS address dialing avoids a SOCKS hostname request. It does not establish absence of TLS SNI disclosure. Describe SNI/ECH separately, and avoid implying Tor hides application identity from every participant.
- **Circuit sharing:** no per-origin isolation tokens means streams may share circuits; it does not mean every socket uses one single circuit. Tor applies other properties and rotation. [Tor stream isolation](https://spec.torproject.org/path-spec/stream-isolation.html).
- **Local proxy boundary:** loopback limits who can reach the listener; it does not authenticate the requesting application. The “local callers gain nothing” rationale assumes a particular local threat model and should not be universal.

### W7 — Keep browser restrictions out of universal conformance

Port 443 is a defensible initial support limit. DANE itself supports per-port records, so say that the reference resolver and certificate integration currently cover only 443. Additional ports need both parts changed together.

Chromium's lack of SOCKS5 authentication is documented. The broader assertion about all HTTP-proxy WebSocket authentication should be a versioned integration observation, backed by a regression test, rather than a requirement that every implementation ship without credentials. A HIP should permit other safe transports and authenticated local integrations. [Chromium proxy support](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md).

### W8 — Replace the HTTP/2 prohibition with deployment guidance

HTTP/2 WebSockets exist through extended CONNECT. The local forward-proxy CONNECT and the origin-side WebSocket handshake are separate layers. Document the exact nginx/browser path tested and use a working HTTP/1.1 configuration as the baseline. Do not recommend disabling HTTP/2 across an entire host as a universal requirement. [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html).

### W9 — Correct the TLSA/NXDOMAIN server guidance

The application chapter says an NXDOMAIN answer prevents no-TLSA handling, but the extracted resolver already accepts NOERROR or NXDOMAIN and verifies authenticated denial. The statement is stale. A nonexistent TLSA owner and an existing owner without that type have different correct negative responses; an underscore prefix does not dictate NODATA.

DO controls inclusion of DNSSEC material, not a second truth about whether TLSA exists. Describe one consistent RRset and its proofs. If a server/client version has an interoperability limitation, identify it rather than telling all servers to change DNS semantics. Evidence: [resolver denial handling](https://github.com/keptlive/wildroot-web3-resolution/blob/5eec37c4bdc8249dfc050fbfd683929407c0d812/src/resolver.js#L1124), [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.html), [RFC 3225](https://www.rfc-editor.org/rfc/rfc3225.html).

## Other findings from the original review

| Item | Reassessment and recommendation |
|---|---|
| NIP-98 native/gateway URL mapping | Deliberate application profile, not demonstrated forged authentication. The inspected application signs a declared gateway URL, verifies a fixed public base, and records event IDs against replay. Correct the claim that URL binding does no work: path/query/method/body binding can remain meaningful. Specify the trusted canonical mapping and exact verifier rules; do not accept arbitrary related origins or untrusted forwarded headers. Keep this out of the transport HIP. [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md). |
| ActivityPub actor authentication | The handler is refused today. An actor document does not generically carry the asserted actor-signature proof. Specify an actual supported mechanism and its key-trust bootstrap before enablement. A future design gap, not an active handler bypass. |
| DID representation/media type | A DID document and a DID-resolution result wrapper are different response contracts. Select matching representations and media types together and negotiate them explicitly. |
| Local DID validation | Offline tests accepted incomplete/invalid EC JWKs, a zero-byte secp256k1 point encoding, and an RSA codec with no key bytes. This establishes malformed-key acceptance, not a signature-verification bypass. Define supported key validation and negative cases. Derivation does not establish possession; lack of an account-existence lookup is not inherently a defect in identifier derivation. |
| Signed authorization header wording | The header contains the complete event as base64 and is a request-bound credential. Correct “never a secret, never the raw event” to say that the private key remains privileged while the page receives the signed authorization header. Replay protection belongs to the server/application. |
| Cookies and storage | Keep browser-specific behavior marked unmeasured. Dropping Cookie in the custom document-fetch path does not prove cookies are absent from the engine's separate WebSocket handshake. Test native and gateway origins, cross-origin requests, and partitions. |
| Service workers | A product and lifecycle decision. Define update, revocation, cached content, and network-policy behavior before enabling them. Do not make them a WebSocket HIP dependency. |
| Unsigned manifests | A known trust limitation. Manifest hashing pins bytes, not publisher identity. A signing proposal needs authenticated key discovery, rotation, revocation, and signed-to-unsigned downgrade rules. |
| Grant revocation | Still a useful application-control improvement. Define revocation behavior for future signing calls and existing application sessions separately. |
| Native discovery for dotted names | Retain as an application-discovery interoperability item with an explicit origin-ownership rule, separate from WebSocket transport. |
| Handshake/session coverage | Browser evidence is still needed for wrong Accept values, Unicode/numeric names, every session receiving the PAC, and complete sign-in. An unresolved name sent to system DNS can disclose the query even if connection establishment fails; remove “failure, not a leak” absolutes. |
| Package/document versions and browser drift | Different version numbers can be intentional. Publish an explicit versioning policy and evidence matrix naming commits/builds. The earlier parity differences are not permission to overwrite the browser. |

## Suggested order of work

1. Correct R3 and R2 with regression tests. Review W1 against browser lifecycle before any Private-mode guarantee. Correct R1's authentication contract and R4's actual byte bound.
2. Fix W2 and the confirmed factual prose errors: R9, relative WebSocket URLs, HTTP/2, NXDOMAIN, loopback semantics, and single-circuit claims.
3. Decide the behavior choices: R6 routing stages, R7 receipt compatibility, R8 HTTPS-on-onion handling, R11 mutable-magnet consent, R13 pointer-path precedence, and R5 result semantics.
4. Freeze a browser build for the unresolved integration tests. Draft the transport HIP around the resulting behavior and shared vectors.

This reassessment did not run or modify the user's browser. New reproductions used local fixtures, mocked fetches, generated test keys, or loopback sockets. They strengthen specific findings; they are not production penetration tests or a complete security audit.
