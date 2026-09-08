# Content review and proposed improvements

Reviewed on 2026-09-08 against repository commit
`bd720c19019b08b6b68f856962deb0956e381961` (package 0.7.2). This review updates
the documentation; it does not change resolver or browser behavior. Findings
below describe this repository's source, not a verified production deployment.

## Completed documentation updates

- Replaced the long README with an introduction and task-based documentation
  links. Moved development and browser-comparison instructions to CONTRIBUTING.
- Shortened the shared model, namespace chapters, deviations, references, and
  changelog. Retained technical section numbers and deviation identifiers.
- Updated stale descriptions of nameserver failover, IPv6 lookups, local DID
  methods, ENS text records, conditional Arweave byte checks, numeric names
  being off by default, and the offline-node delivery policy.
- Replaced inconsistent privacy completion totals with status per operation.
- Clarified that browser parity compares selected checkouts and excludes
  factored modules. It does not identify a released build.
- Corrected the distinction between Electron's custom-scheme registration and
  WHATWG's fixed special-scheme list, and corrected mismatched RFC references.

## Issues to investigate first

### R1. Arweave header fields are not authenticated by the current check

**Evidence:** [`headerMatchesId()`](namespaces/arweave/src/ar.js#L38) hashes
only `header.signature` and compares the result with the transaction ID. It
does not verify that signature over the transaction fields. An offline check
accepted both the original header and a copy with changed `owner`, `tags`,
`data_root`, and `data_size`, while retaining the signature.

**Effect:** the optional body check uses a `data_root` received from the
gateway. Matching bytes to that root does not by itself bind those bytes to
the requested transaction. The rewritten chapter describes this limit;
the current `header` and `bytes` response labels need review.

**Proposed improvement:** verify the transaction signature before treating
header fields as authenticated, and make the response labels distinguish
consistency with a supplied root from authenticated transaction content.

### R2. The WebSocket PAC can select DIRECT in Private mode

**Evidence:** [`buildWsPac()`](namespaces/apps/src/ws-proxy-pac.js) returns
`DIRECT` for every non-Handshake `ws:` or `wss:` target, even when its
`baseDirective` is Tor. An offline evaluation with
`baseDirective: 'SOCKS5 127.0.0.1:9050'` returned:

| Request | PAC result |
|---|---|
| `https://example.com/` | `SOCKS5 127.0.0.1:9050` |
| `wss://example.com/socket` | `DIRECT` |
| `wss://example.wallet/socket` | local Handshake CONNECT proxy |

**Effect:** the extracted PAC conflicts with the stated policy that Private
session traffic uses Tor. This is a confirmed generator result; its effect
in a particular browser build depends on whether that PAC is installed.

**Proposed improvement:** use the base privacy directive for non-Handshake
WebSockets, then test the browser integration, including Tor-unavailable and
onion-service cases. No PAC or browser code is changed in this rewrite.

### R3. Non-pointer TXT answers can bypass a DNSSEC check

**Evidence:** [`src/resolver.js`](src/resolver.js#L896) validates a TXT RRset
when it parses as a content pointer. The checks near lines 964–980 require
authenticated denial only when no TXT/CNAME answer exists. A non-pointer TXT
answer therefore takes neither check. Handshake §6.5e describes the same
exception, despite broader claims that records influencing resolution are
validated.

**Possible effect:** an injected non-pointer TXT answer may suppress a real
content pointer and allow resolution to proceed to address records. This is
a static-code finding, not a completed end-to-end attack reproduction.

**Proposed improvement:** test substituted non-pointer TXT/CNAME answers in a
signed fixture, then decide which complete RRsets must validate before
content-pointer absence can be accepted. Review `car=` metadata from the
same answer for the same reason.

### R4. The Arweave verification threshold does not bound response buffering

**Evidence:** [`ar.js`](namespaces/arweave/src/ar.js#L282) checks the supplied
`data_size` against 8 MiB, then consumes the entire `res.arrayBuffer()` before
checking its actual length. A length mismatch skips the root check and serves
the result with the weaker `header` label.

**Effect:** a small declared size does not limit memory consumption. The
mismatch path supports gateway-rendered bundles and manifests, but also allows
different-length responses to avoid byte checking.

**Proposed improvement:** bound response consumption while streaming and
distinguish raw transaction data from gateway-rendered content. Decide when
a length mismatch should fail rather than downgrade the assurance label.

## Trust model and protocol questions

### R5. Trust output needs the actual resolution result

The shared [`src/trust-path.js`](src/trust-path.js) still describes all DID
documents as remotely fetched, although local methods return
`X-Resolution-Trust: derived`. Its generic ENS content step also claims
verified content without receiving the resolved pointer type; an Arweave
pointer cannot be described like a locally verified IPFS CID.

**Proposed improvement:** pass method, pointer type, and completed checks to
the trust builder. Deriving a document from a key identifier is not proof
that the current user controls that key. Review labels without collapsing
those distinct claims. The reference aggregator also treats `none` as a weak
step, whereas the application chapter's proposed WebSocket table includes
`none` steps and still claims a TRUSTLESS aggregate. Decide whether such
non-applicable steps belong in that input at all. The shared summary has been
updated to state the actual aggregation rule.

### R6. Explicit-scheme rules conflict with browser URL rewrites

The shared model's L1 and [router §3.1](namespaces/router/SPEC.md) say an
explicit scheme is final. Router §6.4 also requires browser navigation to
rewrite explicit HTTP(S) addresses by host into Handshake, ENS, or onion
URLs. The Tor chapter has a related explicit-scheme exception.

**Proposed improvement:** define separate stages for browser URL adaptation,
classification, and dispatch, and state exactly where L1 applies. This is
primarily a specification-scope decision; do not change routing merely to
make one sentence true.

### R7. DID receipt subjects are lowercased without method-specific rules

[`namespaces/did/src/receipt.js`](namespaces/did/src/receipt.js) lowercases
the complete subject DID. Other document and binding checks compare full
identifiers. Some method-specific identifiers contain case-sensitive data.

**Proposed improvement:** define supported receipt methods and canonicalize
each according to its own rules. Add mixed-case identifier examples before
changing signing or verification; existing receipts may need compatibility
handling.

### R8. Onion redirects can remove an HTTPS scheme

[`classifyOnionRedirect()`](namespaces/tor/src/onion-protocol.js#L90) accepts same-
service HTTP and HTTPS locations, then builds an `http://` fetch URL. The
onion address still authenticates the Tor service, but HTTPS and HTTP on that
service need not have the same behavior or application security requirements.

**Proposed improvement:** decide whether to preserve HTTPS, refuse that
transition, or document a deliberate HTTP-only contract. Test explicit ports
and redirects before changing the handler.

### R9. “No resolver” does not establish that an ENS name is unregistered

[`ens-protocol.js`](namespaces/ens/src/ens-protocol.js#L403) emits “is not
registered” for a `no-resolver` result without checking registration
ownership. A registered name may have no resolver.

**Proposed improvement:** report “has no resolver” and separately review the
mapping of unrecognized resolver errors to “no content.”

### R10. Private stated-origin delivery needs a protocol-specific scope

The IPFS origin module supports CAR delivery for IPFS content. The generic
refusal text in [`src/delivery-mode.js`](src/delivery-mode.js) also promises
stated-origin delivery for named peer-to-peer content. The key-addressed
chapter applies that wording to protocols whose origin-delivery engines are
not included here.

**Proposed improvement:** state which IPFS, torrent, and Hyper paths actually
support an origin source, with browser integration tests for each. Keep the
offline-node policy separate from claims about engines this package does not
contain.

### R11. Magnet consent has a mutable-address exception

[Keys §K.7.5](namespaces/keys/SPEC.md) says a clicked magnet must not start
peer traffic before consent, then excludes `xs=urn:btpk:` links from the
confirmation rewrite. The mutable form redirects to the network handler.

**Proposed improvement:** either scope the existing consent requirement to
managed v1 infohash torrents or extend confirmation to mutable-address links.

### R12. Recent ODoH activity is not evidence for a specific navigation

[`servedRecently()`](src/odoh-bridge.js#L170) accepts a ten-minute window and
matches subdomains of a recently answered name. A lookup for `example.com`
can therefore make the test pass for `a.example.com` without a lookup of
that host. This is weaker than the chapter's event-specific disclosure claim.

**Proposed improvement:** attach evidence to the actual lookup/navigation,
narrow the heuristic, or qualify the display as recent activity rather than
proof that this page's lookup used ODoH.

### R13. Merging direct TXT and DNSLink can discard a content path

[`parseDnslink()`](src/pointers.js#L290) retains a path, but
[`mergePointers()`](src/pointers.js#L324) compares only the pointer kind and
identifier, then returns the direct TXT pointer. `ipfs=CID` beside
`dnslink=/ipfs/CID/subdir` loses `/subdir` without reporting a conflict.

**Proposed improvement:** define whether the path participates in equality
or has an explicit precedence rule, then test both matching and conflicting
path combinations. Do not claim unrestricted DNSLink interoperability until
this case is settled.

### R14. Some DNS privacy claims need engine-level evidence

Policy tests establish an empty secure-DNS server list and an injected fetch;
they do not establish Chromium's cache/bootstrap behavior or the route used
by every embedder's fetch. The rewritten ICANN chapter records that limit.

**Proposed improvement:** test failed secure DNS, cached answers, and relay/
target bootstrap in the intended browser build before describing them as
measured fail-closed or OS-resolver behavior.

The `w3://` omission also needs a clearer rationale: a scheme and the `.w3`
Handshake TLD are already separated by explicit-scheme routing. Supporting an
alias remains a product decision, not a syntax collision.

## Application integration follow-up

- **Loopback policy:** AP-D1 describes adding a direct loopback branch as
  restoring the intent of `<-loopback>`. Chromium documents that token as
  *removing* implicit bypasses, the opposite operation. Decide the intended
  policy before implementing that recommendation. See
  [Chromium proxy bypass rules](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md#overriding-the-implicit-bypass-rules).
- **Tunnel guarantee:** port 443 is a destination restriction, not a TLS
  parser. The raw CONNECT proxy does not authenticate TLS for arbitrary local
  clients; the documented DANE guarantee depends on Chromium's certificate
  gate for browser connections. Narrow claims that the port alone prevents
  plaintext traffic.
- **Hostname disclosure:** sending an address in SOCKS avoids a SOCKS
  hostname lookup, but the TLS connection still uses `servername: host`
  (`src/dane-connect.js`). Do not generalize “no name in SOCKS” to “the Tor
  exit cannot see the name”; review SNI/ECH separately.
- **WebSocket server guidance:** Chapter 11's HTTP/2 failure describes a
  particular deployment path. HTTP/2 itself is not a universal prohibition;
  [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441) defines extended CONNECT.
  Replace host-wide configuration advice with versioned deployment guidance.
- **Sign-in binding:** AP-5 already records the native/gateway URL mismatch
  in NIP-98 authentication. Keep this as an explicit interoperability decision;
  a strict verifier can reject that token. Cookie behavior, service workers,
  manifest signatures, and grant revocation also remain open chapter items.

## Additional identity questions

- **ActivityPub authentication:** the proposed enablement requirements call
  for an actor-signature check, but the chapter does not identify a protocol
  that authenticates a fetched actor document in that way. Specify the
  mechanism before enabling the currently refused handler.
- **DID response format:** DI-D6 proposes a resolution-result wrapper while
  referring to a DID-document media type. Choose the representation and
  media type together before changing the response contract.
- **Local DID validation:** the local methods check selected codecs, lengths,
  object fields, and address syntax. They do not establish key possession or
  account existence, and they do not fully validate every accepted key type.
  Define the intended validation level and test malformed public keys.

## Version and evidence maintenance

The package is version 0.7.2; the shared specification still carries draft
version 0.4 and chapters have their own versions. Decide whether document
versions should track package releases or use an independent policy.

The browser comparison during this review reported differences in `src/doh.js`,
`src/resolver.js`, and `namespaces/ipfs/src/cid.js`. The browser has active work;
that result is expected evidence of drift, not a reason to overwrite either
tree. Future status claims should name a repository commit or tested browser
build and distinguish fixture tests from live observations.

## Validation of this rewrite

- 993 tests passed across 11 suites.
- JavaScript Standard lint passed.
- Generated-document freshness and link-target tests passed.
- Local Markdown validation found no broken targets or anchors in 493 links.
- `git diff --check` passed.
- No file under `src/` or `namespaces/*/src/` changed. The only non-document
  changes are package-description text, documentation generation/link handling,
  and the corresponding document test.

The browser parity check reports the three differences listed above. It is
not a passing check for this pair of working trees, and no sync was performed.
