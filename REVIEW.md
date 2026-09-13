# Open review findings

A content review of this repository was carried out on 2026-09-08 against the
source as it then stood, and re-checked on 2026-09-12 against the code in this
release. Its findings were numbered `R1`–`R14`, and those numbers are kept here
so that anything citing them still resolves.

Most of them are now answered **in the code**, which is where an answer
belongs: this specification describes the implementation, so a finding is
closed by changing what the browser does, not by changing what the document
claims. What follows is the part that is **still open** — what this
implementation does not establish, and what it owes. The chapters carry the
same items in their own `DEVIATIONS.md`, with the standards each is measured
against; this file is the short list, in one place, for someone deciding
whether to trust any of it.

Nothing here is a claim about a deployed network or a released build. Findings
describe this repository's source, and the fixture tests that pin it.

## Closed in the code

| # | The finding | Where the answer is |
|---|---|---|
| R1 | Hashing `signature` to the transaction id left `owner`, `data_root`, `data_size` and `tags` free for a gateway to change | The transaction signature is verified over the fields — `namespaces/arweave/src/ar-tx.js` (Chapter 4 §9) |
| R2 | The WebSocket PAC returned `DIRECT` for every non-Handshake `ws:`/`wss:` target even when its base directive was Tor | An ordinary WebSocket follows the base privacy route; a malformed rule throws rather than degrading — `namespaces/apps/src/ws-proxy-pac.js` (Chapter 11) |
| R3 | A non-pointer TXT answer took neither the RRset check nor the denial proof, so an unsigned TXT could suppress a signed content pointer | Every TXT answer on a signed zone is authenticated before its application meaning is read, aliases included — `src/resolver.js` `_validatedTxtAnswer()` (Chapter 1 §6.5) |
| R4 | The 8 MiB verification threshold was checked against a *declared* size after the whole body had been buffered | Reads are bounded and streamed, and never trust `Content-Length` or the signed size as an allocation limit — `namespaces/arweave/src/ar.js` `readBounded()` |
| R6 | The shared model said an explicit scheme is final while the router chapter required browser navigation to rewrite HTTP(S) hosts into other namespaces | The stages are separated and L1 is scoped to the classification stage — Part II (`namespaces/router/SPEC.md`), `classify()` in `src/router.js` |
| R8 | A same-service redirect to `https:` was followed as `onion://`, silently dropping TLS | The transition is refused with a 501 — `namespaces/tor/src/onion-protocol.js` (Chapter 8) |
| R9 | `no-resolver` was reported as "is not registered", which a registered name with no resolver would have been told falsely | The page says the name has no usable resolver and that this establishes nothing about registration — `namespaces/ens/src/ens-protocol.js` (Chapter 5) |
| R11 | A `xs=urn:btpk:` magnet skipped the consent rewrite and went straight to a peer-backed URL | Both magnet forms reach consent, and the handler itself routes through the same rewrite — `namespaces/keys/src/magnet-protocol.js` (Chapter 9) |
| R12 | Ten-minute, subdomain-matching ODoH activity was displayed as though it were this page's provenance | Evidence is exact-host, rcode-filtered, sequenced, and labelled as recent activity — `src/odoh-bridge.js` `recentEvidence()` (Chapter 2) |
| R13 | `ipfs=CID` beside `dnslink=/ipfs/CID/subdir` was judged "the same pointer" and the path was dropped | The path takes part in the comparison; absent and `/` are the root and everything else must match exactly — `src/pointers.js` `mergePointers()` |

## Still open

### R5. A trust step needs the resolution result, not the scheme

**Where it stands.** The two worst cases are closed: a `did:` step now names
its own method and says a derived document proves no possession, and an `ens:`
Content step is `verified` only against a result bound to that exact request
(`ensContentStep()` in `src/trust-path.js`). `summarize()` now excludes a step
only when it is marked explicitly inapplicable.

**What is still owed.** The evidence channel itself is the browser's: this
repository specifies the *shape* of the result a handler must supply and the
rule that an unbound result proves nothing, but not the transport that carries
it. An implementation without that channel shows `unverified`, which is
correct but weaker than it needs to be. And Chapter 11's proposed WebSocket
table still has to decide which of its steps are genuinely non-applicable
rather than merely absent — the mechanism now exists; the decision has not been
made row by row.

### R7. Version 1 atproto receipts keep a lowercased subject

**Where it stands.** Receipts are versioned. Version 2 canonicalises the
subject per method — a `did:web` domain folds, its **path segments do not** —
and a verifier takes the version from the receipt and never retries another
after a failed signature (`namespaces/did/src/receipt.js`). Signing a
`did:web` *path* binding at version 1 is refused outright.

**What is still owed.** Version 1 is still produced by default, because the
deployed registry reconstructs v1 preimages. Until that registry supports v2,
a case-sensitive subject cannot be bound, and the v1 preimage remains a
deliberate deviation from what the method's own canonicalisation would imply.

### R10 / R14. Privacy claims that need engine-level evidence

**Where it stands.** Every claim of this shape has been narrowed to what is
actually observed. The mode disclosure says a *fresh* private lookup has no
plaintext fallback and that a cached answer may still work; the ICANN name
step and route hop name the **configuration** and say the path was not
observed; the route summary refuses to describe a page whose hops it cannot all
account for; the peer-to-peer refusal no longer promises stated-origin delivery
for protocols that have no origin path (that path is IPFS's alone).

**What is still owed.** The measurement. Failed secure DNS, a cached answer,
the relay/target bootstrap and Chromium's provider-upgrade behaviour have not
been observed in the intended browser build, and until they are, this
specification will keep saying "configured", not "measured". Fixture tests
establish what the code does with an injected fetch; they establish nothing
about the engine.

### Application integration (Chapter 11)

- **The tunnel authenticates no application.** Binding to 127.0.0.1 limits
  reach to this device; it does not say which local process is asking. Proxy
  authentication is not available on this path in the tested Electron build,
  which is a fact about that build and not a permanent property of Chromium.
- **Port 443 is this profile's restriction, not a TLS guarantee.** The proxy
  carries opaque TCP after `CONNECT`. The certificate check is the engine's,
  and DANE is not universally confined to `_443._tcp`: other ports would need
  their own TLSA lookup and their own tests.
- **SOCKS hides the name from the proxy, not from the exit.** Dialling by
  address keeps the hostname out of the SOCKS request; the TLS handshake still
  carries `servername`. ECH is the separate unsolved question.
- **HTTP/2 is not a universal prohibition.** RFC 8441 defines extended
  `CONNECT`; the failure this chapter describes belongs to one deployment
  path and is recorded with the version it was measured on.
- **`<-loopback>` does not mean what the earlier recommendation assumed.**
  Chromium documents the token as *removing* the implicit loopback bypass, and
  in the tested Electron build it had no effect under a PAC at all — which is
  why the request guard, not the PAC, decides a loopback WebSocket.
- **Sign-in binding.** The native/gateway URL mismatch in NIP-98 remains an
  explicit interoperability decision: a strict verifier can reject the token.
  Cookie behaviour, service workers, manifest signatures and grant revocation
  are open chapter items.

### Identity (Chapter 7)

- **Local DID validation proves key material, not control.** The local methods
  now check codecs, canonical encodings, curve points, subgroup membership and
  RSA structure, and refuse what they cannot check. None of that establishes
  that anyone possesses the private key or controls the account, and the step
  says so.
- **ActivityPub.** The enablement requirements call for an actor-signature
  check; no protocol that authenticates a fetched actor document in that way is
  identified. The handler stays refused until one is.
- **DID response format.** DI-D6 proposes a resolution-result wrapper while
  citing a DID-document media type. The representation and the media type have
  to be chosen together.

### Scope and versioning

- **`w3://`.** The omission needs a better rationale than a syntax collision:
  explicit-scheme routing already separates a `w3:` scheme from the `.w3`
  Handshake TLD. Whether to support an alias is a product decision.
- **Document versions.** The package is versioned; the spine still carries its
  own draft version and chapters carry theirs. Whether document versions should
  track package releases is undecided.
- **Naming the evidence.** A status claim should name the repository commit or
  the tested build it was established against, and should distinguish a fixture
  test from a live observation. This file and the chapters try to; where one
  does not, that is a defect in the document.

## How this repository is held to it

- `npm run parity` — every module under `src/` and `namespaces/*/src/` is the
  browser's, byte for byte, modulo import paths. A claim here cannot be true of
  a tidied copy and false of the shipped one.
- `npm run docs:check` — the consolidated `DEVIATIONS.md` and `REFERENCES.md`
  are generated from the chapters and cannot drift from them.
- `npm test` — deterministic, no network: every RPC, gateway, relay, directory
  and Tor is a scripted fake that misbehaves on purpose, and several Handshake
  tests spawn a real authoritative nameserver over frozen signed zones.
