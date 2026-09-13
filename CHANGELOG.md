# Changelog

## 0.10.0

Sync with browser 2.78.40 (`39e5147`). **A setting is not an observation.** The
content review this repository declined to merge on 2026-09-08
(`REVIEW-DOCS-REWRITE-2026-09-12.md`) is answered where an answer belongs — in
the code — and twenty-two modules changed with it. Ten of the review's fourteen
findings are closed by behaviour; the rest are written down as what is still
owed (`REVIEW.md`, new). Every chapter that owns one of those modules is
rewritten to describe what it now does.

- **The panel and the route view stop converting configuration into a claim
  about a page** (spine `SPEC.md` §4, §4.1, §4.2; Chapter 2 §6.1–§6.4;
  `src/trust-path.js`, `src/route-path.js`, `src/odoh-bridge.js`,
  `namespaces/icann/src/dns-policy.js`). Chromium resolves an `http(s)` host
  itself, from its own cache, out of this process's sight, so every ICANN name
  step is now `unverified` and names the configuration as configuration — the
  fail-closed plan included, which is a configured refusal of *new* lookups and
  never an observed failure — and the route hop is a new value, `unknown`, in
  every branch. One `unknown` hop decides the route summary. The oblivious
  claim survives only as **evidence**: `recentEvidence()` records the exact
  host answered, the relay and target that actually answered it, the query
  type, a sequence number so a late older query cannot overwrite a newer
  result, and only rcode 0 or 3; the subdomain match that let one
  attacker-chosen name vouch for `example.com` and for `com` is gone, and the
  wording says a lookup happened, not that this page used it. A content step
  is `verified` only against a result bound to that exact request
  (`ensContentStep()`), and `summarize()` drops a step only when it is marked
  explicitly inapplicable — a missing protection still weakens the verdict.
  New: `IC-17`, `IC-18`, `IC-19`, `IC-D5`, §2.11, `EN-8`.
- **An ODoH reply is bound to its question before it is an answer** (Chapter 2
  §5.3; `src/odoh-bridge.js` `dnsEnvelope()`). HPKE authenticates the transport
  bytes, not their DNS meaning. The bridge now parses both packets: one
  question, a frame with no trailing bytes, compression pointers that cannot
  loop, the 255-octet name limit, QR set, no truncation or reserved flags, and
  the reply's id, name (compared as case-folded label bytes, not decoded text),
  type and class equal to the query's. Anything else is a SERVFAIL that also
  masks the success before it. RFC 1035 §4.1.1/§4.1.2/§4.1.4, RFC 4343 and
  RFC 9230 cited per rule; `tests/odoh-bridge.test.js` sweeps fifteen ways to
  miss the binding and `namespaces/icann/tests/odoh-evidence.test.js` pins the
  consequence for the panel.
- **Every `TXT` answer on a signed zone is authenticated before it is read**
  (Chapter 1 §6.5e; `src/resolver.js` `_validatedTxtAnswer()`). The old rule
  validated the RRset only when it parsed as a content pointer and demanded an
  authenticated denial only when nothing answered at all, so a non-pointer
  TXT — an SPF record, a verification token — took neither check and an
  unsigned one could suppress a signed `ipfs=` pointer and walk the browser
  down to an address record. One rule now covers the name's TXT and its
  `_dnslink` alike: NOERROR or NXDOMAIN only; TXT and CNAME may not coexist at
  one owner (RFC 2181 §10.1); a present RRset validates to the on-chain DS or
  fails closed; a CNAME is validated as type 5 over its RFC 4034 §6.2 wire
  name and then followed, one alias per owner, eight owners deep, no loops,
  with a cross-zone or delegated target refused rather than walked under this
  zone's keys; and nothing at the owner is proven absent (RFC 4035 §5.4). New:
  `HS-17`, `HS-18`, §2.8.
- **A DNSLink path takes part in the comparison** (Chapter 1 §10.1;
  `src/pointers.js` `mergePointers()`). `ipfs=<cid>` beside
  `dnslink=/ipfs/<cid>/subdir` was judged the same pointer and the path was
  dropped. Absent and `/` both name the root; every other path must match
  exactly, and a difference is a reported conflict naming each pointer with its
  path. Nothing is percent-decoded or normalised before the comparison,
  deliberately, because the spelling selects the content (`HS-19`).
- **One IPFS node, two schemes** (Chapter 3 §3, §4.2, §12.5; Part II §4.2,
  §10.2; spine §2, §5; `src/router.js`, `src/trust-path.js`,
  `src/route-path.js`). `ipld://` and `pubsub://` are retired with the second
  daemon the browser dropped in 2.78.39: `ipfs://` and `ipns://` are served by
  the one node Handshake names already use, and an `ipns://` name is resolved
  **on the node** — never by trusting a gateway's answer — which is where IP-3's
  rule now meets a reader. The scheme table is 30 rows over 18 namespaces; the
  `libp2p/pubsub`, `ipns-pubsub-router` and `js-ipfs-fetch` reference rows go
  with the schemes they described. Part II also separates the three stages an
  address passes through, so L1 ("an explicit scheme is authoritative") is
  scoped to classification and the browser's own HTTP(S) adaptation is named as
  the earlier stage it is (`RT-14`).
- **What the warmer remembers, and for how long** (Chapter 3 §8.3; new
  `namespaces/ipfs/src/block-presence.js`, the 74th copied module). The node
  garbage-collects unpinned blocks, so an imported archive or window is trusted
  for five minutes and then re-confirmed with one offline block lookup of the
  root; a missing root forgets the CID and every slice under it. Without it a
  collected archive is answered "present" for the life of the process — and in
  Private, where the node is offline and cannot re-fetch, the site simply stops
  loading (`IP-12`). `fileCid()` also gained an `onBlock` sink and there is a
  new `directoryNode()`; neither changes a CID.
- **Consent covers both magnet forms** (Chapter 9 §K.7.4, §K.7.5;
  `namespaces/keys/src/magnet-protocol.js`). A `xs=urn:btpk:` magnet reached
  `bittorrent://<key>` without asking. Both forms now land on the confirmation
  page, and the handler applies the same rewrite itself, so a redirect or a
  subresource that arrives without the navigation rewrite cannot reach a
  peer-backed URL either (`KY-5`, `KY-10` rewritten; `KY-12` new for a
  malformed `xs` still refused by the wrong name).
- **An onion redirect may not drop TLS** (Chapter 8 §5, §6.5;
  `namespaces/tor/src/onion-protocol.js`). `onion://` carries HTTP inside Tor,
  so a same-service redirect to `https:` is refused with a 501 rather than
  re-encoded — which would lose the TLS and, after URL normalisation, an
  explicit `:443`. An HTTPS-only onion service is therefore unreachable here,
  recorded as the limitation it is (`TO-8`, `TO-D6`).
- **A route that stops existing is revoked** (Chapter 8 §3.1, §7.3, §7.7;
  `namespaces/tor/src/tor.js`, `anonymize.js`, `subresource-guard.js`). A dead,
  exited or never-bootstrapped Tor emits `route-unavailable` once a route was
  actually offered, and the controller re-enters its blackhole immediately;
  handlers are bound to their own child so a superseded one cannot clear the
  current route; every `await` in `setMode()` is followed by a sequence check;
  and `torSocks()` returns null during the interval between "Tor was asked for"
  and "the session proxy is installed", which `isSwitchingToTor()` names for
  the raw-socket paths. The single `onBeforeRequest` listener now also
  dispatches `ws:`/`wss:` to an injected policy, and a policy that throws fails
  closed.
- **Ordinary WebSockets follow the privacy route** (Chapter 11 §4.6;
  `namespaces/apps/src/ws-proxy-pac.js`). The PAC returned `DIRECT` for every
  non-Handshake `ws:`/`wss:` target even when its base directive was Tor. It
  now falls through to the base route, and a rule or port it cannot represent
  throws instead of degrading to a direct one.
- **The tunnel's claims, narrowed** (Chapter 11 §4.2–§4.5, §7, §8;
  `namespaces/apps/src/ws-proxy.js`, `src/socks-dial.js`). Loopback is a device
  boundary that authenticates no requesting application; port 443 is this
  profile's `_443._tcp` lookup and a destination restriction, not a TLS or pin
  guarantee (the certificate check is the engine's, and the proxy is an opaque
  pipe); dialling by address keeps the name out of the SOCKS request but not
  out of the ClientHello, so the exit still sees it (`AP-8`, and the same
  correction in Chapter 1 §8.1 and `DIVERGENCE.md` row 24); no stream isolation
  is requested, so which circuit a dial gets is Tor's decision and is not
  observed here; and the HTTP/2 advice is versioned, because RFC 8441 defines
  extended CONNECT. `AP-D1`'s recommendation is corrected: Chromium documents
  `<-loopback>` as *removing* the implicit bypass, and in the tested build it
  had no effect under a PAC at all. The tunnel also gained bounded resources
  and real statuses — `WS_LIMITS`, a per-connection abort, a generation counter
  that tears down pending work and established streams on a mode switch, and
  504 on a timeout / 503 when too many operations are pending / 502 otherwise.
- **"No resolver" is not "not registered"** (Chapter 5 §5.6, §7;
  `namespaces/ens/src/ens-protocol.js`). A revert answers about the resolver.
  The page now says the name has no usable resolver and that this establishes
  nothing about registration, instead of telling the holder of a registered
  name that it does not exist.
- **The local DID methods validate the key material** (Chapter 7 §5.1a, §5.1b;
  `namespaces/did/src/did-local.js`). Canonical multicodec varints, a capped
  identifier, RSA that re-exports to the same PKCS#1 DER, Ed25519 points that
  are valid, non-small-order and torsion-free, an X25519 low-order probe,
  compressed points OpenSSL accepts, and a `did:jwk` that must round-trip as
  unpadded base64url and survive `createPublicKey`. None of it proves anyone
  holds the private key or controls the account, and the step says so
  (`DI-12`).
- **Versioned atproto receipts** (Chapter 7 §9.3;
  `namespaces/did/src/receipt.js`). A verifier takes the version from the
  receipt and never retries another after a failed signature. Version 1 keeps
  its lowercase preimage exactly, for the receipts already deployed; version 2
  canonicalises per method — a `did:web` domain folds, its path segments do
  not — and signing a `did:web` path binding at version 1 is refused outright
  (`DI-13`, `DI-14`).
- **`REVIEW.md`** (new) — the review's open findings, re-checked against this
  code: what is closed and where, and what is still owed (the measurements no
  fixture test can stand in for, the evidence channel this repository does not
  specify, v1 receipts, the tunnel's remaining boundaries, ActivityPub, `w3://`
  and the document-versioning question). **`REVIEW-DOCS-REWRITE-2026-09-12.md`**
  (new) — why the 2026-09-08 documentation rewrite was not merged, and the rule
  a future prose pass is held to: the entry schema, the normative citations,
  the `§` and `src/file.js:123` pointers and the counts may not be removed.
- Deviation ledger — **added**: `HS-17`, `HS-18`, `HS-19`, `IC-17`, `IC-18`,
  `IC-19`, `IC-D5`, `IP-12`, `RT-14`, `EN-8`, `DI-12`, `DI-13`, `DI-14`,
  `TO-8`, `TO-D6`, `KY-12`, `AP-8`, and the uncertainties Chapter 1 §2.8,
  Chapter 2 §2.11, Chapter 8 §2.8, Chapter 9 §2.8. **Changed**: `HS-1`, `HS-3`,
  `HS-9`, `HS-D1`, `IC-4`, `IC-6`, `IC-7`, `IC-15`, §2.4, §2.5, `IP-3`, `IP-5`,
  `IP-6`, `IP-8`, `IP-9`, `IP-10`, `IP-D8`, `RT-3`, `RT-4`, `RT-5`, `RT-6`,
  `RT-8`, `RT-10`, `RT-12`, `RT-D1`, `RT-D4`, `EN-7`, `DI-2`, `KY-5`, `KY-10`,
  `AP-2` (DELIBERATE → OPEN), `AP-4`, `AP-7`, `AP-D1`, `AP-D8`, `AP-D9`.
  **Deleted**: Chapter 3's open item on `js-ipfs-fetch`'s `ipld://` and
  `pubsub://` semantics, with the schemes it described. Twenty-seven stale
  `src/file.js:123` pointers corrected in Chapter 8 alone — among them the
  `.onion`-first classifier, which is `src/classify-host.cjs:116-119`.
- 1058 deterministic tests in 11 suites (90 files), no network; 74 modules
  byte-identical with the browser tree and 8 declared factored; 268 numbered
  entries in the consolidated `DEVIATIONS.md`.

## 0.9.0

Sync with browser 2.78.39 (`cb633bb`): **one** Arweave transaction verifier.
0.8.0 wrote a second implementation of a check the browser already had, and
the two are now the same module — `namespaces/arweave/src/ar-tx.js`, extracted
from the browser's `src/hns/ar.js` and byte-identical to `src/hns/ar-tx.js`.
What the merged module keeps from each side:

- **From the browser** — strict field reading (canonical base64url only, the
  decimal grammar, the `data_size`/`data_root` pairing, the tag budget, the
  32-byte target and 32/48-byte anchor), the optional `denomination` in the
  format-2 payload (`ar_tx.erl`), an explicit `signature_type` refused rather
  than ignored, and, in `ar.js`, the whole fetch contract this repository had
  not caught up with: the representation decided from the *authenticated*
  header before any data is read (`X-Arweave-Representation`: `raw`,
  `gateway-rendered`, `manifest-path`, `gateway`), bounded reads that never
  trust `Content-Length` or the signed size as an allocation limit, a streamed
  size check above 8 MiB, a signed `Content-Type` for a verified raw body, and
  `AbortSignal` all the way through.
- **From this repository** — the legacy **format 1**, verified rather than
  refused (its signature covers the data itself, so the served bytes are
  compared with the signed bytes and reported `bytes`), and the third verdict:
  a header the implementation *cannot* check (an unknown format, an
  unrecognised account type, an owner that is not RSA-4096, a format-1 header
  without its data) is `unsupported` — `X-Arweave-Verified: none`, the signed
  root unused — instead of a refusal. Refusing there stops no attack, because
  a header gateway reaches the same standing by not answering.
- **Decided in the merge** — an owner **MUST** be RSA-4096, the only key size
  an Arweave wallet has; 2048 was a test fixture's size, and a smaller
  attacker-chosen modulus is the easier half of fitting a fixed signature to
  chosen fields.

`headerVerdict` is gone; `verifyTransactionHeader(header, txid)` returns
`{ ok, verdict, dataSize, dataRoot, data, tags }` and `headerMatchesId` is its
boolean. The chapter's tests are the browser's merged set
(`tests/ar-tx.test.js` with the two real transactions, `arweave-header.test.js`,
`ar-bytes.test.js`, `arweave-gateways.test.js`, `ar-transaction-fixture.js`).

1023 tests in 11 suites, 73 modules byte-identical with the browser tree; the
scheme table's `ar` row, Chapter 4 §9 and Chapter 10 §4.1 say what a fetch now
checks and what stays gateway-trusted.

## 0.8.0

- **The Arweave transaction header is authenticated, not just hashed**
  (`namespaces/arweave/src/ar-tx.js`, new) — a transaction id is
  `SHA-256(signature)`, and that hash alone left `owner`, `data_root`,
  `data_size`, `tags`, `target`, `quantity`, `reward` and `last_tx` free for a
  gateway to swap while keeping the signature: the byte check of 0.7.0 would
  then hash the body against a data root the gateway chose and report
  `X-Arweave-Verified: bytes`. The signature is now verified over the
  transaction's own fields — RSA-PSS/SHA-256 under the key `{ n: owner,
  e: 65537 }`, over Arweave's deep hash (SHA-384) of `["2", owner, target,
  quantity, reward, last_tx, tags, data_size, data_root]` for format 2, and
  over the legacy concatenation for format 1 — so the root the bytes are
  measured against is the one the identifier commits to. No dependency: the
  algorithm is arweave-js's, re-implemented on `node:crypto`.
  - A header that is not the identifier's transaction is a **502**, as before,
    now including a signature that does not sign the fields served with it.
  - A header this implementation cannot check — an unknown format, an `owner`
    that is not an RSA-4096 modulus, a format-1 header served without the data
    it signed — is `unsupported`: `X-Arweave-Verified: none`, `data_root`
    unused, nothing claimed. It is never reported as `header`.
  - `tests/ar-tx.test.js`: real format-2 and format-1 transactions fetched
    from arweave.net (`EDGVy6AA…`, `9TbUmxOr…`, stored as fixtures), each
    signed field swapped in turn, and the deep hash pinned against
    arweave-js's own output.
- **ENS EN-1 corrected** (`namespaces/ens/DEVIATIONS.md`) — the entry still
  said only `contenthash` is read; the no-website page has read seven ENSIP-5
  text keys, capped at 512 characters, since 0.7.0.
- 1005 tests in 11 suites, 73 modules byte-identical with the browser tree.

## 0.7.2

Sync with browser 2.78.28 (`93cdc62`). No behaviour change in resolution:

- `src/resolver.js` — the failover's first-candidate pick is written as a
  plain `for await` (a lint pass in the browser); same answer, same order.
- `namespaces/ipfs/src/cid.js` — `fileCid` yields to the event loop every
  4 MiB (`YIELD_EVERY`) so hashing a large file cannot starve the caller;
  the CID is unchanged (kubo equality tests untouched).

## 0.7.1

- **Arweave byte check limited to the transaction's own bytes** — verified
  only when the body length equals the header's `data_size`; a gateway's
  rendered page for a bundle or manifest is reported `header`, not refused.

## 0.7.0

The open items the 2026-09-06 review left, closed where they belong to the
resolver:

- **Nameserver failover** (HS-15, resolved) — a server that cannot be asked
  hands the whole question to the zone's next nameserver, in the zone's
  order, IPv4 glue before IPv6; a validation failure is never retried
  elsewhere. `tests/nameserver-failover.test.js`.
- **Arweave bytes verified** (AR-1, resolved with a stated limit) —
  `namespaces/arweave/src/ar-merkle.js` is the chunk Merkle tree, validated
  live against top-level transactions; a body under 8 MiB must hash to the
  proven header's `data_root` or is refused; `X-Arweave-Verified: bytes`.
- **did:key, did:jwk, did:pkh** (`namespaces/did/src/did-local.js`) —
  derived from the identifier with no network and no trust decision,
  answered as `X-Resolution-Trust: derived`; pinned to the specifications'
  own vectors.
- **ENSIP-5 text records** on the no-website page (Chapter 5 §5.6a) —
  read through the Universal Resolver, shown as text, `url` a link only
  when https.
- **Numeric Handshake names decided** (NT-1) — off by default, behind one
  switch (`setNumericNames`, `buildWsPac({ numericNames })`); the method and
  the `_` URL form stay in the code and Part B.
- **The content node is offline in Private** (DIVERGENCE row 8, done) —
  the policy table carries `contentNode`; the browser restarts its kubo
  with `--offline`.

## 0.6.0

- **The route workup** (`src/route-path.js`, the mirror of
  `src/trust-path.js`) — beside "what was verified", the lock now answers
  "who saw what": for each hop the route it took in the mode the page loaded
  under — `local`, `oblivious`, `tor`, `direct` or `refused` — what the far
  end learned, and one sentence saying what the other mode does for that hop.
  The same page yields the same hops in both modes and only the route column
  differs (`tests/route-path.test.js`); the trust verdict never changes with
  the mode. `SPEC.md` §4.2 names it.
- **`sync`**: ar.js notes that the fetch handed in must really return the 3xx
  on a manual redirect — Electron's `net.fetch` rejects, and the browser
  hands in a `net.request`-based fetch (an application concern, not part of
  this specification).

## 0.5.0

- **IPv6 for Handshake names** (RFC 3596; Handshake chapter §6.5f, §6.4,
  §6.2) — `AAAA` is asked beside `A` at the zone in the same round trip, and
  whichever RRset is used validates to the on-chain DS by the same rule as
  the `A`; `GLUE6` and `SYNTH6` are read beside `GLUE4` and `SYNTH4`; the
  ICANN-host lookup over DoH, the DANE-pinned dial and the SOCKS5 dial to Tor
  (`IPv6Traffic`) take either family; every address passes the same guard.
  One family rule, `preferV4`: the IPv4 when a name has one, the IPv6 when
  that is all it has — recorded as HS-2 with what it leaves out (RFC 6724 /
  RFC 8305 selection). An attacker who forges an empty `A` can only steer a
  client to the zone's own signed `AAAA`; a tampered `AAAA` fails closed; an
  address family that could not be asked is `unreachable`, never
  `unregistered` (`tests/ipv6.test.js`, against the frozen zone regenerated
  with an AAAA-only pinned host and a dual-stack host).
- **The SPV reader decodes `_synth`** (`src/spv.js`) — hsd's root server
  renders a `SYNTH4`/`SYNTH6` record as a referral to
  `_<base32hex(address)>._synth.` with the address as that name's glue; the
  reader kept that name AS a nameserver and looked for the apex address in
  the answer section, where the root server never puts it, so no SYNTH apex
  resolved from an SPV node. The label (or its glue) is now the address.

## 0.4.0

The public specification of Wildroot's web3 name resolution: every namespace
the browser resolves, with the reference implementation behind each.

- **`SPEC.md`** — the spine: the shared model (terminology, the two laws, five
  trust verdicts), namespace selection (the scheme registry with its `trust`
  column, the classification order, dispatch and failure), and one chapter per
  namespace under `namespaces/<ns>/SPEC.md`: Handshake; ICANN names; IPFS,
  IPNS and DNSLink; Arweave; ENS and `web3://`; Nostr; DID, AT Protocol and
  ActivityPub; Tor; the key-addressed namespaces (hyper, SSB, Gemini,
  BitTorrent); an experimental chapter for HIP-5 `_op` on-chain resolution and
  numeric Handshake TLDs; and a chapter on native applications on a Handshake
  name — `hns://` as an origin, WebSockets to a Handshake name through the
  loopback CONNECT tunnel, and sign-in with a name.
- **DNSLink as the migration path** — `_dnslink.<name>` is read on the chain
  path and over DoH under the same rules as `ipfs=` (validated on a signed
  zone, absence proven before an address is consulted); the two sources merge
  when they agree and a disagreement is surfaced, never picked.
- **The chain proof survives anonymization** — the authoritative hop is
  dialled through the device-local Tor (`src/socks-dial.js`), the SPV node's
  peers go through hsd's own proxy, ICANN hosts met in a walk are resolved
  through DoH/ODoH in every mode, and a synced chain's "unregistered" is final.
- **`REFERENCES.md`** — every standard the implementation reads: an index of
  every identifier with the chapters that cite it, then each chapter's table
  with what each is used for. Generated from the chapters.
- **`DEVIATIONS.md`** — every departure from a cited standard, every open
  question and every open design decision, per chapter, each open item with a
  recommendation. Generated from the chapters.
- **The Fast / Private switch** (`SPEC.md` §4.2, `src/delivery-mode.js`) —
  one control, two handles (Settings › Content delivery › Mode and the Privacy
  menu), driving the Tor session proxy — which fails closed on a loopback
  blackhole when Tor cannot be had — and every private path together: a
  Handshake name over DoH looked up obliviously or not at all
  (`DoHResolver({ strictOblivious })`), ICANN names through the oblivious
  bridge only (`privateDns()`), an A-record Handshake site dialled through Tor
  by address with the DANE pin on the same handshake (`src/dane-connect.js`),
  Nostr relays dialled through Tor by name (`nostr/tor-websocket.js`),
  hyper / SSB / BitTorrent discovery refused with the reason, a stated-origin
  name served from its origin. Every refusal names the mode and points at the
  switch (`privateRefusal()`); no verdict changes.
- **`DIVERGENCE.md`** — the cross-cutting inventory of where the fast path
  and a private path differ, with a no-trade-off attempt for each row;
  eighteen both-sides rows are built, and the five that survive are shipped
  as the Fast / Private switch.
- **`src/`, `namespaces/*/src/`** — the resolution modules, byte-identical to
  the Wildroot browser tree modulo import paths (`scripts/parity.mjs` proves
  it; 73 copied modules, 8 declared factored).
- **`tests/`, `namespaces/*/tests/`** — 1023 deterministic tests in 11 suites,
  no network; `npm test` runs them all.
