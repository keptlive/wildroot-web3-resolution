# Changelog

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
