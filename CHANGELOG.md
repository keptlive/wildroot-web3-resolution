# Changelog

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
  it; 69 copied modules, 8 declared factored).
- **`tests/`, `namespaces/*/tests/`** — 931 deterministic tests in 11 suites,
  no network; `npm test` runs them all.
