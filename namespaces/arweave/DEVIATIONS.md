# Chapter 4 — Arweave: deviations and open questions

Every place this chapter's implementation departs from a specification it
cites, from common practice, or from its own stated design — plus every place
we are not sure we have made the right call, and every design item still open.

The rule this file serves, inherited from the spine: **a deviation that is not
written down is just a bug nobody has found yet.**

Everything measured below was measured against
`namespaces/arweave/src/ar.js`, which is byte-identical to `src/hns/ar.js` in
the Wildroot tree, and against `../../src/pointers.js` and
`../../src/trust-path.js`, which this chapter shares with its siblings.

---

## 1. Deviations

### AR-1. Bytes are never verified against the transaction id

*SPEC §9.2 · `src/ar.js` (whole module)*

**What.** No chunk proof is checked, `data_root` is never read, the transaction
signature is never fetched, and `SHA-256(signature) == id` is never recomputed.
The gateway is trusted like any HTTPS host.

**The standard says.** An Arweave transaction id is the SHA-256 digest of the
transaction's signature, and a format-2 transaction's data is committed by the
`data_root` Merkle root inside that signed header (the Arweave reference
implementation's documentation; ANS-104 states the same derivation verbatim for
a bundled data item: *"The id of the DataItem, is the SHA256 digest of this
signature."*). The identifier is therefore checkable, and a client that does
not check it is trusting whoever answered.

**Why.** Stated honestly in the module header from the first version: full
chunk verification is a real amount of work — the transaction header, the chunk
endpoint, the Merkle proof format — and the intermediate step, a second-gateway
spot check, has not been built either. The scheme's namespace-table row records
`status: 'partial'` rather than `live` for exactly this reason, which is the
model this file wants: the deviation lives in the code's own metadata, not only
in prose.

**Consequence.** SPEC §11.7: a successful `ar://` fetch establishes only that a
TLS-authenticated host from a list we shipped returned these bytes for this
identifier. A hostile or compromised gateway serves arbitrary bytes and nothing
notices. Contrast `ipfs://`, where the local node checks every block hash, and
`bittorrent://`, where the infohash does it — Arweave is the one content scheme
in this browser whose bytes are not checked at all. What limits the damage is
that the claim is not overstated anywhere: the trust panel calls the content
step `unverified`, the aggregate verdict is `partial`, and the scheme table
says `partial` (SPEC §9.2).

**Status: OPEN.** The order of work is AR-D1 first — a header fetched from a
*second* gateway plus one SHA-256, which needs no Merkle code and closes most of
the gap for the content a browser actually loads — and full chunk verification
after it. The label may say `verified` only for content that was actually
checked, and never for content above whatever size threshold the cheap check
uses.

---

### AR-2. `ar://` is a de-facto scheme with no registration

*SPEC §4.1 · `src/ar.js`, `../../src/contenthash.js`, `../../src/router.js`*

**What.** We use `ar://<txid>` because ar.io gateways and the Wander (formerly
ArConnect) wallet do. There is no RFC, no IANA URI-scheme registration, and no
normative grammar anywhere for us to conform to.

**The standard says.** RFC 3986 §3.1 defines the syntax of a scheme name;
RFC 7595 §3 sets out the guidelines and the IANA registration procedure for a
new URI scheme, including a provisional registration for exactly this kind of
established-but-unregistered convention. `ar` appears in no IANA registry.

**Why.** Adopting the ecosystem's form unchanged is better than inventing a
second one. This is the same reasoning the spine applies elsewhere, and the
opposite of the case where no convention existed at all and one had to be
invented.

**Consequence.** Interoperability rests on convention. If ar.io changed the
form, or if a registration standardised a different one, we would follow rather
than argue. Nothing in this implementation depends on the scheme being
registered, and the parsing rule that matters — read the identifier from the
raw string, never from a URL host accessor (SPEC §4.2) — is ours to keep
either way.

**Status: DELIBERATE.** Registering `ar` is not ours to do: the scheme belongs
to the Arweave ecosystem, and a registration filed by a browser vendor that did
not define it would be presumptuous. We would support and follow one.

---

### AR-3. An `arweave` resolution is cached for a flat 60 seconds

*Spine `../../DEVIATIONS.md` D-1 · `../../src/resolver.js` `CACHEABLE`*

**What.** `CACHEABLE` includes `'arweave'`, so a name that resolves to an
Arweave pointer is remembered for 60 seconds and the record's TTL is ignored,
exactly as for every other positive resolution.

**The standard says.** RFC 2181 §5.2 and RFC 1035 §3.2.1: the TTL is the
authoritative server's statement of how long an RRset may be cached, and a
resolver honours it.

**Why.** Inherited from the spine's D-1; no Arweave-specific decision was made.

**Consequence.** Worth naming separately only because Arweave is the one kind
where a *longer* cache would be safe by construction: the identifier is
immutable, so the answer cannot go stale in a way that matters until the name's
owner republishes, and a republish already calls `forget()`. The deviation here
is that we are more conservative than we need to be, which costs lookups and
nothing else.

**Status: DELIBERATE** as an Arweave decision — there is nothing to change in
this chapter. The underlying flat-60-second cache is the spine's D-1 and is
open on its own terms; when it starts honouring TTLs, an `ar=` pointer is the
safest kind to give a generous ceiling.

---

## 2. Things we are not sure about

These are not settled positions. They are the places where we think the
implementation may be wrong and would like to be told so.

### AR-U1. Is delegating manifest resolution to the gateway defensible at all?

SPEC §7: the client never parses a manifest. It appends the path and lets the
gateway map it to a transaction id.

The argument for: gateways implement the manifest specification — including
whatever version and fallback behaviour is current — and a client that
reimplements it will be subtly behind. The argument against: it makes the
**path→id mapping** gateway-trusted on top of the bytes being gateway-trusted,
and it means the multi-gateway failover of §6.1 carries no cross-check
whatsoever, because the client never learns which id a gateway resolved a path
to. Even a client that verified bytes (AR-1) would still be trusting the
mapping.

We do not know whether the right answer is "parse manifests client-side" (real
work, real drift risk) or "keep delegating and be loud about it" (what we do).

### AR-U2. We have not verified the manifest version 0.2.0 clauses

The canonical Arweave repository schema document specifies
`"version": "0.1.0"`, an `index` object whose `path` must be a key of `paths`,
and a `paths` object of `{ id }` values. Version **0.2.0** — `index.id`, and a
`fallback` — is an ar.io-side extension, and we were unable to retrieve a
document for it. Since the implementation reads neither version, nothing turns
on it; we flag it so that a future manifest reader does not start from this
chapter's summary as though it were checked.

### AR-U3. What should an `ar://`-adjacent ArNS implementation look like?

SPEC §8: ArNS is not resolved. If it were, it could not simply reuse this
chapter, because the failover rule of §6.2 is safe **only** because an
identifier is immutable. An ArNS name is mutable and its current value lives in
an ANT contract on another chain; two gateways answering differently for a name
is a legitimate state (one is stale), not evidence of tampering, and the client
has no way to tell which. A correct ArNS client probably has to read the ANT
itself, which makes it a chain-reading namespace like HIP-5 `_op` and not a
gateway-fetching one like this.

There is a second, sharper question underneath. We hold `<label>_persist.ar.io`
and it resolves through ordinary DNS and an ordinary CA-issued certificate —
which is *precisely* the trust model this whole project exists to improve on.
Presenting an ar.io URL as a durability story while it is CA-authenticated
deserves a clearer statement than it currently gets anywhere.

### AR-U4. Is one hardcoded gateway list the right shape?

`AR_GATEWAYS` is three hosts, frozen, in a fixed order, with a stated criterion
and a review date (SPEC §6.1). The first still sees nearly every request
(SPEC §11.2, §11.5). Alternatives we have not evaluated: randomizing the order
(spreads disclosure, defeats caching and makes failures non-reproducible);
reading the ar.io gateway registry at runtime (a larger, more current set — and
a new trusted source to bootstrap from); letting the user choose. The
configuration passthrough that would make the list changeable is itself
unfinished — AR-D2.

### AR-U5. Should an `ar=` pointer close the padlock at all?

What ships: the content step is `unverified`, so the aggregate verdict is
`partial` and never green; and the padlock **closes** in the neutral *trusted*
colour on the chain proof alone, without a DANE pin, on the reasoning that the
bytes arrive over ordinary HTTPS from a TLS-authenticated host — the same
transport an `https://` page has, which this model also calls
*trusted-but-not-trustless* with a closed lock (SPEC §9.2, `../../SPEC.md` §4).

The part we are sure of is the step: `unverified` is not in doubt, and no
Arweave step may borrow the content-addressed sentence. The part we still argue
about is the lock. Against the current choice: the user is being shown the same
lock for "a CA vouched for this host" and for "a chain proved this binding and
then nobody checked the bytes", and the difference lives only in a panel most
people will not open. For it: an open lock would say *less* than the truth,
since the transport really is authenticated HTTPS and the content really is
immutable, and reserving the open lock for genuinely unauthenticated transports
keeps that signal meaningful. We would like other implementers to argue with
us.

---

## 3. Open design items

### AR-D1. Cheap verification, before full chunk proofs

Full verification (AR-1) is the transaction header, the chunk endpoint and the
Merkle proof format. There is a much smaller step that closes most of the gap
for the content this browser actually loads, and doing it first is what makes
the big one optional rather than blocking.

**Recommendation.** After a successful fetch, when the response is small enough
to buffer (a threshold — 4 MB covers a manifest and most pages): fetch
`GET <a DIFFERENT gateway>/tx/<txid>` for the transaction header; recompute
`SHA-256(base64url-decode(signature))`, base64url-encode it and require it to
equal the identifier — that alone proves the header is the transaction the id
names, using nothing but a hash; then, for a single-chunk transaction, hash the
body against `data_root`, falling back for a multi-chunk transaction to
comparing the body with the same path fetched from the second gateway. The
header **must** come from a different gateway than the bytes, because a lying
gateway would otherwise supply the `data_root` too. Prove it with a mock
gateway returning correct-looking bytes for a tampered header, and a second
returning tampered bytes for a valid header: both must fail closed, and the
failure must be an Arweave-namespace failure, never a fall-through. Only then
may the trust step change (AR-1, AR-U5).

### AR-D2. `Config.arOptions` has no schema, default or validation

The composition layer spreads `...(Config.arOptions || {})` straight into
`createArHandler`, so an rc file can replace the gateway list — but there is no
schema, no documented default, no validation and no settings UI. In practice
the list is compiled in, and a typo in an rc key fails silently. Nothing checks
that a configured gateway is `https:`, so a user or a bad rc file can put the
whole fetch in plaintext, which SPEC §6.1 requires against.

**Recommendation.** Declare `arOptions` in the configuration schema with
`AR_GATEWAYS` as its documented default; validate that every entry parses as an
`https:` URL and reject the configuration loudly when one does not; report an
unrecognised key rather than ignoring it. Then either surface the list in
settings or state in the documentation that it is rc-only. AR-U4 is the
question of what the list *should* be; this is only about making the existing
knob real.

---

## 4. What this chapter leaves out

1. **Any Electron dependency.** `src/ar.js` is extracted byte-identical — it
   imports only `isCanonicalTxid` from the shared pointer module, uses
   `Response`, `Headers`, `Request`, `Buffer` and an injected fetch, and runs
   unmodified under `node --test`. Nothing had to be factored or stubbed.

2. **The composition layer**, which is Electron-bound and stays in the browser
   tree: the module that injects the proxied `net.fetch` and registers the
   scheme into the router, the main entry's privilege registration (SPEC §10),
   and the Handshake handler that composes `ar://<txid><path><query>` from a
   resolution (SPEC §5.2). Their *policy* is specified normatively in SPEC
   §5.2, §6.6 and §10; the code is not extracted. If you are implementing from
   this chapter, that layer is yours.

3. **The pointer grammar, the contenthash decoder and the trust panel**, which
   are *not* absent — they are at the repository root
   (`../../src/pointers.js`, `../../src/contenthash.js`,
   `../../src/trust-path.js`) because the spine specifies them and all three
   are shared with the IPFS, BitTorrent, Hyper and ENS chapters. This chapter's
   tests import them from there rather than copying them, so a fix in one is
   provably the same fix here.

4. **Any Arweave write path.** Bundling, signing, chunking, paying, posting: no
   code, no specification, not in this repository. The browser has no Arweave
   publish target either — every `ar=` record this stack reads was written by
   external tooling.

5. **An ArNS client.** SPEC §8, AR-U3.

6. **Manifest parsing.** SPEC §7, AR-U1.
