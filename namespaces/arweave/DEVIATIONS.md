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

### AR-1. What a gateway's answer is now checked against, and what is still taken on its word

*SPEC §9.1.1, §9.2 · `src/ar.js`, `src/ar-tx.js`, `src/ar-merkle.js`*

**What is checked (2026-09-12).** Two things, in order, and each one's value
depends on the one before it.

1. **The header is the identifier's transaction.** The header is fetched from a
   gateway *other* than the one that served the bytes, and `src/ar-tx.js`
   requires both halves of the protocol's own definition: `SHA-256(signature)`
   is the identifier, **and** the signature verifies over the transaction's
   fields — RSA-PSS/SHA-256 under the key `{ n: owner, e: 65537 }`, over the
   deep hash of `["2", owner, target, quantity, reward, last_tx, tags,
   data_size, data_root]` for format 2, and over the legacy concatenation
   (which includes the data itself) for format 1. `owner`, `data_root`,
   `data_size`, `tags`, `target`, `quantity`, `reward` and `last_tx` are
   therefore all bound to the identifier.
2. **The bytes are the transaction's.** The whole body of a plain fetch (no
   manifest path, no `Range`) whose `data_size` is at most `MAX_VERIFY_BYTES`
   (8 MiB) and whose length is exactly that is hashed against the now-proven
   `data_root` with `src/ar-merkle.js` (256 KiB chunks, the last two
   rebalanced; leaf `H(H(H(chunk))‖H(note))`, branch `H(H(l)‖H(r)‖H(note))`).
   A body of the declared length that does not hash to the root is a 502; the
   response says `X-Arweave-Verified: bytes` when it does.

**What this fixed.** Until 2026-09-12 step 1 hashed the signature and stopped
there, which is a check on the *signature* and not on the header: a gateway
could keep a real signature and serve any `data_root`, `data_size`, `tags` or
`owner` beside it and pass. Step 2 then hashed the bytes against that root and
reported `bytes` — a verified-looking answer aimed at a root the gateway chose.
The signature is what binds the fields, so it is verified now rather than
hashed, and the earlier claim in this file (that step 1 authenticated the
header) was ahead of the code.

**The standard says.** An Arweave transaction id is the SHA-256 digest of the
transaction's signature, and the signature is over the transaction's fields
(the Arweave reference implementation; arweave-js `Transaction.getSignatureData()`
and `NodeCryptoDriver.verify()`, which this reimplements without a dependency).
ANS-104 states the same id derivation verbatim for a bundled data item: *"The
id of the DataItem, is the SHA256 digest of this signature."*

**What is still taken on the gateway's word.**

- **Which transaction.** The header proves what a transaction says about
  itself; nothing here proves that *this* owner's transaction is the one the
  network accepted at that identifier, because that lives in the block index
  and this implementation reads no chain. (The identifier is a hash of a
  signature, so a second transaction with the same id would be a SHA-256
  collision — but an identifier that was never mined, or was mined under a
  different wallet than the header claims, is not distinguishable from here.)
- **A header this implementation cannot check** — a format it constructs no
  payload for, an `owner` that is not an RSA-4096 modulus, a format-1 header
  served without the data it signed — is reported as `unsupported`: nothing is
  claimed, `data_root` is not used, the response says `none`. A gateway can
  therefore always *downgrade* itself to the standing it had before any of this
  existed; what it cannot do is be believed while lying.
- **The bytes of anything the byte check cannot hold**: a transaction over
  8 MiB, a `Range` request, a manifest path (SPEC §7 hands the path→id mapping
  to the gateway entirely — AR-U1), and a bundled data item, which has no
  top-level header at all (`/tx/<id>` is 404 on every gateway for one). A
  gateway also RENDERS some transactions rather than serving them (arweave.net,
  2026-09-06: a 10,386-byte bundle came back as a 2,285-byte page); that page
  is the gateway's, so a body whose length is not `data_size` is reported
  `header`, never refused and never called `bytes`.
- **Availability.** A gateway that answers nothing, or serves a valid header
  and then withholds the data, is indistinguishable from an outage.

**Consequence.** A successful `ar://` fetch of a plain transaction under the
limit now establishes that these bytes are the bytes the transaction at this
identifier committed to, with both gateways treated as couriers. Everything
above keeps the resolution-time verdict at `partial`: the trust panel's content
step is written before the fetch and cannot know which outcome a body will get,
so it stays `unverified` and the per-fetch truth lives in `X-Arweave-Verified`
(SPEC §9.2, AR-U5).

**Status: PARTIALLY IMPLEMENTED.** The header is authenticated and the common
body is verified. What remains: chunk proofs for bodies above the limit and for
`Range` requests, verification of a bundled item through its bundle, a bound on
what is buffered before a length is compared (8 MiB is a *declared*-size
threshold, not a limit on a hostile response), a client-side manifest reader
(AR-U1), and the chain read that would anchor `owner` to a mined transaction.

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
to. This is also exactly why the header check is skipped for a manifest path
(SPEC §9.1.1): there is no single transaction the second gateway could be asked
about, so a site served through a manifest — which is most published sites — gets
the weakest form of every guarantee in this chapter. Even a client that verified
bytes (AR-1) would still be trusting the mapping.

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

### AR-D1. Chunk proofs, for everything the in-memory check cannot hold

This item had three steps and two are built: the header is authenticated
against the identifier (SPEC §9.1.1, `src/ar-tx.js`, `tests/ar-tx.test.js`) and
a whole body under `MAX_VERIFY_BYTES` is hashed against its `data_root`
(`src/ar-merkle.js`, `tests/ar-bytes.test.js`). A mismatch in either is a 502 in
the Arweave namespace, never a fall-through, and `X-Arweave-Verified` reports
which of `bytes`, `header` and `none` happened.

**What is left.** Everything the in-memory check cannot hold: a transaction over
the limit, a `Range` request, and a bundled data item. Recommendation, in order:
the `/chunk` endpoint and the `data_path` Merkle proof format, which verify a
transaction a chunk at a time and would lift the size limit and serve a `Range`
honestly; then a bundled item verified through its bundle's own header (ANS-104
gives the item id the same signature derivation, so the machinery is the one
already here). A streaming check would also remove the buffer-before-compare
noted in AR-1.

**Two things to preserve.** The header request must keep coming from a gateway
other than the one that served the bytes: a lying gateway would supply a
matching `data_root` too. And a check that cannot be made must keep saying so —
`none`, and no use of an unproven `data_root` — rather than reporting the
weaker check under the stronger name.

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
   imports `isCanonicalTxid` from the shared pointer module and its two
   siblings `src/ar-merkle.js` and `src/ar-tx.js` (both also byte-identical
   copies), uses `Response`, `Headers`, `Request`, `Buffer`, `node:crypto` and
   an injected fetch, and runs unmodified under `node --test`. Nothing had to
   be factored or stubbed, and no dependency was added for the cryptography.

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
