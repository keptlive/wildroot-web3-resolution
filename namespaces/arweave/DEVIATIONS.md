# Chapter 4 — Arweave: deviations and open questions

Known deviations, unresolved questions and proposed changes for Arweave identifiers, gateway retrieval and verification limits.

Entries distinguish current behaviour from recommendations. Paths beginning
`src/` or `tests/` are relative to this chapter; `../../src/` names shared
modules. Browser paths refer to the Wildroot source tree. Historical line
references may have moved since extraction.

[Chapter specification](SPEC.md) · [References](REFERENCES.md)

---

## 1. Deviations

<a id="ar-1-the-bytes-are-verified-against-the-transaction-for-a-top-level-transaction-under-8-mib-resolved-2026-09-06-with-a-stated-limit"></a>

### AR-1. Conditional body checks and the remaining authentication gap

*SPEC §9 · `src/ar.js`, `src/ar-merkle.js`*

**Current behaviour.** Since 2026-09-06, the handler compares eligible response
bodies with a gateway-supplied `data_root`. The header's signature must first
hash to the txid. A body is eligible when the request has no path or range,
the header's declared size is at most 8 MiB, and the buffered body has exactly
that size. A root mismatch returns 502; a match returns
`X-Arweave-Verified: bytes`.

**Limits.** A length mismatch is reported as `header` so gateway-rendered index
pages can be served. Large declared transactions, ranges, manifest paths and
bundled items without a top-level header remain unchecked. The body is buffered
before its length is compared; 8 MiB is a declared-size threshold, not a bound
on a hostile response.

**Authentication gap.** `headerMatchesId()` hashes the signature bytes but does
not verify that the signature covers the supplied header fields. Changing
`owner`, `data_root`, `data_size` or `tags` while preserving `signature`
does not change the result. The conditional body check therefore establishes
agreement with the supplied root, not the complete binding to the Arweave id.

**Status: PARTIALLY IMPLEMENTED.** The small-body comparison is implemented.
Header authentication, bounded response buffering, larger-body verification and
bundled-item verification remain open. The resolution-time trust panel stays
`unverified` / `partial`; the response header reports the fetch check. See
[REVIEW.md](../../REVIEW.md) and AR-D1.

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

**Why.** The handler follows the existing ecosystem URL form.

**Consequence.** Interoperability depends on convention. A future ecosystem
standard may require updating the URL form. The case-preserving parsing rule
is specified in SPEC §4.2.

**Status: DELIBERATE.** This project follows the ecosystem convention and
does not propose its own scheme registration.

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

**Consequence.** The transaction id is immutable, but the name-to-id binding
can change. Caching that binding still needs the authoritative TTL. Local
republishing calls `forget()`; that does not invalidate other clients' caches.

**Status: OPEN in the shared resolver.** The flat positive-cache policy is
tracked as D-1 in the Handshake deviations. Arweave does not define a separate
cache policy.

---

## 2. Things we are not sure about

The questions below remain unresolved.

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

The choice is between client-side manifest parsing and continued delegation
with an explicit trust limit.

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

The documentation should also distinguish ArNS durability claims from the
ordinary DNS and CA authentication used for `<label>_persist.ar.io`.

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

### AR-D1. The `data_root` half of the cheap check

The small-body Merkle comparison is implemented (AR-1). The original proposal
for a 4 MB threshold is superseded by `MAX_VERIFY_BYTES = 8 MiB`.

**Remaining work.** Verify the transaction signature over its fields before
treating `data_root` as authenticated. Bound response buffering independently
of the gateway-supplied size. Define verification for larger transactions,
bundled items and manifest mappings.

Cross-gateway byte comparison can detect disagreement, but agreement is not a
cryptographic proof. Keep that distinction in any future response-header or
trust-panel change. [REVIEW.md](../../REVIEW.md) records the decisions needed.

### AR-D2. `Config.arOptions` has no schema, default or validation

The composition layer spreads `...(Config.arOptions || {})` straight into
`createArHandler`, so an rc file can replace the gateway list — but there is no
schema, no documented default, no validation and no settings UI. In practice
the list is compiled in, and a typo in an rc key fails silently. Nothing checks
that a configured gateway is `https:`, so a user or a bad rc file can put the
whole fetch in plaintext, which SPEC §6.1 requires against.

**Recommendation.** Declare `arOptions` in the configuration schema with
`AR_GATEWAYS` as its documented default; validate that every entry parses as an
`https:` URL and reject the configuration with an error when one does not; report an
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
