# Chapter 1 — Handshake: deviations and open questions

Every place this chapter's implementation departs from a standard it cites,
from common resolver practice, or from its own stated design — plus every place
we are not sure we have made the right call, and every design item that is open.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

Identifiers are prefixed `HS-` so they cannot collide with another chapter's.
Everything below is measured against `../../src/`, the reference implementation
of this chapter, and its tests in `../../tests/`.

---

## 1. Deviations

### HS-1. TTLs are ignored; a flat 60-second positive cache

**What.** A successful resolution is cached for 60 seconds regardless of the
records' TTLs. Only positive results are cached — every failure kind
(`unreachable`, `dnssec-fail`, `unregistered`) is re-asked. `../../src/resolver.js`.

**The standard says.** RFC 2181 §5.2: the TTL is the operator's statement of
how long an RRset may be reused, and every record in an RRset carries the same
one.

**Why.** The cache exists to stop a page's own subresources re-resolving the
name a dozen times, not to be a recursive resolver. A publish flow that moves a
pointer invalidates its own name explicitly (`forget()`), which is the case a
short TTL is usually protecting.

**Consequence.** A record with a TTL below 60 s is honoured late. A record with
a very long TTL is re-fetched more often than the operator asked. Neither is a
security property; both are impolite to the authoritative server.

**Status.** OPEN. Honour the minimum TTL of the RRsets a resolution rests on,
clamped to a floor and a ceiling, and keep the rule that failures are never
cached (SPEC §6.8). It is a small change and there is no argument against it.

---

### HS-2. No IPv6: AAAA, GLUE6 and SYNTH6 are not resolved

**What.** Only `A`, `GLUE4` and `SYNTH4` are read. `AAAA` is in the type table
and is never queried. `../../src/resolver.js`.

**The standard says.** RFC 3596 defines AAAA as the address record for IPv6,
and a resolver that reads only A cannot reach an IPv6-only host.

**Why.** No reason worth defending. It is not done.

**Consequence.** An IPv6-only Handshake site is unreachable. The SSRF guard
(`../../src/safe-address.js`) already understands IPv6 ranges, so the gap is
entirely in the resolver.

**Status.** OPEN. Query `AAAA` beside `A`, read `GLUE6`/`SYNTH6` where `GLUE4`
and `SYNTH4` are read, and put every address through the same guard. Nothing
about the validation or pinning rules changes.

---

### HS-3. SVCB / HTTPS records are parsed but never queried, and ECH is not usable

**What.** A complete RFC 9460 parser exists and is tested against real
Cloudflare RDATA, including a live 71-byte ECHConfigList. Nothing in the
resolution algorithm ever issues a query for type 65. `../../src/dns-query.js`.

**The standard says.** RFC 9460 defines the SVCB/HTTPS RR and expects a client
to query it before connecting; RFC 9848 requires the client to take its
ECHConfigList from that record.

**Why.** Two independent reasons.

1. Querying type 65 costs a round trip on every A-record navigation, and no
   Handshake zone publishes one today — including ours. Our own authoritative
   server cannot serve the record.
2. Even holding a valid ECHConfigList the transport could not use it. The
   `hns://` transport is a raw Node TLS socket, and **Node exposes no ECH
   option at all**. There is nothing to hand the config to. (Chromium does ECH
   for ordinary `https://` on its own, outside this code path.)

**Consequence.** `hns://` connections send the server name in the clear in the
TLS ClientHello. An observer learns which Handshake site is being visited even
though the DNS lookup may have been oblivious — so the ODoH work is partly
undone by the transport. Any SvcParam an operator publishes (`alpn`, `port`,
`ipv4hint`) is ignored.

**Status.** OPEN, and blocked on something that is not ours: Node's TLS
bindings. Until they expose ECH, the honest position is this entry rather than
listing ECH as "planned". The cheap half — reading the `port` SvcParam — is
worth doing together with HS-6, not before it.

---

### HS-5. One DANE profile; an unusable TLSA RRset is refused rather than ignored

**What.** Only usage 3 / selector 1 / matching type 1 (DANE-EE, SPKI, SHA-256)
is accepted. Any other parameter combination is treated as a **mismatch** — the
connection fails — not as an unusable record. `../../src/dane.js`.

**The standard says.** RFC 7671 §4.1: when *every* record in a TLSA RRset is
unusable, the client should treat the RRset as absent and fall back to PKIX.

**Why.** `3 1 1` is what the Handshake ecosystem standardised on. Supporting
usages 0/1/2 would require implementing PKIX chain validation, which
reintroduces exactly the CA trust this design exists to remove — and there is
no PKIX to fall back to for a Handshake name in the first place, because no CA
can issue for one. Falling back on confusion is how a pinning scheme quietly
stops pinning.

**Consequence.** A zone that publishes, say, `2 0 1` gets a hard connection
failure here where a §4.1-conforming client would connect over PKIX. For a
Handshake name that "PKIX connection" would be to a certificate no CA will
sign, so in practice this costs nothing — but it is a real deviation from the
RFC's text.

**Status.** DELIBERATE. The RFC's fallback assumes a PKIX world that does not
exist for these names; refusing is the only behaviour that keeps the pin
meaning what it says.

---

### HS-6. The TLSA owner is always `_443._tcp`; a port in the URL is ignored

**What.** The pin is looked up at `_443._tcp.<host>` whatever port the URL
names, and the connection is made to 443 (or 80) regardless.
`../../src/resolver.js`.

**The standard says.** RFC 6698 §3: the TLSA owner name is
`_<port>._tcp.<host>` for the port the connection is actually made to.

**Why.** Not a decision so much as an unfinished one. It is coupled to HS-3:
the right fix reads the HTTPS record's `port` SvcParam, connects there, and
moves the TLSA owner to `_<port>._tcp.<host>`. Doing the port without the
record, or the record without the port, gets the pin wrong.

**Consequence.** A Handshake site on a non-standard port is unreachable over
`hns://`.

**Status.** OPEN, deliberately paired with HS-3. Read the port from the URL and
from the HTTPS record in the same change, and derive the TLSA owner from the
port actually dialled.

---

### HS-8. A DoH-resolved TLSA is used as a pin, on the resolver's word

**What.** On the DoH fallback path a `_443._tcp.<host>` TLSA lookup is made and
the returned record **is used to pin the TLS handshake**, marked as the
resolver's word. A DoH NODATA for that owner allows a plaintext connection; a
DoH lookup that *fails* refuses to connect. `../../src/doh.js`.

**The standard says.** RFC 6698 assumes the TLSA record arrives through a
DNSSEC-validating path; RFC 8484 provides a channel to a resolver, not a proof.
A pin taken on a resolver's word is not the guarantee DANE describes.

**Why.** A DoH path that reads no TLSA means an attacker who merely breaks the
chain path — drop TCP/53 to the authoritative server, the resolver throws, the
browser falls back — downgrades **every** DANE-pinned Handshake site to
plaintext. Pinning to the resolver's word is strictly stronger than the
plaintext it replaces.

**Consequence.** A malicious DoH resolver can substitute a pin, and can assert
"no pin exists" and get a plaintext connection. The trust panel says so — the
lock reads TRUSTED, not trustless, and names the resolver — but a user who does
not read the panel gets a weaker guarantee than the closed lock suggests.

**Status.** DELIBERATE as against the alternative (reading no TLSA at all,
which is a strictly worse outcome). The residual gap is that nothing remembers
a host was ever pinned; that is HS-12, and it is open.

---

### HS-9. A CNAME target's own RRset is not validated under the target's owner

**What.** The `CNAME` RRset itself **is** validated: on the address path a
`CNAME` in a signed zone is not followed until the RRset validates to the
on-chain DS anchor, with the RFC 4035 §5.3.4 wildcard proof where the answer was
wildcard-expanded (SPEC §6.5f). What is not done is the rest of RFC 4035
§5.3.1's chain: the **target's** RRset is not validated under the target's own
owner name. In practice the target of a Handshake `CNAME` is an ICANN host,
whose address comes back through the ICANN-host lookup seam (SPEC §6.11) and is
therefore ICANN's word, not the Handshake zone's. `../../src/resolver.js`.

**The standard says.** RFC 4035 §5.3.1 describes validating each RRset in a
CNAME chain under its own owner name.

**Consequence.** Two things, of different sizes. A `CNAME` to an ICANN host
works and the resolution is reported as unvalidated from that point on
(`dnssecValidated` stays false and the trust panel names the source of the
address) — which is the truth and cannot be anything else, because the target's
zone is not anchored to the Handshake chain at all. A `CNAME` *within* a signed
Handshake zone, pointing at another name in the same zone or a delegated one, is
not chased and validated the way §5.3.1 describes; its RRset is validated, its
target's is not.

It also decides which half of RFC 7671 §7.2 the DANE base-domain rule rests on
(SPEC §8): because the expansion is not *secure* in the RFC's sense, the pin is
correctly looked up at the original name.

**Status.** OPEN, and narrow: what remains is chasing the target
inside the zone and validating each RRset under its own owner. Keep the
ICANN-target case reported as unvalidated.

---

### HS-10. No RRSIG clock-skew tolerance

**What.** The RRSIG inception/expiration window is checked against the real
system clock with zero tolerance. `../../src/dnssec.js`.

**The standard says.** RFC 4034 §3.1.5 defines the window; it does not require
a tolerance, and it does not forbid one.

**Why.** unbound and BIND allow none by default either, so this is
conventional. There is also an explicit guard preventing any module in the
resolution stack from reading a clock other than the one guarded call site,
pinned by `../../tests/dnssec-clock-guard.test.js`.

**Consequence.** A machine with a badly wrong clock fails every signed zone
closed. That is the correct direction, but it is a total outage rather than a
degraded one, and a user has no way to tell it apart from an attack.

**Status.** DELIBERATE, and recorded because the failure mode is confusing
rather than because the rule is doubtful. What could improve is the *message*,
not the tolerance: a validator that notices every zone failing at once can say
"this machine's clock is wrong" instead of "this zone is bogus".

---

### HS-11. Standards not implemented at all

**What and why.** Listed so their absence is a decision on the record rather
than an oversight.

| Standard | Why not |
|---|---|
| **RFC 9462 DDR** (Discovery of Designated Resolvers) | Nobody's browser does it and the records are live. An opportunity not taken, not a gap we are unaware of. |
| **draft-ietf-dnsop-deleg** | In WG Last Call; the RR types are not allocated at IANA, so nothing can interoperate. Revisit on allocation. |
| **RFC 5011 trust-anchor rollover** | Structurally inapplicable: the anchor is a DS record on the Handshake chain, which rolls by a chain transaction, not by a hold-down timer. We use §2.1 (the REVOKE bit) and nothing else. |
| **RFC 6891 extended RCODEs, RFC 8914 EDE** | The OPT record is written to carry the DO bit and dropped on parse. Extended DNS Errors would make several failure messages much better; they are not read. |
| **PKIX chain validation on the `hns://` path** | Deliberate — see HS-5. |

**Consequence.** Per row: no designated-resolver discovery, no DELEG, no
automated anchor rollover (and none needed), failure messages coarser than the
protocol allows, and no CA path on `hns://` by design.

**Status.** DELIBERATE for RFC 5011 and PKIX; OPEN for RFC 8914 EDE, which is
the cheapest real improvement in the table — read the OPT record back and carry
the extended error into the failure kind and the panel text.

---

### HS-12. A DANE mismatch re-resolves once, then fails closed; there is no "pinned before" memory

**What.** When the certificate does not match the pin, the cache entry is
dropped and the name is resolved once more; a second mismatch fails closed.
Nothing records that a host was ever pinned. `../../src/resolver.js`.

**The standard says.** RFC 7671 §8.1 expects operators to pre-publish the new
TLSA before rotating the key, which would make any retry unnecessary.

**Why.** Real operators sometimes do not pre-publish, and a browser that fails
permanently on a few seconds of skew is unusable. One retry recovers the
"published the TLSA seconds late" case without weakening the pin — the second
answer must still match.

**Consequence.** The retry itself is sound. The gap is the missing memory: break
the chain path entirely, answer over DoH with a proven "no TLSA", and a host
that has always been pinned is served in the clear, because nothing knows it
used to be pinned.

**Status.** OPEN. An HSTS-shaped rule — *a host that ever resolved chain-proven
with a pin refuses plaintext until a proven absence says otherwise* — closes the
last availability-driven downgrade. It also introduces a persistent, per-host,
attacker-influenceable state store, whose own failure mode is pinning a host
into unreachability; the shape needs deciding before the code (§2.4).

---

### HS-13. Product decisions that deviate from what the naming systems themselves say

These are not standards deviations so much as places where we resolve a conflict
between systems in a way the systems' own advocates would dispute.

**What, and why.**

- **ICANN wins for ICANN TLDs, even though the Handshake root is the root.** A
  dotted name whose final label is a delegated ICANN top-level domain is an
  ICANN domain; every other name is a Handshake name. In Handshake's own model,
  ICANN TLDs are reserved and claimable with a DNSSEC proof, and a claimed one
  would make the chain authoritative — we route to ICANN anyway. That is what
  makes the browser safe to use as somebody's only browser.
- **Every other alt-root is Handshake.** `.crypto`, `.sol`, `.bnb`, `.nft` and
  anything else non-ICANN, non-`.eth`, non-`.onion` goes to whoever holds the
  Handshake TLD of that name. So `brad.crypto` resolves to the Handshake
  `crypto` owner's records, not to Unstoppable's registry. Consistent
  application of the rule above; other implementers may reasonably differ.
- **A `_<chain>` pseudo-TLD other than `_op` is not read.** HIP-5's own shipped
  example is `_eth` (ENS on Ethereum mainnet). A top-level name that delegates
  through one — the Handshake name `hns` does — is resolved here through its
  remaining ordinary `NS` records. The `_op` route itself is Chapter 10.
- **ODoH is implemented and is not called a privacy feature.** Two ODoH relays
  exist worldwide and one is run by a target operator, so RFC 9230's
  non-collusion assumption does not hold at that scale. The code stays; the
  interface must not claim privacy from it.
- **A single authoritative "hop" is really a bounded walk.** A registry TLD
  holds none of the names it sells, so it *refers* rather than answers, and its
  NS targets are frequently themselves Handshake names (§2.2).

**Consequence.** A user of this implementation reaches ICANN names the way
every other browser does, reaches alt-root names as their Handshake owner
publishes them (which is not what the alt-root's own client would show), and is
told the truth about what ODoH buys at today's scale.

**Status.** DELIBERATE, each of them. The ODoH line is unusual and worth
stating: most implementations claim the property the RFC describes rather than
the one the deployment provides.

---

### HS-14. Internationalized names go through the URL parser, not through our own IDNA

**What.** A Unicode host is punycoded by handing it to `new URL()` and reading
back `hostname`, before it reaches the resolver or the ICANN comparison.
`../../src/router.js`.

**The standard says.** RFC 5890/5891 define IDNA2008; UTS #46 defines the
compatibility processing the WHATWG URL Standard actually requires. The two
differ on a small set of characters (the deviation characters, and transitional
processing).

**Consequence.** What is implemented is UTS-46 as the URL Standard specifies
it, not IDNA2008 as RFC 5891 specifies it. Which Handshake labels this can
affect has not been audited.

**Status.** OPEN, and under-examined. The work is an audit first — enumerate the
deviation characters against the registered Handshake label set — and a decision
second; there is no point implementing IDNA2008 by hand before knowing whether
any real name differs.

---

### HS-15. No nameserver failover at query time

**What.** `_nameserverFor` tries every `NS` record while it is looking for an
*address*, but once a nameserver has been chosen, the first query failure
against it is final. `../../src/resolver.js`.

**The standard says.** RFC 1034 §4.3.2 and ordinary resolver practice: a zone's
NS set is a set, and a resolver is expected to try another server when one does
not answer.

**Consequence.** A zone with two nameservers, one of which is dark, does not
resolve — even though the other one would have answered.

**Status.** OPEN. Carry the remaining candidates into the query step and retry
the *whole* zone context against the next one on a transport failure, keeping
every validation rule unchanged; a failure that is a validation failure must
not be retried against another server, which would be shopping for an answer.

---

### HS-16. Changing the anonymization mode restarts the SPV node, which re-syncs

**What.** The chain path survives anonymization by pointing the SPV node's own
peer traffic at the device-local SOCKS proxy and dialling this
implementation's authoritative queries through the same port (SPEC §6.11). hsd
reads its `--proxy` setting **once, at start**, so a change of mode is a
respawn of the node: the process is stopped and started with the new setting,
and its headers sync again — from the persisted chain in the ordinary case, or
from scratch for a node running entirely in memory (the fallback when no native
LevelDB backend is available). Until it reaches the tip its proofs are null,
so resolution rides DoH over the proxied fetch in the meantime, exactly as it
does at launch. An adopted or externally-configured node is not restarted at
all: the wish is recorded and the caller can see that the running node does not
honour it. `../../src/spv.js` (`setProxy`, `_nodeIsProxied`).

**The standard says.** Nothing. This is a property of hsd's command line, and
through it of every client that spawns hsd rather than linking it.

**Consequence.** Switching between Fast and Private (the one control,
`../../SPEC.md` §4.2) costs a window — seconds from a persisted chain, minutes
from scratch — in which every Handshake name resolves `unverified` over DoH
rather than chain-proven, and the trust panel says so while it lasts. In
Private the interim is narrower still: the DoH answer is oblivious or the name
is `unreachable` (SPEC §9.3), so the window costs availability where in Fast it
costs a disclosure. The guarantee a page load receives therefore depends on the
clock (§2.5) at one more moment than it used to: not only at launch, but at
every mode change. It is a degradation to the weaker-but-honest path, never to
a false answer, and the alternative — keeping a node whose peers see the real
address while protection is on — is worse.

**Status.** OPEN, and the fix is not in this tree. The clean answer is a node
that can be told to change its proxy at runtime (an hsd RPC, or a peer manager
that re-dials) so a mode change costs a reconnection instead of a re-sync; the
cheap mitigation is to keep the chain directory persisted on every platform, so
the re-sync is always the short one. A composition that spawns the node
**MUST** report the interim honestly rather than presenting a DoH answer as
chain-proven.

---



## 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each is
a real decision that is currently shipping, and each could be wrong.

### 2.1. SVCB/HTTPS and ECH (HS-3)

We are not sure the right answer is "query type 65 on every navigation". The
cost is a round trip per A-record site for a record essentially no Handshake
zone publishes. A DNSSEC-signed zone could advertise its presence more cheaply
— that is roughly what the type bitmap in an NSEC record already does, and
those are already fetched for other reasons. We have not worked this out.

### 2.2. Registry TLDs that refer, and NS targets that are themselves Handshake names

A registry TLD (`persist`, `hns`) holds none of the names it sells. Asked about
`maya.persist`, its nameserver returns a **referral** — NS records with no SOA —
not an answer. An implementation that treats the authoritative hop as literally
one query resolves every such name as unregistered.

So the hop is a **bounded walk**: `_fromZone` re-enters itself per delegation up
to `MAX_DELEGATIONS`, a referral is told from a NODATA by the presence of an SOA
(RFC 1034 §4.3.2), and `_descend` validates the parent's DS for the child —
under keys the on-chain DS anchors — before anything the child says is believed.

Two things about this we are not certain of:

1. **An NS target that is itself a Handshake name.** `pinner.hns` delegates to
   `ns1.lumeweb`, which is not resolvable in ICANN's DNS at all. It is resolved
   from the `lumeweb` chain resource (`_chainAddress`). That is right, and it is
   also a second chain lookup inside a resolution, with its own failure modes
   and its own cache. Whether the depth of that recursion should be bounded
   separately from `MAX_DELEGATIONS`, and what a cycle looks like, is not fully
   worked out. The related budget question is HS-D1.
2. **Bailiwick.** Sideways and upward referrals are refused. We believe the
   check is right and it is tested, but "which referrals are in bailiwick" is
   the classic place a resolver gets subtly wrong, and we would like another
   pair of eyes on it.

### 2.3. What the DoH fallback actually promises

When the chain path fails, resolution falls back to DoH (`query.hns.one`, then
`hnsdoh.com`, then `dns.easyhns.com`). Everything resolved that way is marked
as the resolver's word and the trust panel names the resolver. Three things we
are not settled on:

- **In Fast mode the fallback is unconditional on infrastructure failure.**
  Any thrown error on the chain path leads to a DoH attempt, oblivious first and
  plain beneath it. That is availability-first. An attacker who can reliably
  break the chain path can therefore *choose* which resolver answers, and gets
  HS-8's weaker pin semantics as a bonus. In Private mode (SPEC §9.3) the plain
  transport is never taken, so the same attacker gets the oblivious resolver's
  answer or nothing — narrower, and still the resolver's word. We think the
  answer in both modes is the "pinned before" memory (§2.4) rather than
  removing the fallback, but we are not sure.
- **Where the fallback is *not* allowed is settled**, and it is the part that
  matters: a synced chain's authoritative `unregistered` is final, and a DoH
  answer never overrides it (SPEC §9.1). DoH answers only the three states in
  which the chain said nothing — no node, a node short of the tip, and a thrown
  chain-path failure — and even on the third a DoH `unregistered` is not adopted
  in place of the failure. What is left unsettled is the paragraph above, which
  is about availability, not about precedence.
- **What "trusted" should mean in an interface.** The lock has three visible
  states, not two (SPEC §4.1). Whether that is comprehensible to anybody who has
  not read this specification is an open product question, not just an
  engineering one.

### 2.4. DANE pin rotation windows (HS-12)

Exactly one re-resolve is allowed on a mismatch. A too-generous retry policy is
a downgrade oracle; a too-strict one breaks sites during a legitimate rotation.
We have no data on what real Handshake operators' rotation windows look like,
so "one retry" is a guess, not a measurement.

The related and larger gap is that there is no memory of having pinned a host
before. An HSTS-shaped rule would close the last availability-driven downgrade,
and would introduce a persistent, per-host, attacker-influenceable state store,
which is its own class of problem (pinning a host into unreachability). It is
not built and we are not sure of the right shape.

### 2.5. What an SPV proof actually proves

The chain path's guarantee is: *hsd, running on this machine, verified an Urkel
tree proof for this name against a tree root committed in a block header on the
most-work header chain it has seen.* That is a strong property and it is the
reason this project exists. It is not the same as running a full node:

- SPV follows the most-work header chain. It does not validate blocks, so it
  inherits the standard SPV assumption that the most-work chain is the valid
  chain.
- The browser process reads the verified result from the local hsd over
  loopback RPC or the node's own root nameserver. It trusts that local process.
- A node that is still syncing returns null proofs. That is reported
  `unreachable` and the client rides DoH until it reaches the tip, then flips to
  chain proof mid-session. That is correct, but it means the guarantee a given
  page load got depends on the clock, which the trust panel has to explain and
  which nobody expects. Turning anonymization on or off restarts the node and
  re-opens that window deliberately (HS-16), so the clock dependence is not
  only a launch-time artefact.

### 2.6. Whether a proven absence should raise the lock as far as it does

A signed zone's proven "no TLSA", beside a validated `A` RRset, is treated as a
fully validated resolution over plaintext (SPEC §8). Every record the answer
rests on is chained to the on-chain DS, so the claim is true. It still means a
closed-book plaintext connection is reported as validated, and we are not
certain users read the distinction the way the model intends.

### 2.7. What DNSLink interoperation is worth while the gateways it was for retire

Reading DNSLink (SPEC §10.1) is justified as the migration path, and the
ecosystem that path leads to is contracting on a published timetable: the public
gateways `ipfs.io` and `dweb.link` retire on **2026-09-21**, and the Shipyard
bootstrap nodes that every default kubo configuration dials on **2026-09-30**.

What that changes and what it does not:

- **The record convention does not retire.** `_dnslink.<name> TXT dnslink=/…`
  is read by kubo, IPFS Companion and Brave in the client, not by a gateway.
  A site published for those clients keeps working, which is exactly the
  interoperation the read buys, and it becomes *more* valuable rather than less
  when the hosted middlemen go away.
- **A gateway URL in documentation does retire.** This chapter names no public
  gateway, and where an example needs one it is a gateway whose operator is
  known to whoever publishes the example (`https://pinthis.cloud/ipfs/<cid>`).
  Quoting `ipfs.io` would put a dead host in a specification.
- **Retrieval is somebody else's chapter, and it has the harder problem.**
  Losing the default bootstrap peers is a Chapter 3 concern (an implementation
  that ships a node needs peers of its own); it does not touch what a name
  *means*.

The uncertainty is one of emphasis rather than mechanism: we are confident the
read is right, and not confident how long "the ecosystem reads DNSLink" stays
true if the ecosystem's own defaults keep shrinking. If it stops being true the
read costs one query per resolution and should be re-argued, not quietly kept.

---

## 3. Open design items

Items considered and not applied. Each states the problem and what we would do.

### HS-D1. No per-resolution query budget on NS hops

A resolution's cost is bounded only by a delegation depth of 3 and a per-query
timeout. Nothing counts the *total* queries one navigation can cause: each zone
in the walk fetches DNSKEYs, TXT, `_dnslink` TXT, A and TLSA, each nameserver
name may need its own chain lookup and its own queries, and a hostile registry
TLD can compose those into far more work than any legitimate zone needs. The
DNSLink query (SPEC §6.5d) is one more per zone on every name, including a plain
address-record name that carries no pointer at all, which is the price of being
able to detect a disagreement rather than only a missing record; on the DoH
route it is asked in parallel and costs no round trip, on the
authoritative-DNS route it costs one.

**Recommendation.** Thread a counter through the resolution context — one
object, incremented at the single place a query is issued — cap it at roughly
32 queries per resolution, and refuse with `unreachable` (never `unregistered`,
which would state something false about the name) when it is exhausted. A cap
in the resolution context also bounds the nameserver-address recursion of §2.2
without a second mechanism.

### HS-D2. `hns:` has no IANA URI scheme registration

`hns:` is used as a standard, secure, web-origin-bearing scheme, and it appears
in no IANA registry. Anyone else may use the same token for something else, and
a browser vendor asked to support it has nothing to point at.

**Recommendation.** File a **provisional** registration under RFC 7595 §3.8:
scheme name, syntax (SPEC §5), the operations it supports, security
considerations by reference to SPEC §11, and this document as the
specification. A provisional registration costs an email, does not require a
standards-track document, and is the only thing that makes the scheme name
citable.

---

## 4. What this chapter leaves out

Four things this chapter deliberately does not contain, each of which affects
how the code reads:

1. **The composition layer.** In Wildroot, `src/hns/index.js` is the Electron
   `hns://` protocol handler: it chooses per request between the chain resolver
   and DoH, applies the DoH fallback policy, injects the two egress seams of
   SPEC §6.11 (the SOCKS dialler for the authoritative hop and the DoH/ODoH
   client for ICANN hosts) and the proxied fetch, keeps the SPV node's proxy
   setting following the delivery mode, opens the TLS connection through
   `connectDane` with the route the mode decides (SPEC §8.1), applies the
   Private-mode decisions at the pointer (SPEC §10.2) and turns a private
   lookup failure into the page and trust state of SPEC §9.3, and records the
   trust steps. It is Electron-bound and is not extracted into `../../src/`;
   the pieces that are — `dane-connect.js`, `socks-dial.js`, `doh.js`,
   `delivery-mode.js` — are the ones its policy rests on. Its *policy* is
   specified normatively here (SPEC §6.11, §8, §9, §10.2); the deviations that
   live in it is HS-8, and the restart cost of the proxy switch is
   HS-16 — but the code for them is not in this tree. An implementation of this chapter writes
   that layer itself, and the rule that makes it auditable is that the seams are
   injected rather than defaulted: a composition that omits one gets a working
   resolver that leaks, silently, because it works.

2. **Content fetching.** What happens to an `ipfs=`, `ar=`, `hyper=` or torrent
   pointer once resolved — the IPFS node, the Arweave gateway, the torrent
   client — belongs to Chapters 3, 4 and 9. This chapter ends at the pointer,
   and states only what a pointer's *kind* implies about verification (SPEC
   §10), because that changes the trust state.

3. **The `_op` route.** A top-level name that delegates through an
   `<registry>._op.` NS record is resolved by Chapter 10, which is marked
   experimental. This chapter states where that route is entered and what its
   trust step is, and nothing else about it.

4. **The browser chrome.** How the address bar, the padlock and the security
   panel render the model of SPEC §4 is not specified here; SPEC §11.4 says only
   what such an interface must not claim.
