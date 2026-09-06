# Deviations and open questions

Every place this implementation departs from a standard it cites, from common
resolver practice, or from its own stated design — plus every place we are not
sure we have made the right call.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.** Some of these are deliberate and settled, some are
unfinished work, and some we genuinely do not know the right answer to. Each
row says which.

Each entry gives: **what** we do, **why**, the **consequence** (including the
attack it does or does not enable), and a **status** — one of:

- **settled** — deliberate, we would defend it, no plan to change.
- **open** — we intend to change it; the work is not done.
- **uncertain** — we are not confident this is right and would like other
  implementers to argue with us.

Section 1 is the deviations. Section 2 is the honest-uncertainty list, called
out separately because those are the ones we most want challenged. Section 3 is
what this repository deliberately leaves out.

---

## 1. Deviations from cited standards

### D-1. TTLs are ignored; a flat 60-second positive cache
*RFC 2181 §5.2 · `src/resolver.js`*

**What.** A successful resolution is cached for 60 seconds regardless of the
records' TTLs. Only positive results are cached — every failure kind
(`unreachable`, `dnssec-fail`, `unregistered`) is re-asked.

**Why.** The cache exists to stop a page's own subresources re-resolving the
name a dozen times, not to be a recursive resolver. A publish flow that moves a
pointer invalidates its own name explicitly (`forget()`), which is the case a
short TTL is usually protecting.

**Consequence.** A record with a TTL below 60 s is honoured late. A record with
a very long TTL is re-fetched more often than the operator asked. Neither is a
security property; both are impolite to the authoritative server.

**Status: open.** Honouring the minimum TTL of the RRsets a resolution rests on,
clamped to a floor and a ceiling, is the correct behaviour and is not hard.

---

### D-2. No IPv6: AAAA, GLUE6 and SYNTH6 are not resolved
*RFC 3596 · `src/resolver.js`*

**What.** Only `A`, `GLUE4` and `SYNTH4` are read. `AAAA` is in the type table
and is never queried.

**Why.** No reason worth defending. It was not done.

**Consequence.** An IPv6-only Handshake site is unreachable. The SSRF guard
(`src/safe-address.js`) already understands IPv6 ranges, so the gap is entirely
in the resolver.

**Status: open.**

---

### D-3. SVCB / HTTPS records are parsed but never queried, and ECH is not usable
*RFC 9460, RFC 9848 · `src/dns-query.js`*

**What.** A complete RFC 9460 parser exists and is tested against real
Cloudflare RDATA, including a live 71-byte ECHConfigList. Nothing in the
resolution algorithm ever issues a query for type 65.

**Why.** Two independent reasons.

1. Querying type 65 costs a round trip on every A-record navigation, and no
   Handshake zone publishes one today — including ours. Our own authoritative
   server cannot even serve the record yet.
2. Even holding a valid ECHConfigList we could not use it. The `hns://`
   transport is a raw Node TLS socket, and **Node exposes no ECH option at
   all.** There is nothing to hand the config to. (Chromium does ECH for
   ordinary `https://` on its own, outside this code path.)

**Consequence.** `hns://` connections send the server name in the clear in the
TLS ClientHello. An observer learns which Handshake site is being visited even
though the DNS lookup may have been oblivious — so the ODoH work is partly
undone by the transport. Any SvcParam an operator publishes (`alpn`, `port`,
`ipv4hint`) is ignored.

**Status: open**, and blocked on something that is not ours: Node's TLS
bindings. Worth stating plainly rather than listing ECH as "planned".

---

### D-4. A numeric TLD is written with a leading underscore in a URL
*WHATWG URL Standard §3.5 · `src/hns-url.cjs` · **see also §2.1 below***

**What.** In an `hns://` URL, a final label consisting entirely of ASCII digits
is written with a `_` prefix:

```
name             URL form
14898            hns://_14898/
hello.14898      hns://hello._14898/
```

The marker is stripped before the name reaches the resolver and re-added
before a URL is built; the address bar displays the unmarked form.

**Why.** `hns:` is registered as a **standard** scheme, so Chromium parses its
host with the URL Standard's host parser. That parser's ["ends in a number"
checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) returns true
when the last label is non-empty and contains only ASCII digits, and the host
is then run through the [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser).
So `hns://14898/` canonicalises to `hns://0.0.58.50/` and `hns://hello.14898/`
is not a valid URL at all — not navigable, not linkable, not typeable. This is
not an Electron quirk; `new URL('http://hello.14898')` throws in every browser
for the same reason.

`_` is chosen because a Handshake label is `[a-z0-9-]` and can never contain
one, so decoding is unambiguous, and because `_` is not a forbidden host code
point — `_dmarc.example.com` is a host every browser has parsed for twenty
years.

**Consequence.** Every name under a numeric Handshake TLD has two written
forms, and any third party writing a link to one must know the convention or
the link is dead on arrival. It is a Wildroot convention with no standing
anywhere else.

**A trailing dot is part of the rule, and easy to miss.** The URL Standard's
"ends in a number" checker strips a single trailing empty label *before* testing
the last one, so `hello.14898.` hits the IPv4 rule exactly as `hello.14898` does
(`new URL('http://hello.14898./')` throws). The marker therefore goes on the last
**non-empty** label, not simply the last one — `hns://hello._14898./`. An
implementation that splits on `.` and marks the final element will find the empty
string there and leave the host unmarked and unnavigable.

**Status: uncertain.** See §2.1 — this is the deviation we are least confident
about.

---

### D-5. DNSLink is written but never read
*[DNSLink](https://dnslink.dev/) · `src/resolver.js`, `src/doh.js`*

**What.** The publish path writes `_dnslink.<label> TXT dnslink=/ipfs/<cid>` so
kubo, Brave and the public gateways can resolve our names. The resolver itself
reads only `ipfs=` / `ar=` at the label, and never looks at `_dnslink`.

**Why.** Historical. Our own publisher writes both forms, so the gap never bit
us.

**Consequence.** A Handshake site published by somebody else the normal
IPFS-Companion way — `_dnslink` only, no `ipfs=` — resolves in this browser as
an A-record site, or as unregistered. That is exactly backwards: the
ecosystem-standard publication is the one we cannot read.

**Status: open**, and the highest-value item on the list. It costs one extra
query, issued only when the label has no `ipfs=`.

---

### D-6. One DANE profile; an unusable TLSA RRset is refused rather than ignored
*RFC 6698, RFC 7671 §4.1 · `src/dane.js`*

**What.** Only usage 3 / selector 1 / matching type 1 (DANE-EE, SPKI,
SHA-256) is accepted. Any other parameter combination is treated as a
**mismatch** — the connection fails — not as an unusable record.

RFC 7671 §4.1 says that when *every* record in a TLSA RRset is unusable, the
client should treat the RRset as absent and fall back to PKIX.

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

**Status: settled.**

---

### D-7. The TLSA owner is always `_443._tcp`; a port in the URL is ignored
*RFC 6698 §3 · `src/resolver.js`*

**What.** The pin is looked up at `_443._tcp.<host>` whatever port the URL
names, and the connection is made to 443 (or 80) regardless.

**Why.** Not a decision so much as an unfinished one. It is coupled to D-3: the
right fix reads the HTTPS record's `port` SvcParam, connects there, and moves
the TLSA owner to `_<port>._tcp.<host>`. Doing the port without the record, or
the record without the port, gets the pin wrong.

**Consequence.** A Handshake site on a non-standard port is unreachable over
`hns://`.

**Status: open**, deliberately paired with D-3.

---

### D-8. HIP-5 `_op`: two fall-throughs to the seller's nameservers
*HIP-0005, ENSIP-10 · `src/hip5-op.js`, `src/resolver.js`*

**What.** When a TLD delegates to an Optimism registry contract via an
`0x<addr>._op.` NS record, the `_op` route is preferred. It falls back to the
TLD's ordinary NS records in two cases the route's own rationale argues
against:

1. **Every RPC endpoint failed or timed out.** Arguably this should be
   `unreachable`, not "ask the box the contract exists not to trust".
2. **A sub-name of a sold name** (`www.maya.persist`) whose own namehash has no
   resolver in the registry also falls back. ENSIP-10 would instead walk **up**
   to `maya.persist`'s resolver and ask it about the sub-name.

**Why.** Availability. Today the "seller" whose nameservers we fall back to is
us, so this is a design point rather than a live exposure.

**Consequence.** The exact weakness the registry exists to remove — the
seller's nameserver answering for a name the seller no longer holds — is
reachable by an attacker who can make every Optimism RPC endpoint fail. That is
not a trivial capability, but it is not a high bar either.

Not a fallback, and deliberately so: a **private or link-local address** from
the registry is `blocked`, never retried against DNS. The record was found and
we refuse to fetch it; asking a second source for permission would be theatre.

**Status: open.** The current behaviour is pinned by a test
(`hip5-op.test.js`, "every RPC failing falls back …") so that changing it is a
deliberate act.

---

### D-9. The chain's authoritative "unregistered" can be overridden by DoH
*`src/index.js` in the Wildroot tree — the composition layer, see §3*

**What.** When the chain-proof path returns `unregistered`, the browser asks a
DoH resolver a second time, and prefers the DoH answer if it is not
`unregistered`.

**Why.** Availability, historically: a proof-starved or mid-sync node must
degrade to "resolved, less verified" rather than to a false 404 — the sentence
"There is no name alice.w3" shown about a name that plainly exists is the worst
possible failure for a naming system.

**Consequence.** This is the one place in the design where a **weaker source
outranks a stronger one**. Handshake consensus said the name has no records; a
resolver said it does; we believe the resolver. It is not a namespace breach
(RFC 9498 §9.10 — both answers are in the Handshake namespace), but it is a
trust downgrade with the chain proof in hand.

The availability argument does not in fact hold any more: a mid-sync node
returns `unreachable`, not `unregistered` (§6.1 of the spec), so the case this
branch exists for never reaches it.

**Status: open**, and the honest answer is that it should simply be removed.

---

### D-10. A DoH-resolved TLSA is used as a pin, on the resolver's word
*RFC 8484 · `src/doh.js`*

**What.** On the DoH fallback path a `_443._tcp.<host>` TLSA lookup is made and
the returned record **is used to pin the TLS handshake**, marked
`trust: 'doh'`. A DoH NODATA for that owner allows a plaintext connection. A
DoH lookup that *fails* refuses to connect.

**Why.** A DoH path that reads no TLSA means an attacker who merely breaks the
chain path — drop TCP/53 to the authoritative server, the resolver throws, the
browser falls back — downgrades **every** DANE-pinned Handshake site to
plaintext. Pinning to the resolver's word is strictly stronger than the
plaintext it replaces.

**Consequence.** A malicious DoH resolver can substitute a pin, and can assert
"no pin exists" and get a plaintext connection. The trust panel says so — the
lock reads TRUSTED, not trustless, and names the resolver — but a user who does
not read the panel gets a weaker guarantee than the closed lock suggests.

**Status: settled as an improvement, open as a design.** The proper fix is D-15,
a "pinned before" memory.

---

### D-11. CNAME chains inside a signed zone are not validated under the target's owner
*RFC 4035 §5.3.1 · `src/resolver.js`*

**What.** A `CNAME` in a signed zone is validated as an RRset before it is
followed (SPEC §6.5f), but the **target's** RRset is not validated under the
target's own owner name. In practice the target of a Handshake CNAME is an
ICANN host, whose address is resolved through the operating system's resolver
and is therefore ICANN's word.

**Consequence.** A CNAME to an ICANN host works, and the resolution is reported
as unvalidated from that point on (`dnssecValidated` stays false, the trust
panel says the address came from the system resolver). A CNAME *within* a
signed Handshake zone, pointing at another name in the same or a delegated
zone, is not chased and validated the way RFC 4035 §5.3.1 describes.

**Status: open.**

---

### D-12. No RRSIG clock-skew tolerance
*RFC 4034 §3.1.5 · `src/dnssec.js`*

**What.** The RRSIG inception/expiration window is checked against the real
system clock with zero tolerance.

**Why.** unbound and BIND allow none by default either, so this is
conventional. There is also an explicit guard preventing any module in the
resolution stack from reading a clock other than the one guarded call site.

**Consequence.** A machine with a badly wrong clock fails every signed zone
closed. That is the correct direction, but it is a total outage rather than a
degraded one, and a user has no way to tell it apart from an attack.

**Status: settled**, noted because the failure mode is confusing.

---

### D-13. Not implemented at all
*Listed so their absence is a decision on the record.*

| Standard | Why not |
|---|---|
| **RFC 9462 DDR** (Discovery of Designated Resolvers) | Nobody's browser does it and the records are live. An opportunity we have not taken, not a gap we are unaware of. |
| **draft-ietf-dnsop-deleg** | In WG Last Call; the RR types are not allocated at IANA, so nothing can interoperate. Revisit on allocation. |
| **RFC 5011 trust-anchor rollover** | Structurally inapplicable: the anchor is a DS record on the Handshake chain, which rolls by a chain transaction, not by a hold-down timer. We use §2.1 (the REVOKE bit) and nothing else. |
| **RFC 6891 extended RCODEs, RFC 8914 EDE** | The OPT record is written to carry the DO bit and dropped on parse. Extended DNS Errors would make several of our failure messages much better; we do not read them. |
| **PKIX chain validation on the `hns://` path** | Deliberate — see D-6. |

---

### D-14. Special-use names are carved out on one path and not the other
*RFC 6761 / 6762 / 7686 / 8375 · `src/hns-host.js` vs `src/router.js`*

**What.** `hns-host.js` refuses to treat `localhost`, `local`, `internal`,
`home`, `lan`, `corp`, `intranet`, `private`, `invalid`, `test`, `example`,
`onion` and `arpa` as Handshake names. The omnibox classifier in `router.js`
does **not** consult that list, so a typed `nas.local` still classifies as
`hns` there.

**Consequence.** The carve-out bites where it matters most — the `http→hns`
rewrite, which is what would otherwise send your NAS's name to whoever
registers the Handshake TLD `local`. But the two code paths disagree about what
a name is, and one of them is wrong.

**Status: open.** They should share one function.

---

### D-15. A DANE mismatch re-resolves once, then fails closed; there is no "pinned before" memory
*RFC 7671 §8.1 · `src/resolver.js`*

**What.** When the certificate does not match the pin, the cache entry is
dropped and the name is resolved once more; a second mismatch fails closed.

**Why.** §8.1 expects operators to pre-publish the new TLSA before rotating the
key. Real operators sometimes do not, and a browser that fails permanently on a
few seconds of skew is unusable. One retry recovers the "published the TLSA
seconds late" case without weakening the pin — the second answer must still
match.

**Consequence and the honest gap.** There is no memory that a host was *ever*
pinned. So the last availability-driven downgrade remains open: break the chain
path entirely, answer over DoH with a proven "no TLSA", and a host that has
always been pinned is served in the clear. See §2.5.

**Status: settled for the retry, open for the memory.**

---

### D-16. Product decisions that deviate from what the naming systems themselves say

These are not standards deviations so much as places where we resolve a
conflict between systems in a way the systems' own advocates would dispute.

- **ICANN wins for ICANN TLDs, even though the Handshake root is the root.** A
  dotted name whose final label is a delegated ICANN TLD is an ICANN domain;
  every other name is a Handshake name. In Handshake's own model, ICANN TLDs are
  reserved and claimable with a DNSSEC proof, and a claimed one would make the
  chain authoritative — we route to ICANN anyway. That is what makes the browser
  safe to use as somebody's only browser. **Settled.**
- **Every other alt-root is Handshake.** `.crypto`, `.sol`, `.bnb`, `.nft` and
  anything else non-ICANN, non-`.eth`, non-`.onion` goes to whoever holds the
  Handshake TLD of that name. So `brad.crypto` resolves to the Handshake `crypto`
  owner's records, not to Unstoppable's registry. Consistent application of the
  rule above; other implementers may reasonably differ. **Settled.**
- **`_eth` is not implemented.** HIP-5's own shipped example is ENS on Ethereum
  mainnet; we implement only `_op`. A TLD that delegates via `_eth` (the
  Handshake name `hns` does) is resolved through its ordinary nameservers here.
  **Open.**
- **ODoH is implemented and is not called a privacy feature.** Two ODoH relays
  exist worldwide and one is run by a target operator, so RFC 9230's
  non-collusion assumption does not hold at that scale. The code stays; the UI
  must not claim privacy from it. **Settled, and unusual — most implementations
  claim the property the RFC describes rather than the one the deployment
  provides.**
- **A single authoritative "hop" is really a bounded walk.** A registry TLD
  holds none of the names it sells, so it *refers* rather than answers, and its
  NS targets are frequently themselves Handshake names. See §2.3.

---

### D-17. Internationalized names go through the URL parser, not through our own IDNA
*RFC 5890/5891, UTS #46 · `src/router.js`*

**What.** A Unicode host is punycoded by handing it to `new URL()` and reading
back `hostname`, before it reaches the resolver or the ICANN comparison.

**Consequence.** What we actually implement is UTS-46 as the URL Standard
specifies it, not IDNA2008 as RFC 5891 specifies it. The two differ on a small
set of characters (the deviation characters, and transitional processing). We
have not audited which Handshake labels this can affect. Note also that the
numeric-TLD case (D-4) must be handled *before* this pass, because
`new URL('http://hello.14898')` throws.

**Status: open**, and under-examined.

---

### D-18. No nameserver failover at query time
*`src/resolver.js`*

**What.** `_nameserverFor` tries every NS record when it is looking for an
*address*, but once a nameserver has been chosen, the first query failure
against it is final.

**Consequence.** A zone with two nameservers, one of which is dark, does not
resolve — even though the other one would have answered.

**Status: open.**

---

---

## 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each is
a real decision that is currently shipping, and each could be wrong.

### 2.1. The numeric-TLD `_` convention (D-4) is a local invention

**PROVISIONAL. This is a Wildroot convention. It is not a standard, it has no
standing anywhere, and we are not confident it is the right long-term answer.**

The constraint is real and is not ours: a standard-scheme URL host whose last
label is all digits is an IPv4 address, per the URL Standard, in every browser.
A Handshake TLD may legitimately be all digits — our own free-name TLD `14898`
is. Something has to give.

Alternatives we considered and why we did not take them:

| Alternative | Why not |
|---|---|
| **Register `hns:` as a non-standard (opaque) scheme.** The URL Standard only runs the IPv4 parser for special/standard schemes, so the problem disappears. | It also disappears origins, `fetch`, service workers, secure-context features, and same-origin policy. The entire point of registering the scheme as standard is that a Handshake site is a real web origin. Not a trade we will make. |
| **Percent-encode or otherwise escape the digits.** | The host component is not percent-decoded by the URL parser the way a path is; the escape survives into the canonical host and is worse to read than `_`. |
| **Use a different marker character** (`-`, `.`, a Unicode digit). | `-` is a legal Handshake label character, so it would be ambiguous. A trailing dot is stripped. A non-ASCII digit is punycoded and then *is* a valid label but an unreadable one. `_` is the only character that is (a) illegal in a Handshake label, so unambiguous, and (b) legal in a URL host, so parseable. |
| **Suffix the name into a real domain** (`hello.14898.hns.one`). | That is what the outside world does, and it requires our infrastructure to exist. A browser that resolves from the chain should not need a gateway to name a site. |
| **Get the URL Standard changed.** | The IPv4 rule exists for compatibility with a very long tail of the web. A per-scheme opt-out is a plausible ask but is not a thing we can ship against. |
| **Refuse to support numeric TLDs.** | They are valid Handshake names that people have registered and paid for, including ours. |

What we are unsure about:

- Whether the marker belongs on the **numeric label** (`hello._14898`) or as a
  **whole-host** marker. A prefix on the label is minimal and local; a host-wide
  marker would be uglier but would not change meaning depending on which label
  it lands on.
- Whether `_` conflicts with anything in practice. Handshake labels cannot
  contain `_`, but DNS **owner names** in a Handshake zone routinely do
  (`_443._tcp.…`, `_dnslink.…`). The marker only ever applies to the final TLD
  label, where those never appear — but that is a rule the convention has to
  state, not a property it gets for free.
- Whether other Handshake clients will do something different, at which point a
  link written by one is dead in the other. **This is the reason it is in the
  spec at all: if there is going to be a convention, it should be one
  convention, and we would rather adopt somebody else's than defend ours.**

### 2.2. SVCB/HTTPS and ECH (D-3)

Restated here as an uncertainty rather than a to-do: we are not sure the right
answer is "query type 65 on every navigation". The cost is a round trip per
A-record site for a record essentially no Handshake zone publishes. A
DNSSEC-signed zone could advertise its presence more cheaply — that is roughly
what the type bitmap in an NSEC record already does, and we already fetch those
for other reasons. We have not worked this out.

### 2.3. Registry TLDs that refer, and NS targets that are themselves Handshake names

A registry TLD (`persist`, `hns`) holds none of the names it sells. Asked about
`maya.persist`, its nameserver returns a **referral** — NS records with no SOA —
not an answer. An implementation that treats the authoritative hop as literally
one query resolves every such name as unregistered; ours did, once.

So the hop is a **bounded walk**: `_fromZone` re-enters itself per delegation up
to `MAX_DELEGATIONS`, a referral is told from a NODATA by the presence of an SOA
(RFC 1034 §4.3.2), and `_descend` validates the parent's DS for the child —
under keys the on-chain DS anchors — before anything the child says is believed.

Two things about this we are not certain of:

1. **An NS target that is itself a Handshake name.** `pinner.hns` delegates to
   `ns1.lumeweb`, which is not resolvable in ICANN's DNS at all. We resolve it
   from the `lumeweb` chain resource (`_chainAddress`). That is right, and it is
   also a second chain lookup inside a resolution, with its own failure modes
   and its own cache. Whether the depth of this recursion should be bounded
   separately from `MAX_DELEGATIONS`, and what a cycle looks like, is not fully
   worked out.
2. **Bailiwick.** Sideways and upward referrals are refused. We believe the
   check is right and it is tested, but "which referrals are in bailiwick" is
   the classic place a resolver gets subtly wrong, and we would like another
   pair of eyes on it.

### 2.4. What the DoH fallback actually promises

When the chain path fails, resolution falls back to DoH (`query.hns.one`, then
`hnsdoh.com`, then `dns.easyhns.com`). Everything resolved that way carries
`trust: 'doh'` and the trust panel names the resolver. Three things we are not
settled on:

- **The fallback is unconditional on infrastructure failure.** Any thrown error
  on the chain path leads to a DoH attempt. That is availability-first. An
  attacker who can reliably break the chain path can therefore *choose* which
  resolver answers, and gets D-10's weaker pin semantics as a bonus. We think
  the answer is the "pinned before" memory (§2.5) rather than removing the
  fallback, but we are not sure.
- **D-9**, the `unregistered` override, is the one place a weaker source
  overrides a stronger one, and we think it should go.
- **What "trusted" should mean in a UI.** Our lock has three visible states, not
  two (§4 of SPEC.md). Whether that is comprehensible to anybody who has not
  read the spec is an open product question, not just an engineering one.

### 2.5. DANE pin rotation windows (D-15)

We allow exactly one re-resolve on mismatch. A too-generous retry policy is a
downgrade oracle; a too-strict one breaks sites during a legitimate rotation.
We have no data on what real Handshake operators' rotation windows look like,
so "one retry" is a guess, not a measurement.

The related and larger gap is that we have no memory of having pinned a host
before. An HSTS-shaped rule — *a host that ever resolved chain-proven with a pin
refuses plaintext until a proven absence says otherwise* — would close the last
availability-driven downgrade. It also introduces a persistent, per-host,
attacker-influenceable state store, which is its own class of problem (pinning
a host into unreachability). We have not built it and are not sure of the right
shape.

### 2.6. What an SPV proof actually proves

The chain path's guarantee is: *hsd, running on this machine, verified an Urkel
tree proof for this name against a tree root committed in a block header on the
most-work header chain it has seen.* That is a strong property and it is the
reason this project exists. It is not the same as running a full node:

- SPV follows the most-work header chain. It does not validate blocks, so it
  inherits the standard SPV assumption that the most-work chain is the valid
  chain.
- The browser process reads the verified result from the local hsd over
  loopback RPC or the node's own root nameserver. It trusts that local process.
- A node that is still syncing returns null proofs. We report `unreachable` and
  ride DoH until it reaches the tip, then flip to chain proof mid-session. That
  is correct, but it means the guarantee a given page load got depends on the
  clock, which the trust panel has to explain and which nobody expects.

### 2.7. `_op` is chain-pointed and RPC-answered

The Handshake chain proves *which contract* answers for a name. Nothing proves
the contract's *answer*: it is read from a public Optimism JSON-RPC endpoint over
HTTPS with no light client and no Merkle proof against a block header. The
endpoint is trusted for the record and sees which name was asked.

We mark this `unverified` in the trust panel and name the registry and the RPC
host in words. The padlock follows the DNS route's rule — a content pointer
closes it on the chain proof, an A-record site closes it only on a matched DANE
pin — on the argument that the honest comparison is with the DNS route (whose
unsigned answer is also taken on a nameserver's word, over plaintext) and not
with `ens://` (which has no chain anchor at all and stays open).

We are not certain that is the right line. A reasonable implementer could hold
that an RPC-trusted answer should never close a lock, full stop.

---

## 3. What this repository leaves out, and why

This package is the resolution stack. Three things it deliberately does not
contain, each of which affects how the code reads:

1. **The composition layer.** In Wildroot, `src/hns/index.js` is the Electron
   `hns://` protocol handler: it chooses per request between the chain resolver
   and DoH, applies the DoH fallback policy, applies D-9, opens the TLS
   connection, checks the DANE pin against the peer certificate, and calls
   `recordTrust`. It is entirely Electron-bound and is not extracted here. Its
   *policy* is specified normatively in SPEC.md §3 and §8, and the two
   deviations that live in it (D-9, D-10) are documented above — but you will
   not find the code for them in this tree. If you are implementing from this
   spec, that layer is yours to write.

2. **Content fetching.** What happens to an `ipfs=` or `ar=` pointer once
   resolved — the IPFS node, the Arweave gateway, the torrent client — is out of
   scope. One honesty note that belongs with the resolution story: Arweave bytes
   are *not* verified against the transaction's `data_root` (the gateway is
   trusted like any HTTPS host), whereas IPFS bytes are verified against the CID
   by the local node. A resolution that yields `ar://` is therefore weaker than
   one that yields `ipfs://`, and the trust panel says so.

3. **The browser chrome.** Two tests in `tests/lock-semantics.test.js` were
   removed during extraction because they assert that the browser's address bar
   and stylesheet render these verdicts without recomputing them. They remain in
   the Wildroot tree. `tests/publish-pointers.test.js` similarly lost one test
   that scanned two non-resolution modules for a duplicated CID regex.
