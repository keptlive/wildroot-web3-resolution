# Chapter 1 — Handshake

**Namespace:** `hns` (`hns://`)
**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in
`../../src/`, which ships in the Wildroot browser. Not endorsed by any
standards body. Normative statements below describe what an implementation
must do *to interoperate with this one*; where they are inherited from an
existing standard, that standard is cited and its rule governs.
**Licence:** CC-BY-4.0 (see `../../LICENSE-SPEC`). The reference
implementation is licensed separately.

This chapter is part of the integrated specification whose spine is
`../../SPEC.md`, and **namespace selection — which hosts reach this chapter at
all — is specified there**, not here.

The reference implementation of this chapter is `../../src/`, its tests
`../../tests/`. Every deviation from a cited standard, and every question we
are unsure of, is in `../../DEVIATIONS.md` under the prefix `HS-`. Every
standard cited is listed with its purpose in `REFERENCES.md` beside this file.
**Those two files are part of this specification, not appendices to it.**

---

## Contents

1. [What this specifies, and why it exists](#1-what-this-specifies-and-why-it-exists) — including [**scope**](#11-scope)
2. [Terminology](#2-terminology)
3. [Namespace selection](#3-namespace-selection)
4. [Trust states](#4-trust-states)
5. [The `hns://` URL form](#5-the-hns-url-form)
6. [The resolution algorithm](#6-the-resolution-algorithm)
7. [HIP-5 `_op`: on-chain resolution — Chapter 10](#7-hip-5-_op-on-chain-resolution--chapter-10)
8. [DANE for HTTPS](#8-dane-for-https)
9. [Transport: DoH and Oblivious DoH](#9-transport-doh-and-oblivious-doh)
10. [Content pointers](#10-content-pointers)
11. [Security considerations](#11-security-considerations)

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## 1. What this specifies, and why it exists

Handshake replaces the ICANN root zone with a blockchain. A name's records —
its nameservers, its glue, and critically its **DS record** — are committed in
an authenticated tree whose root is in a block header. A client with a header
chain can therefore prove, without asking anybody's permission and without
trusting any resolver, what a top-level name's records are.

Almost no client does this. The usual Handshake browser or extension asks a
DNS-over-HTTPS resolver that happens to understand Handshake names, which
means the entire chain guarantee is replaced by "hnsdoh.com said so". That is a
reasonable engineering choice and a poor security story, and it is worth being
explicit that it is *the same trust model as ordinary DNS with a different
operator*.

This chapter specifies the other thing: resolution that starts from a chain
proof, carries a DNSSEC validation anchored to the **on-chain DS** rather than
to the ICANN root, pins TLS with DANE because no CA can issue for a Handshake
name, fails closed on every unproven step, and reports honestly — in a form a
user interface can render — which parts of the answer were proven and which
were taken on somebody's word.

It also specifies the awkward parts: what a URL for such a name looks like when
the WHATWG URL parser refuses to accept it (§5), and what happens when the chain
delegates a name to a smart contract instead of a nameserver (§7).

### 1.1 Scope

**In scope: Handshake name resolution, and only that.** Precisely: how a
Handshake name becomes an *answer*, where an answer is one of

- an **address** (with the trust facts that go with it),
- a **content pointer** — `ipfs=`, `ipns=`, `ar=` and the torrent/hypercore
  forms — as a parsed record, not as fetched bytes,
- a **DANE pin** (a TLSA record) to be applied to the TLS handshake, or
- a **failure**, distinguished by kind (§6.9),

together with the **trust state** that says which parts of that answer were
proven and which were taken on somebody's word (§4).

The mechanisms in scope are the ones that produce those answers: the chain
proof via an SPV node, DNSSEC validation anchored to the on-chain DS, DANE,
HIP-5 `_op`, the DoH and Oblivious DoH transports, and the `hns://` URL form.

**Out of scope, explicitly.** A browser that resolves Handshake names generally
resolves other things too and has to fetch something at the end. None of that
is specified here:

| Out of scope | Where it belongs |
|---|---|
| **Fetching content once a pointer is resolved** — IPFS, Arweave, Hyper, BitTorrent: retrieval, verification of the retrieved bytes, rendering, caching, privilege | Each is its own chapter of `../../SPEC.md`. This chapter ends at the pointer. What a pointer *guarantees* is stated in §10 because it changes the trust state; how bytes are obtained does not. |
| **Other naming systems** — ENS (`.eth`), Nostr, AT Protocol / DID, Tor `.onion`, Gemini, SSB, and the ordinary ICANN DNS path | Each has its own trust model and its own chapter. Which hosts are Handshake's at all is the spine's decision (§3). |
| **The user interface** — the padlock, the security panel, the address bar | §4 specifies the *model* an interface must be given and the claims it must not make. It does not specify a rendering. |
| **Publishing** — how a record gets into a zone, who may write it, what a publish must invalidate | The read path and the write path are different problems with different threat models. |
| **Handshake itself** — consensus, the auction, hsd's internals, the Urkel tree | Cited (`REFERENCES.md`, *Handshake*), not restated. §11.5 states what an implementation may conclude from a proof, which is the only part a resolver needs. |

A consequence worth stating plainly: an implementation of this chapter is a
**resolver**, not a browser. It answers "what does this name mean, and how sure
are we?" and stops there.

---

## 2. Terminology

DNS terms are used as defined in **RFC 8499**: *authoritative server*, *zone*,
*zone cut*, *delegation*, *referral*, *NODATA*, *bailiwick*, *validating
resolver*, *secure*/*insecure*/*bogus*, *insecure delegation*, *closest
encloser*, *source of synthesis*. Where this chapter uses one of those words it
means what RFC 8499 says it means.

DNSSEC validation states are those of **RFC 4033 §5**. Note the mapping this
chapter makes:

| RFC 4033 state | Here |
|---|---|
| Secure | the answer validated to the on-chain DS anchor |
| Insecure | the zone has **no** DS *and the absence was proven* (§6.6) |
| Bogus | any validation failure — **the resolution fails**, §11.1 |
| Indeterminate | does not arise: the anchor is either on the chain or it is not |

Terms specific to this chapter:

- **Chain resource** — the record set committed on the Handshake chain for a
  top-level name. It may contain `NS`, `GLUE4`/`GLUE6`, `SYNTH4`/`SYNTH6`, `DS`
  and `TXT` records.
- **Chain proof** — an Urkel tree inclusion (or exclusion) proof for a name,
  verified against a tree root committed in a block header on the most-work
  header chain the client has verified. See §11.5 for exactly what this does
  and does not establish.
- **On-chain DS anchor** — a `DS` record in the chain resource. It plays the
  role the ICANN root's trust anchor plays in ordinary DNSSEC, with the
  difference that it is *proven*, not configured.
- **Authoritative walk** — the sequence of queries to authoritative servers
  that follows the chain proof. It is a walk, not a single query, because a
  registry TLD refers rather than answers (§6.5).
- **Content pointer** — a `TXT` record, or an EIP-1577 contenthash, naming
  content by a self-authenticating address (`ipfs=`, `ipns=`, `ar=`, …).
- **Trust state** — the four-valued per-step verdict of §4.
- **Resolution kind** — the discriminant of a resolution result (§6.9).

---

## 3. Namespace selection

**Namespace selection belongs to the spine.** `../../SPEC.md` specifies the
router that decides, once and in one place, which chapter a host belongs to;
this chapter's algorithm begins after that decision has been made. Four parts
of that decision are Handshake's own and are stated here.

**Which inputs are Handshake names.** A host reaches this chapter when its
final label is neither a delegated ICANN top-level domain nor a label another
chapter owns (`.eth`, `.onion`), and it is not a reserved name (below). That
includes every alt-root label another system claims (`.crypto`, `.sol`,
`.bnb`), every all-numeric final label — ICANN has none, so a numeric label is
routed here, and what happens to it after that is **experimental**: see
Chapter 10, Part B — and a single non-ICANN label typed as a URL host
(`http://hnshosting/`), because a URL with a host has already settled the
question of navigation intent. The two product
decisions inside that rule — ICANN wins for ICANN top-level domains even though
the Handshake root is the root, and every other alt-root is Handshake's — are
`HS-13` in `../../DEVIATIONS.md`.

**A reserved name is never a Handshake name, on any path.** The labels reserved
by RFC 6761 (`localhost`, `invalid`, `test`, `example`), RFC 6762 (`local`),
RFC 7686 (`onion`), and RFC 8375 and adjacent practice (`arpa`, `internal`,
`home`, `lan`, `corp`, `intranet`, `private`) name the mechanism that owns
them, and `nas.local`, `printer.lan` or `app.localhost` is a device on the
user's own network. Such a host MUST be routed to that mechanism — plain
`http://` through the platform resolver — and MUST NOT be sent to a Handshake
resolver. This is not politeness: without it, every NAS, printer and internal
service name on a user's network is disclosed to whoever registers the
Handshake top-level name `local`, who can then answer for it.

The list MUST be **one list, consulted by one function, on every path that
classifies a host** — typed input, link click, the `http→hns` rewrite, a
subresource load, an omnibox suggestion row, a proxy auto-config script. A list
kept in two places is a list that disagrees with itself, and a carve-out that
holds on the rewrite path but not on typed input still leaks the user's own
device names. Here that list is `../../src/reserved-names.cjs` and that
function is `isReservedHost`, called from the classifier in
`../../src/router.js` and re-exported by `../../src/hns-host.js`.

**A Handshake resolution failure is final.** Per **RFC 9498 §9.10** — stated
there for GNS, and the only place this rule is written down in an RFC — an
implementation MUST NOT continue into the ordinary DNS when a Handshake
resolution fails. `unregistered` means the name does not exist; it does not
mean "try ICANN".

**Internationalized hosts are converted before resolution.** A Unicode host is
converted to A-labels before any comparison against the chain or the ICANN list
and before resolution (`HS-14` records that the conversion is the URL host
parser's UTS-46, not an IDNA2008 implementation of our own).

---

## 4. Trust states

The four states (`verified`, `unverified`, `failed`, `none`), the rule that an
implementation MUST expose the steps rather than a boolean, and the three-state
lock are the shared model of `../../SPEC.md` §4. This section says which steps a
**Handshake** resolution produces and where they land.

The steps, in order:

1. **Handshake name** — `verified` when the records came from a chain proof;
   `unverified` when they came from a DoH resolver (which MUST be named, and
   which MUST be distinguished from an oblivious lookup — §9.2).
2. **Name records** — present only on the `_op` route (§7). Always
   `unverified`, naming the registry contract and the RPC endpoint; the reason
   is Chapter 10's.
3. **Zone records** — the authoritative hop. `verified` only if step 4 is
   `verified`; a nameserver's unsigned answer is `unverified` however the
   nameserver was found.
4. **DNSSEC** — `verified` when the answer validated to the on-chain DS anchor;
   `none` when the zone provably has no DS (an insecure delegation, §6.6);
   `failed` otherwise, in which case the resolution has already failed.
5. **Connection** — `verified` when a DANE pin matched the presented
   certificate; `none` when the zone *proved* it publishes no pin and the
   connection is therefore plaintext; `unverified` when the pin came from a DoH
   resolver (§9.1); `failed` on a mismatch.
6. **Content** — `verified` for a content pointer whose bytes authenticate
   themselves against the pointer, `unverified` for one whose bytes do not
   (§10). The content-addressed kinds are exactly `ipfs`, `ipns`, `bittorrent`
   and `hyper`; an `ar=` pointer is not one of them.

### 4.1 Where a Handshake resolution lands

- **TRUSTLESS** — a chain-proven name resolving to a content-addressed pointer,
  or to an address with a matched DANE pin under a zone that validated to the
  on-chain DS. Every step is `verified` or `none`; nobody was believed.
- **TRUSTED** — the same name resolved over DoH, or pinned on a resolver's word
  (§9.1), or read through the `_op` route (Chapter 10), or resolving to an
  `ar=` pointer. The last of those is worth stating explicitly: the transaction
  id names immutable content, but the bytes come from a gateway and are not
  checked against the transaction, so the Content step is `unverified`, the
  aggregate verdict is `partial`, and the lock closes in the trusted colour —
  exactly as it does for an ordinary `https://` page.
- **OPEN** — any step `failed`, or a plaintext connection (§8, *Absence*).

Where an implementation's presentation layer can render `partial` in the same
colour as `trustless`, that is a bug in the presentation layer and should be
pinned by a test.

---

## 5. The `hns://` URL form

```
hns://<host>[:<port>]/<path>[?<query>][#<fragment>]
```

The host is a Handshake name, lowercased, with no trailing dot; the rest is an
ordinary URL.

`hns:` SHOULD be registered as a **standard** (special) URL scheme. That is
what gives a Handshake site a real web origin — `fetch`, service workers,
same-origin policy, secure-context features — rather than an opaque-origin
sandbox. In Electron this is
`protocol.registerSchemesAsPrivileged({ scheme: 'hns', privileges: { standard: true, secure: true, ... } })`.

Registering it as standard has one consequence: the host is then parsed by the
WHATWG URL host parser, and a host whose final label is all digits is parsed as
an IPv4 address rather than as a name. A Handshake top-level name may
legitimately be all digits, so such names need a written form of their own.
That form, and whether numeric top-level names are supported at all, is
**Chapter 10, Part B (experimental)**.

---

## 6. The resolution algorithm

Input: a lowercased host with any trailing dot removed, already classified as a
Handshake name by the spine (§3). Output: a **resolution** (§6.9) and a list of
trust steps (§4).

Throughout: `tld` is the final label of the host, and `host === tld` is the
apex case. Every DNS reply used anywhere in this algorithm, on every transport,
MUST be checked to answer the question that was asked (§6.10).

### 6.1 Step 1 — the chain resource

Fetch the chain resource for `tld` and its inclusion/exclusion proof, and
verify the proof against the header chain.

Three outcomes must be told apart, and conflating any two of them is a
user-visible defect:

| Outcome | Result |
|---|---|
| a proven record set | continue |
| the chain answered, and there is nothing for this name | `unregistered` |
| we could not ask the chain at all (node down, not synced) | `unreachable` |

An implementation **MUST NOT** report the third case as the second. "There is
no name *alice.w3*", stated with confidence about a name that exists, because a
local daemon was not running, is the worst failure a naming system can produce.

### 6.2 Step 2 — decisions made from the chain resource alone

Before any server is contacted:

- **Apex content pointer.** If `host === tld`, the resource carries a content
  pointer (§10), and it carries **no** `NS` record, return that pointer. (The
  `NS` condition matters: a zone with a nameserver can be asked for a TLSA
  record and this branch cannot, so the nameserver is the better source.)
- **Unsupported anchor.** If the resource carries `DS` records and **none** of
  them uses a supported algorithm and digest (§6.7), fail immediately with
  `dnssec-unsupported`. No nameserver answer could change the outcome, and
  reporting this as a validation failure would tell the user somebody is
  tampering with a zone that has merely chosen an algorithm we do not
  implement.
- **`SYNTH4` apex.** If `host === tld`, the resource has a `SYNTH4` address and
  no `NS` record, the address is a chain-attested address for the name itself.
  It MUST pass the address guard of §11.2. Plaintext to it is permitted:
  consensus attests the address, which is a stronger source than an off-chain
  `A` record, and there is no zone to ask for a pin. An implementation **MUST
  NOT** apply this branch to a name *below* the apex — serving the top-level
  name's own address for every name under it is a total compromise of a
  registry TLD.

### 6.3 Step 3 — a pseudo-TLD delegation

If `host !== tld` and the chain resource carries an `NS` record whose target is
`<registry>._op.`, the top-level name delegates resolution of the names beneath
it to a registry contract on Optimism; that route is specified in **Chapter 10
(experimental)** of `../../SPEC.md`, is attempted first, and the algorithm
continues from its result — either the resolution it produced, or step 4 when
it produced none.

Every `._op.` target, well-formed or not, **MUST** be removed from the list of
nameservers offered to step 4. Nothing under that pseudo-TLD is a host. The
same is true of any other `_<chain>` pseudo-TLD label; a top-level name that
delegates through one this implementation does not read (`_eth`) is resolved
through its remaining ordinary `NS` records.

### 6.4 Step 4 — finding the authoritative server

From the chain resource's `NS` records, in order, find an address for each
until one yields a usable server:

1. `GLUE4` in the chain resource matching that nameserver host;
2. otherwise **the chain**: take the nameserver host's own final label, fetch
   *its* chain resource, and read its glue or `SYNTH4`, or make one query to
   its own nameservers. This step is bounded to **one level** — a nameserver
   whose address needs a nameserver whose address needs a nameserver is a loop
   waiting to happen, and no legitimate zone requires it. It is also not an
   optimisation: `pinner.hns` delegates to `ns1.lumeweb`, a host that exists
   only on Handshake. Without this step, every name sold under such a registry
   resolves as `unregistered`.
3. otherwise the operating system's resolver (an ICANN nameserver host). What
   that lookup rides — encrypted or not, and which resolver — is the ICANN DNS
   transport plan of Chapter 2.

Chain before OS is the correct precedence and is what hsd's own resolver does:
the Handshake root is authoritative for any name registered on it, and a
top-level name with no chain records — which today is every ICANN TLD — is the
only case that falls through.

Every address obtained here **MUST** pass §11.2 before a query is sent to it. A
query to `127.0.0.1:53` is server-side request forgery just as much as an HTTP
fetch is. Once a server has been chosen, a query failure against it is final
here (`HS-15`).

If the chain resource carries no `NS` records at all: if `host === tld` and
there is a content pointer, return it; otherwise `unregistered`. In particular
an implementation **MUST NOT** answer a *sub*-name from the top-level name's own
chain resource.

### 6.5 Step 5 — the authoritative walk

The remainder is a re-entrant step over a delegation chain, not a single query.
A registry top-level name holds none of the names it sells: asked about
`maya.persist`, its server returns a **referral**.

The walk carries a context: the zone currently authoritative for the question,
the server that answers for it, and the DS records that anchor that zone's
keys — the on-chain DS at the top, and at each level below, the DS the parent
published *and this client verified*. Depth is bounded (3 in the reference
implementation).

For each zone:

**a. Anchor.** If the context has DS records, this zone is signed and every
record the resolution rests on MUST validate up to them. Fetch the zone's
`DNSKEY` RRset **once** per resolution and reuse it. If none of the DS records
uses a supported algorithm, fail `dnssec-unsupported` (not a validation
failure — say the true thing).

**b. Pointer query.** Query `TXT` for `host` with DO=1.

**c. Referral check.** RFC 1034 §4.3.2: if the reply has an empty ANSWER
section and the AUTHORITY section contains `NS` records **and no `SOA`**, this
is a referral, not an answer. Detecting it from the `TXT` reply already made,
rather than a speculative `NS` query, costs an ordinary name nothing. A
referral out of bailiwick (sideways or upward) MUST be refused. Then descend
(§6.6) and re-enter.

**d. Pointer.** If the `TXT` answer yields a content pointer (§10):
  - on a **signed** zone, the RRset MUST validate to the anchor, including the
    wildcard proof of RFC 4035 §5.3.4 if it was wildcard-expanded. A signed
    zone whose pointer does not validate is an attack or a broken zone; fail
    closed.
  - return the pointer.

**e. Proven absence of a pointer.** If the `TXT` answer is **empty** and the
zone is signed, the absence MUST be proven (NSEC/NSEC3 NODATA or NXDOMAIN,
§6.7) *before* the algorithm moves on to the address. Without this, an on-path
party who merely withholds the `ipfs=` record walks the browser from a
content-addressed site down to an address. A `TXT` that exists and is not a
pointer (SPF, a verification token) is an ordinary non-answer and needs no
proof.

**f. Address.** Query `A` for `host` with DO=1 (only `A`: `HS-2` records that
`AAAA` is never queried). On a signed zone the `A` RRset
MUST validate to the anchor, wildcard proof included. (This is not optional
hardening. An unvalidated address beside the zone's own honest proof of "no
TLSA" is a complete plaintext downgrade to a forged address, with the trust
panel reporting the zone as anchored — so the most protected configuration a
zone can publish becomes the easiest one to redirect; §11.3 rung 1.) A `CNAME`
to an ICANN host MAY be followed through the system resolver; the target's
address is then ICANN's word and the resolution MUST be reported as
unvalidated. See `HS-9` for CNAME *within* a signed zone.

On a signed zone a `CNAME` in the reply **MUST NOT** be followed until the
`CNAME` RRset itself validates to the anchor, with the §5.3.4 wildcard proof
where the answer was wildcard-expanded. Its canonical RDATA is the target name,
lowercased, in wire form (RFC 4034 §6.2). An unsigned or invalid `CNAME` on a
signed zone is a validation failure, not an unvalidated answer.

No separate proof of the `A` RRset's absence is required alongside it: **RFC
1034 §3.6.2** — a CNAME stands alone, and a name that owns one owns no other
data — so a *validated* `CNAME` is the zone's own signed statement that no `A`
exists at that name. Requiring an NSEC on top would demand a proof the zone has
no reason to produce.

A `CNAME` that is followed without this check is a fail-open on the most
protected configuration a zone can have: strip the signed `A`, inject a `CNAME`,
and the zone's own honest proof of "no TLSA" completes a plaintext redirect to
an attacker-chosen host. `HS-9` records what is still not validated beyond
this point.

The address MUST pass §11.2.

**g. Pin.** Query `TLSA` at `_443._tcp.<host>` (`HS-6` on the fixed port).
Three outcomes, which MUST be told apart, and which are decided by the reply's
RCODE (§8, *Absence*):

| | |
|---|---|
| records present | HTTPS with a DANE pin (§8) |
| **authenticated** NODATA or NXDOMAIN | the zone declares it publishes no pin — plaintext permitted |
| server error, lookup error or timeout | **unknown** — refuse; do not downgrade |

On a signed zone the absence MUST be proven. "No answer" is forgeable by anyone
on the cleartext DNS path, and treating it as "no pin" is the downgrade this
whole design exists to prevent.

### 6.6 Descending a zone cut

When following a referral to a child zone, before anything the child says is
believed:

- **Secure delegation:** the parent's `DS` RRset for the child must be present
  and must validate under the parent's anchored keys. That DS becomes the
  child's anchor.
- **Insecure delegation:** a signed parent with *no* DS for the child is
  accepted **only when the parent proves the absence** — its NSEC or NSEC3 at
  the cut without the DS bit set, or an NSEC3 Opt-Out gap covering the cut
  (RFC 4035 §5.2, RFC 5155 §8.9). The child is then read unsigned: its DANE pin
  still applies, its answers are simply not chain-anchored.
- **A DS deleted from a referral is a validation failure**, not an insecure
  delegation. Believing an empty DS answer lets an on-path party demote a
  signed child to unsigned — re-opening at the cut exactly the hole that §6.5(e)
  and §6.5(g) close at the leaf.

### 6.7 Validation rules

Anchored to the **on-chain DS**, not to the ICANN root. That substitution is
the whole design.

**Algorithms** (RFC 8624 §3.1, §3.3). Supported:

| | |
|---|---|
| 8 RSASHA256 | RFC 5702; key format RFC 3110 §2; modulus bounded 1024–4096 bits |
| 13 ECDSAP256SHA256 | RFC 6605 §4; key X‖Y uncompressed |
| 14 ECDSAP384SHA384 | RFC 6605 §4 |
| 15 ED25519 | RFC 8080 §3 |
| DS digest 2 (SHA-256) | RFC 4509 |
| DS digest 4 (SHA-384) | RFC 6605 §5 |

Refused, fail-closed, with the gap named as the implementation's: 5 and 7
(SHA-1), 12 (GOST), 16 (Ed448), DS digest 1 (SHA-1 — a validator MUST NOT use
it). RSASHA256 is a validator **MUST** in RFC 8624: an implementation that omits it
refuses every RSA-signed zone, which is an easy omission to ship because the
zones it breaks are somebody else's.

**Keys.** A DNSKEY anchors or verifies nothing unless it has the Zone Key bit
set (RFC 4034 §2.1.1), does **not** have the REVOKE bit set (RFC 5011 §2.1),
and has protocol 3. An RRSIG MUST be verified with a key of the RRSIG's own
algorithm; keys of another algorithm MUST NOT be tried.

**Canonical form.** RRs are sorted by raw RDATA before the signing input is
built (RFC 4034 §6.2). Owner names are ordered rightmost-label-first with octet
comparison, a missing label sorting first (RFC 4034 §6.1).

**Wildcards.** The RRSIG **Labels** field counts labels excluding the root and
excluding a leading `*` — RFC 4034 §3.1.3's own example, `*.example.com.` = 2.
Counting the `*` makes every RRset *owned* by a wildcard name look
wildcard-expanded, demand a proof that cannot exist, and drop out of every
denial — including the NSEC of `*.zone`, which is the record most denials need.
A wildcard-expanded answer MUST be verified against `*.` plus the rightmost
*Labels* labels (RFC 4035 §5.3.2), and MUST be accompanied by a proof that the
queried name has no exact match (RFC 4035 §5.3.4). That proof is required on
every path: pointer, address, TLSA and identity records alike.

**Validity period.** The RRSIG inception/expiration window is checked against
the real clock with no skew tolerance (`HS-10`).

**Denial of existence.** NSEC (RFC 4035 §5.4) and NSEC3 (RFC 5155). NXDOMAIN
requires **both** halves — the name covered, *and* the source of synthesis
`*.<closest encloser>` covered (RFC 4592 §3.3.1). NODATA includes the wildcard
form (RFC 4035 §3.1.3.4, RFC 5155 §8.7). NSEC3 requires the closest-encloser
proof of RFC 5155 §8.3, and iterations MUST be capped (RFC 9276 §3.1; 100 here)
— the hashing work is the validator's to do, so an uncapped count is a cost a
hostile zone imposes on the client.

Two rules that are easy to get wrong and are the difference between a proof and
a shrug:

- **NSEC3 Opt-Out proves exactly one thing: an insecure delegation** (RFC 5155
  §8.9). It is accepted for the DS-absence case of §6.6 and refused everywhere
  else. "There is no signed delegation here" is not "there is no TLSA here".
- **A mixed NSEC/NSEC3 answer proves nothing.** A zone signs with one scheme or
  the other. Records of both kinds in one reply is a broken signer or somebody
  splicing, and reading it as either leaves the other kind's records sitting
  there unexamined. The whole set MUST be refused.

**Unvalidatable ⇒ refuse** (RFC 4035 §5.5). Every failure kind is a refusal,
including a failure to *fetch* the keys. See §11.1.

### 6.8 Caching

The reference implementation caches only **positive** resolutions, for a flat
60 seconds, ignoring TTLs (`HS-1`). Caching a failure is a real defect and not
merely impolite: one dropped DNSKEY query then pins a name as failed through
exactly the retry the user is already making. An implementation **MUST NOT**
cache `unreachable` or a validation failure.

A publish flow that moves a pointer SHOULD invalidate the affected name
explicitly.

### 6.9 Resolution kinds

| Kind | Meaning |
|---|---|
| `ipfs` / `ipns` / `arweave` / `bittorrent` / `hyper` | a content pointer (§10) |
| `site` | an address, with `tlsa` (possibly empty) and `allowInsecure` |
| `txt` | a non-pointer TXT answer |
| `unregistered` | the chain, or the zone, authoritatively has nothing |
| `unreachable` | we could not ask — **not** the same as the above |
| `dnssec-fail` | validation failed; fail closed |
| `dnssec-unsupported` | the zone is signed with an algorithm we do not implement |
| `blocked` | the address is not a public-internet address (§11.2) |
| `unsupported-pointer` | a pointer whose codec we recognise and cannot fetch — refused **by name**, never silently discarded |

### 6.10 Every reply answers the question that was asked

A DNS reply is bound to its query by the question section, and an
implementation **MUST** check it: a parsed reply is accepted only when its
first question matches the owner name (compared case-insensitively, trailing
dot stripped — RFC 4343) and the QTYPE that was sent. A reply carrying no
question section is refused.

This is not redundant with the message id. Over TCP the id is checked as well,
but an id is 16 bits and a reply that answers a *different question* is exactly
what a cache-poisoning or type-confusion attempt looks like — a `TXT` answer
accepted as the reply to the `TLSA` query is a pin that silently disappears.
Over **DoH the id is fixed at zero** (RFC 8484 §4.1, so that identical queries
are cacheable by HTTP), which leaves the question section as *the only* thing
binding a reply to the query that asked it. The check therefore applies on
every transport: the TCP path, every plain DoH answer and every oblivious one.

---

## 7. HIP-5 `_op`: on-chain resolution — Chapter 10

A top-level name whose chain resource carries an `NS` record of the form
`<registry>._op.` delegates resolution of the names beneath it to a registry
contract on Optimism mainnet instead of to a nameserver. That route is
**Chapter 10 (experimental)** of `../../SPEC.md`; this chapter states only
where it is entered (§6.3), that its `Name records` trust step is `unverified`
(§4), and that its result, when it produces one, is a resolution of the same
shape and the same kinds as the DNS route's (§6.9).

---

## 8. DANE for HTTPS

No CA can issue a certificate for a Handshake name, so PKIX is not available
and is not the fallback. Trust is pinned in the zone instead. As far as we can
establish this is the only shipping browser that validates DANE for HTTPS at
all — Firefox closed its bug WONTFIX and Chrome has no such feature.

**Profile.** Exactly one: `_443._tcp.<host> TLSA 3 1 1 <sha256(SPKI)>` —
DANE-EE / SPKI / SHA-256. Any other parameter combination MUST be treated as a
**mismatch**, not as an unusable record (`HS-5`: this deviates from RFC 7671
§4.1, deliberately). Downgrading on confusion is how a pinning scheme quietly
stops pinning.

**Validation.** The DER certificate the peer presents is parsed (RFC 5280), its
SubjectPublicKeyInfo hashed with SHA-256, and the digest compared against the
record. No chain is built. No CA store is consulted.

**Expiry.** Per RFC 7671 §5.1 the pin replaces the CA chain, expiry included.
An implementation **MUST NOT** reject a DANE-EE match on `notAfter`: doing so
breaks a correctly-pinned self-signed site the day its arbitrary expiry passes,
for no security gain.

**Base domain across a CNAME.** The pin is looked up at the **original** name,
never at a CNAME target. RFC 7671 §7.2 requires exactly this when the CNAME
expansion is not secure, and ours never is (`HS-9`). We conform, by accident;
worth knowing which.

**Rotation.** On a mismatch, the cache entry is dropped and the name is
re-resolved **once**; a second mismatch fails closed. This recovers the case
where a zone published its new TLSA seconds after rotating the key. Operators
are still expected to pre-publish per RFC 7671 §8.1. There is no memory that a
host was ever pinned — see `HS-12` and `../../DEVIATIONS.md` (Chapter 1, §2.4)
for the downgrade this leaves open.

**Absence.** Plaintext is permitted **only** when the zone's own authenticated
statement proves there is no pin. Which replies to the TLSA query count as such
a statement is decided by the RCODE, and an implementation MUST distinguish
three classes:

| RCODE of the `_443._tcp.<host>` TLSA reply | Meaning |
|---|---|
| **NOERROR (0)** — records, or an empty answer | an authoritative statement about the pin. Records present: pin to them. Empty: the zone says it publishes none. |
| **NXDOMAIN (3)** | equally authoritative: the `_443._tcp` node does not exist, which is the ordinary shape of "no TLSA published". |
| **SERVFAIL (2), NOTIMP (4), REFUSED (5)**, any other RCODE, a transport error or a timeout | **not** a statement about the pin. The pin is *unknown*: refuse the connection rather than allow plaintext. |

Reading a server error as "no pin" hands the downgrade to anyone who can make a
nameserver fail — an on-path party dropping a TCP connection, or a minimal
server that answers TLSA with REFUSED. A failed TLSA lookup is not an absence.

On a **signed** zone, an authoritative NOERROR-empty or NXDOMAIN is still not
enough on its own: the denial MUST be proven by the zone's own NSEC/NSEC3
records, validated to the same anchor (§6.5g, §6.7). An unproven absence on a
signed zone is not permission to downgrade — it leaves the pin unknown, and the
caller refuses, which is the entire point of having asked. A proven absence, on
the other hand, is a *validated* answer about the pin: an address from the
zone's signed `A` RRset beside the zone's signed statement that there is
nothing to pin to is a fully validated resolution, and reporting it as
"signatures not checked" would understate it (§11.4).

A mismatch whose reported SPKI equals the *current* published pin means the
zone rotated its key before its TLSA; that is a correct refusal, and the
certificate's `notBefore` is the thing to check before hunting a resolver bug.

---

## 9. Transport: DoH and Oblivious DoH

### 9.1 DoH fallback

When the chain path is unavailable — no local node, node not synced, or an
infrastructure failure — an implementation MAY fall back to DNS-over-HTTPS
against resolvers that understand Handshake names (RFC 8484, wire format, GET
with `?dns=<base64url>`; POST is rejected by several Handshake DoH servers).

Everything resolved this way:

- **MUST** be marked `unverified` with the resolver named. There is no chain
  proof. This is ordinary DNS with a different operator, and an implementation
  that does not say so is misrepresenting its own security model.
- **MUST** be checked to answer the question that was asked (§6.10). The DoH
  message id is fixed at zero, so the question section is the only binding
  between a reply and its query.
- **MUST** still query `_443._tcp.<host>` TLSA and pin the handshake to what
  comes back, marked as the resolver's word. A DoH path that reads no TLSA
  means an attacker who merely breaks the chain path — drop TCP/53 to the
  authoritative server and the chain path throws — downgrades **every**
  DANE-pinned site to plaintext. Pinning on a resolver's word is strictly
  stronger than the plaintext it replaces. See `HS-8`.
- **MUST** report an outage of every endpoint as `unreachable`, never as
  `unregistered`.

An implementation **SHOULD NOT** let a DoH answer override the chain's
authoritative `unregistered` (`HS-7` records that ours does, and the conditions
under which that is defensible).

### 9.2 Oblivious DoH

RFC 9230 is implemented: HPKE (X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM,
RFC 9180) with the §6.3 response key and nonce derived from the HPKE exporter
secret and a target-chosen nonce, over HKDF (RFC 5869) on WebCrypto. The query
is encrypted to a target and carried by an independent relay, so no single party
sees both who is asking and what.

**An implementation MUST NOT present this as a privacy guarantee at current
deployment scale.** Two ODoH relays exist worldwide, and one of them is run by a
target operator. RFC 9230's security argument rests entirely on the relay and
the target not colluding, and at that scale the assumption does not hold. The
code is worth having; the claim is not.

An oblivious lookup **MUST** be reported distinctly from a plain DoH lookup in
the trust steps — the relay and the target both named — because the difference
is real even though the guarantee is not what the RFC describes.

An oblivious answer is subject to §6.10 like any other. An empty NOERROR
arriving obliviously is weak — it is what an A-record site's `TXT` query always
looks like — and confirming it over *plain* DoH would leak the name in the
common case, defeating the transport in exactly the situation it was chosen
for. It is confirmed obliviously instead: a second independent oblivious answer
agreeing on empty stands, and plain DoH is involved only when the confirmation
*transport* fails.

For the same honesty reason: a bridge that presents ODoH to a browser engine's
own DNS stack (as `../../src/odoh-bridge.js` does, a loopback HTTPS endpoint on
a per-launch secret path with a self-signed certificate) MUST bind to loopback
only and MUST reject cross-site requests.

---

## 10. Content pointers

A Handshake name's best use is to name **content**, not a machine. A content
pointer resolves to bytes that authenticate themselves against the pointer, so
a lying zone or a lying resolver can only point at *different* content — it
cannot tamper with the content a pointer names. That is true of the
content-addressed kinds; it is not true of every carrier (below).

Two carriers:

- **DNS TXT**, at the name itself: `ipfs=<cid>`, `ipns=<key>`, `ar=<txid>`, and
  the torrent/hypercore forms.
- **EIP-1577 contenthash**, on the `_op` route (Chapter 10).

Rules:

- **A record's `<character-string>`s are ONE value, concatenated** (RFC 1035
  §3.3.14). Separate records are separate values. A pointer longer than 255
  bytes arrives split, and an implementation that spreads the strings instead
  of joining them reads it as nothing. This rule MUST be applied identically on
  every path — the DNS route, the DoH route and the on-chain route — or the
  same record resolves differently depending on which path a user happens to be
  on.
- **A codec we recognise and cannot fetch MUST be refused by name**, never
  silently discarded. "This name points at Swarm content, which this client
  cannot fetch" is a true and useful sentence; falling through to an address is
  not.
- **Not all content pointers are equally verified.** The kinds whose bytes
  authenticate themselves are `ipfs`, `ipns`, `bittorrent` and `hyper`: a CID,
  a signed IPNS/BEP-46 record, an infohash or a hypercore key is checked
  against the bytes by the fetching component. An `ar=` pointer is **not** one
  of them — Arweave bytes fetched from a gateway are not checked against the
  transaction's `data_root`, so the gateway is trusted the way any HTTPS host
  is. An implementation MUST report the `ar=` case as `unverified` rather than
  borrowing the content-addressed claim (§4, §4.1), and SHOULD run the weaker
  one at reduced privilege.

DNSLink (`_dnslink.<name> TXT dnslink=/ipfs/<cid>`) is the ecosystem's
convention and SHOULD be read as a second pointer source. We write it and do
not read it (`HS-4`).

---

## 11. Security considerations

### 11.1 Fail closed, and say which failure

Every unproven step is a refusal, not a downgrade. Specifically: a signature
that does not verify, a denial that is not proven, a `TLSA` lookup that errors,
a `DNSKEY` fetch that fails, an unsupported algorithm, a mixed NSEC/NSEC3
answer, an opt-out gap offered as a denial of anything but a DS, a reply that
answers a different question than the one asked.

Two failures that look alike and must be reported differently:

- **"this zone is signed with an algorithm I cannot verify"** is not **"these
  signatures do not check out"**. Telling a user that somebody is tampering
  with a zone that merely chose RSASHA256 destroys the credibility of the
  warning for the case that matters.
- **"I could not ask"** is not **"there is no such name"** (§6.1).

An error in the resolution code path is itself a security event, because the
usual handler for a thrown error is a fallback to a weaker path. A thrown
error on the branch that decides whether a signed zone's "no TLSA" was proven
must therefore not be caught into a fall-through: caught there, it becomes a
DoH lookup that serves the site in plaintext, and a signed zone with a broken
denial ends up **less** safe than an unsigned one. Validation MUST sit outside
the handler that turns a lookup failure into "unknown", and a failure to *fetch*
the keys MUST be a validation failure exactly like a bad signature — otherwise
a resolver that validates when it can and shrugs when it cannot is a resolver
an attacker simply makes unable to validate. Fail-closed is a property of the
whole composition, not of the validator alone.

### 11.2 Every address is attacker-chosen

An `A` record, an on-chain `SYNTH4` or `GLUE4`, a nameserver address, and an
address from a registry contract are all chosen by whoever registered the name.
Without a guard, `hns://evil.tld/` publishing `A 169.254.169.254` makes the
client fetch cloud metadata from a privileged process, and page script reads the
response.

Every address, on every route, before any connection or query, **MUST** be
rejected unless it is a public-internet address: reject `0.0.0.0/8`, `10/8`,
`100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.168/16`,
`198.18/15`, `224/4`, `240/4` and the IPv6 equivalents. This includes addresses
used as *nameservers* — a DNS query to `127.0.0.1:53` is server-side request
forgery too.

### 11.3 The downgrade ladder

Partial validation is the failure mode this design is prone to, and it is worse
than no validation at all — because the interface reports the zone as anchored
while an on-path party uses the part that was not checked.

Every rung below is a place where a signed zone can be walked down to a weaker
answer if one record is validated and its neighbour is not. An implementation
**MUST** close all of them, and a test suite **SHOULD** drive each one by
actually removing or forging the record in question rather than by unit-testing
the validator in isolation:

1. **The address.** Validate the `A` RRset. An address read with DO=0 and taken
   as served, beside the zone's own honest NSEC proving "no TLSA", is a complete
   plaintext redirect to a forged address with the padlock reporting the zone as
   anchored. The most protected configuration a zone can publish becomes the
   easiest one to redirect.
2. **The DS at a cut.** Prove a missing DS missing. A believed empty DS answer
   lets an attacker delete the DS from a referral and demote a signed child to
   unsigned — re-opening at the cut every hole closed at the leaf.
3. **The pointer's absence.** Prove it. An unproven empty `TXT` lets an attacker
   delete the `ipfs=` and walk the browser from content-addressed bytes down to
   an address.
4. **The alias.** Validate the `CNAME` RRset before following it. Otherwise the
   same trick as (1) works one branch over: strip the signed `A`, inject a
   `CNAME`, and let the zone's honest "no TLSA" complete the redirect.
5. **The pin on the fallback path.** A DoH path that reads no TLSA means
   breaking the chain path — one dropped TCP connection to the authoritative
   server — downgrades every pinned site to plaintext (§9.1).
6. **The failure cache.** Do not cache failures. A cached `unreachable` or
   `dnssec-fail` pins a name as dead through exactly the retry the user is
   already making, and turns one dropped query into a lasting outage (§6.8).
7. **The reply itself.** Bind every reply to its question (§6.10). A `TXT`
   answer accepted as the reply to the `TLSA` query is a pin that vanishes with
   nothing reported as failed.

The common shape is worth stating on its own, because it is what makes these
easy to ship: **each rung is individually plausible as an optimisation.**
Skipping DO=1 on an `A` query saves nothing anyone will notice; believing an
empty DS answer looks like handling insecure delegations; not reading a TLSA on
a fallback path looks like keeping the fallback cheap. The security property is
not in any single check but in the rule that *every record a resolution rests on
is validated or the resolution fails* (§11.1).

### 11.4 What the trust panel must not do

Under-claiming is as misleading as over-claiming. A signed zone whose "no TLSA"
*was* proven must not render as "signatures not checked"; a signed zone we
failed to validate must not render as "this zone is not signed", which is the
false statement in exactly the case that matters most; and a DoH-carried pin
must not claim anything about a chain that was never consulted. A panel nobody
believes is a panel nobody reads.

### 11.5 What a chain proof establishes

*hsd, running on this machine, verified an Urkel tree inclusion proof for this
name against a tree root committed in a block header on the most-work header
chain it has seen.*

That is strong and it is the reason for this design. It is not the same as
running a full node: SPV inherits the assumption that the most-work chain is the
valid chain, and the client process trusts the local node over loopback. A node
that is still syncing returns null proofs and the client rides DoH until it
reaches the tip, then flips to chain proof mid-session — so the guarantee a
given page load received depends on the clock. See `../../DEVIATIONS.md`
(Chapter 1, §2.5).

### 11.6 Privacy

- A chain lookup queries Handshake peers over the node's own TCP connections,
  which do not ride an HTTP proxy. If a client is proxying traffic for IP
  privacy it MUST NOT use the chain path, because doing so leaks both the real
  address and the queried name; it should use the (weaker) DoH path, which can
  be proxied. That trade — weaker trust, no leak — is the right one when the
  user has chosen anonymity, and the interface must state which they got.
- Every HTTPS egress this stack makes on the user's behalf — the DoH lookup,
  the oblivious relay leg, and the registry read of Chapter 10 — MUST be made
  through an injected fetch that the embedder can point at its proxied session.
  A module that falls back to the platform's global fetch leaves the machine
  unproxied while anonymization is on, and does so silently, because it works.
- ODoH's guarantee is not what the RFC describes at current relay scale (§9.2).
- Without ECH (`HS-3`) the server name is in the ClientHello regardless, so an
  oblivious DNS lookup does not by itself hide which Handshake site was visited.
