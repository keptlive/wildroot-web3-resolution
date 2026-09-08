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

This chapter specifies Handshake resolution. The [router chapter](../router/SPEC.md)
defines which inputs reach it; the [overview](../../SPEC.md) explains the full
resolution model.

The implementation is in `../../src/` and tests are in `../../tests/`.
Unprefixed `src/` and `tests/` paths below are relative to the repository root;
browser composition paths are identified separately.
[Deviations](DEVIATIONS.md) use the `HS-` prefix; [references](REFERENCES.md)
identify the standards behind each mechanism.

**Review status:** [REVIEW.md](../../REVIEW.md) records contradictions and claims
that need a decision. This editorial revision changes documentation only.

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

Handshake commits top-level name records to an authenticated tree whose root
appears in a block header. A local SPV node verifies inclusion or exclusion
proofs against its header chain. The resolver uses the resulting DS records
as DNSSEC anchors and TLSA records as DANE pins.

This chapter specifies that chain path, the weaker DoH fallback, the
`hns://` URL form, and the trust facts returned with each answer. HIP-5 `_op`
delegation is defined in experimental Chapter 10. SPV's assumptions and the
trust placed in the local node are stated in §11.5.

### 1.1 Scope

**In scope: Handshake name resolution, and only that.** Precisely: how a
Handshake name becomes an *answer*, where an answer is one of

- an **address** (with the trust facts that go with it),
- a **content pointer** — `ipfs=`, `ipns=`, `ar=` and the torrent/hypercore
  forms at the name, or a `dnslink=` value at `_dnslink.<name>` — as a parsed
  record, not as fetched bytes,
- a **DANE pin** (a TLSA record) to be applied to the TLS handshake, or
- a **failure**, distinguished by kind (§6.9),

together with the **trust state** that says which parts of that answer were
proven and which were taken on somebody's word (§4).

The mechanisms in scope are the ones that produce those answers: the chain
proof via an SPV node, DNSSEC validation anchored to the on-chain DS, DANE,
HIP-5 `_op`, the DoH and Oblivious DoH transports, the two injected egress
seams that keep the chain path usable under an anonymizing proxy (§6.11), and
the `hns://` URL form.

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

The resolver returns an answer and its trust state. Fetching and rendering
the resulting content are separate operations.

---

## 2. Terminology

DNS terminology follows RFC 8499. DNSSEC states follow RFC 4033 §5.

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
- **Content pointer** — a `TXT` record at the name, a DNSLink `TXT` record at
  `_dnslink.<name>`, or an EIP-1577 contenthash, naming content by a
  self-authenticating address (`ipfs=`, `ipns=`, `ar=`, `dnslink=/ipfs/…`, …).
- **Trust state** — the four-valued per-step verdict of §4.
- **Resolution kind** — the discriminant of a resolution result (§6.9).

---

## 3. Namespace selection

The [router chapter](../router/SPEC.md) defines classification. In summary,
dotted hosts outside ICANN's delegated TLD list select Handshake, except ENS,
Tor, IP literals, and the reserved-name list. This includes other alternative
roots such as `.crypto`, `.sol`, and `.bnb`. Numeric names are disabled by default; when enabled they use the
experimental URL form in Chapter 10, Part B. A single non-ICANN label in an
explicit HTTP URL is also treated as Handshake.

Reserved names MUST use their designated mechanism and MUST NOT be sent to a
Handshake resolver. `src/reserved-names.cjs` contains both standards-based
reservations and additional local-network conventions; router §7 documents
the distinction. `.onion` selects Tor before the reserved-name branch. Other
reserved inputs select the platform's web path with `http://`.

The list MUST be shared across every classification path. The common host rule
uses `isReservedHost`; the WebSocket PAC limitation is recorded as RT-7.

A Handshake resolution failure MUST NOT trigger an ordinary DNS lookup. This
adopts RFC 9498 §9.10's namespace-precedence rule. `unregistered` is a final
answer, not a request to try another root.

Unicode hosts are converted to A-labels before comparison and resolution.
The implementation uses the URL parser's UTS #46 processing (HS-14).

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
   and `hyper`; an `ar=` pointer is not one of them. The step SHOULD also name
   **which record** the pointer came from when it came from the name's DNSLink
   record (§10.1): the trust state is the same either way, and a publisher
   debugging a name needs to know which of the two records was read.

### 4.1 Where a Handshake resolution lands

- **TRUSTLESS** — a chain-proven name resolving to a content-addressed pointer,
  or to an address with a matched DANE pin under a zone that validated to the
  on-chain DS. Every reported step is `verified`. An absent or unverified step lowers the
  aggregate according to the shared model.
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

Fast and Private select network routes; they **MUST NOT** change the trust
verdict for equivalent evidence. A DoH answer remains `unverified` when
carried through ODoH and Tor. Sections 8.1, 9.3, and 10.2 define which requests
Private permits.

A refusal caused by the mode is reported as `failed`, with a `Private mode`
step. Its source points to *Settings › Content delivery*, and its detail
matches the refusal page. The report must identify the mode as the cause
rather than blaming the site (`privateFailure` in the browser handler).

---

## 5. The `hns://` URL form

```
hns://<host>[:<port>]/<path>[?<query>][#<fragment>]
```

The host is a Handshake name, lowercased, with no trailing dot; the rest is an
ordinary URL.

`hns:` SHOULD be registered as a standard custom scheme so it has Chromium's
standard URL parsing and tuple-origin behavior. Electron's `standard` flag
is separate from `secure`, fetch support, and service-worker privileges; it
does not add `hns` to WHATWG's fixed special-scheme list. Wildroot disables
service workers for `hns` (router §4.4).

The original Electron registration example is:

```js
protocol.registerSchemesAsPrivileged({ scheme: 'hns', privileges: { standard: true, secure: true, ... } })
```

Numeric names are off by default. The optional form and its parser constraints
are specified in Chapter 10, Part B (experimental).

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

Distinguish these outcomes:

| Outcome | Result |
|---|---|
| a proven record set | continue |
| the chain answered, and there is nothing for this name | `unregistered` |
| we could not ask the chain at all (node down, not synced) | `unreachable` |

An implementation **MUST NOT** report an unavailable chain node as proof
that a name is unregistered.

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
- **`SYNTH4`/`SYNTH6` apex.** If `host === tld`, the resource has a `SYNTH4`
  (else `SYNTH6`) address and
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

The registry read is an HTTPS request to a JSON-RPC endpoint, and it is made
through the fetch the embedder injects (§11.6, Chapter 10 §A.6). It therefore
runs **while anonymized** on the same condition as the rest of the chain path
(§6.11): the composition reaches this step at all only when the chain route is
alive, and the request itself has always ridden the proxied fetch rather than a
platform default.

Every `._op.` target, well-formed or not, **MUST** be removed from the list of
nameservers offered to step 4. Nothing under that pseudo-TLD is a host. The
same is true of any other `_<chain>` pseudo-TLD label; a top-level name that
delegates through one this implementation does not read (`_eth`) is resolved
through its remaining ordinary `NS` records.

### 6.4 Step 4 — finding the authoritative server

From the chain resource's `NS` records, in order, find an address for each
until one yields a usable server:

1. `GLUE4`, else `GLUE6`, in the chain resource matching that nameserver host
   (the family rule of §6.5f: IPv4 when the host has one, IPv6 when that is
   all it has);
2. otherwise **the chain**: take the nameserver host's own final label, fetch
   *its* chain resource, and read its glue or `SYNTH4`/`SYNTH6`, or make one
   query (`A` and `AAAA` together) to
   its own nameservers. This step is bounded to **one level** — a nameserver
   whose address needs a nameserver whose address needs a nameserver is a loop
   waiting to happen, and no legitimate zone requires it. It is also not an
   optimisation: `pinner.hns` delegates to `ns1.lumeweb`, a host that exists
   only on Handshake. Without this step, every name sold under such a registry
   resolves as `unregistered`.
3. otherwise the **ICANN-host lookup** of §6.11 (the nameserver is an ICANN
   host). What that lookup rides — encrypted or not, and which resolver — is
   the ICANN DNS transport plan of Chapter 2; what this chapter requires is
   that it is not a plaintext query the chain path made on its own account
   (§6.11).

Nameserver address discovery checks Handshake before the ICANN-host lookup.
Only a name without chain records falls through to that lookup.

Every address obtained here **MUST** pass §11.2 before a query is sent to it. A
query to `127.0.0.1:53` is server-side request forgery just as much as an HTTP
fetch is. A server that cannot be asked — unreachable, timed out, a reply to a
different question — hands the whole question to the zone's next server, in
the zone's order (`HS-15`); an answer that fails validation is never retried
elsewhere.

If the chain resource carries no `NS` records at all: if `host === tld` and
there is a content pointer, return it; otherwise `unregistered`. In particular
an implementation **MUST NOT** answer a *sub*-name from the top-level name's own
chain resource.

### 6.5 Step 5 — the authoritative walk

A registry TLD can return a referral rather than the requested record. The
resolver follows a bounded delegation walk.

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

**d. Pointer, from two sources.** A name may publish a content pointer in two
places, and **both are read** (§10):

  1. the name's own `TXT` — `ipfs=`, `ipns=`, `ar=`, the torrent/hypercore
     forms — taken from the reply of step (b);
  2. **DNSLink**, a second `TXT` query at `_dnslink.<host>`
     (`dnslink=/ipfs/<cid>`, `dnslink=/ipns/<key>`, either with an optional
     path).

The DNSLink query runs even when direct TXT contains a pointer, allowing
conflicts to be detected. It adds one query on the authoritative route; DoH
issues both queries in parallel (HS-D1). A referral at `_dnslink` is not a
pointer answer.

Each source is held to the same rules:

  - on a **signed** zone the RRset — the pointer TXT at the name, the DNSLink
    TXT at `_dnslink.<host>`, whichever is present — MUST validate to the
    anchor, including the wildcard proof of RFC 4035 §5.3.4 if it was
    wildcard-expanded. A signed zone whose pointer does not validate is an
    attack or a broken zone; fail closed.
  - the two are then merged by the rule of §10.1: either alone **is** the
    pointer; agreement (same kind, same address) yields that pointer, recorded
    as also published as DNSLink so an interface can say which record it came
    from; **disagreement is `pointer-conflict`** (§6.9) — neither pointer is
    followed and neither is preferred.
  - return the merged pointer.

**e. Proven absence of a pointer.** On a signed zone, an empty TXT answer
MUST have authenticated NODATA or NXDOMAIN before proceeding to an address.
This applies to both `host` and `_dnslink.<host>` (§6.7). The current algorithm
treats a present non-pointer TXT as sufficient to continue without validating
it. That exception conflicts with the stated protection against pointer
suppression and requires a security decision; see [REVIEW.md](../../REVIEW.md).

**f. Address.** Query `A` and `AAAA` for `host` together, with DO=1 (RFC
3596). Use the `A` when there is one and the `AAAA` when that is all the name
has — the one family rule, applied here, to chain glue (§6.4), to the apex
(§6.2) and to the ICANN-host lookup (§6.11): the current implementation selects IPv4 first,
with the IPv6-only-client limitation recorded in HS-2. Whichever
RRset is used MUST, on a signed zone, validate to the anchor, wildcard proof
included; the other is not consulted. The fall-through from an empty `A` to
the `AAAA` needs no denial proof: an attacker who forges an empty `A` answer
can only steer the client to the zone's own signed `AAAA`, and suppressing
both is the denial of service an on-path attacker always had. An address
family that could not be ASKED beside one that answered empty is
`unreachable`, not `unregistered`. (This is not optional
hardening. An unvalidated address beside the zone's own honest proof of "no
TLSA" is a complete plaintext downgrade to a forged address, with the trust
panel reporting the zone as anchored — so the most protected configuration a
zone can publish becomes the easiest one to redirect; §11.3 rung 1.) A `CNAME`
to an ICANN host MAY be followed by resolving the target through the ICANN-host
lookup of §6.11; the target's address is then ICANN's word and the resolution
MUST be reported as unvalidated. See `HS-9` for what remains unvalidated about
the target's own RRset.

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

Without CNAME validation, an attacker could replace the signed address
with an alias and use a genuine TLSA-absence proof to complete a plaintext
redirect (HS-9).

The address MUST pass §11.2.

**g. Pin.** Query `TLSA` at `_443._tcp.<host>` (`HS-6` on the fixed port).
Three outcomes, which MUST be told apart, and which are decided by the reply's
RCODE (§8, *Absence*):

| | |
|---|---|
| records present | HTTPS with a DANE pin (§8) |
| **authenticated** NODATA or NXDOMAIN | the zone declares it publishes no pin — plaintext permitted |
| server error, lookup error or timeout | **unknown** — refuse; do not downgrade |

On a signed zone TLSA absence MUST be proven. A missing answer alone does
not permit plaintext.

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

Validation uses the on-chain DS anchor rather than the ICANN root anchor.

**Algorithms** (RFC 8624 §3.1, §3.3). Supported:

| | |
|---|---|
| 8 RSASHA256 | RFC 5702; key format RFC 3110 §2; modulus bounded 1024–4096 bits |
| 13 ECDSAP256SHA256 | RFC 6605 §4; key X‖Y uncompressed |
| 14 ECDSAP384SHA384 | RFC 6605 §4 |
| 15 ED25519 | RFC 8080 §3 |
| DS digest 2 (SHA-256) | RFC 4509 |
| DS digest 4 (SHA-384) | RFC 6605 §5 |

Unsupported algorithms fail closed and identify the support gap: 5 and 7
(SHA-1), 12 (GOST), 16 (Ed448), and DS digest 1 (SHA-1). A validator MUST NOT
use DS digest 1 under this specification. RFC 8624 requires validator support
for RSASHA256.

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

Additional denial-proof restrictions:

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

The implementation caches positive results for a fixed 60 seconds and ignores
record TTLs (HS-1). An implementation **MUST NOT** cache `unreachable` or a
validation failure. A publisher changing a pointer SHOULD invalidate the
affected name explicitly.

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
| `pointer-conflict` | the name's own `TXT` and its DNSLink record name **different** content (§6.5d, §10.1); neither is followed |

### 6.10 Every reply answers the question that was asked

An implementation **MUST** check that a DNS reply's first question matches
the requested owner name and QTYPE. Owner comparison is case-insensitive with
the trailing dot removed (RFC 4343). A missing question section is refused.

TCP also checks the message ID. The DoH client uses ID zero for HTTP cache
compatibility (RFC 8484 §4.1), so question matching remains necessary. Apply
the check to authoritative TCP, DoH, and ODoH replies.

### 6.11 Two seams the embedder owns: `dial` and `lookup`

The embedder supplies two network operations:

- **`dial(host, port)`** opens authoritative TCP sockets. The library default
  is a direct connection. Under anonymization, the implementation MUST use a
  SOCKS5 CONNECT dialler to the device-local proxy (RFC 1928, no authentication).
  IPv4 literals use ATYP `0x01`; other targets use ATYP `0x03` and are resolved
  by the proxy. A proxy failure must not produce a direct connection.
- **`lookup(host)`** resolves ICANN names encountered as nameservers, glue-less
  NS targets, or CNAME targets. All three cases MUST use the injected lookup.
  Wildroot supplies its DoH/ODoH client in every mode. The library default uses
  the OS resolver, which may disclose these names (IC-16).

While anonymized, the chain resolver may be selected only if a proxy port is
available **and the running SPV node uses that proxy**. The node's peer traffic
and the authoritative walk are separate connections; both must be covered.
Otherwise the browser uses the proxied DoH path and reports its weaker evidence
(§9.1). A node still syncing also uses that fallback (§11.5).

The node reads its proxy setting at startup and must be restarted when the
mode changes. It resyncs from persisted headers, or from scratch for an in-memory
node. DoH serves requests during that interval (HS-16).

The site connection uses the same injected dialler through `connectDane({ dial })`
or `connectPlain({ dial })` in `src/dane-connect.js` (§8.1).

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

The Handshake transport uses DANE in place of the platform CA trust store.
Its supported TLSA profile and fallback policy are specified below.

**Profile.** The supported profile is
`_443._tcp.<host> TLSA 3 1 1 <sha256(SPKI)>` (DANE-EE / SPKI / SHA-256).
If TLSA records exist but none uses that profile, the connection MUST be
treated as a mismatch rather than downgraded. When supported records exist,
any matching supported pin succeeds; unsupported records do not veto it. This
describes `verifyDane()`; HS-5 records the unusable-RRset policy.

**Validation.** The DER certificate the peer presents is parsed (RFC 5280), its
SubjectPublicKeyInfo hashed with SHA-256, and the digest compared against the
record. No chain is built. No CA store is consulted.

**Expiry.** Under RFC 7671 §5.1 an implementation **MUST NOT** reject a
matching DANE-EE certificate solely because of `notAfter`. The authenticated
TLSA pin supplies the binding in place of PKIX validation.

**Base domain across a CNAME.** Query TLSA at the original name. The CNAME
RRset is validated (§6.5f), but the target address RRset is not validated under
its own owner (HS-9); therefore the expansion is not fully secure and the
original-name rule from RFC 7671 §7.2 applies.

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

A failed TLSA lookup leaves the pin unknown and does not permit plaintext.

On a signed zone, empty NOERROR or NXDOMAIN still requires validated
NSEC/NSEC3 denial under the same anchor (§6.5g, §6.7). The denial MUST be
proven before plaintext is permitted. This authenticates the DNS result,
not the subsequent plaintext connection.

The original text attributes a mismatch whose SPKI equals the current pin to
key rotation. Those conditions are inconsistent without further context; see
[REVIEW.md](../../REVIEW.md).

### 8.1 The route: direct, or through the device-local Tor, by address

`connectDane()` in `src/dane-connect.js` checks the certificate on the same
TLS handshake used for the request. It sets `servername` to the Handshake name,
disables PKIX verification, and calls `verifyDane()` on `secureConnect`.
Anything other than `verified` destroys the socket. Connections are not pooled.
`connectPlain()` uses the same route selection for permitted plaintext loads.

The caller supplies `dial(address, port)`, or `null` for direct TCP. In Private
mode the SOCKS5 dialler uses the local Tor port. An IPv4 address is sent as
ATYP `0x01`; the SOCKS request does not need the name. The TLS ClientHello
still carries the Handshake name, which the exit can see without ECH (§11.6).

An implementation offering Private mode **MUST NOT** connect directly to an
address-record site while the mode is enabled and **MUST NOT** weaken the pin
check to use Tor. If no Tor port is available, it refuses before opening a
socket. This also applies to plaintext sites.

`privateRefusal('site')` identifies the mode, explains that the connection
requires the local Tor client, states that nothing was sent, and points to the
delivery-mode control. It does not attribute the refusal to the site. Fast mode
uses a direct connection, so the site sees the user's address.

`tests/dane-connect.test.js` checks matching and mismatching pins on both routes
and the corresponding plaintext connection behavior.

## 9. Transport: DoH and Oblivious DoH

### 9.1 DoH fallback

When the chain path is unavailable — no local node, node not synced, or an
infrastructure failure — an implementation MAY fall back to DNS-over-HTTPS
against resolvers that understand Handshake names (RFC 8484, wire format, GET
with `?dns=<base64url>`; POST is rejected by several Handshake DoH servers).
Which transports that fallback may use depends on the mode (§9.3): oblivious
first in both modes, and plain DoH beneath it in **Fast only**.

Everything resolved this way:

- **MUST** be marked `unverified` with the resolver named. There is no chain
  proof. This is ordinary DNS with a different operator, and an implementation
  that does not say so is misrepresenting its own security model.
- **MUST** be checked to answer the question that was asked (§6.10). This client uses DoH ID zero for cache compatibility, so it also checks
  the question section.
- **MUST** still query `_443._tcp.<host>` TLSA and pin the handshake to what
  comes back, marked as the resolver's word. A DoH path that reads no TLSA
  means an attacker who merely breaks the chain path — drop TCP/53 to the
  authoritative server and the chain path throws — downgrades **every**
  DANE-pinned site to plaintext. Pinning on a resolver's word is strictly
  stronger than the plaintext it replaces. See `HS-8`.
- **MUST** report an outage of every endpoint as `unreachable`, never as
  `unregistered`.

**A synced chain's `unregistered` is final.** An implementation **MUST NOT**
let a DoH answer override it. The distinction that makes this safe to hold is
the one §6.1 insists on: "the chain answered and there is nothing for this
name" is a different outcome from "we could not ask", and only the first is an
answer. DoH is therefore reached in three states and no others — no local node,
a node that is not yet at the tip, and a chain-path *failure* (a thrown error:
an unreachable authoritative server, a mid-sync tree serving garbage). Even
there, a DoH `unregistered` is not adopted in place of the failure: a weaker
source may answer a question the stronger one could not, and may not contradict
the stronger one's answer.

The `unreachable`/`unregistered` distinction determines whether fallback is
permitted.

### 9.2 Oblivious DoH

RFC 9230 is implemented: HPKE (X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM,
RFC 9180) with the §6.3 response key and nonce derived from the HPKE exporter
secret and a target-chosen nonce, over HKDF (RFC 5869) on WebCrypto. The query
is encrypted to a target and carried by an independent relay, so no single party
sees both who is asking and what.

**An implementation MUST NOT present ODoH as a privacy guarantee at current
deployment scale.** Its privacy argument requires independent, non-colluding
relay and target operators. The original claim that only two relays exist
worldwide is unverified; see [REVIEW.md](../../REVIEW.md).

An oblivious lookup **MUST** be reported distinctly from a plain DoH lookup in
the trust steps — the relay and the target both named — because the difference
is real even though the guarantee is not what the RFC describes.

An oblivious answer is subject to §6.10 like any other. An empty NOERROR
arriving obliviously is weak — it is what an A-record site's `TXT` query always
looks like — and confirming it over *plain* DoH would leak the name in the
common case, defeating the transport in exactly the situation it was chosen
for. It is confirmed obliviously instead: a second independent oblivious answer
agreeing on empty stands, and plain DoH is involved only when the confirmation
*transport* fails — in Fast mode. In Private mode a confirmation whose
transport fails leaves the name `unreachable` (§9.3): a weak empty answer that
cannot be confirmed obliviously is not confirmed at all.

A loopback ODoH bridge, such as `src/odoh-bridge.js`, MUST bind only to
loopback and MUST reject cross-site requests.

### 9.3 Private mode: obliviously, or not at all

`DoHResolver.strictOblivious` is a boolean or live predicate evaluated per
query. In Private mode it enforces these rules:

- A Handshake query tries ODoH and **MUST NOT** fall back to plain DoH. This
  covers TXT, DNSLink TXT, address, and TLSA queries.
- Weak empty-NOERROR answers are confirmed through ODoH (§9.2). Failed
  confirmation leaves the query unanswered.
- With no oblivious transport configured, the lookup is refused.
- Failures carry the underlying reason and a `private` marker through
  `privateLookupFailure`. `resolve()` and `txtRecords()` return
  `{ kind: 'unreachable', reason }`; they do not claim the name is absent.
  A synced chain's authoritative `unregistered` remains final.

An implementation **MUST** identify a mode-caused refusal as such and
**MUST NOT** report it as a zone failure, `unregistered`, or a generic error.
The reference handler uses `privateRefusal('lookup')` and records a `failed`
`Private mode` step whose detail matches the page. It states that the private
lookup failed, no unprotected fallback was made, and the site's condition is
unknown. It points to *Settings › Content delivery*.

The same reporting applies when a chain-path failure cannot be answered by
the oblivious fallback, or a chain resolution returns `unreachable` in Private.
Fast tries ODoH first and permits plain DoH beneath it; the answering resolver
is named in the trust steps. Transport privacy does not upgrade the answer's
`unverified` state.

`tests/doh.test.js` covers success, relay failure, missing ODoH configuration,
and the permitted Fast-mode fallback.

## 10. Content pointers

A content pointer identifies content independently of its retrieval location.
The verification guarantee depends on the pointer kind and the fetching
component; not every supported kind is verified locally.

Three carriers:

- **DNS TXT**, at the name itself: `ipfs=<cid>`, `ipns=<key>`, `ar=<txid>`, and
  the torrent/hypercore forms.
- **DNS TXT at `_dnslink.<name>`** — DNSLink, the IPFS ecosystem's convention
  (below).
- **EIP-1577 contenthash**, on the `_op` route (Chapter 10).

Rules:

- **This pointer convention concatenates a TXT record’s `<character-string>`s.**
  RFC 1035 §3.3.14 defines the multi-string record format. Separate records are separate values. A pointer longer than 255
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

### 10.1 DNSLink: the second pointer source, and the migration path

DNSLink (<https://dnslink.dev/>) publishes a name→content binding at a
**`_dnslink.` prefixed owner**, as a `TXT` record whose value is a path:

```
_dnslink.<name>.  TXT  "dnslink=/ipfs/<cid>[/<path>]"
_dnslink.<name>.  TXT  "dnslink=/ipns/<key>[/<path>]"
```

DNSLink supports records published by IPFS clients and gateways. An
implementation **MUST** read it as a second pointer source on both the
authoritative-DNS and DoH routes (§6.5d–e). It adds a query; the DoH route
issues it in parallel with the direct TXT query.

Reading DNSLink allows a site with only an `_dnslink` record to resolve
without republishing. Writing both formats supports clients that read only
DNSLink.

Grammar and reading rules:

- Only `/ipfs/` and `/ipns/` are pointers here. Any other DNSLink namespace
  (`/hyper/`, a nested `/dnslink/`) is **not** a pointer, and a value whose
  address fails the shape check for its kind is not a pointer either — in
  neither case is it half-trusted and in neither case does it cause a
  fall-through to an address.
- A trailing path is carried with the pointer.
- DNSLink says a name carries **one** `dnslink=` value. Where several parse,
  the first in record order wins, which is what every other DNSLink reader
  does.
- The `<character-string>` join rule above applies to this record too: a
  `dnslink=` value over 255 bytes arrives split and MUST be concatenated.

**Merge rule.** Compare the direct pointer with the DNSLink pointer:

| | |
|---|---|
| neither | no pointer; continue to the address (§6.5e first) |
| one of the two | that one **is** the pointer |
| both, agreeing (same kind, same address) | that pointer, recorded as also published as DNSLink so an interface can name the record it came from |
| both, **disagreeing** | `pointer-conflict` (§6.9): refuse, and say what was found |

A disagreement **MUST NOT** be settled by preferring one record. Two records
naming different content is a broken zone or a tampered answer, and a
precedence rule would let whoever controls one of the two records decide the
answer while the other record sat there contradicting it. Refusing is also the
only outcome a publisher can act on: the reference implementation returns a
`502` page naming both pointers and saying the two records must agree. A
non-IPFS pointer at the name (`ar=`, a torrent, a hypercore key) beside a
DNSLink record is not a disagreement *about the same content* — DNSLink can
only name IPFS content — but it is still two different answers, and it is
surfaced the same way.

**Where the read does not apply.** A top-level name whose pointer is answered
from the chain resource alone (§6.2 — a `TXT` on chain, no `NS`) is not a DNS
answer at all: there is no zone to ask for `_dnslink.<name>`, so there is no
second source and no merge. Such a name publishes its pointer once, on chain,
and the record convention does not reach it.

**Writing.** An implementation that publishes SHOULD write both records and
SHOULD prefer `dnslink=/ipns/<key>` when an IPNS key is available. The IPNS
record can change without rewriting DNS. Updates must keep the two pointer
records consistent to avoid `pointer-conflict`.

### 10.2 Content pointers in Private mode

The browser handler applies delivery policy before fetching a resolved pointer
(Chapters 3 and 9; `DIVERGENCE.md`).

- **IPFS:** Private permits a fetch only when the complete CAR can be obtained
  without peer routing from a stated origin: a published `car=` origin or the
  origin for a `<label>.pinthis` name. `warmFromOrigin(host, cid, { origin })`
  fetches the whole archive through the proxied session, verifies each block
  during import, and lets the local node serve it from disk. Missing origin,
  an archive over the private limit, failed fetching, an unavailable node, or
  disabled origin fetching causes `privateRefusal('ipfs')`. Partial archives,
  ranges, and subpaths do not satisfy this condition. Fast permits peer
  routing and treats origin fetching as an optimization.
- **BitTorrent and Hyper:** Private refuses these peer-to-peer lookups with
  `privateRefusal('p2p')`. An implementation **MUST NOT** silently substitute a
  weaker retrieval mechanism. The original refusal text suggests that a stated
  origin could make these names load; whether that path exists is recorded in
  [REVIEW.md](../../REVIEW.md).
- **Arweave:** gateway fetching uses the proxied session. Its gateway-trusted
  verification state is unchanged.

Each refusal names the mode and protocol, says what was not requested and why,
points to the delivery control, and records the `failed` `Private mode` step.
A complete CID-verified archive has the same content-verification state
regardless of whether it came from an origin or peers.

## 11. Security considerations

### 11.1 Fail closed, and say which failure

Refuse invalid signatures, unproven denials, failed TLSA lookups, unavailable
DNSKEYs, unsupported algorithms, mixed NSEC/NSEC3 answers, inappropriate
Opt-Out proofs, and replies to a different question.

Distinguish unsupported algorithms from invalid signatures, and infrastructure
failure from authoritative absence (§6.9). Validation MUST remain outside
handlers that convert transport exceptions into fallback results. Failure to
fetch required keys MUST be a validation failure, so an attacker cannot disable
validation by making the key query fail.

### 11.2 Every address is attacker-chosen

An `A` or `AAAA` record, an on-chain `SYNTH4`/`SYNTH6` or `GLUE4`/`GLUE6`, a
nameserver address, and an
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

An implementation **MUST** enforce all of the following checks. Tests
**SHOULD** exercise missing and forged records through the complete resolution
path, as well as testing the validator:

1. Validate the address RRset. A signed denial of TLSA does not authenticate
   an unchecked address.
2. Prove DS absence at a delegation. A removed DS must not turn a signed child
   into an insecure delegation.
3. Prove pointer absence at both the name and `_dnslink.<host>` before using
   an address. Withholding either pointer must not cause a downgrade.
4. Validate a CNAME RRset before following it.
5. Read and apply TLSA on the DoH fallback path, with the resolver identified
   as its source (§9.1).
6. Do not cache resolution failures (§6.8).
7. Bind each reply to its question (§6.10).

The required property is that every record needed to authenticate a signed
resolution validates, or that resolution fails.

### 11.4 What the trust panel must not do

The panel must distinguish a proven absence from an unchecked signature,
an invalid signed zone from an unsigned zone, and a resolver-supplied pin from
a chain-authenticated pin. A validated address and proven absence of TLSA can
describe a validated DNS result while the plaintext connection remains OPEN.

### 11.5 What a chain proof establishes

*hsd, running on this machine, verified an Urkel tree inclusion proof for this
name against a tree root committed in a block header on the most-work header
chain it has seen.*

SPV assumes the most-work header chain is valid; it does not validate full
blocks. The client also trusts the local hsd process over loopback. During
header sync, null proofs cause resolution to use DoH until the node reaches
the tip. A proxy-mode change restarts the node and reopens that interval
(§6.11, HS-16). The trust report must describe the path used for each load.

### 11.6 Privacy

- The SPV node's peer traffic and authoritative TCP queries require separate
  proxy configuration. Under anonymization an implementation **MUST NOT** make
  either connection directly. The node uses its SOCKS setting; the resolver
  uses `dial`; ICANN-host lookups use the injected DoH/ODoH client (§6.11).
- If either proxy path is unavailable, use the proxied DoH path and report its
  weaker evidence. Private requires ODoH or refusal (§9.3). An implementation
  without the required dialler MUST use that fallback rather than direct DNS.
- Private applies the same routing rule to site sockets and refuses unsupported
  peer retrieval (§8.1, §10.2). Mode-caused failures name the mode and point to
  its control; they do not blame the site.
- Every HTTPS operation made on the user's behalf, including DoH, relay
  requests, and registry reads, MUST use an injected fetch that the embedder
  can route through its proxied session.
- ODoH requires relay/target non-collusion (§9.2). It does not by itself hide
  later site connections. Without ECH the ClientHello exposes the site name to
  an observer on that connection, including a Tor exit (HS-3).
