# Chapter 7 — DID, AT Protocol and ActivityPub: deviations and open questions

Every place this chapter's implementation departs from a standard it cites,
from common practice, or from its own stated design — plus every place we are
not sure we have made the right call.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

Each entry gives **what** we do, **what the standard says**, **why**, the
**consequence** (including the attack it does and does not enable), and a
**status** — `DELIBERATE` (we would defend it) or `OPEN` (we intend to change
it, with the change we would make).

A cross-cutting note before the list. This namespace is *thinner* than the
Handshake chapter of this specification. The Handshake path fails closed on
every unproven step; this path resolves two things itself, refuses two more,
and takes a third party's word for a fourth. Most of what follows is therefore
not "we chose a different rule from the RFC" but "we have not implemented the
check yet, and here is exactly which check". That is a worse position to be
in, and writing it down is the point.

---

## 1. Deviations

### DI-1. A resolved DID document is served with `Access-Control-Allow-Origin: *`

**What.** A successful document is answered with `Access-Control-Allow-Origin: *`,
`Allow-CSP-From: *`, and wildcard allowed headers and methods
(`src/did-protocol.js`).

**The standard says.** The WHATWG Fetch Standard makes
`Access-Control-Allow-Origin: *` a grant of cross-origin read access to every
origin. A response fetched on behalf of a navigation, from a host a stranger
named, is not a response that wants that grant.

**Why.** Inherited from the browser's protocol-handler conventions, where a
handler serves content pages are meant to read.

**Consequence.** Read literally, the header makes the handler a cross-origin
reader for a DID document on any host the caller names. In this build it is
inert: `did:` is registered non-standard with `supportFetchAPI: false`, so a
page cannot `fetch('did:…')` at all, and a non-standard scheme's response is an
opaque origin. The exposure it would otherwise pair with is closed
independently — the host guard refuses private and reserved hosts before
connecting (SPEC §5.3), so there is no address space to read out of. What
remains is that the headers describe an intent the scheme's privileges
contradict, and a future decision to make `did:` a standard scheme — a
reasonable thing to want — turns an inert header into a live one with no other
edit.

**Status: OPEN.** The headers should say what is intended. A document no page
can read does not need `*`; the change belongs with DI-3, which rewrites the
response anyway. Pinned by `tests/did-protocol.test.js` so it cannot change
silently.

---

### DI-2. `did:plc` is directory-trusted; the operation log is never fetched

**What.** `did:plc` is resolved by `GET https://plc.directory/<did>` and the
returned document is used once its `id` matches. The method's audit log
(`GET /<did>/log/audit`) is never requested and never checked
(`src/did-protocol.js`, and `resolvePds` in `src/bsky.js`).

**The standard says.** The did:plc method specification derives the identifier
from the genesis operation — base32 of a truncated hash of the signed operation
— so the DID commits to its own creation, and the directory publishes the full
signed operation log. Verifying that log against the DID is what makes the
method self-certifying rather than a database lookup.

**Why.** Not attempted. The document endpoint is one request and answers the
question the callers ask.

**Consequence.** `did:plc` is reduced from a *verifiable* method to *one
operator's database lookup*. It is the same shape of gap as the `ens://`
handler's — the binding is RPC-trusted, not chain-proven — and this chapter
reports it the same way: SPEC §4 marks the step unverified, the lock is
TRUSTED and never green, and the trust panel says in words that this is the
server's word.

**Status: OPEN**, and it is the highest-value thing that could be *added*
rather than fixed. Fetch the audit log, verify the operation chain — each
operation signed by a rotation key valid at that point, each carrying the
previous operation's CID, the DID equal to the hash of the genesis operation —
and check the served document against the head of that chain. It is
self-contained, needs no infrastructure and no chain, and would make `did:plc`
the strongest link in this chapter instead of the weakest. See DI-D5.

---

### DI-3. The result is a bare DID document, as `application/json`

**What.** A successful resolution answers with the DID document alone, as
`Content-Type: application/json; charset=utf-8` (`src/did-protocol.js`).

**The standard says.** W3C DID Core §7.1 defines resolution as returning a
**result**: `didDocument` alongside `didResolutionMetadata` (content type,
error) and `didDocumentMetadata` (created, updated, deactivated, versionId).
The registered media type for a DID document is `application/did+json`.

**Why.** The consumers are a page renderer and a PDS lookup; neither reads the
metadata.

**Consequence.** Mostly cosmetic, and one thing that is not: the metadata
envelope is the natural place to say *"resolved, and here is what was and was
not checked"* — that the `id` was compared (it is) and that the `did:plc`
operation log was not (DI-2). Returning a bare document means those facts live
only in the trust panel, which is a UI surface rather than data a caller can
act on.

**Status: OPEN.** Wrap the document as DID Core §7.1 specifies and serve it as
`application/did+json`, with the verification facts in
`didResolutionMetadata`. Do it after DI-2, so there is something interesting
to put there. See DI-D6.

---

### DI-4. `did://` is accepted as an alias for `did:`

**What.** `did://plc:abc` is normalised to `did:plc:abc` before parsing
(`src/did-protocol.js`).

**The standard says.** W3C DID Core §3.1 gives the syntax as
`did:<method-name>:<method-specific-id>`. A DID has no authority component, so
`did://…` is not valid DID syntax.

**Why.** Stated in the code: a rendering engine handed a registered scheme
sometimes returns it in authority form, and Electron's protocol layer does.

**Consequence.** A tolerated input form that is not a DID. It is only a
*receiving* leniency — nothing in this tree emits `did://`, and the normalised
identifier is what every downstream comparison uses — so no invalid DID escapes
into a document or a link. Worth stating because a reader implementing from
this chapter will otherwise see the branch and wonder whether it is a form they
must produce. It is not.

**Status: DELIBERATE.** It is a compatibility shim for one engine, it accepts
strictly more than the syntax rather than resolving something different, and
SPEC §3.1 states it so nobody mistakes it for a URL form. An implementation
SHOULD NOT emit it.

---

### DI-5. AT Protocol handle resolution is not implemented; the AppView is asked instead

**What.** `resolveHandle` (`src/bsky.js`) calls
`com.atproto.identity.resolveHandle` on Bluesky's public AppView
(`https://public.api.bsky.app`) and takes the answer.

**The standard says.** The AT Protocol handle resolution specification gives
two authoritative methods, either of which a client may use, DNS preferred: a
`_atproto.<handle>` DNS `TXT` record carrying `did=…`, or
`GET https://<handle>/.well-known/atproto-did`. It further requires
**bidirectional verification** — the DID document reached from the handle must
list `at://<handle>` in its `alsoKnownAs`, or the handle is not that account's.
None of that is done here.

**Why.** The adapter was written for the *social client*, where the AppView is
already the read path for everything else and one more endpoint is free. It was
not written as a resolver.

**Consequence.** Handle → DID is a third party's word. That is an ordinary
posture for an ordinary client and an odd one here, for a specific reason: the
DNS method resolves a `TXT` record under a domain, and this browser already
resolves Handshake names from a chain proof, validates DNSSEC against an
on-chain DS, and has an oblivious DNS transport. It is the one client on the
network that could make `_atproto.<handshake-name>` mean something no stock
client can check, and it asks an AppView instead. The privacy cost is separate
and also real: every handle looked at is disclosed to one operator (SPEC
§10.4).

**Status: OPEN**, and it is the largest single gap in this chapter. Implement
the DNS `TXT` method against the browser's own validating resolver, fall back
to the well-known method, verify bidirectionally against `alsoKnownAs`, and
keep the AppView only as a last resort reported as unverified. See DI-D1.

---

### Experimental: identity anchors

The two deviations below are in the **experimental** part of this chapter
(SPEC §9): record formats that are shipped and signed by the browser's
keystore but are not a proposed standard and may change. They are separated
here so a reader does not weigh them against the stable resolution path.

### DI-10. Nothing enforces that an identity anchor's `epoch` moves forward

**What.** A claim receipt binds `(name, pubkey, epoch, created_at)` and
verifies for ever. A receipt for epoch 1 is still valid after the name has
moved to epoch 2. No component in this chapter, and nothing in the browser's
consumer of it, remembers the highest epoch it has seen for a name
(`src/record.js`, `src/receipt.js`).

**The standard says.** No cited standard governs this — the `_hns` record is
our own format (SPEC §9.1). The relevant expectation is the design's own: an
`epoch` field exists to make a key rotation legible, and a monotonic counter
that nothing enforces is not a counter.

**Why.** The defence was placed entirely on publication: the registry serves
one current record, DNSSEC-signed, under a Handshake name.

**Consequence.** A previous holder of a name keeps a permanently valid receipt
for their own epoch. Using it requires getting that record served, which needs
control of the zone — the thing they no longer have — so this is a
defence-in-depth gap rather than a live attack. But "the only thing stopping
rollback is that the zone is honest" is a weaker statement than the rest of
this design makes, and rollback is exactly what a DNS cache, a stale ODoH
answer or a compromised-then-recovered registry produces. Pinned by
`tests/identity-anchor.test.js` ("DI-10").

**Status: OPEN**, with a recommendation we hold loosely. The obvious fix — a
per-name highest-epoch memory that refuses anything lower — has three problems
set out in §2.4, and we are not confident it is right. What we are confident
of is that the resolver MUST report the epoch it accepted alongside the key, so
a caller that *does* have durable memory can apply a floor. Do that first; it
is unambiguous and it unblocks the rest.

---

### DI-11. `_nostr.<name>` is designed and not published

**What.** `record.js` and `keys.js` describe a sibling anchor,
`_nostr.<name>`, sharing the `_hns` schema and answering a different question —
who the name *is* on Nostr, as opposed to which key *controls* it. Nothing in
this chapter builds, publishes, parses or verifies it. `_hns` is the only
anchor the code implements end to end.

**The standard says.** NIP-05 specifies how a Nostr identifier is verified
against a domain (`/.well-known/nostr.json`), and this is not that. The
`_nostr` record is a second, DNS-side binding of our own design, intended to be
attested *by* the control key rather than by a well-known endpoint.

**Why.** Keeping the two records apart is what lets an owner hand a delegate
the control key for one domain without handing over their social identity. The
social half was deferred until the control half had shipped.

**Consequence.** A reader of `src/record.js` meets a record format that does
not exist yet, described in the present tense beside one that does. The
practical gap is that a Handshake name's Nostr identity currently has no
attested anchor at all: NIP-05 verification against `<name>.hns.one` is the
operator's word, exactly the thing `_hns` was built to stop being.

**Status: OPEN.** Either specify and publish `_nostr.<name>` with a receipt of
its own — the `hns:nostr:` `d`-tag prefix, by the same argument that makes
`hns:atproto:` non-interchangeable with `hns:` (SPEC §9.3) — or remove it from
the code's documentation until it is real. Half a format is worse than either.

---

## 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each is
a real decision that is currently shipping, and each could be wrong.

### 2.1. Whether "recognised, fail-closed" is a resting state

`at://` and `activitypub:` are *recognised and refused*. The refusal is
defensible: it is honest, it leaks nothing, and it is strictly better than the
cross-namespace hijack that created the category. But a refusal is not a
resolution, and there is a version of this argument where "we recognise it and
will not resolve it" is a way of never having to state a trust model.

We think the fail-closed contract (SPEC §8) is right, and we think the bar in
SPEC §10.5 is the right bar, and we are **not** sure those two things together
are not a well-documented way of not shipping. The counter-argument is the
`ens://` and `nostr:` precedent in this same browser: both moved from refused
to *resolved with the lock open*, on the principle that an unverified answer
clearly marked unverified beats no answer. We have not applied that principle
here and we cannot fully articulate why not, beyond that `at://`'s verification
path is genuinely reachable (SPEC §10.5) in a way that ENS's is not, so
shipping the unverified version first may make it permanent.

If you have shipped an `at://` resolver, we would like to know whether the
unverified stage was a stepping stone or a resting place.

### 2.2. Whether a DID document should be a *page* at all

`did:` is registered as a non-standard, non-secure scheme, so a resolved
document renders in an opaque origin with no storage, no service workers and no
`fetch`. That is a deliberately minimal posture for a document from a host a
stranger named, and we would defend it.

What we are not sure about is whether "navigate to a DID and look at the JSON"
is a feature, versus an artefact of the protocol-handler architecture making it
nearly free. The useful consumers of DID resolution in this product are
internal — find a PDS, check a binding — and they call the adapter directly
rather than going through the scheme. If the scheme exists mainly so that a DID
is a clickable link, it should render a *rendered* document — subject, keys,
services, and what was and was not checked — rather than raw JSON with wildcard
CORS headers (DI-1, DI-3).

### 2.3. Whether a bare atproto handle should be classified as an atproto address

A bare `@user@host` classifies to `activitypub`, and we think that is clearly
right: it is not a host, and the URL parser reads it as a credential. The same
question for AT Protocol is much less clear, because an atproto handle **is** a
domain name. `alice.bsky.social` is a real host serving a real website; so is
`alice.hns.one`. A classifier routing every domain-shaped input to `atproto`
would break the web; one routing none of them means a handle is never
addressable as a handle.

The honest answer is probably that a bare domain is a website and an atproto
handle needs a scheme — which is what happens today, by inheritance rather than
by decision. We would like it to be a decision, and we are not sure it is the
right one, because a user who types their friend's Bluesky handle gets a
website they did not want.

### 2.4. Whether a client-side epoch memory actually fixes DI-10

The obvious fix for identity-anchor rollback is: remember the highest epoch seen
per name, refuse anything lower. We are not confident that is right.

- It turns a **legitimate key rotation that resets or renumbers** into a
  permanent lockout, with no recovery path that is not "trust the registry
  again" — the thing the memory was protecting against.
- It is per-device, so the same user is protected on one machine and not
  another, and a fresh install has no memory at all, which is precisely the
  state an attacker would want to induce.
- It does not distinguish a rollback from a **transfer**, and a transfer *is* a
  legitimate change of both key and epoch. The `d`-tag replaceability semantics
  (newest claim per name wins) were chosen for transfers; an epoch floor argues
  with them.

What a monotonic counter wants is somewhere durable and shared to live, and the
only such place in this design is the chain — which knows the TLD and not the
SLD, which is the whole reason `_hns` is a mutual attestation in the first
place. This is the interesting problem in SPEC §9.

### 2.5. `did:web:<name>.hns.one` versus `did:plc`

SPEC §9.4 records the decision: a Handshake name's AT Protocol identity is a
`did:web` on the operator's ICANN subdomain, because that resolves for every
stock client and not only inside this browser. Both methods resolve here, and
the binding receipt is method-agnostic; the choice is only which is the
default, and the code commits to neither — the method is chosen by the
provisioning worker, outside this chapter.

We are not sure the decision is right, and it is **irreversible per account**:

- `did:web` is not portable off the domain. If the operator's infrastructure
  goes away, so does every identity anchored to it — a strange default for this
  project.
- `did:web` has no in-document key rotation. `did:plc`'s operation log does,
  and is what makes DI-2's verification possible at all; choosing `did:web`
  forecloses the strongest verification story available in this chapter.
- Against that: `did:plc` depends on `plc.directory`, which is *also* one
  operator, and one we do not run. Both are dependencies; only one is a
  dependency we can fix when it breaks.
- And it is not established that Bluesky's relay and AppView handle `did:web`
  accounts as well as `did:plc` at network scale.

The decision is recorded as made; the reasoning above is why we would not
object to it being remade.

### 2.6. What the AppView path should be *called*

DI-5 says handle resolution should not go through the AppView. Suppose it is
implemented properly and the AppView is kept as a fallback for when DNS and the
well-known both fail. What is that step's trust state?

"Unverified" (SPEC §4) is the mechanically correct answer and it is
unsatisfying, because it puts a query to a well-run public service in the same
bucket as a document from a host an attacker named. The Handshake chapter had
the same problem with its DoH fallback and answered it by naming *who* was
trusted rather than only *that* someone was. We have not done the equivalent
here, and we suspect a single "unverified" loses information a user would want.

### 2.7. Whether this chapter should exist yet

Stated plainly, because it is the honest uncertainty behind all the others: of
the four things this chapter names, one resolves with a real check but no proof
(`did:`), one resolves by proxy (atproto identity), and two are refused. A
chapter for a namespace that mostly refuses is a strange document.

We publish it anyway for two reasons. The fail-closed contract (SPEC §8) is a
real, reusable design rule that we think other clients get wrong, and it is
worth writing down independently of what is behind it. And the list above is
the actual state of the code, which is more useful to a reviewer than a
document that waits until the state is flattering.

### 2.8. Whether a labelled default PDS should exist at all

A PDS lookup that cannot resolve returns `{ pds: 'https://bsky.social',
assumed: true, reason }` (SPEC §6.2 rule 4). The AT Protocol DID specification
says an unresolvable DID is a resolution failure, full stop, and we keep a
default because the sign-in path is right for almost everyone and fails loudly
when it is wrong.

The label carries the weight: nothing can present the substitution as a
resolution without ignoring a field that says otherwise. What we cannot settle
is whether the default should exist at all. Against it: a value
labelled "assumed" is still a value, and the failure mode of a caller that
forgets to read one field is the failure mode we just fixed. For it: refusing
outright turns a momentarily unreachable directory into "you cannot log in",
for a network where one directory serves nearly every account.

We think the labelled default is right for a client and wrong for a resolver,
and this chapter is trying to be both.

---

## 3. Open design items

Work we think should be done, ranked by (security or correctness impact) ×
(how cheap the fix is), with the tie broken toward things that unblock other
things. This is opinion; §1 is description.

### DI-D1. Resolve AT Protocol handles locally, not through the AppView

`resolveHandle` asks Bluesky's public AppView for handle → DID, so the mapping
this browser is uniquely equipped to check itself is a third party's word
(DI-5). The DNS `TXT` method resolves a record under a domain, and this browser
already validates DNSSEC against an on-chain DS and has an oblivious transport
for the query.

**Recommendation.** Implement the DNS `TXT` method against the browser's own
validating resolver, fall back to `GET https://<handle>/.well-known/atproto-did`,
verify bidirectionally against the DID document's `alsoKnownAs`, and keep the
AppView only as a last resort, reported as unverified and distinguishable in
the returned value. Highest impact in this chapter.

### DI-D5. Verify the `did:plc` operation log

`GET https://plc.directory/<did>` and believe it (DI-2).

**Recommendation.** Fetch `GET /<did>/log/audit`, verify the operation chain to
the genesis operation — each operation signed by a rotation key valid at that
point, each carrying the previous operation's CID, the DID equal to the base32
of the truncated hash of the signed genesis operation — and check the served
document against the head. It is the only change in this list that would move a
step in SPEC §4 from **unverified** to **verified**, and it needs no
infrastructure, no operator and no chain. It is ranked here rather than first
only because it is genuinely a piece of work: signature verification over the
operation's DAG-CBOR encoding, rotation and recovery-window semantics, and a
cache so it is not re-fetched per navigation.

### DI-D6. Return a DID resolution result, not a bare document

The response is the document alone, as `application/json` (DI-3).

**Recommendation.** Wrap it as DID Core §7.1 specifies — `didDocument`,
`didResolutionMetadata`, `didDocumentMetadata` — and serve
`application/did+json`, putting the verification facts in the metadata. Do it
after DI-D5, because the value is not conformance for its own sake: the
envelope is where "resolved, and here is what was and was not checked" belongs.
Reconsider DI-1's wildcard CORS headers in the same change.

---

## 4. What this chapter leaves out

**1. The Electron layer.** Two things SPEC describes are engine-bound and are
not extracted:

- **Scheme registration and privileges** (SPEC §3.1, §8) — `did`, `at` and
  `activitypub` are declared non-standard, non-secure, `corsEnabled`, without
  service workers or `fetch`, in the browser's `src/main.cjs`. The *policy* is
  normative here; the declaration is Electron's API.
- **The `_hns` resolution policy** (SPEC §9.2) — the chain-first / DoH-labelled
  algorithm lives in the browser's `src/folders/index.js`, bound to its vault,
  its resolver instances and its dynamic-import wiring. It is specified
  normatively because it is the only security-relevant consumer of `record.js`,
  and a reader who takes the verifier without the policy has taken half of it.

**2. The write half of the anchors.** The browser's
`src/identity/identity-account.js` signs a binding receipt and posts it to the
registry with a NIP-98 header. The *receipt format* is specified (SPEC §9.3)
and extracted (`src/receipt.js`), because a reader verifies it. The endpoint,
the registry's checks and the zone write are the publish path, which this
specification puts out of scope everywhere.

**3. The published `_atproto` record and the `atproto-did` well-known.** Both
are produced by the operator's gateway, outside this tree, and — as SPEC §9.3
says out loud — neither is read by anything in this chapter. This chapter signs
the authorisation for an anchor it never verifies.

**4. The social surface.** `src/bsky.js` is extracted whole and only
`resolveHandle` and `resolvePds` are specified. Everything else in it —
sessions, timelines, posting, follows, likes — belongs to the client, not the
resolver. It is kept whole because byte-identity with the browser tree is worth
more than a tidy package (SPEC, *Layout*).

**5. What is done with the object once resolved.** Signing in to a PDS,
reading or writing a repository, rendering a feed. This chapter ends at "here
is the DID document / here is the PDS / here is the key".

**Dependencies.** This chapter adds exactly one runtime dependency beyond the
Node standard library and the shared modules of `../../src/`:
**`@noble/curves`**, for BIP-340 over secp256k1, reached through `src/keys.js`
and `src/nostr-event.js`. `src/did-protocol.js`, `src/unimplemented-protocol.js`,
`src/gate.js`, `src/bsky.js` and `src/xrpc.js` need nothing beyond `fetch`,
`Response`, `URL` and `AbortSignal` from the platform.
