# Chapter 6 — Nostr: deviations and open questions

Every place this chapter's implementation departs from a standard it cites,
from common Nostr client practice, or from its own stated design — plus every
place we are not sure we have made the right call.

The rule this file serves, inherited from the repository's consolidated
`../../DEVIATIONS.md`: **a deviation that is not written down is just a bug
nobody has found yet.** Some of these are deliberate and settled; some are
unfinished work. Each entry says which.

Section 1 is the deviations, numbered `NO-…`. Section 2 is the
honest-uncertainty list, called out separately because those are the ones we
most want challenged. Section 3 is the open design items — changes we think
are right and have not made. Section 4 is what this chapter deliberately
leaves out.

---

## 1. Deviations

### NO-1. A NIP-05 address is classified nowhere
*SPEC §3 · `../../src/router.js` `classify`, `../../src/classify-host.cjs`*

**What.** A bare NIP-19 identifier has a classifier row and is routed to this
namespace (SPEC §3). A pasted **NIP-05 address** does not: `alice@example.com`
carries a single `@`, and a scheme-less input with an `@` in it that is not the
canonical `@user@host` Fediverse form is a search. So the one Nostr address
form that looks like an email address is neither Nostr nor anything else.

**The standard says.** Nothing directly: neither NIP-05 nor NIP-21 specifies
how an address bar should behave. What makes this a deviation rather than a
missing feature is that the form is genuinely ambiguous — `alice@example.com`
is the NIP-05 shape *and* the Mastodon shape *and* an email address — and the
browser resolves it as both elsewhere while the address bar resolves it as
neither.

**Why.** The `@` rule exists for a real hazard: the URL constructor reads
everything before the last `@` as userinfo and silently drops it, so
`alice@example` typed as a host navigates to `example` with a stray credential.
Making every `@` a search is the safe direction. The cost is that the one
address form that would benefit from a lookup gets a search.

**Consequence.** Wildroot's `social-model.js` classifies the ambiguous form as
`fediverse-or-nip05` and resolves *both*, presenting whichever answers — so the
capability exists in the product and is unreachable from the address bar. It is
not a security problem: a search discloses the string to the search backend,
which is what a search always does, and no namespace is entered on a guess.
Pinned by `tests/classification.test.js` ("DOCUMENTED GAP (NO-1)").

**Status: OPEN.** The honest fix is not a classifier row — one input cannot
belong to two namespaces — but an omnibox that *offers* both resolutions as
suggestions and lets the user choose, which is where "I meant to look that up"
is answered for a bare word already. NO-D1 is the related work on the `nip05`
claim itself.

---

### NO-2. The `nip05` claim on a protocol page is displayed, but never looked up
*NIP-05 · `src/nostr-protocol.js` (`renderProfile`), `src/nip05.js`*

**What.** A profile page renders a kind:0's `nip05` field as *"claims
`<handle>` (not verified — the handle was not looked up)"*. The handle is
marked, honestly, as an unverified claim. It is not resolved: no
`.well-known/nostr.json` request is made from this page.

**The standard says.** NIP-05, "Showing just the domain as an identifier": a
client that displays a `nip05` field is expected to verify it against the
domain, and NIP-05 exists precisely to close the impersonation gap that an
unchecked handle leaves open.

**Why.** The lookup exists in the tree — it is what `src/nip05.js` factors out,
and the social page uses it correctly — but resolving a handle costs an HTTPS
request to a domain a *stranger* named, which is the SSRF surface SPEC §10.5 is
about. Shipping the marking first and the lookup second was the order that kept
the page honest at every step.

**Consequence.** Any key can display any handle. `satoshi@bitcoin.org` renders
the same whether or not bitcoin.org has ever heard of that key. The marking
means a careful reader is not misled, and it does not tell a reader what the
domain would have said.

**Status: OPEN.** Resolve the claim with `lookupNip05` (which already derives
the host from the identifier and refuses redirects) and render three states
rather than two: verified against the domain, contradicted by the domain, and
not reachable. The host validation the lookup needs is already in place, so
this is wiring rather than design. The concrete shape is NO-D1.

---

### NO-3. Relay selection is a bundled set plus the link author's hints; NIP-65 is never read
*NIP-65 · SPEC §8.2 · `src/relay.js` (`DEFAULT_RELAYS`)*

**What.** With no hints in the identifier, the resolver queries
`wss://social.hns.one`, `wss://relay.damus.io`, `wss://nos.lol` and
`wss://relay.nostr.band`. It never asks for the author's own kind:10002 relay
list.

**The standard says.** NIP-65 defines kind:10002 as the mechanism by which an
author announces where their events can be found, and says clients SHOULD
consult it when looking for a user's data.

**Why.** The bundled set works for the common case, because the large public
relays hold most of the network's events. Reading NIP-65 requires a *first*
query to find out where to send the *real* one, on relays chosen the same
arbitrary way, so it does not eliminate the bootstrap problem — it moves it.

**Consequence.** A key that publishes only to relays outside this set resolves
as empty. A key whose author has deliberately moved to their own relay is
invisible unless the link carries a hint. It also means **we** chose four
servers on the user's behalf, and every query discloses the user's interest to
all four (SPEC §10.3). A set of unreachable relays returns 502 rather than 404,
so "we asked and nobody had it" is at least distinguishable from "we could not
ask" — but "the four we chose did not have it" still reads as an empty key.

**Status: OPEN.** For a target that carries a pubkey, issue
`{kinds:[10002], authors:[pubkey]}` first, read the `r` tags, honour the
`read`/`write` markers, and query the union of that list with the current set,
each entry passing the same `isSafeRelayUrl` check a hint passes. Cache the
list for the navigation. The concrete shape is NO-D4.

---

### NO-4. BIP-173's 90-character limit is not enforced, and bech32 is implemented locally
*BIP-173 · `src/nip19.js`*

**What.** The decoder implements BIP-173 exactly — charset, HRP expansion,
polymod checksum, mixed-case prohibition, non-zero-padding rejection — with
the single exception of the 90-character length cap, which is not applied. The
implementation is local rather than a dependency.

**The standard says.** BIP-173, "Bech32": *"the string is at most 90
characters"*, and its error-detection proof is stated for strings within that
bound.

**Why.** NIP-19 identifiers routinely exceed 90 characters: an `nevent` with an
author and two relay hints does, an `naddr` with a long `d` tag comfortably
does. A limit-enforcing decoder rejects perfectly valid Nostr identifiers. The
two bech32 implementations already present in the browser's tree are both
transitive dependencies (they arrive under `hsd`) and both enforce the limit,
so neither can be used, and taking an undeclared transitive dependency breaks
the day that tree reshuffles.

**Consequence.** A pathological identifier can be arbitrarily long. BIP-173's
guarantee — at most 4 errors detected *within* 90 characters — does not hold
beyond it, so a longer identifier has a weaker (though still ~2⁻³⁰ against
random corruption) guarantee. The decoder is total and the payload is
length-checked per type, so a long string wastes work and does not do damage.

**Status: DELIBERATE.** Every Nostr implementation does this; enforcing the
limit would reject valid identifiers and interoperate with nobody. Pinned by a
test that builds an over-90-character `nevent` with an independent encoder.

---

### NO-5. `nostr://` is accepted although NIP-21 defines only `nostr:`
*NIP-21 · RFC 3986 · `src/nip19.js` (`parseNostrURI`)*

**What.** `nostr://npub1…` parses identically to `nostr:npub1…`, and a trailing
`/`, `?…` or `#…` is stripped.

**The standard says.** NIP-21: the URI is the scheme token followed *directly*
by a NIP-19 entity, with no authority component. In RFC 3986 terms `nostr:` is
a path and `nostr://` introduces an authority — two different productions.

**Why.** Chromium normalises a registered scheme's URL into the authority form
before the protocol handler sees it, and appends a path to a bare authority.
Refusing the shape would mean refusing requests our own browser generates.

**Consequence.** We accept a form NIP-21 does not define, which is lenient in
the direction that costs nothing: no valid identifier is rejected and no
invalid one is accepted, since the bech32 checksum still governs. A link
*written* as `nostr://` does not work in a client that reads NIP-21 strictly,
so this affects what we accept and must never affect what we emit.

**Status: DELIBERATE**, with the standing rule that anything this
implementation *generates* uses the bare `nostr:` form.

---

### NO-6. An `nsec` is refused by name, quoting it back to nobody
*NIP-21 · `src/nip19.js` (`decodeNip19`)*

**What.** An `nsec` is not treated as an unsupported prefix. It is matched
explicitly and refused with: *"that is a PRIVATE KEY (nsec). It was not sent
anywhere. Never paste it into a browser or share it."*

**The standard says.** NIP-21 excludes `nsec` from the URI scheme; a strict
reading is satisfied by "unknown prefix", and NIP-19 says nothing about error
text.

**Why.** The person who has just pasted their secret key into an address bar
needs to be told it is a secret, not that the browser lacks a handler. The
message is also a factual claim we are able to make: parsing happens before any
network access, and a test asserts nothing is dialled before the address
parses, so "it was not sent anywhere" is true.

**Consequence.** The error text names the string's *type*. It never echoes the
key. Anyone reading over the user's shoulder learns that a secret was pasted,
which is a disclosure we accept as strictly better than the alternative. The
claim holds on both paths a secret can arrive on: a bare `nsec` typed into the
address bar is classified into this namespace on its prefix, before any name
rule sees it (SPEC §3), so it reaches this refusal rather than a resolver.

**Status: DELIBERATE.** The wording is the feature and a test pins both halves
of it.

---

### NO-7. No NIP-42 AUTH: a relay that wants sign-in is a relay that answered nothing
*NIP-42 · `src/relay.js`*

**What.** `AUTH` frames are ignored — they fall into the "not our subscription
id" branch. A relay that requires authentication before serving reads
contributes zero events, and the relay report shows it as having answered with
nothing rather than as having demanded something.

**The standard says.** NIP-42 defines the `AUTH` challenge/response by which a
relay may require a client to prove control of a key before serving it.

**Why.** Not implementing the handshake is deliberate: the resolver holds no
key. `nostr:` resolution is anonymous by construction, and authenticating would
mean either using the user's identity — turning a page load into an identified
request — or minting a throwaway key, which most auth-gated relays exist to
prevent. What is *not* deliberate is the silence: the condition is
distinguishable on the wire and is not reported.

**Consequence.** Paid and members-only relays are unusable from `nostr:`, and
the user cannot tell *why*. Wildroot's social client, which does hold a key,
distinguishes this case ("wants sign-in") in `relayHealth`; the resolver does
not.

**Status: OPEN** on the reporting half. Recognise an `AUTH` frame for our
subscription and finish the query with an error string naming the condition —
"relay requires sign-in" — so the relay report says why the relay contributed
nothing. The anonymity property is unaffected: nothing is signed and no key is
held. Answering the challenge stays out of scope.

---

### NO-8. Fixed result limits, no pagination, no time window
*NIP-01 · `src/nostr-protocol.js` (`renderProfile`, `renderNote`, `renderAddressable`)*

**What.** A profile fetches at most 5 kind:0 events and 20 kind:1 events; a
note or addressable lookup fetches 1. `since`, `until` and any form of paging
are unimplemented, and a caller-supplied `limit` inside a filter is overwritten
by the option.

**The standard says.** NIP-01 defines `limit`, `since` and `until` as filter
fields a client may use, and describes `limit` as applying to the initial
query.

**Why.** A resolver returns *an answer*, not a feed. Paging belongs to a
client, and this chapter specifies a resolver (SPEC §1.1).

**Consequence.** "20 verified notes" is 20 notes out of an unknown number, and
the heading says "verified", which is true, rather than "all", which would not
be. There is no way to see the 21st. For a prolific author the page is a
window, not an archive.

**Status: DELIBERATE** for a resolver. A client built on this chapter needs its
own paging, and inherits `matchesFilter` for free when it adds `since`/`until`
to a query.

---

### NO-9. Three independent NIP-01 implementations, and a trust header nobody reads
*`src/event.js`; in the browser, `src/nostr/nostr-event.js`, `src/identity/nostr-event.js`, `src/hns/trust-path.js`*

**What.** The Wildroot tree contains three separate implementations of the
NIP-01 serialisation and signature check: this one (verifies, on
`node:crypto`), the identity keystore's (signs, on `node:crypto`), and a
vendored copy of a standalone package (both, on `@noble/hashes`). They are held
in agreement by a cross-verification test and a hash manifest.

Separately, every response carries `X-Nostr-Trust: signature-verified;
completeness-unverified` and `X-Nostr-Pubkey`, described in a comment as
"machine-readable for the lock UI". **Nothing reads either header.** The trust
panel's Nostr arm exists and is correct, and it derives its two steps from the
URL's *scheme*, not from the header the page emitted.

**The standard says.** Nothing — no NIP governs either half. The rule broken is
the ordinary one about a single source of truth, and about a comment that
describes a thing that does not happen.

**Why.** The three copies have real causes: `electron-builder` packages one
directory, so a cross-repo import resolves in a dev checkout and is absent from
the installed app; and the keystore's copy signs while this one only verifies.
The header is a wiring step that stopped one file short of its reader.

**Consequence.** A fix to the serialisation must be made three times, and the
drift test tells you when you forgot rather than preventing it. The header is
harmless and inert: because the panel's arm is keyed on the scheme, a page that
somehow reached the panel *without* verifying anything would still be described
as verified — the panel is stating the handler's contract, not observing its
output.

**Status: OPEN** on both halves. For the header: have the trust panel read
`X-Nostr-Trust` where the response is available to it, so the claim is the
page's own rather than the scheme's, or delete the header and the comment that
oversells it. For the implementations: one module that both signs and verifies,
vendored once, with the drift test kept as a guard rather than as the
mechanism. The concrete shapes are NO-D5 and NO-D6.

---

### NO-10. The canonical serialisation is delegated to the host's `JSON.stringify`
*NIP-01 · RFC 8259 · `src/event.js` (`eventId`)*

**What.** NIP-01 specifies the event-id serialisation exactly, including which
characters are escaped. The implementation builds the array and calls
`JSON.stringify` on it, relying on the host to produce that byte string.

**The standard says.** NIP-01: the id is the SHA-256 of the UTF-8 serialisation
of `[0, pubkey, created_at, kind, tags, content]` with no whitespace, escaping
`"`, `\`, `\n`, `\r`, `\t`, `\b`, `\f` and nothing else.

**Why.** NIP-01's own text says the serialisation *is* the JSON of that array,
and every implementation in the ecosystem does this. Hand-rolling it would be
three copies of an escaping table (NO-9) rather than one.

**Consequence.** It is an assumption about the runtime, not a check. It holds
in V8 for the cases that matter, including well-formed-`JSON.stringify`
behaviour for lone surrogates and literal U+2028/U+2029 in strings, and it is
pinned by a cross-implementation test whose fixture deliberately contains
quotes, a backslash, a newline, non-ASCII, an astral character and U+2028. It
has never been tested against a *non-V8* JSON implementation, and a runtime
that escaped differently would compute different ids and reject valid events —
failing closed, which is the right direction, and confusingly.

**Status: DELIBERATE**, with the assumption stated rather than hidden.

---

### NO-11. The `_nostr` DNS record is designed and documented but not published
*In the browser, `docs/RESOLUTION-ROUTER.md`, `docs/Protocols.md`, `src/identity/record.js` — not in this chapter*

**What.** The Wildroot design has a Handshake name's zone bind the name to a
Nostr key with a `_nostr.<name>` TXT record, attested by the name's control
key. Three design documents describe it and the record parser exists. The live
zone contains `_hns` records and **no** `_nostr` records.

**The standard says.** Nothing — no NIP and no RFC governs this. It is our own
design, and the deviation is from our own documents, which describe the binding
in the present tense.

**Why.** Unfinished work, not a decision.

**Consequence.** The Handshake→Nostr binding that would make a name→key mapping
*chain-proven* rather than WebPKI-asserted does not exist in practice. The only
name→key mapping that works today is NIP-05, with the trust properties of SPEC
§7.3. Any document that describes the `_nostr` binding in the present tense is
describing a design, not a deployment.

**Status: OPEN.** Publish the record for the names that already have a Nostr
key, and read it on the Handshake path so a name resolves to a key through the
chain proof and the DNSSEC chain anchored to the on-chain DS. This is the
single most valuable thing this namespace could gain: it is the one available
route to a Nostr identity mapping that is not somebody's word. Until it exists,
every document describes it in the future tense — this one does. The concrete
shape is NO-D3.

---

### NO-12. On a `.hns.one` NIP-05 address the Handshake guarantees do not apply to the lookup
*SPEC §7.3 · `src/nip05.js`*

**What.** `_@alice.w3.hns.one` is verified by fetching
`https://alice.w3.hns.one/.well-known/nostr.json?name=_` with the platform
`fetch`. That request goes through the host's own resolver and WebPKI. It does
**not** go through the chain-proof, DNSSEC-to-on-chain-DS, DANE-pinned path
that the Handshake chapter of this specification defines for `hns://`.

**The standard says.** NIP-05 requires an HTTPS GET and forbids following
redirects; it says nothing about which resolver or which trust anchor. The
deviation is from *our own* stronger path, not from NIP-05.

**Why.** It is deliberate that the address be *ordinarily* resolvable — the
point of `_@<name>.hns.one` is that a client with no Handshake support can
verify it. What is not deliberate is that our own browser, which has the
stronger path available, does not use it.

**Consequence.** A NIP-05 verification performed inside Wildroot is exactly as
strong as one performed inside any other client, and no stronger. A reader who
knows the Handshake chapter may reasonably assume otherwise, which is the only
reason this is a deviation and not a footnote.

**Status: OPEN.** Route the well-known fetch for a `.hns.one` name through the
`hns://` path, so the hop is DANE-pinned and chain-anchored, while keeping the
address ordinarily resolvable for every other client — the cost is that our own
client no longer exercises the same code path everyone else does, which is a
real loss of "we test what they test" and is why this is worth arguing about
rather than simply doing.

---

### NO-14. The `nsec` arm is claimed on its prefix, not on its checksum
*SPEC §3, §5.3 · `../../src/router.js` `classify`*

**What.** The five public prefixes are claimed only when `decodeNip19`
succeeds. `nsec` is claimed whenever the input matches `nsec1` followed by six
or more bech32 characters, decode or no decode — because its decode is
*designed* to fail (§5.3). So `nsec1qqqqqq`, which is not a valid identifier,
is routed to this namespace and met with the PRIVATE KEY refusal, and a
Handshake name of that shape can never be reached.

**The standard says.** Nothing. NIP-21 excludes `nsec` from the URI scheme,
which is consistent with refusing it rather than resolving it.

**Why.** The alternative is worse in the only direction that matters. A
checksum-gated `nsec` arm would release a mistyped or truncated secret key to
the bare-label rule, which transmits it to a chain node or a DoH resolver *as a
name*. A mistyped secret is exactly the case where the refusal is most needed.

**Consequence.** A narrow range of the Handshake namespace — names beginning
`nsec1` with a bech32 tail — is unreachable from the address bar. We know of no
such registration, and it can still be reached with an explicit `hns://`, which
is what L1 is for. The trade is a deliberate one: an unreachable name is
recoverable, a disclosed secret is not.

**Status: DELIBERATE.** An implementation **MAY** narrow the arm to
prefix + valid bech32 *charset* (which is what is implemented) and **MUST NOT**
narrow it to a valid checksum.

---

## 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each
is a real decision that is currently shipping, and each could be wrong.

### 2.1. Whether a lock can ever close for Nostr — and whether a padlock is the right instrument

Our position (SPEC §4.1) is that completeness is permanently `unverified`,
therefore the aggregate is permanently `partial`, therefore a Nostr page never
gets a closed green lock however much verification happened. We think that is
right and we are aware it produces a strange result: the namespace with the
*strongest* per-object guarantee in the browser — every byte displayed is
signature-checked in-process, which is more than `https://` can say — presents
with an indicator weaker than the one an ordinary web page gets.

The alternative would be a fourth aggregate state meaning "the object is
proven, the answer set is not", which is honest and is one more thing a user
has to learn.

What we are unsure of: whether the right conclusion is instead that a padlock
is simply the wrong instrument for a namespace like this, and that the relay
report should be the primary surface with no lock at all.

### 2.2. What "the right event" means, once the answer is bound to the query

Binding the answer to the filter closes substitution. It does not close
**currency**, and we do not think anything can.

For a replaceable event — kind:0 profile metadata, kind:3, kind:10002 — the
"right" answer is the newest one its author signed, and a relay can serve an
older one that matches the filter and verifies perfectly. There is no signed
sequence number, no chain, no proof that a newer one does not exist. Ordering
by `created_at` is ordering by a number the author chose, so an author who
backdates — or a relay that only holds a backdated copy — wins. A profile shown
here may be a year stale and correct-looking.

We do not know what to do about this beyond saying it. "You are seeing the
newest of N relays' answers, here are the N" is what we have. If there is prior
art on freshness in a system with no root, we have not found it.

### 2.3. Whether NIP-05 belongs in a resolution specification at all

NIP-05 is the only name→key mapping most Nostr users ever use, so leaving it
out would make this chapter useless. But it is not cryptographic, it is WebPKI
with extra steps, and putting it in a document that also specifies BIP-340
signature verification risks the reader averaging the two.

We try to solve this by stating SPEC §7.3 as bluntly as we can. We are not sure
that is enough, and we are not sure a specification is even the right place for
the warning — the place a user meets the claim is the interface, not the spec.
A related worry: NIP-05's own text says the mapping is not an identity proof,
and essentially every client in the ecosystem renders it as a blue tick anyway.

### 2.4. The default relay list is a decision we made for the user

Four relays, chosen by us, one of them ours. Every `nostr:` navigation
discloses the target key to all four, from the user's address, and the answer
the user sees is bounded by what those four hold.

We think a default is unavoidable — an empty relay set resolves nothing, and
asking a user to configure relays before their first link works is not a
product. We are much less comfortable that the list is a constant in a source
file rather than something the user can see and change, and least comfortable
that ours is first in it. A relay operated by the party shipping the browser,
queried on every navigation, is a log of what the user looked at. We do not
keep such a log; the correct answer is not "trust us" but "you can see this and
change it", and that surface does not exist.

Reading NIP-65 (NO-3) reduces but does not remove this: the bootstrap query
still goes somewhere chosen by us.

### 2.5. Whether `nostr:` should be a standard scheme

`nostr:` is registered with **low** privileges in Electron: no origin, no
`fetch`, no service workers, no secure context. `hns:` is registered as
standard, which is what makes a Handshake site a real web origin and is also
what drags in the URL Standard's IPv4 host rule.

Low privileges are right for what the handler does: it renders a static
document with no script. If a Nostr *client* ever lived at `nostr:` it would
need an origin, and then a key becomes an origin — a genuinely interesting
question, since 32 bytes of x-only pubkey is a far better origin than a
hostname in that it cannot be transferred or seized, and one we have not
thought through. Storage keyed by an npub would be a real thing to have. It
would also mean a page's origin changes when it is the same author under a
different identifier form (`npub` vs `nprofile`), which is exactly the kind of
detail that turns into a security bug.

### 2.6. Whether a bare `npub` should navigate

It does, and the rule that decides it is explicit and tested (SPEC §3). What we
are still not certain of is the collision itself: Handshake's bare-label rule
claims the same input space (most Handshake sites are bare TLDs), and we
settled it with the bech32 checksum — a 30-bit checksum over a fixed
human-readable part, which we think is not thin evidence for a namespace claim.

The residue is the `nsec` arm, which does *not* have that evidence: it is
claimed on the prefix alone, so it takes a small range of the Handshake
namespace with it (NO-14). We are confident that is the right trade for a
secret key and we would rather it were argued with than assumed.

### 2.7. What we should be doing about relay disclosure

The Handshake chapter has an answer for the equivalent problem: Oblivious DoH,
where the resolver learns the query and not who asked. Nostr has no analogue. A
relay learns the key you asked about and your address, and the fan-out that
makes answers better makes the disclosure wider.

We do not have a design. Querying through a proxy moves the disclosure rather
than removing it. Asking every relay for a superset and filtering locally is
the classic answer and is prohibitively expensive here. Today we handle it by
refusing to run at all when IP protection is on, which is honest and is not a
solution.

### 2.8. Whether a refused relay hint should be silent

A hint that fails `isSafeRelayUrl` is listed in the relay report with its URL
and the reason. That is the honest choice and it also prints an
attacker-supplied string — escaped, on a page with no script source — onto the
user's screen, which is a small phishing surface: a link author can put text of
their choosing in the report by encoding it as a relay hint. We think naming
the refusal beats hiding it, and we are not certain the trade is right.

---

## 3. Open design items

Changes we think are correct and have not made. Each names the deviation it
closes.

### NO-D1. Resolve the `nip05` claim, or say the domain was unreachable

**Problem.** The profile page marks a `nip05` field as an unverified claim
(NO-2) and never asks the domain. `lookupNip05` in `src/nip05.js` already does
the request correctly — the host is derived from the identifier, redirects are
refused, the local part is checked against NIP-05's grammar — and the profile
renderer does not call it.

**Recommendation.** Call it, with the injected `fetchImpl` so the request rides
the same proxied session fetch the rest of the browser uses, and render three
outcomes instead of one: the domain names this key (a fact about the domain,
still `unverified` in the trust model and still labelled with the domain's
name); the domain names a *different* key or none (a contradiction, which is
worth saying loudly); the domain could not be asked. Bound it with the same
deadline the relay query uses, and never let a slow domain hold the page.

### NO-D3. Publish the `_nostr` record, or stop documenting it

**Problem.** Three design documents and a record parser describe a
`_nostr.<name>` TXT record binding a Handshake name to a Nostr key. The live
zone has none (NO-11).

**Recommendation.** Publish it for the names that already carry a Nostr key,
and read it on the Handshake path. This is worth doing rather than deleting
because it is the only available route to a Nostr name→key mapping that is not
somebody's word: NIP-05 is WebPKI, while a `_nostr` TXT record in a
DNSSEC-signed zone anchored to the on-chain DS is chain-proven, using the entire
apparatus the Handshake chapter already specifies and tests. It would make this
the only client that can say "this key is this name" and mean it
cryptographically.

### NO-D4. Read NIP-65 relay lists

**Problem.** Relay selection is four relays we chose plus whatever the link
author chose, so an author who has moved to their own relay is unreachable
(NO-3).

**Recommendation.** For a target that carries a pubkey (`npub`, `nprofile`,
`naddr`, and `nevent` with an author), issue `{kinds:[10002], authors:[pubkey]}`
first, read the `r` tags, honour the `read`/`write` markers, and query the union
of that with the current set — each URL through `isSafeRelayUrl` and
`normalizeRelayUrl`, and under the same bound hints get, because a kind:10002
is also a stranger's choice of who this browser talks to. Cache the list for
the navigation. It does not remove the bootstrap problem — the kind:10002 query
goes to relays chosen the same arbitrary way — and it is still worth it.

### NO-D5. Read `X-Nostr-Trust`, or delete it

**Problem.** The response header is emitted with a comment calling it
"machine-readable for the lock UI", and nothing reads it. The trust panel's
Nostr arm derives its steps from the scheme instead (NO-9).

**Recommendation.** Either give the panel the response's headers where the
navigation makes them available, so the two steps it shows are the ones the
handler actually performed rather than the ones the scheme promises — which
also makes the arm degrade correctly if the handler ever changes — or delete
both headers and the comment. The current state is a comment describing a wire
that was never connected, which is the kind of thing a reader believes.

### NO-D6. Collapse the three NIP-01 implementations

**Problem.** Three implementations of one serialisation and one signature
check, held in agreement by a cross-verification test and a hash manifest
(NO-9). A fix must be made three times.

**Recommendation.** One module in the tree that both signs and verifies,
vendored once, with the drift test kept as a guard rather than as the
mechanism. The causes are real — `electron-builder` packages one directory, and
the keystore's copy signs while the protocol's only verifies — so this is a
design task rather than an edit, and the design constraint to solve is
packaging, not cryptography.

Two changes that look like improvements and are not, recorded so they are not
re-proposed: **enforcing BIP-173's 90-character limit**, which would reject
valid NIP-19 identifiers (NO-4 is deliberate and every implementation agrees);
and **closing the lock when a signature verifies**, which would be the precise
misrepresentation SPEC §4.1 and §10.2 exist to prevent — authorship is proven
per event, completeness never is, and with the answer bound to the query as
well the temptation is stronger and the answer is still no.

---

## 4. What this chapter leaves out

1. **The social client.** `src/social.js`, `src/nostr/relay-pool.js`,
   `src/nostr/social-core.js`, `src/pages/social/` and the identity keystore in
   the Wildroot tree are a Nostr *client*: publishing, follow lists, reposts,
   threads, reactions, key custody. None of it is extracted. Two pure functions
   from `social-core.js` (`verificationHost`, `nip05For`/`displayName`) are
   reproduced verbatim inside `src/nip05.js` because they are the NIP-05
   resolution rules and nothing else; that file's header says exactly which
   lines came from where.

2. **The NIP-05 fetch, as it exists in the browser.** There it is a branch of a
   `switch` inside an Electron IPC handler (`src/social.js`, `case 'verify':`).
   There is no function to import, so `lookupNip05` in `src/nip05.js` is that
   branch lifted into one, generalised from the hardcoded `_` local part, with
   `fetch` made injectable so it can be tested without a network. **It is the
   only module here that is not byte-identical to shipping code**, and it is
   labelled as such at the top.

3. **The trust panel and the browser chrome.** `schemeSteps()` in the browser's
   `src/hns/trust-path.js` carries the Nostr arm SPEC §4.1 describes. It is the
   browser's UI, not a resolver, and is specified here as a model rather than
   extracted.

4. **Electron.** Nothing here imports it. `src/nostr-protocol.js` uses only the
   global `Response`, and `src/relay.js` takes its WebSocket implementation
   from an injected seam or the global — so the handler runs, and is tested,
   under plain `node --test`. The one Electron-shaped thing it is missing is
   the IP-protection gate (`createNonProxiedGate`, SPEC §10.3), which wraps the
   handler at registration time in the browser and is a composition concern.

5. **Everything the fan-out is not.** No caching, no connection reuse, no
   subscription that stays open, no streaming. A resolution opens sockets, asks
   once, and closes. That is a resolver's shape and it would be the wrong shape
   for a client.
