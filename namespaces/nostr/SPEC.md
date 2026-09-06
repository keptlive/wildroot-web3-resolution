# Chapter 6 — Nostr

**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in
`namespaces/nostr/src/`, which ships in the Wildroot browser. Not endorsed by
any standards body, and emphatically not by the NIPs repository. Normative
statements describe what an implementation must do *to interoperate with this
one*; where a rule is inherited from a NIP or an RFC, that document is cited
and its text governs.
**Licence:** CC-BY-4.0 (`../../LICENSE-SPEC`). The reference implementation is
licensed separately (Apache-2.0, `../../LICENSE`).

This chapter is part of the integrated specification whose spine is
[`../../SPEC.md`](../../SPEC.md), and namespace selection — which input reaches
which chapter — is specified there.

The spine's house rules apply here unchanged: its four trust states, its
namespace-selection rule, its fail-closed requirement. This chapter says what
they mean for Nostr, which is a different kind of naming system: it has no
chain, no zone, no delegation and no authoritative server, and the honest
answer it produces is weaker than a Handshake one in a way this chapter is
written to make impossible to miss.

Every deviation from a cited standard, and every question we are unsure of, is
in [`../../DEVIATIONS.md`](../../DEVIATIONS.md) under the `NO-` prefix. Every
standard cited is listed with its purpose in `REFERENCES.md`. **Both are part
of this specification, not appendices to it.**

---

## Contents

1. [What this specifies, and why](#1-what-this-specifies-and-why) — including [**scope**](#11-scope)
2. [Terminology](#2-terminology)
3. [Namespace selection](#3-namespace-selection)
4. [Trust states](#4-trust-states)
5. [Identifiers: NIP-19 and the `nostr:` URI](#5-identifiers-nip-19-and-the-nostr-uri)
6. [Event verification](#6-event-verification)
7. [NIP-05: a name to a key](#7-nip-05-a-name-to-a-key)
8. [Relay selection and the query](#8-relay-selection-and-the-query)
9. [The resolution algorithm](#9-the-resolution-algorithm)
10. [Security considerations](#10-security-considerations)

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## 1. What this specifies, and why

Nostr has no names. It has **keys** — a 32-byte secp256k1 x-only public key is
the whole of an identity — and **relays**, which are dumb stores that anyone
can run and nobody is required to be honest. The interesting thing about the
design, and the reason it belongs in a document about resolution, is that this
combination gives a client an unusually clean guarantee and an unusually bad
one at the same time:

- **Unusually clean:** every object is self-authenticating. An event carries
  its author's public key and a BIP-340 signature over an id which is a hash of
  the event's own contents. A client that recomputes the id and checks the
  signature — *locally, in its own process* — needs to trust nothing about
  where the bytes came from. A relay that alters one byte produces an id that
  no longer matches. A relay that invents an event cannot sign it.

- **Unusually bad:** nothing whatsoever is proven about *completeness* or
  *currency*. A relay can withhold. A relay can answer a question with an
  event other than the one asked for — which the client can and must catch by
  matching the answer against the question (§9.3), because the signature never
  will. The set of relays a client asks is a guess. There is no root, no
  quorum, no proof of absence, and — this is the part that has no fix — **no
  way to establish that you were shown everything, or the newest thing.** A
  profile you are reading may have been replaced an hour ago on a relay you did
  not ask.

This chapter specifies what a client may therefore conclude. Its thesis is
one sentence: **the protocol proves authorship, and everything about the
*answer* is the client's own work.** The distinction is not pedantry. A green
tick that means "this event is genuinely signed by *somebody*", placed next to
a page headed "the note you asked for", is a lie by adjacency unless the client
has itself established that the event is the one asked for. §9.3 is how that is
established and §10.2 is the rule for showing it.

It also specifies the two mappings that turn something a human can type into a
key: **NIP-19** bech32 identifiers (`npub1…`, `note1…`, `nprofile1…`,
`nevent1…`, `naddr1…`) carried in a **NIP-21** `nostr:` URI, and **NIP-05**
`<local>@<domain>` addresses resolved over ordinary HTTPS. The second of those
is not cryptographic at all, and §7 says so at length, because a name→key
mapping that rests on WebPKI is the weakest link in every Nostr client and is
routinely presented as if it were a verification.

### 1.1 Scope

**In scope: turning a Nostr identifier into a verified event, and stating the
trust.** Precisely: how

- a NIP-21 `nostr:` URI or a bare NIP-19 identifier, or
- a NIP-05 `<local>@<domain>` address

becomes one of

- a **key** (32 bytes of x-only secp256k1 public key),
- an **event** whose id and signature were checked in this process,
- a **profile** (a kind:0 event, parsed), or
- a **failure**, distinguished by kind (§9.4),

together with the **trust state** that says which parts of that answer were
proven and which were taken on somebody's word (§4).

**Out of scope, explicitly.** Everything a *social client* does. The Wildroot
browser contains one — `src/social.js`, `src/nostr/`, `src/pages/social/` — and
it is not specified here and not extracted into `src/`:

| Out of scope | Why it is a different document |
|---|---|
| **Publishing** — signing, `["EVENT", …]`, `OK` handling, what counts as a successful post | The read path and the write path have different threat models. The one publishing rule that touches resolution is stated in §8.4 as a warning, not a specification. |
| **Feeds and the social graph** — NIP-02 follow lists, NIP-18 reposts, threading, reactions | These are applications built on resolved events. They consume this specification's output. |
| **Key custody** — how a `nsec` is stored, derived or unlocked | §5.3 says only what a *resolver* must do when handed one: refuse, loudly. |
| **NIP-98 HTTP auth** | Used in Wildroot to authenticate requests to our own panel with a name's control key. It is an authorization scheme, not a resolution mechanism, and no part of the `nostr:` path touches it. |
| **The user interface** | §4 specifies the model an interface must be given and the claims it must not make. It does not specify a rendering. |
| **Nostr itself** — relay operation, spam control, NIP process | Cited (`REFERENCES.md`), not restated. |

A consequence worth stating plainly: an implementation of this specification is
a **resolver**, not a Nostr client. It answers "what does this identifier
name, and how sure are we?" and stops there.

---

## 2. Terminology

Nostr terms are used as defined in **NIP-01**: *event*, *event id*, *kind*,
*tag*, *filter*, *subscription*, *relay*, *EOSE*, *replaceable event*,
*addressable event*. Where this chapter uses one of those words it means what
NIP-01 says it means.

Terms specific to this chapter:

- **Identifier** — the thing a user has: a NIP-19 bech32 string, optionally
  wrapped in a `nostr:` URI (NIP-21), or a NIP-05 address.
- **Target** — what an identifier decodes to before any network access: a
  key, an event id, or an addressable-event coordinate (kind, author, `d`
  tag), plus zero or more **relay hints**.
- **Relay hint** — a relay URL carried *inside* an identifier (NIP-19 TLV type
  1) or *inside* a NIP-05 document. In both cases it is chosen by whoever
  wrote the identifier, who is not the user. §10.4.
- **Answer** — the event or events a relay returns for a query.
- **Authorship** — the property that an event was signed by the key it names.
  This is the only thing Nostr proves, and it is proven per *event*.
- **Answer binding** — the property that a returned event is the one the query
  asked for. This is **not** implied by authorship, is not provided by any NIP,
  and is enforced by the client. See §9.3.
- **Completeness** — the property that the events returned are all the events
  that exist matching the query. **Nostr cannot provide this** (§10.1).
- **Currency** — the property that a replaceable event returned is the newest
  one its author signed. **Nostr cannot provide this either** (§10.1).

---

## 3. Namespace selection

Nostr is a namespace in the sense of the spine's `../../SPEC.md` §3
and `docs/RESOLUTION-ROUTER.md`: a distinct address space with its own root of
trust (a public key). The two structural rules apply unchanged.

**L1 — an explicit scheme selects the namespace.** An input beginning `nostr:`
**MUST** be routed to a Nostr resolver and **MUST NOT** be re-inspected,
"improved", or re-classified by any host heuristic. In the reference
implementation this is `classify()` in `../../src/router.js`, which returns
`{ explicit: true }` the moment a scheme is present, and the Electron
`session.protocol.handle('nostr', …)` binding, which dispatches by scheme and
nothing else.

**L2 — a failure never crosses the boundary.** A `nostr:` identifier that does
not decode, or that no relay can answer, **MUST** fail as a Nostr failure. It
**MUST NOT** become a DNS lookup, a Handshake lookup, or a search. There is no
"try Nostr, then fall back". This is the rule of RFC 9498 §9.10, adopted
repository-wide.

**What is *not* a Nostr identifier.** Two boundaries are easy to get wrong and
are drawn here explicitly:

1. **A Handshake name that publishes a Nostr key is a Handshake name.** The
   Wildroot design has a name's zone answer for its owner's Nostr identity — a
   `_nostr.<name>` TXT record, and the NIP-05 document at
   `<name>.hns.one/.well-known/nostr.json`. Such a name classifies as `hns`
   and is resolved by the Handshake section of this repository. Handshake
   authenticates the *mapping*; Nostr authenticates the *object*. They are two
   layers, not two candidates. (The `_nostr` TXT record is designed and
   documented; it is **not published** — NO-11.)

2. **A NIP-05 address is not a domain.** `alice@example.com` shares its shape
   with a Mastodon address and with an email address. An implementation
   **MUST NOT** guess. Wildroot's `social-model.js` classifies the ambiguous
   form as `fediverse-or-nip05` and resolves *both*, presenting whichever
   answers; the omnibox classifier has no row for it at all and treats it as
   neither (NO-1).

**A bare NIP-19 identifier SHOULD be classified as Nostr.** `npub1…`,
`note1…`, `nprofile1…`, `nevent1…` and `naddr1…` are self-describing: the
human-readable part *is* the type, and a bech32 checksum makes a false positive
a 1-in-2³⁰ event. The reference implementation's decoder accepts a bare
identifier (§5.2) but its omnibox classifier does not route one — a pasted
`npub1…` is a single label with no dot, so it goes to the Handshake chain as a
name. **We do not meet our own SHOULD here.** See NO-1.

---

## 4. Trust states

The four states of the spine's `../../SPEC.md` §4 apply verbatim:

| State | Meaning |
|---|---|
| `verified` | checked cryptographically, in this process, in this resolution |
| `unverified` | taken on somebody's word — a relay, a CA, a domain operator |
| `failed` | checked and did not pass |
| `none` | does not apply, or is absent and *known* to be absent |

A Nostr resolution produces these steps, in order:

1. **Address** — `verified` when the identifier's bech32 checksum and TLV
   structure decoded. This is an integrity check on the string, not on
   anything it names; an implementation **MUST NOT** present it as more.
2. **Authorship** — `verified` when the event's id was recomputed from its own
   contents and its BIP-340 signature checked against the pubkey it names
   (§6). `failed` for any event that does not pass — and a `failed` event
   **MUST NOT** be displayed at all (§6.3).
3. **Answer** — whether the returned event is the one the identifier named
   (§9.3). `verified` when the event matches every field of the filter it was
   returned for; an event that does not is discarded and reported, never
   rendered.
4. **Completeness** — always `unverified`, and an implementation **MUST NOT**
   ever report it otherwise. §10.1.
5. **Name** — present only when the resolution began from a NIP-05 address, or
   when a resolved profile carries a `nip05` field. Always `unverified`; the
   step **MUST** name the domain that asserted it, or say that the domain was
   never asked (§7).

### 4.1 Aggregating to a lock

**A Nostr resolution MUST NOT produce a closed lock.** Step 4 is permanently
`unverified` and no amount of verification elsewhere retires it, so the
aggregate of the spine's §4.1 is `partial` — never `verified` — always, by
construction rather than by policy.

An implementation **MUST** additionally state, in whatever surface it gives
the user, *which relays answered and which did not*, and *which relays it
refused to ask*. This is the substitute for a proof of completeness: it cannot
establish what you were not shown, but it can name who you asked. The reference
implementation renders it as a collapsible "Where this came from" report on
every page, including error pages, listing each relay, whether it was reached,
its event count or its error, every relay hint that was refused and why, and
every event that was discarded — as unverifiable, or as not an answer — and
why.

**In the reference implementation the trust panel carries this as two steps.**
`schemeSteps()` in the browser's `src/hns/trust-path.js` gives a `nostr:` page
**Authorship — `verified`** ("Schnorr signature (BIP-340) checked in this
browser") and **Completeness — `unverified`** ("whichever relays answered"),
and the aggregate of a `verified` step and an `unverified` one is `partial`:
a neutral indicator, never green. That is the whole trust story on one surface,
and it is the shape the rest of this chapter is about.

Two things are worth naming about how it is derived. The panel keys its arm on
the URL's **scheme**, not on anything the response said — so it states the
handler's contract rather than observing that this particular resolution kept
it. And the handler emits `X-Nostr-Trust: signature-verified;
completeness-unverified`, an accurate machine-readable version of exactly those
two steps, which nothing reads. NO-9.

---

## 5. Identifiers: NIP-19 and the `nostr:` URI

### 5.1 The bech32 encoding

NIP-19 identifiers are **bech32** as defined by **BIP-173**: a human-readable
part, the separator `1`, a data part in the charset
`qpzry9x8gf2tvdw0s3jn54khce6mua7l`, and a six-character checksum over the
expanded HRP and the data. An implementation:

- **MUST** verify the checksum and refuse a string that fails it.
- **MUST** refuse a mixed-case string (BIP-173), and **MUST** lower-case a
  uniform-case one before decoding — that is BIP-173's own normalisation.
- **MUST** reject non-zero padding bits when regrouping 5-bit values into
  8-bit bytes.
- **MUST NOT** enforce BIP-173's 90-character limit. NIP-19 identifiers
  routinely exceed it — an `nevent` with an author and two relay hints is past
  90 characters, an `naddr` with a long `d` tag comfortably so — and a
  limit-enforcing decoder rejects perfectly valid identifiers. This is a
  deliberate deviation from BIP-173, recorded as NO-4 and pinned by a test.
- **MUST NOT** use bech32m. NIP-19 uses the original BIP-173 constant.

The reference decoder is **total**: it never throws for untrusted input,
returning `{ error }` instead. Every caller is handling a string somebody typed
or a page linked to.

### 5.2 The types

| HRP | Payload | Decodes to |
|---|---|---|
| `npub` | 32 raw bytes | `{ type: 'npub', pubkey }` |
| `note` | 32 raw bytes | `{ type: 'note', id }` |
| `nprofile` | TLV | `{ type: 'nprofile', pubkey, relays }` |
| `nevent` | TLV | `{ type: 'nevent', id, relays, author?, kind? }` |
| `naddr` | TLV | `{ type: 'naddr', identifier, pubkey, kind, relays }` |
| `nsec` | 32 raw bytes | **refused** — §5.3 |

The TLV stream is a sequence of `type` (1 byte), `length` (1 byte), `value`
(`length` bytes). NIP-19 defines four types: `0` special, `1` relay, `2`
author, `3` kind. An implementation:

- **MUST** treat a TLV whose declared length runs past the end of the buffer as
  a decoding failure, and **MUST** treat a trailing byte too short to begin a
  type/length pair the same way. Silently dropping it would let two distinct
  byte strings decode to one target, and would make this decoder disagree with
  a stricter one about what an identifier means.
- **MUST** require the `special` value to be exactly 32 bytes for `nprofile`
  (the pubkey) and `nevent` (the event id).
- **MUST** require, for `naddr`, an `author` of exactly 32 bytes and a `kind`
  of exactly 4 bytes, read as a big-endian unsigned 32-bit integer. The
  `special` value is the `d` tag and **MAY** be empty — an addressable event
  with an empty `d` is legal.
- **MUST** read an `nevent`'s optional `kind` (TLV type 3, big-endian unsigned
  32-bit) when it is present, and **SHOULD** carry it into the query: a hint
  the link author gave is a hint an answer can be checked against (§9.3).
- **MAY** accept repeated type-1 values; NIP-19 defines no maximum. A decoder
  therefore **MUST NOT** treat the count as bounded, and the *resolver* **MUST**
  bound how many it will dial (§10.4).

### 5.3 `nsec` is refused by name

A **secret** key is not an address. An implementation **MUST NOT** decode an
`nsec` into a resolvable target, **MUST NOT** transmit it, and **MUST NOT**
echo it back in an error message or a log line.

It **SHOULD** refuse it *by name* rather than as an unknown prefix. The useful
thing to tell someone who has just pasted their secret key into an address bar
is that it is a secret and what to do about it — not that the browser lacks a
handler for that prefix. The reference implementation's error text is:

> that is a PRIVATE KEY (nsec). It was not sent anywhere. Never paste it into
> a browser or share it.

and a test asserts both the "PRIVATE KEY" and the "not sent anywhere" halves,
because the wording is the feature. NO-6 records why refusing by name is worth
the small disclosure it makes, and NO-1 records the one path on which the
promise does not yet hold: a bare `nsec` typed into the address bar does not
reach this handler at all.

### 5.4 The `nostr:` URI

**NIP-21** defines the URI as the scheme `nostr:` followed directly by a
NIP-19 identifier, with no authority component: `nostr:npub1…`. An
implementation **MUST** accept that form.

The reference implementation additionally accepts:

- `nostr://npub1…` — the authority form. NIP-21 does not define it. It is
  accepted because Chromium normalises a registered scheme's URL into this
  shape before the handler sees it, so refusing it would refuse our own
  browser's requests. NO-5.
- a **bare** identifier with no scheme, which is what makes a pasted `npub1…`
  usable if the classifier ever routes one (§3).
- a trailing `/`, `?…` or `#…`, which is stripped. Chromium appends a path to
  a bare authority; the identifier is the authority and the rest is noise.

Comparison is case-insensitive on the scheme (`NOSTR:` works) and the
identifier is lower-cased per BIP-173.

**`nostr:` is not a registered URI scheme.** It is not in the IANA URI Schemes
registry and there is no RFC 7595 registration to cite. It is a de-facto
scheme with wide implementation. Stated because a specification that quietly
implies otherwise is doing the reader a disservice.

---

## 6. Event verification

### 6.1 The id

**NIP-01** defines an event's id as the SHA-256 of the UTF-8 serialisation of

```
[0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
```

with no whitespace. An implementation **MUST** recompute this from the event's
own fields and **MUST NOT** trust the `id` field the relay sent.

The serialisation depends on the escaping used inside the two string fields.
NIP-01 specifies it exactly (escape `"`, `\`, `\n`, `\r`, `\t`, `\b`, `\f`;
everything else literal UTF-8). The reference implementation delegates this to
the host's `JSON.stringify`, which produces exactly that set for those
characters and `\uXXXX` for other control characters. **This is an assumption
about the host runtime, not a check** — see NO-10.
Wildroot pins it with a cross-implementation test whose fixture content
deliberately contains quotes, a backslash, a newline, non-ASCII, an astral
character and U+2028.

### 6.2 The signature

**BIP-340** Schnorr over **secp256k1**: a 64-byte signature over the 32-byte
event id, verified against the 32-byte x-only public key in `pubkey`. An
implementation **MUST** use BIP-340's tagged-hash construction — this is not
ECDSA and a generic secp256k1 verifier will not do.

### 6.3 The order, and the totality

An implementation **MUST** check the id **before** the signature. The
signature is over the id; an event whose id does not match its contents is one
where a *valid* signature would still be signing something other than what is
about to be displayed. Checking in the other order produces a green tick on
altered content.

An implementation **MUST** validate the shape of every field before either
check — `pubkey` and `id` 64 lowercase hex, `sig` 128 lowercase hex,
`created_at` and `kind` integers, `tags` an array, `content` a string — and
**MUST** treat a failure at any point as a rejection with a reason rather than
an exception. Every event reaching this code came off a network somebody else
controls.

An implementation **MUST NOT** display, store, link to, or act on an event
that failed verification, and **SHOULD** report that it discarded one and why.
The reference implementation lists each discarded event's truncated id, the
relay that sent it, and the reason.

### 6.4 What this establishes, and what it does not

A passing verification establishes exactly one proposition:

> The holder of the private key corresponding to `pubkey` signed these exact
> bytes at some point.

It does **not** establish that the key belongs to any particular person (that
is §7, and §7 is weak), that this is the event you asked for (§9.3), that it
has not been superseded (§10.1), that it has not been deleted (NIP-09 requests
deletion; it cannot enforce it), or that `created_at` is true — `created_at` is
a number the author chose and an author may choose any number.

---

## 7. NIP-05: a name to a key

### 7.1 The mapping

**NIP-05** maps `<local>@<domain>` to a public key by an HTTPS GET of

```
https://<domain>/.well-known/nostr.json?name=<local>
```

whose body is a JSON document (**RFC 8259**) of the form

```json
{ "names":  { "<local>": "<64-hex pubkey>" },
  "relays": { "<64-hex pubkey>": ["wss://…"] } }
```

An implementation:

- **MUST** derive the request URL from the identifier itself and **MUST NOT**
  accept a URL, host or path from any other source. §10.5.
- **MUST NOT** follow redirects (NIP-05 states this). A redirect moves the
  answer to a host other than the one whose assertion is being sought, which
  is the whole of the assertion.
- **MUST** restrict the local part to NIP-05's grammar (`a-z0-9-_.`) and refuse
  anything else rather than escaping it.
- **MUST** compare the returned key to `names[<local>]` for the exact local
  part queried — not to any key in the document.
- **SHOULD** treat a `relays` entry as a hint subject to §10.4, not as
  authority. The reference implementation filters it to `wss://` URLs.
- **MUST** treat the bare form `<domain>` as `_@<domain>`; NIP-05 renders a `_`
  local part as the bare domain, and a client that does not will display two
  different strings for one identity.

### 7.2 The Wildroot form: `_@<name>.hns.one`

A Handshake identity's NIP-05 address is `_@<name>.hns.one` — for the name
`alice.w3`, `_@alice.w3.hns.one`, which every ordinary Nostr client displays as
`alice.w3.hns.one`: exactly the string the user typed to claim the name.

The alternative form `alice.w3@hns.one` also resolves and is **deliberately not
used**. It reads as a mailbox at a domain the user does not control, which is
name confusion at the precise boundary where an identity is being asserted.

The reverse direction — a stranger's kind:0 carrying an `hns` field claiming a
Handshake name — is a **claim**, and becomes a verified name only when a NIP-05
lookup against *that name's own zone* returns this exact key. The host for
that lookup **MUST** be derived from the claim by a function that refuses
anything which is not purely a hostname (§10.5), and **MUST NOT** be assembled
at the call site. One function, called from every site, is the difference
between one place to get this right and as many places as there are callers.

### 7.3 What a NIP-05 answer is worth

This is the weakest step in the whole document and the one most often
misrepresented.

A NIP-05 answer establishes: **whoever currently controls that domain's web
server and holds a certificate a public CA issued for it says this name maps to
this key.** That is the ordinary trust model of the web (WebPKI, RFC 5280,
RFC 8446, RFC 9110) and nothing more. There is no signature by the key, no
chain, no proof of absence, no history, and no way to detect that the answer
changed a minute ago.

Three consequences an implementation **MUST** carry into its trust model:

1. The step is **`unverified`**, permanently, and **MUST** name the domain that
   asserted it. "alice@example.com ✓" without "…according to example.com" is
   the misrepresentation.
2. **On a `.hns.one` NIP-05 address, the Handshake guarantees do not apply to
   this hop.** The Handshake section of this repository resolves
   `alice.w3.hns.one` from a chain proof with a DANE pin. The NIP-05 fetch does
   not go through it: it is an ordinary `fetch()` in the main process, on
   WebPKI, through Chromium's own resolver. The chain-proven name and the
   WebPKI-fetched document are different hops with different guarantees. NO-12.
3. A key that displays a `nip05` field has asserted nothing. The field is
   inside a kind:0 the key signed, so the *key* said it; the *domain* has said
   nothing until it is asked. **An implementation that displays a `nip05` field
   MUST either resolve it or mark it unresolved.** The reference `nostr:` page
   takes the second route: it renders the field as *"claims `<handle>` (not
   verified — the handle was not looked up)"*, which is a true statement about
   what was and was not done. It does not make the lookup — NO-2 — while
   Wildroot's social page does, so the resolver is honest and incomplete rather
   than misleading.

---

## 8. Relay selection and the query

### 8.1 The protocol

Relays speak NIP-01 over a **WebSocket** (RFC 6455) carried on TLS (`wss://`).
The exchange for a read is:

```
client → ["REQ",   "<subid>", { …filter… , "limit": n }]
relay  → ["EVENT", "<subid>", { …event… }]           (zero or more)
relay  → ["EOSE",  "<subid>"]                         or ["CLOSED", "<subid>", …]
client → ["CLOSE", "<subid>"]
```

Every frame is a JSON array (RFC 8259). An implementation **MUST** ignore a
frame it cannot parse, a frame that is not an array, and a frame whose
subscription id is not one it opened. A relay that speaks nonsense is a relay
with nothing to say, not an error.

**A finished query MUST stop processing frames.** This is not an efficiency
note. If the client answers `EOSE` with `CLOSE` and then processes the relay's
reply to that `CLOSE`, a relay that replies gets answered again, and again:
a **livelock**, and the cheapest denial of service a hostile relay has. The
reference implementation guards it with a `done` flag checked at the top of
the message handler, and the comment there records that it cost a hung test
process to find.

**A relay is never allowed to hang a resolution.** Each socket carries its own
deadline (6 seconds by default), a dead socket resolves as an error rather than
rejecting, and a query fanned out across several relays is not taken down by
any one of them. A runtime with no WebSocket implementation is *reported*, never
silently resolved as zero events (§9.4).

**The WebSocket implementation is an injected seam.** `queryRelay` and
`queryRelays` take a `WebSocketImpl` option, and `createHandler` takes
`{ relays, timeout, WebSocketImpl }` and threads it through; the global is only
the default. That is what lets the whole handler — status codes, escaping,
hint refusal, answer binding — be driven against scripted, misbehaving relays
under plain `node --test` without touching the network and without any test
mutating a global that another test depends on.

### 8.2 Which relays

An implementation queries the union of:

1. the **relay hints** carried in the identifier (§5.2), and
2. a **default relay set**.

The reference implementation's default set is four relays — one of ours
(`wss://social.hns.one`) and three large public ones — bundled in
`src/relay.js`. Both parts of this are decisions made on the user's behalf and
both are stated as such in `../../DEVIATIONS.md` §2.4.

**Relay hints are checked before they are dialled and are bounded**, because
they are the link writer's choice and not the user's: §10.4 gives the rules and
§9.1 step 3 gives the algorithm. Every hint, accepted or refused, appears in
the relay report — a refusal that is silent looks exactly like a relay that had
nothing.

**NIP-65 relay lists are not read on this path.** NIP-65 (kind:10002) is the
mechanism by which an author says where their events can be found, and reading
it is the closest Nostr has to a resolution step for "where does this key
live". Wildroot *publishes* a NIP-65 list for every name it creates and its
social client *reads* one; the `nostr:` resolver does neither. It asks four
relays chosen by us and whatever the link's author chose. NO-3.

**No NIP-42 AUTH.** A relay that requires authentication is, to this
implementation, a relay that returned nothing — which is at least reported
honestly (the relay report shows it failed), but is not a distinguishable
condition. NO-7.

### 8.3 Fan-out, union, and why it is safe

Relays are queried **in parallel**, and the result is the **union** of the
verified events from all of them, de-duplicated by event id and sorted newest
first.

Taking a union rather than a quorum is safe *because of §6 and §9.3*, and only
because of both. Verification alone stops a relay altering or forging an event;
answer binding alone stops it substituting a genuine event for the one asked
for. With both, a hostile relay's options are limited to **omission** and
**delay**: it cannot make the result worse than it would have been without it,
it can only fail to improve it. With only the first, the union is worse than
useless against a hostile relay — its substitute is *added* to the honest
relays' answers rather than competing with them, and `created_at` ordering
decides which is shown. Tests drive both halves: one honest relay against one
tampering relay, and one honest relay against one answering a different
question, with the honest event surviving each time and the other reported as
discarded.

The converse also holds and is why the fan-out exists at all: **adding a relay
can only help.** This is unusual and worth noticing. It is the property that
lets a client query a relay it has no reason to trust, including ours.

### 8.4 Failure is not silence

An unreachable relay **MUST** be distinguishable from a relay that answered
with nothing. They mean opposite things: one is "we have no idea", the other is
"there is nothing here". The reference implementation returns, per relay, its
URL, whether it was reached, its event count, and its error string, and never
signals a relay failure by throwing.

This matters most on a path this specification does not cover — publishing a
**replaceable** event (kind:0, kind:3, kind:10002) assembled from a read. A
read that reached no relay returns "nothing", and publishing a replacement
built from that nothing destroys the previous one irrecoverably. That is the
standard way Nostr clients lose people's follow lists. It is out of scope here
and named anyway, because it is the reason the read API has to report
reachability.

The reference `nostr:` handler carries this distinction into its **HTTP
status**, not only into its prose. "Nothing was found" may be said only if at
least one relay answered:

- at least one relay answered and none had a matching event → **404**;
- no relay was reached at all → **502**, with the body saying that nothing is
  known about the address rather than that the address is empty — *"it was not
  found to be absent"*.

An implementation **MUST NOT** emit a machine-readable "this does not exist"
for "we could not ask anybody". Absence of proof is not proof of absence, and
in a system with no proof of absence at all (§10.1) the distinction between
"nobody answered" and "everybody who answered had nothing" is the only part of
that question a client can answer honestly.

---

## 9. The resolution algorithm

### 9.1 Steps

1. **Parse.** Strip an optional `nostr:` or `nostr://` prefix and any trailing
   path, query or fragment. Decode the remainder as NIP-19 (§5). On failure,
   stop: this is a `400`-class failure and **MUST NOT** cause any network
   access. (A test asserts that nothing is dialled before the address parses.)
2. **Refuse an `nsec`** (§5.3).
3. **Assemble the relay set.** Canonicalise every URL to one spelling
   (`normalizeRelayUrl`: host lower-cased, a bare path collapsed, fragment
   dropped), so one relay is one socket and the relay report counts it once.
   Then, for each **hint** in the identifier, in order: refuse it unless it is
   a public `wss://` URL (§10.4), refuse it once `MAX_RELAY_HINTS` — four in
   the reference implementation — have been accepted, and otherwise accept it
   if it is not already in the set. Append the configured relays. **Every
   refusal is recorded with its reason and rendered in the relay report**
   (§8.2).
4. **Build the filter** from the target type:

   | Target | Filter | Limit |
   |---|---|---|
   | `npub` / `nprofile` | `{kinds:[0], authors:[pubkey]}` **and** `{kinds:[1], authors:[pubkey]}` | 5 and 20 |
   | `note` | `{ids:[id]}` | 1 |
   | `nevent` | `{ids:[id]}`, plus `authors:[author]` and `kinds:[kind]` for each TLV the identifier carried | 1 |
   | `naddr` | `{kinds:[kind], authors:[pubkey], '#d':[identifier]}` | 1 |

   The two profile queries are issued concurrently. An `nevent`'s optional
   author and kind become **part of the question**: the link author said who
   wrote it and what it is, so an event that does not match is not an answer
   (§9.3). The limits are fixed and there is no paging — a resolver returns an
   answer, not a feed, and NO-8 says what that costs.
5. **Query** every relay in parallel (§8.1), verifying every event as it
   arrives (§6) and discarding — with a reason — every event that fails.
6. **Bind the answer** to the query, on the same event, before it can reach any
   caller (§9.3).
7. **Union, de-duplicate, sort** newest first by `created_at` (§8.3).
8. **Report** the answer, the relay outcomes, the refused hints, the discards,
   and the trust state (§4).

### 9.2 The profile

A kind:0 event's `content` is a JSON string (**RFC 8259**) which an
implementation **MUST** parse defensively: a malformed profile is an absent
profile, not an error. The fields read are `display_name`, `name`, `about` and
`nip05`. `nip05` is subject to §7.3.

`created_at` ordering picks the newest kind:0 across the relays that answered.
This is a heuristic, not a resolution: `created_at` is author-chosen (§6.4), so
"newest" means "claiming the latest timestamp".

### 9.3 Answer binding

**An implementation MUST verify that each returned event matches the filter it
was returned for**, at minimum:

- for an `ids` filter, `event.id` **MUST** be one of the requested ids;
- for an `authors` filter, `event.pubkey` **MUST** be one of the requested
  authors;
- for a `kinds` filter, `event.kind` **MUST** be one of the requested kinds;
- for a `#<letter>` filter, the event **MUST** carry a tag whose name is that
  letter and whose value is one of the requested values — `#d` for an
  addressable event's identifier, and the same rule for every other tag;
- for `since` and `until`, `created_at` **MUST** fall within the window.

A filter field an implementation does not understand is a field it cannot
match, so it **MUST** either implement the field or refuse to send it. Sending
a constraint the client cannot check is asking a question whose answer it will
believe unconditionally.

NIP-01 says a relay *should* return matching events. Nothing makes it. A
signature check does not do this job and cannot: an event by a different author
is *validly signed by that author*, so it passes §6 with a green tick while
answering a question nobody asked.

**The check MUST live beside the signature check, not in the renderer.** In the
reference implementation `matchesFilter` is applied in `src/relay.js`
immediately after `verifyEvent`, on the same event, in the same branch — so it
holds for every caller rather than for whichever renderer remembers, and a new
caller inherits it by construction.

An event that fails it is **discarded and reported**, not dropped: it goes into
the same `rejected` list as an event that failed verification, with the reason
*"does not match the filter it was returned for"* and the relay that sent it,
and the relay report names both. "This relay answered a different question" is
the most useful thing a relay report can say about a relay, and a client that
merely ignores the event throws that away.

Three consequences follow, and the tests drive each:

- a relay answering `{ids:[X]}` with event Y produces a **404** naming X, not a
  page rendering Y;
- a relay answering `{authors:[A]}` with B's notes produces a profile listing
  **none** of them;
- an `nevent` carrying an author or a kind narrows the question, so a relay
  that has an event with the right id but the wrong author, or the wrong kind,
  is answering a different question and is treated as such.

One property is easy to lose and worth stating: an **empty filter matches
everything**. That is correct — a query that asks nothing cannot be answered
wrongly — and it means the guarantee of this section is exactly as strong as
the filter the caller built, no stronger. §9.1 step 4 is where that strength
comes from, and it is why an `nevent`'s author and kind TLVs are read rather
than discarded.

What this does **not** close is **currency** (§10.1): a relay may serve an older
replaceable event that matches the filter perfectly and verifies perfectly.
Answer binding closes substitution. Nothing closes staleness.

### 9.4 Failure kinds

An implementation **MUST** distinguish, and **MUST NOT** collapse into a
generic error:

| Kind | Meaning | Reference status |
|---|---|---|
| `malformed` | the identifier did not decode | 400 |
| `secret` | an `nsec` was pasted | 400, with the §5.3 wording |
| `unsupported` | a valid NIP-19 prefix with no handler | 501 |
| `not-found` | relays answered and had nothing | 404 |
| `unreachable` | no relay answered | 502, naming the distinction |
| `transport` | the runtime has no WebSocket, or the query threw | 502 |

A runtime with no WebSocket implementation **MUST** say so rather than
resolving to zero results. Silently resolving nothing is indistinguishable
from "this key has no events", and the difference is the difference between a
broken build and an empty profile.

---

## 10. Security considerations

### 10.1 Completeness and currency are unprovable

This is the central limitation and it is not an implementation gap. A relay
can withhold an event and no client can detect it. There is no proof of
absence in Nostr: nothing signs "these are all the events", nobody is obliged
to have them, and the set of relays that *might* have them is unbounded.
Consequently:

- A profile may have been replaced on a relay you did not ask.
- A note may have been deleted (NIP-09) by a request that never reached the
  relay that answered you.
- A "complete" thread, follower list or article set is unknowable.
- **A key's absence from the answer is not evidence of anything.**

An implementation **MUST NOT** present any of these as resolved, **MUST NOT**
close a lock on a Nostr page, and **SHOULD** name the relays that answered so
the user can see the size of what they are trusting.

### 10.2 Authorship is proven per event, not per page

The green tick belongs to the *event*, not to the *answer*. §9.3 is the
mechanism; this is the presentational consequence, and it is a rule for the
interface: an implementation **MUST NOT** place a verification indicator where
it can be read as vouching for the *identifier→event* mapping unless §9.3 is
actually enforced. A per-event badge next to an unbound answer is the exact
shape of a lie by adjacency.

An implementation **MUST** display the author of every event it renders, and
**MUST** say so when that author is not the key the page is about. A page
headed by one key that lists notes without naming their authors cannot show the
user that a substitution happened even in principle — and §9.3 making such a
substitution unreachable through the filter is not a reason to stop showing it,
because the author is the one thing a careful reader can check against the
page's own heading without trusting the implementation.

The reference implementation's note card shows the badge, the timestamp, the
event id, and the author as a truncated key with the full key in its title
attribute; where the author differs from the page's key the card says *"— NOT
the key this page is about"* in the error colour. The remaining place an author
legitimately differs is a page about an event rather than about a key, where
there is no page key to compare against.

### 10.3 Asking is disclosing

A query tells every relay in the set which key, or which event, the user is
interested in, from the user's IP address, at that moment. There is no
oblivious transport for Nostr comparable to the ODoH path the Handshake section
uses for DNS. Fanning out across more relays makes the answer better and the
disclosure wider; that trade is real and this specification does not resolve
it.

In the reference implementation the `nostr:` handler is gated off entirely
while IP-protection is on, because it dials relays from the main process over
a path the session proxy does not cover. A blocked handler that says so is the
correct behaviour; a handler that leaks the real address while a UI claims
anonymity is not.

### 10.4 Relay hints are attacker-chosen

A relay hint inside an `nprofile`, `nevent` or `naddr` is whatever bytes were
bech32-encoded into the link the user clicked. It is not the user's choice and
not the author's — it is the *link writer's*. Without a check it is a
network-scanning and internal-service-probing primitive reachable from a link,
plus a plaintext downgrade for anything a `ws://` relay would have carried. An
implementation therefore **MUST**:

- require the `wss://` scheme, refusing `ws://` (plaintext) and everything
  else;
- refuse a host that is a loopback, private, link-local, CGNAT or otherwise
  reserved address — the same guard it applies to any other attacker-supplied
  fetch target — and refuse a reserved *name*: `localhost` and anything under
  `.localhost`, `.local`, `.internal`, `.lan`, `.home` or `.arpa`;
- refuse a `.onion` host, because a WebSocket to one outside a Tor proxy puts
  the name in a DNS query;
- bound the number of hints it will dial;
- **report every refusal**, since a silently dropped hint is indistinguishable
  from a relay that had nothing.

The reference implementation does this in `isSafeRelayUrl` in `src/relay.js`,
which is applied by the handler to each hint after `normalizeRelayUrl` and
before anything is dialled, and which shares
`../../src/safe-address.js` — the address guard the Handshake chapter uses for
exactly the same reason — for the numeric cases. `MAX_RELAY_HINTS` is four.
Refusals are rendered in the relay report with the offending URL, escaped, and
the reason.

Note what the check is *not*: it inspects the URL, not the DNS answer. A hint
naming a public hostname that resolves to a private address is refused by
neither this function nor anything below it, and the socket is opened by the
platform. Closing that requires the resolution and the connection to be
separated, which the WebSocket API does not offer.

### 10.5 Every fetched host is attacker-chosen

The NIP-05 path takes a hostname from a stranger's profile and puts it in a URL
this process fetches. Left unvalidated that is a server-side request forgery
primitive pointed at whatever the user's machine can reach. Appending a
suffix does not save you — every one of these already contains the character
that ends the host:

```
127.0.0.1:8080/x?y=                     → fetches loopback
169.254.169.254/latest/meta-data/?x=    → fetches the cloud metadata service
evil.example/#                          → the fragment truncates the path, so the
                                          fetch hits the attacker's document root
                                          and any JSON there is believed
evil.example\.hns.one                   → a backslash is a path separator to the
                                          URL parser, so a string that ENDS in
                                          .hns.one resolves to a host that does not
```

An implementation **MUST** validate the *shape* first: LDH labels, at least
two of them, no port, no path, no credentials, no percent-escapes, no Unicode —
and **MUST** re-check after appending any suffix, because the join must not
have produced something new. The reference implementation does this
(`verificationHost` in `src/nip05.js`) and a test drives each vector above.

### 10.6 Content is hostile bytes

An event's `content` is a string a stranger chose. A resolver that renders it
**MUST** escape it before it reaches any markup, and **SHOULD** serve the
result under a content-security policy that grants no script and no network
origin. The reference implementation escapes `& < > " '`, then linkifies
`http(s)://` and `nostr:` runs, and serves every page — including error
pages — under `default-src 'none'; style-src 'unsafe-inline'; img-src https:
data:`, so a page has no script source at all.

Note that a kind:0's `content` is a *nested* JSON document from the same
stranger. Parsing it is another place to be total rather than clever.

### 10.7 A note on the three implementations

The Wildroot tree contains **three** independent implementations of the NIP-01
serialisation and signature check: the one specified here, one in the identity
keystore that *signs*, and one vendored from a standalone package. They are
held in agreement by a test that signs with each and verifies under the others,
because the moment they drift our own posts fail our own verifier and nothing
else notices. This is recorded as NO-9 rather than presented as a design:
three copies with a test is better than three copies without one, and worse
than one copy.
