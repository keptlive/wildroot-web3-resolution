# Part II — Namespace selection

**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in this
repository, which ships in the Wildroot browser. Not endorsed by any standards
body. Normative statements below describe what an implementation must do *to
interoperate with this one*; where they are inherited from an existing
standard, that standard is cited and its rule governs.
**Licence:** CC-BY-4.0 (see `../../LICENSE-SPEC`). The reference implementation
is licensed separately.

This part belongs to the integrated specification whose spine is
[`../../SPEC.md`](../../SPEC.md), and it is the part that specifies namespace
selection: **which namespace an input belongs to, how a failure is prevented
from leaving that namespace, and how every namespace reports into one trust
model.** The spine's Handshake chapters specify what happens once §6 decides an
input is a Handshake name; the sibling chapters under `namespaces/` specify what
happens once it decides otherwise. Both should link here rather than restate
these rules.

Reference implementation, all paths relative to the repository root:

| Module | What it is |
|---|---|
| [`src/router.js`](../../src/router.js) | The scheme registry, the dispatcher, and the bare-input classifier |
| [`src/classify-host.cjs`](../../src/classify-host.cjs) | The host rule — **one** implementation, loaded by the router and by the address bar |
| [`src/reserved-names.cjs`](../../src/reserved-names.cjs) | The special-use label list — one list, three consumers |
| [`src/hns-host.js`](../../src/hns-host.js) | The `http→hns` rewrite applied at every navigation entry point |
| [`src/search-url.js`](../../src/search-url.js) | The `search://` URL grammar |
| [`src/trust-path.js`](../../src/trust-path.js) | `schemeSteps()` — the cross-namespace trust model |
| [`src/hns-url.cjs`](../../src/hns-url.cjs) | The experimental numeric-TLD URL convention (§8.2) |
| [`src/icann-tlds.cjs`](../../src/icann-tlds.cjs) | The bundled IANA root-zone snapshot |
| [`src/unimplemented-protocol.js`](src/unimplemented-protocol.js) | The fail-closed 501 handler a recognised-but-unresolved namespace gets |

Every departure from a cited standard, and every question we are unsure of, is
in [`../../DEVIATIONS.md`](../../DEVIATIONS.md) under the prefix `RT`. Every
standard cited is listed with its purpose in [`REFERENCES.md`](REFERENCES.md).
**Those two files are part of this specification, not appendices to it.**

---

## Contents

1. [What this specifies](#1-what-this-specifies)
2. [Terminology](#2-terminology)
3. [The two laws](#3-the-two-laws)
4. [The scheme registry](#4-the-scheme-registry)
5. [Dispatch](#5-dispatch)
6. [Classification of bare input](#6-classification-of-bare-input)
7. [Special-use names](#7-special-use-names)
8. [Internationalized and numeric labels](#8-internationalized-and-numeric-labels)
9. [Search is a terminal, not a fallback](#9-search-is-a-terminal-not-a-fallback)
10. [The unified trust model](#10-the-unified-trust-model)
11. [Security considerations](#11-security-considerations)
12. [Conformance](#12-conformance)

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## 1. What this specifies

A client that resolves more than one naming system has a problem that a
single-namespace resolver does not: **an input has to be assigned to exactly
one address space before anything is looked up, and a failure in that address
space must not become a lookup in another one.**

Both halves of that sentence are security properties, not conveniences. What
each one prevents is concrete:

- A rule that reads "the final label is not in the ICANN root, therefore
  Handshake" sends `vitalik.eth` to the Handshake chain, so whoever registers
  the Handshake top-level name `eth` receives traffic meant for ENS.
- The same rule puts a `.onion` address into a DNS query. For a Tor user that
  is not a failed page, it is a deanonymising disclosure — and a *malformed*
  onion address discloses exactly as much as a valid one.
- The same rule sends `nas.local`, `printer.lan` and `app.localhost` to a
  Handshake resolver, where whoever registers the Handshake top-level name
  `local` receives the names of every device on a home network and can answer
  for them.

So this part specifies the decision itself: the registry that says which schemes
exist and what each one's verification story is (§4), the dispatcher that is the
choke point where a failure is confined (§5), the classifier that turns a typed
string into exactly one namespace (§6), the names that are never any namespace's
to claim (§7), and the single trust vocabulary every namespace reports into
(§10).

**In scope.** The classification and dispatch decision, and the trust
*reporting* contract every namespace shares.

**Out of scope, explicitly:**

| Out of scope | Where it belongs |
|---|---|
| **Resolving a Handshake name** once §6 has decided it is one | the spine, [`../../SPEC.md`](../../SPEC.md) |
| **Resolving any other namespace** — ENS, Nostr, AT Protocol, Tor, Gemini, SSB, ICANN DNS | the sibling chapters under `namespaces/` |
| **Fetching content** once a name resolves to a pointer, and verifying the bytes | out of this repository entirely |
| **The user interface** — the padlock, the omnibox, the security panel | §10 specifies the model an interface is given and the claims it MUST NOT make; it does not specify a rendering |
| **The `hns://` URL form** | the spine's SPEC §5 |
| **The numeric-TLD URL convention** | [Chapter 10 — Experimental](../experimental/SPEC.md), Part B — §8.2 below states only the constraint it puts on the classifier |

A consequence worth stating plainly: an implementation of this part is a
**router**, not a resolver. It answers "whose name is this, and what happens
when that owner cannot answer?" and hands off.

---

## 2. Terminology

- **Namespace** — a distinct address space with its own root of trust. Several
  schemes may share one: `ipfs`, `ipns`, `ipld` and `pubsub` are all the IPFS
  namespace. The boundary this part protects is the *namespace* boundary, not
  the scheme boundary.
- **Scheme** — a URI scheme name as defined by
  [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986#section-3.1):
  `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, compared case-insensitively.
- **Explicit input** — an input that already names a scheme. **Bare input** —
  one that does not.
- **Classification** — assigning a bare input to exactly one namespace.
- **Dispatch** — handing a request to the handler its scheme names.
- **Carrier scheme** — an internal scheme this implementation invents so that a
  bare host can be dispatched: a bare `.onion` host becomes `onion://<host>`,
  a bare `.eth` host becomes `ens://<host>`, a pasted CID becomes
  `ipfs://<cid>/`, an `@user@host` handle becomes `activitypub:@user@host`.
- **Alias scheme** — a scheme served identically to another and rewritten to it
  on navigation (`agregore://` and `browser://` are aliases of `wildroot://`).
- **Fail-closed handler** — a handler for a namespace the implementation can
  *name* but not *resolve*. It answers an error and makes **no network request
  of any kind**; that is its entire security value.
- **Trust step** — one entry in the ordered list §10 defines, carrying a label,
  a state, a source ("who told us") and a human-readable detail.

DNS terms are used as in **RFC 8499**. Special-use names are those of **RFC
6761**, **RFC 6762** and **RFC 7686**.

---

## 3. The two laws

The implementation calls these L1 and L2. They are stated here as normative
rules because everything else in this part is machinery for enforcing them.

### 3.1 L1 — an explicit scheme always wins

> If an input names a scheme, that scheme selects the protocol. An
> implementation **MUST NOT** re-classify, sniff, or "improve" an input that
> already names a scheme, and **MUST NOT** consult the host in order to
> override it.

`ipfs://vitalik.eth/` is an IPFS request. The host looking like an ENS name is
irrelevant; `at://foo.14898/` is an AT Protocol request and not a Handshake
one. An **unknown** scheme is preserved as itself with a null namespace and
fails closed at dispatch (§5); it is never reinterpreted as a bare host, an
ICANN name, or a search.

L1 is enforced in two places that must agree:

1. **At the runtime layer.** Every scheme is bound to the dispatcher, which
   reads the scheme from the URL and nothing else
   ([`src/router.js:504-533`](../../src/router.js)).
2. **In the classifier.** The first thing `classify()` does with a non-empty
   input is test for an explicit scheme and return the input untouched
   ([`src/router.js:288-300`](../../src/router.js)).

An explicit decision also carries `known`, which is whether the registry has a
row for the scheme. A caller that navigates **SHOULD** require it rather than
inherit a rule from a comment: `javascript:`, `data:` and `file:` come back
`known: false` (§11.4).

An implementation **MUST** distinguish a scheme from the `host:port` shape. An
input matching the scheme grammar whose remainder is a bare port number
(`example.com:8080`, `localhost:3000`) is a host, not a scheme, unless the
token is a scheme the registry knows
([`src/router.js:205-217`](../../src/router.js)). See RT-4 for the case this
gets wrong.

### 3.2 L2 — no silent cross-namespace fallback

> A failure in one namespace surfaces as *that namespace's* failure. An
> implementation **MUST NOT** retry the same input in a second namespace,
> whatever the first one answered.

This is the rule of **RFC 9498 §9.10**, stated there for GNS and adopted here
as normative — it is the only place in an RFC where "resolve in the alternative
namespace when its suffix matches, and do not continue into DNS when that
resolution fails" is written down. An HNS SERVFAIL never becomes an ICANN
lookup. A missing `_nostr` record never becomes an AT Protocol lookup. A `.eth`
name with no contenthash is not then looked up on the Handshake chain.

L2 is enforced structurally in two ways:

- **The classifier returns one namespace and one reason.** There is no list of
  candidates, no ordering to fall through, and no second guess
  ([`src/router.js:277-411`](../../src/router.js)).
- **The dispatcher has no path that calls a second handler.** All four of its
  outcomes (§5) stay inside the scheme that was named.

An implementation **SHOULD** emit a machine-readable marker on every routed
failure naming the namespace it stayed in, so the trust layer can *show* that
no fallback occurred. Ours is the `X-Resolution-Namespace` response header,
which speaks the scheme table's vocabulary (§4.3).

### 3.3 The one allowed "fallback", and why it is not one

The Handshake handler retries a failed **chain** lookup over **DoH** (spine
SPEC §9.1, `../../DEVIATIONS.md` D-9/D-10). That is not an L2 violation, and the
distinction is worth stating precisely because it is the distinction L2 is
about:

> L2 forbids a failure in namespace **A** becoming a lookup in namespace **B**.
> A DoH retry resolves the *same Handshake name* in the *same namespace* over a
> *weaker transport*.

The trust cost is real and is not hidden: the answer is reported `unverified`
with the resolver named (§10), and the spine's D-9 records the one place where
this lets a resolver's word override the chain's authoritative "unregistered".

An implementation MAY offer such a transport downgrade. If it does it **MUST**
report the downgraded step as `unverified` and **MUST** name the party whose
word the answer rests on. The router deliberately models the namespace
boundary and nothing finer: it does not reach inside a handler's own transport
choices.

---

## 4. The scheme registry

### 4.1 The table is the single source of truth

Every scheme the implementation serves has exactly one row in a table that
records its **namespace**, its **maturity**, its **verification story** — the
native layer that authenticates the canonical object — and the **trust verdict
it can at best reach**. The router does not perform verification; it *names*
it, so that no scheme can be wired in without one. Registration of a scheme
with no row **MUST** be refused
([`src/router.js:475`](../../src/router.js)).

The verification story is not prose. It is the sentence the trust model (§10)
is held to: a row that over-claims becomes a padlock that over-claims, and the
two are checked against each other by test
(`tests/namespace-trust.test.js`). Where the honest answer is unflattering the
row says so — `ar` is "shape only", `ens` is "never green", `gemini` is "none",
`did` is "not proven".

`trust` states the same fact as a verdict rather than as a sentence, in the
vocabulary of §10.4, so that the claim is machine-checkable:

| `trust` | The verdict a page in this scheme aggregates to |
|---|---|
| `trustless` | `verified` — every step was checked here |
| `trusted` | `partial` — the transport is protected and something in the path is somebody's word |
| `open` | `open` — the connection itself carries no protection |
| `refused` | `partial`, with **no** verified step: a fail-closed stub verifies nothing |
| `builtin` | `verified` — the page came from the application and never touched the network |

Every row's claim is resolved to a sample URL, run through the trust model, and
compared with the verdict that comes back, row by row, by the reference
implementation's lock-semantics tests. A row cannot claim what the panel does
not deliver, in either direction, and an implementation **SHOULD** hold its own
table to its own trust model the same way.

`status` is a maturity claim and is required to be honest:

| Status | Meaning |
|---|---|
| `live` | handler shipped and wired |
| `partial` | handler exists and works, with a named gap in what it verifies |
| `planned` | greenfield; a fail-closed stub registers so dispatch fails *inside* the right namespace (§4.5) |

A `partial` row **MUST NOT** report the trustless lock state (§10.4).

### 4.2 The table

32 rows, 18 namespaces. Reproduced from
[`src/router.js:105-175`](../../src/router.js). The **Trust** column is the
verdict the row claims (§4.1). The **IANA** column is the scheme's status in
the [IANA URI Schemes
registry](https://www.iana.org/assignments/uri-schemes/) (see RT-6); "—" means
not registered at all.

| Scheme | Namespace | Status | Trust | Verification (L3) | IANA |
|---|---|---|---|---|---|
| `hns` | `hns` | live | trustless | SPV chain proof + DANE (TLSA `3 1 1`) or content CID | — |
| `ipfs` | `ipfs` | live | trustless | CID | Provisional |
| `ipns` | `ipfs` | live | trustless | IPNS record + CID | Provisional |
| `ipld` | `ipfs` | live | trustless | CID | — |
| `pubsub` | `ipfs` | live | trusted | **libp2p publisher signature** — a topic is not a content address | — |
| `ar` | `arweave` | partial | trusted | immutable txid — **shape only**, bytes gateway-trusted | Provisional |
| `ens` | `ens` | partial | trusted | contenthash via a public Ethereum RPC — RPC-trusted, not chain-proven; lock **TRUSTED, never green** | Provisional |
| `web3` | `web3` | partial | trusted | ERC-4804 EVM read | Provisional |
| `nostr` | `nostr` | partial | trusted | schnorr signature + event id recomputed locally; relay completeness **not** proven | Provisional |
| `at` | `atproto` | planned | **refused** | DID document | Provisional |
| `did` | `did` | partial | trusted | DID document from `plc.directory` / the `did:web` host — id checked, **not proven**; lock TRUSTED | Provisional |
| `activitypub` | `activitypub` | planned | **refused** | WebFinger / actor signature | — |
| `onion` | `tor` | partial | trusted | Tor onion-service key via the **device-local** Tor circuit — **never DNS** | — |
| `https` | `web` | live | trusted | WebPKI (address via the ICANN DNS policy) | Permanent |
| `http` | `web` | live | **open** | none (plaintext) | Permanent |
| `https+raw` | `web` | live | trusted | WebPKI | — |
| `gemini` | `gemini` | live | trusted | **none** — TLS with no certificate verification; **not TOFU**, nothing is pinned | — |
| `hyper` | `hyper` | live | trustless | hypercore key (a DNSLink name→key binding is resolver-trusted) | Provisional |
| `ssb` | `ssb` | live | trustless | feed signature | Provisional |
| `bittorrent` | `bittorrent` | live | trustless | infohash | — |
| `bt` | `bittorrent` | live | trustless | infohash | — |
| `magnet` | `magnet` | live | trusted | infohash | Provisional |
| `wildroot` | `browser` | live | builtin | built-in | — |
| `agregore` | `browser` | live | builtin | built-in — **alias of** `wildroot` | — |
| `browser` | `browser` | live | builtin | built-in — **alias of** `wildroot` | — |
| `search` | `search` | live | trusted | n/a (private metasearch) | — |
| `paste` | `browser` | live | builtin | built-in; content verified against its CID in the page | — |
| `editor` | `browser` | live | builtin | built-in; published document addressed by CID | — |
| `bluesky` | `browser` | live | trusted | built-in app; network content via WebPKI | — |
| `mastodon` | `browser` | live | trusted | built-in app; network content via WebPKI | — |
| `media` | `browser` | live | builtin | built-in; bytes derived locally — **not navigable** | — |
| `docview` | `browser` | live | builtin | built-in sandbox — **not navigable** | — |

Two deliberate non-conflations, called out because they are easy to get wrong:

- **`web3://` (a scheme) vs `.w3` (a Handshake top-level name).** The scheme
  executes an ERC-4804 EVM call; the name is an ordinary Handshake name. They
  share a fragment of spelling and nothing else. ERC-4804's `w3://` short form
  is **deliberately not offered**, because it would shadow the `.w3` Handshake
  namespace (RT-9). An implementation of this specification **MUST NOT**
  register `w3` as a scheme.
- **`did:` / `at://` vs bare social names.** A Handshake name whose zone
  publishes `_nostr` / `_atproto` / `_activitypub` records classifies as `hns`.
  The `at:`, `nostr:` and `did:` schemes address the native objects directly
  and classify to their own namespaces. Handshake authenticates the *mapping*;
  the native layer authenticates the *object*.

### 4.3 Namespaces without a scheme, and which vocabulary the marker speaks

One declared namespace, `icann`, has **no** row in the table: an ICANN name is
navigated as `https://`, whose row is in namespace `web`. So
`classify('example.com').namespace` is `icann` while
`namespaceForScheme('https')` is `web`.

`X-Resolution-Namespace` speaks the **scheme table's** vocabulary. An ICANN
navigation is an `https://` URL and therefore carries `web`, while `classify()`
reports the finer `icann` for the same input. An implementation **MUST** state
which of the two vocabularies its marker speaks; a reader comparing the two
without being told will find they differ for every ordinary web page. That the
model needs the sentence at all is a modelling wrinkle: see RT-5.

### 4.4 Scheme privileges

In Chromium (and therefore in Electron, via
[`protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes)),
a custom scheme is inert until it is declared **before application startup**.
Two properties matter for resolution:

- **`standard: true`** makes the scheme a WHATWG *special* scheme. Its URLs get
  a real tuple origin (`hns://<host>`), which is what makes `localStorage`,
  IndexedDB, `blob:`, `crypto.subtle` and same-origin policy work. The cost is
  that the host is parsed by the [WHATWG host
  parser](https://url.spec.whatwg.org/#host-parsing), which is the entire
  reason for §8.2's numeric-TLD convention. **The two are the same decision and
  cannot be separated.**
- **`secure: true`** makes it a secure *context*. It does **not** decide the
  padlock. An implementation **MUST NOT** derive a trust verdict from a
  scheme's privilege flags — `onion://` is standard and secure and still
  reports a closed-but-never-green lock, and `http://` is neither and reports
  an open one (§10).

An implementation **MUST** declare every scheme it dispatches. A scheme that is
dispatched but not declared is unknown to the URL parser, and loading one as a
main-frame document has hard-crashed this application on Windows. The
declaration site is a separate file from the registry (`src/main.cjs` in the
Wildroot tree, not extracted here), which is a duplication we would rather not
have: see RT-D1.

The privilege classes this implementation uses:

| Class | `standard` | `secure` | Service workers | `stream` | Schemes |
|---|---|---|---|---|---|
| p2p | yes | yes | **yes** | yes | `https+raw`, `hyper`, `gemini`, `ipfs`, `ipns`, `ipld`, `pubsub`, `bittorrent`, `bt`, `ssb`, `web3`, `media` |
| chrome | yes | yes | no | no | `wildroot`, `agregore`, `browser`, `search`, `editor`, `paste`, `bluesky`, `mastodon` |
| low | **no** | **no** | no | no | `magnet`, `did`, `nostr`, `at`, `activitypub` |
| low + `stream` | **no** | **no** | no | yes | `ar`, `ens` |
| `hns` | yes | yes | **no** | yes | — |
| `onion` | yes | yes | **no** | yes | — |
| `docview` | yes | yes | no | yes | — |

`stream` is what makes `Range`/`206` work, which is the difference between a
video a viewer can scrub and one they can only watch from the start.

`hns` and `onion` are their own rows because each is a deliberate combination:
a real persistent origin (so real web applications run at all) with service
workers **off** (so a page cannot persist a copy of itself under a name whose
records may change). `ar` and `ens` are deliberately **low**: an opaque origin
is never a secure context, which is the honest posture for content whose
name→bytes binding is not verified.

### 4.5 Registration rules

An implementation **MUST**:

- refuse to register a scheme that has no registry row (§4.1);
- refuse a double registration, which is always a wiring bug, unless an
  override is asked for explicitly;
- register a **fail-closed handler** for every namespace it can name but cannot
  resolve, rather than leaving the scheme unregistered. An unregistered scheme
  is a crash risk and, worse, invites the classifier to guess. The fail-closed
  handler answers `501`, carries the namespace marker, echoes the input
  **escaped** so the user can see it was understood, and makes no network
  request ([`src/unimplemented-protocol.js`](src/unimplemented-protocol.js)).

An implementation **SHOULD** mark schemes that are origins for subresources and
main-process loads only, and **MUST NOT** allow a page to navigate a tab into
one. `media` and `docview` are so marked.

---

## 5. Dispatch

`dispatch(request)` reads the scheme from the URL **and nothing else**. There
is no content sniffing, ever. It has exactly four outcomes, and none of them
crosses a namespace ([`src/router.js:504-533`](../../src/router.js)):

| Outcome | Response | Namespace marker |
|---|---|---|
| The URL does not parse **and names no scheme** | `400` | none — no scheme was established (RT-12) |
| No handler registered for the scheme | `501`, body naming the scheme | the scheme's namespace, or the scheme itself when it has no row |
| The handler returns — **including a 404 or a 500** | that response, verbatim | whatever the handler set |
| The handler throws | `502`, body carrying the error | the scheme's namespace |

**A named scheme keeps its namespace even when its URL will not parse.** The
scheme is read by prefix when the WHATWG parse fails, and the request still
reaches — or fails inside — the namespace the user named. This is not an edge
case: the canonical AT-URI puts a DID in the authority (`at://did:plc:…/…`) and
a WHATWG host may not carry a colon that is not a port, so the commonest
spelling of an AT Protocol address parses nowhere. Every namespace whose
addresses are not WHATWG hosts — DIDs, multibase keys, sub-schemed identifiers —
depends on this. An implementation **MUST** attribute such a failure to the
scheme that was named rather than reporting it as a malformed address, because
losing the namespace on the way to the interface is an L2 failure in reporting
even when no second lookup occurred.

A `404` from the Handshake handler is a Handshake `404`. It is **not** retried
as an ICANN lookup, and an implementation **MUST NOT** interpose a "did you
mean" retry at this layer.

The `501` body **SHOULD** say that no other protocol will be guessed. The point
of the sentence is that "we could not load this" and "we refused to go looking
for it somewhere else" are different statements and the user is entitled to the
second one.

---

## 6. Classification of bare input

Input: a string with no scheme, as typed. Output: exactly one decision —

```
{ url, scheme, namespace, explicit, reason }
```

with `known` added when `explicit` is true (§3.1) and `validV3` added for a
`.onion` host (§6.1).

`reason` is not decoration. An implementation **SHOULD** carry the reason
through to the interface, because "this was treated as a Handshake name because
its final label is not an ICANN top-level domain" is a checkable claim and "we
guessed" is not.

### 6.1 The order

The decision is made **once**, in this fixed order; the first match wins and is
final ([`src/router.js:277-411`](../../src/router.js)):

1. **Empty input** (after trimming) → the search terminal with an empty query.
   `reason: empty`.
2. **An explicit scheme** → returned untouched, `explicit: true` (§3.1).
   `reason: explicit-scheme`.
3. **`@user@host`** — the canonical Fediverse address — → `activitypub:`.
   `reason: fedi-handle`. It is not a host: the URL parser reads the second `@`
   as a userinfo separator and would navigate to the instance carrying a stray
   credential. **Any other `@`** in a scheme-less input is a search: no
   namespace here has one in an address, and the URL constructor would read
   what precedes it as userinfo and silently drop it.
4. **A bare NIP-19 identifier** — `npub`, `note`, `nprofile`, `nevent`,
   `naddr` or `nsec`, followed by `1` and a bech32 body → `nostr:`.
   `reason: nip19-identifier`. The identifier is **decoded** before it is
   claimed (below).
5. **A bare CID**, with no separator character anywhere in the input →
   `ipfs://<cid>/`. `reason: bare-cid`. A CIDv0 is written in its CIDv1 base32
   form, which names the same bytes (§6.5).
6. **An `/ipfs/…` or `/ipns/…` gateway path** → `ipfs://` / `ipns://`.
   `reason: ipfs-path` / `ipns-path`.
7. **`localhost` or `localhost:<port>`, optionally with a trailing slash** →
   `http://`. Never Handshake, never a search. `reason: localhost`.
8. **Host classification** (§6.2), on the input with any path, query, fragment,
   port and trailing dot removed
   ([`src/classify-host.cjs:87-116`](../../src/classify-host.cjs)):
   1. **an empty host, or one containing whitespace** → undecided; fall to
      step 9, where whitespace is what a search query looks like.
   2. **`*.onion`** → the Tor namespace, **unconditionally and first**.
      `reason: onion-host`.
   3. **`*.eth`** → the ENS namespace. `reason: eth-name`.
   4. **a special-use label** (§7) → the web namespace, `http://`, because it
      is a device on the user's own network. `reason: reserved-host`.
   5. **an IPv4 or IPv6 literal**, bracketed or not → the web namespace,
      `https://`. `reason: ip-literal`.
   6. **a single label** (no dot) → undecided; fall to step 9.
   7. **an all-numeric final label** → Handshake (ICANN has no numeric
      top-level domains). `reason: hns-tld`. The URL form this produces is
      experimental — §8.2.
   8. **a final label in the ICANN root** → the ICANN namespace, `https://`.
      `reason: icann-tld`.
   9. **anything else** → Handshake. `reason: hns-tld`.
9. **A single bare label** (step 8.6), and no whitespace anywhere in the input:
   Handshake **unless the label is itself an ICANN top-level domain**, in which
   case search. `reason: hns-bare-label` or `search`.
10. **Anything else** — in practice anything containing whitespace — search.
    `reason: search`.

Five notes on the order, each of which is load-bearing:

- **`.onion` is matched first and unconditionally.** A *malformed* onion
  address stays in the Tor namespace and fails there. It **MUST NOT** be
  validated first and sent to a resolver when validation fails: a typo
  discloses the hidden service exactly as effectively as a valid address does.
  Validity is reported alongside the decision (`validV3`), never used to
  re-route it.
- **`.onion` is matched before the special-use list**, in which `onion` also
  appears (RFC 7686). Reversing the two would divert every onion address into
  the web namespace.
- **`.eth` returns ENS with no backstop.** If ENS has no record, that is an ENS
  failure. There is no Handshake or ICANN second attempt (L2).
- **The IP-literal test runs before the label count.** An IPv6 literal has no
  dot, so a label count tested first hands it to the bare-label branch and
  makes it a Handshake name. For the same reason the host reducer **MUST NOT**
  strip a `:port` suffix from a bracketed or colon-dense host: `::1` is an
  address, not a host with a port of `1`
  ([`src/classify-host.cjs:55-64`](../../src/classify-host.cjs)).
- **A NIP-19 identifier is decoded before it is claimed, and `nsec` is routed
  on purpose.** The prefix alone is not enough: a Handshake name that merely
  begins `npub` must stay a name, so the branch runs the bech32 decode
  (`decodeNip19`) and only claims the input when the 30-bit checksum holds —
  which makes a false positive a 1-in-2³⁰ event rather than a guess. The one
  exception is `nsec`: a secret key is claimed on its prefix, without waiting
  for a decode that is *designed* to fail, because the alternative is the
  bare-label rule transmitting the secret to a resolver as a name. Routed to
  the Nostr namespace it reaches the handler's "that is a PRIVATE KEY" refusal
  instead ([`src/router.js:323-328`](../../src/router.js), and
  [Chapter 6 — Nostr](../nostr/SPEC.md) §5.3).
  The identifier must be the **whole** input: an identifier carrying a path or
  a trailing slash is not matched and falls through to the host rules
  ([Chapter 6's `DEVIATIONS.md`](../nostr/DEVIATIONS.md) `NO-13`).

### 6.2 The host rule, in one sentence

> **ICANN first, Handshake second.** A dotted host whose final label is a
> delegated ICANN top-level domain is an ICANN domain; every other final label
> is a Handshake name.

The ICANN side of that comparison **MUST** be made against the **full IANA root
zone list**, not a hand-written allowlist. A short list silently hijacks real
sites: `shop.blog`, `foo.link`, and most country-code domains are exactly the
names an abbreviated list gets wrong. The bundled snapshot is 1,438 A-label
entries ([`src/icann-tlds.cjs`](../../src/icann-tlds.cjs)) and **SHOULD** be
checked against the live IANA list by a periodic test.

Rule ordering is a deliberate deviation from Handshake's own model, in which
ICANN labels are reserved and claimable and a claimed one would make the chain
authoritative. We route to ICANN regardless. That is what makes the browser
safe to use as somebody's only browser (spine `../../DEVIATIONS.md` D-16).

### 6.3 The single bare label

A single label with no dot — `pinner`, `hnshosting`, `14898`, `🤝` — is a
Handshake name unless the label is itself an ICANN top-level domain.

This is a product decision and an implementation MAY differ. The reasoning, and
the honest cost, both belong on the record:

- Most Handshake sites *are* bare top-level names. A browser whose subject is
  names does not answer `pinner` by asking a search engine.
- `com`, `org`, `app`, `blog` and `link` stay searches, because a bare ICANN
  top-level domain is a word somebody is part-way through typing.
- The cost is a privacy cost: every mistyped word becomes a name lookup, and
  therefore something a chain node or a DoH resolver may observe. An
  implementation choosing this rule **SHOULD** offer the search as a visible
  second choice rather than making the user retype, and **SHOULD** consider
  what the lookup discloses (RT-3).

Whitespace anywhere in the input **MUST** exclude it from this rule. A host
classifier that returns "undecided" for both a single label *and* a string with
spaces in it will otherwise turn every multi-word search into a name lookup.
The exclusion has to be deliberate, and it is
([`src/router.js:406`](../../src/router.js)).

### 6.4 The `http→hns` rewrite

Classification is not only an address-bar concern. A literal
`http://nathan.woodburn/` link on an ordinary web page reaches the system
resolver, which knows nothing about Handshake, and produces a blank page with
no error. An implementation **MUST** apply the same classification at every
navigation entry point — typed input, link click, tab restore, programmatic
load — and rewrite a main-frame load on a Handshake host to the Handshake
scheme, preserving everything but the scheme
([`src/hns-host.js:85-98`](../../src/hns-host.js)).

The same path **MUST** rewrite a host in a namespace somebody else owns into
*that* namespace's scheme, so that `http://vitalik.eth/` becomes an ENS request
and `http://<addr>.onion/` becomes a Tor request rather than a DNS query. One
classifier, consumed everywhere: `hns-host.js` delegates the decision to
`classifyHost()` rather than carrying rules of its own, because a second copy of
this rule is how `.eth` came to mean two different things in one browser.

There is one deliberate asymmetry between the two paths. A single bare label is
**undecided** when typed (it might be a word) but **decided** when it arrives
as a URL host: `http://hnshosting/` has already settled the question of
navigation intent, so it is a Handshake host
([`src/hns-host.js:59-77`](../../src/hns-host.js)).

### 6.5 Pasted content addresses

A pasted CID is the most natural thing anybody does with one, and it is
self-describing, so it is recognised without a scheme. Two rules apply:

- **A CIDv0 is written as its CIDv1 base32 form.** `Qm…` is case-sensitive
  base58 and a standard scheme's host is lowercased by the URL parser, so the
  v0 spelling cannot survive as a host. The v1 form names the same bytes
  ([`src/router.js:414-421`](../../src/router.js)).
- **An IPNS key is deliberately not recognised here.** `Qm…` is both a legacy
  IPNS key and a CIDv0, and guessing between them is exactly the sniffing this
  part exists to prevent. An IPNS name **MUST** be named explicitly
  (`ipns://…` or `/ipns/…`).

---

## 7. Special-use names

Some labels are not any namespace's to claim. An implementation **MUST NOT**
send them to an alternative-naming resolver, and the reason is concrete rather
than procedural: without the carve-out, every NAS, printer, router and internal
service name on a user's network is disclosed to whoever registers the
Handshake top-level name `local`, who can then answer for it.

The labels this implementation refuses
([`src/reserved-names.cjs:19-33`](../../src/reserved-names.cjs)), and their
standing:

| Label | Standing |
|---|---|
| `localhost` | **RFC 6761 §6.3** — the whole subtree is loopback, so `app.localhost` is covered too |
| `invalid` | **RFC 6761 §6.4** — guaranteed not to resolve |
| `test` | **RFC 6761 §6.2** — reserved for testing |
| `example` | **RFC 6761 §6.5** |
| `local` | **RFC 6762 §3** — mDNS |
| `onion` | **RFC 7686** — Tor's, and routed to the Tor namespace rather than merely refused |
| `arpa` | **RFC 3172** — infrastructure; `home.arpa` (**RFC 8375**) lives here |
| `internal` | **Not an IETF reservation.** Reserved by ICANN for private use in 2024 |
| `home`, `lan`, `corp`, `intranet`, `private` | **Not reservations at all** — conventions that home routers and corporate networks actually use. `corp` and `home` were deferred indefinitely from ICANN's new-gTLD programme on name-collision grounds |

The distinction in the last two rows matters and is stated in
[`../../DEVIATIONS.md`](../../DEVIATIONS.md) RT-1: an implementation copying
this list should know that it is refusing more than the RFCs reserve, and why.

The test is on the **final label**, applied to the lowercased host with any
trailing dot removed, so the whole subtree under each label is covered
([`src/reserved-names.cjs:36-41`](../../src/reserved-names.cjs)).

**One list, every consumer.** The classifier, the address bar and the WebSocket
proxy script all read this one list; a list kept in two places is a list that
disagrees with itself, and the disagreement is silent. A reserved name reaches
the web namespace over plain `http://` — the way `localhost` does — because
that is what a user asking for a device on their own network means. Returning
"undecided" instead would send it back to the bare-label branch and to
Handshake.

---

## 8. Internationalized and numeric labels

### 8.1 IDNA

A host **MUST** be converted to A-labels before it is compared against the
ICANN root list and before it is resolved, or a Unicode top-level domain
(`пример.рф`) is compared against a punycode list, fails, and is hijacked to
the wrong namespace — while an emoji label, which genuinely is a Handshake
name, must come out the other way.

This implementation performs the conversion by handing the host to the URL
parser and reading back the parsed hostname
([`src/classify-host.cjs:68-76`](../../src/classify-host.cjs)). What that delivers is
therefore **UTS #46 as the WHATWG URL Standard specifies it**, not IDNA2008 as
RFC 5891 specifies it. The two differ on the deviation characters and on
transitional processing. We have not audited which Handshake labels this can
affect (spine `../../DEVIATIONS.md` D-17).

The conversion **MUST NOT** fail open. Ours does: when the URL parser rejects
the host, the raw final label is used for the ICANN comparison instead. See
RT-11 and RT-D5.

### 8.2 The numeric top-level name — EXPERIMENTAL

**This subsection is experimental.** It ships, and it is not a proposed
standard: whether a numeric Handshake top-level name should be supported at all
is undecided, and the URL form that carries one is a local invention. The form,
its rationale and its deviations are specified in
[Chapter 10 — Experimental](../experimental/SPEC.md), Part B, under the `NT`
deviation prefix, and are **not restated here**.

A Handshake top-level name may legitimately be all digits, and a *standard*
scheme's host is run through the WHATWG ["ends in a number"
checker](https://url.spec.whatwg.org/#ends-in-a-number-checker) and then parsed
as an IPv4 address. So `hns://14898/` canonicalises to `hns://0.0.58.50/` and
`hns://hello.14898/` is not a valid URL at all.

What belongs in this part is only the ordering constraint the marker places on
the classifier:

> A classifier that builds a URL from user input applies the numeric-TLD marker
> **before** the IDNA pass, because the IDNA pass is performed by the URL
> constructor and the URL constructor throws on the unmarked form
> ([`src/router.js:430-440`](../../src/router.js)).

The classification rule itself — an all-numeric final label is Handshake,
because ICANN has no numeric top-level domains (§6.1 step 7.6) — stands
independently of how the resulting URL is written.

---

## 9. Search is a terminal, not a fallback

A typed string that names no protocol and is not a name is a **query**, and the
namespace it goes to is `search`.

**A search is not a cross-namespace fallback.** L2 governs a *named* protocol
failing; here no protocol was ever named, so there is nothing to fall back
*from*. An implementation **MUST NOT** reach the search terminal from a
resolution failure — only from a classification that never identified a
namespace in the first place.

### 9.1 The `search://` URL form

```
search://<category>/?q=<query>          results
search://<category>/                    the category's home
```

The host names the **category** because the metasearch runs a query against
exactly one category's engines, so the category is what a search URL is *on*,
the way a site is what an `http` URL is on. The categories are `web`
(the default), `academic`, `code`, `wiki` and `custom`
([`src/search-url.js:33`](../../src/search-url.js)).

**A standard scheme's URL MUST have a host.** This is not stylistic. A standard
scheme with an empty host is an invalid URL: it will not load, and — the reason
this grammar exists at all — a session-restore path can create a history entry
for it anyway, after which every subsequent read of the history trips an
internal invariant in the URL library. An implementation that registers a
scheme as standard (§4.4) **MUST NOT** mint hostless URLs in it.

An implementation **SHOULD** accept legacy spellings and rewrite them rather
than 404 them, since old bookmarks, history rows and saved provider templates
carry them: `search://?q=x&cat=y`, bare `search://`, and `search://<terms>`
with the query in the host position are all read and canonicalised
([`src/search-url.js:92-136`](../../src/search-url.js)). An unparseable
`search:` string reads as the search home rather than throwing — the scheme was
named, and the answer to a broken search URL is the search page.

Category normalisation is total: an unknown or absent category is `web`, so no
caller has to guard the fallback. On a canonical URL the host wins; on a legacy
form the `?cat=` parameter is honoured.

### 9.2 What a search does and does not promise

`search` is the one namespace in the table whose verification story is `n/a`.
Its trust step is `none`, sourced "private metasearch" (§10). An implementation
**MUST NOT** present a search result page as verified content, and **MUST NOT**
let a search URL inherit the trust state of the page that produced it.

---

## 10. The unified trust model

Every namespace reports into **one** vocabulary. This is what makes a single
indicator possible at all: the alternative is a per-namespace notion of "secure"
and an interface that cannot compare them.

### 10.1 Steps and states

A resolution — in *any* namespace — produces an ordered list of **steps**. Each
step says what was checked, **who told us**, and one of four states:

| State | Meaning |
|---|---|
| `verified` | checked cryptographically, in this process, in this resolution |
| `unverified` | taken on somebody's word — a resolver, a CA, an RPC endpoint, a gateway, the network |
| `failed` | checked and did not pass |
| `none` | does not apply, or is absent and *known* to be absent |

An implementation **MUST** expose these steps, or an equivalent, to the
interface, and **MUST NOT** collapse them into a boolean before the user sees
them. The `source` field is the part that matters and the part usually missing:
"chain-verified, DANE pinned" hides whether the *pin itself* was proven, and a
lock that cannot explain itself is decoration.

The Handshake step list is specified in the spine's [SPEC §4](../../SPEC.md)
and is not restated here. This section specifies the **cross-namespace**
model — what every *other* scheme reports
([`src/trust-path.js:256-447`](../../src/trust-path.js)).

### 10.2 The per-scheme step lists

Every scheme with a verification story worth naming has its own arm. The
default arm is reached only by schemes that genuinely have none.

The arm is chosen by the scheme, and **a named scheme keeps its arm even when
its URL will not parse.** `at://did:plc:…` — the canonical AT-URI — carries a
colon in its authority that is not a port, so the WHATWG parser refuses it; the
scheme is then read by prefix and that scheme's arm answers. Only an input with
**no** scheme at all is an `Address` `failed` step. Reporting a namespace's own
address form as an unparseable address would say the browser cannot read a URL
when what it cannot do is verify the thing the URL names, and it would put a
`failed` verdict on a page that a `refused` scheme is supposed to answer for
(§4.5).

| Scheme(s) | Steps | Verdict |
|---|---|---|
| `https` | Domain name `unverified` (how it was looked up, §10.3) · Connection `unverified` — "a CA vouched for it" | TRUSTED |
| `http` | Domain name `unverified` · Connection `none` — plaintext | OPEN |
| `ipfs`, `ipns`, `ipld` | Content `verified` — CID, or a signed IPNS record whose content is CID-verified | TRUSTLESS |
| `pubsub` | Content `none` — a topic is **not a content address**; a message carries only its publishing peer's libp2p signature, and anyone may publish to a topic | TRUSTED |
| `bt`, `bittorrent` | Content `verified` — infohash, or BEP-46 key-addressed. Proves who published, not that this is the newest version | TRUSTLESS |
| `ssb` | Content `verified` — feed key signature. Proves who wrote it, not that the feed is complete | TRUSTLESS |
| `hyper` (bare key) | Content `verified` — every block checked against the key in the address | TRUSTLESS |
| `hyper` (dotted host) | Name records `unverified` — a DNSLink name read from a public DoH resolver, no DNSSEC, no chain proof · Content `verified` once resolved | TRUSTED |
| `magnet` | Address `none` — a pointer to a torrent; nothing loads until it is added | — |
| `ar` | Content `unverified` — the transaction id names immutable content, but the bytes came from a gateway and were **not** checked against the transaction | TRUSTED |
| `ens` | Name records `unverified` — public Ethereum RPC, no light client · Content `verified` once resolved | TRUSTED, **never green** |
| `gemini` | Connection `unverified` — TLS with the certificate neither checked against an authority nor remembered from a previous visit. **Not TOFU**: nothing is pinned, so nothing can be compared | TRUSTED |
| `nostr` | Authorship `verified` — id recomputed and the BIP-340 signature checked here · Completeness `unverified` — relays can withhold, and nothing signs "these are all the events" | TRUSTED |
| `did` | Identifier `unverified` — the document was fetched and checked to be about the identifier asked for; for `did:plc` the operation log that would prove it is not audited, and `did:web` rests on WebPKI | TRUSTED |
| `onion` | Connection `unverified` — the onion key authenticates the *service* at the Tor layer; the page is plain HTTP inside the tunnel | TRUSTED |
| `wildroot`, `agregore`, `browser`, `about`, `editor`, `paste`, `media`, `docview` | Page `verified` — built in, never touched the network | TRUSTLESS |
| `bluesky`, `mastodon` | Page `verified` — the **app** is built into this browser · Content `unverified` — what it shows came from the network's own servers over WebPKI HTTPS | TRUSTED |
| `search` | Search `none` — private metasearch | — |
| `file` | File `none` — local filesystem | — |
| anything else | Address `none` — "this browser has no verification path for this scheme" | — |
| an input with no scheme that will not parse | Address `failed` | FAILED |

Five rules this table encodes are worth stating normatively:

- **A namespace with no verification path gets a step saying so.** An empty
  step list aggregates to "nothing is known", which a naive interface renders
  as neutral; a `none` step with an honest source renders as unverified. An
  implementation **MUST NOT** return an empty step list for a scheme it
  dispatched.
- **A step's state describes what was proven, not what the address looks like.**
  An Arweave transaction id is immutable and still yields an `unverified`
  Content step, because the bytes were never checked against it; a `pubsub`
  topic looks like a content address and is not one. An implementation **MUST
  NOT** infer verification from the *shape* of an identifier.
- **A pointer and its content are separate steps.** `ens`, `hyper` over
  DNSLink, and the Handshake path all have the same shape: the mapping is
  somebody's word, the bytes it names verify. Reporting one step hides which
  half is weak.
- **Privilege is not trust (§4.4).** `onion://` is a standard, secure,
  persistent origin *and* is never green. An implementation **MUST** derive the
  verdict from the steps, never from the scheme's registration.
- **An embedded application is two steps, not one.** `bluesky://` and
  `mastodon://` serve their own code from the application — which is the
  trustless half — and fill it with a social network's content over ordinary
  HTTPS, which is not. Reporting only the first step would let a built-in app
  present somebody else's servers as this browser's own bytes, so the verdict
  is TRUSTED and the second step names whose servers answered.

### 10.3 The ICANN name step

The step for an ordinary web address says **how the name was looked up**, and
must not let anyone assume it was oblivious
([`src/trust-path.js:449-511`](../../src/trust-path.js)).

It describes **the transport plan the engine was given**, not the static
configuration — a configuration can name resolvers the engine has stopped
using, and a panel reading it makes claims the network does not support. The
plan is decided once and recorded; the sibling ICANN chapter specifies it
([`../icann/src/dns-policy.js`](../icann/src/dns-policy.js)). The step this
part requires is one of five:

| Condition | Step |
|---|---|
| An oblivious bridge answered **this name** | `unverified` — "Oblivious DoH — relay X → target Y"; neither party alone can link the user to the lookup, and the **answer** is still their word |
| The bridge is the only resolver the engine has and did **not** answer this name, mode `secure` | `unverified` — "Oblivious bridge only — this name was not answered by it"; unencrypted DNS is refused, so the answer may have come from the engine's cache |
| The same, mode `automatic` | `unverified` — "Resolver not determined"; in automatic mode the engine falls back to unencrypted system DNS, so this lookup may have gone out in the clear |
| Mode `secure` with **no** server configured | `failed` — "Secure DNS with no server — lookups refused". The name was not looked up at all; unencrypted DNS was refused rather than used |
| Encrypted DNS configured, or no resolver / DNS off | `unverified` — names the resolver and says **NOT oblivious**, or "System DNS, unencrypted" when there is none |

An implementation **MUST NOT** describe a lookup as oblivious unless it was.
"The bridge is configured" and "the bridge answered this name" are different
claims and only the second one licenses the word. An implementation **MUST**
report a fail-closed DNS policy as a `failed` step rather than an unverified
one: nothing was resolved, and a lock over an unresolved name must not close.

### 10.4 Aggregating to a lock

The rule is **the weakest link**, and it produces **five** verdicts
([`src/trust-path.js:513-536`](../../src/trust-path.js)):

- no steps at all → **unknown**;
- any step `failed` → **failed**;
- otherwise a step labelled `Connection` in state `none` → **open**;
- otherwise any step `unverified` or `none` → **partial**, and the summary
  names the steps that were not verified;
- otherwise → **verified**.

`open` is a verdict of the **model**, not a flourish of one renderer. An
implementation **MUST** aggregate a plaintext connection to it rather than
deriving it separately where the padlock is drawn: two implementations of one
rule is how a padlock and the panel behind it come to disagree, and the one
that lacks the rule reports a plaintext page with the verdict an encrypted one
gets.

An implementation that shows a single indicator **SHOULD** distinguish three
states, not two:

| Verdict | Aggregate | Meaning |
|---|---|---|
| **TRUSTLESS** | `verified` | Nobody was believed. Every step was checked on this computer |
| **TRUSTED** | `partial` | It loaded, and something in the path rests on somebody else's assurance — *this is what an ordinary `https://` page is*, and it is also what `ar://`, `ens://` and `onion://` are |
| **OPEN** | `open`, or `failed` | The transport itself carries no protection, or a step did not pass |

An indicator that renders the first two identically is lying by omission.

The lock is **open** on exactly two conditions: the aggregate is `open`, or it
is `failed`. It is deliberately *not* "any unverified step" — an ordinary
`https://` page has one and is a closed lock. So plaintext `http://` is open,
an unresolvable name under a fail-closed DNS policy is open, and `onion://` —
whose Connection step is `unverified`, not `none` — is closed and never green.

A `failed` step **MUST NOT** aggregate to a closed lock. Where a presentation
layer can paint `partial` in the same colour as `verified`, that is a bug in
the presentation layer and **SHOULD** be pinned by a test.

Each scheme's ceiling is declared in the registry (§4.1's `trust` column) and
the two are checked against each other row by row, so the table cannot promise
a verdict the model does not produce.

The lock and the detailed panel **MUST** be computed from the same step list. A
second implementation of "is this trustworthy" in the interface is how the two
come to disagree, and a lock that disagrees with the panel behind it is worse
than no lock.

---

## 11. Security considerations

**11.1 A classifier is a disclosure decision.** Every classification chooses
who learns what the user typed. Sending `.onion` to DNS deanonymises; sending
`nas.local` to a Handshake resolver discloses a home network's device names to
whoever bought a top-level name; sending `.eth` to Handshake hands ENS traffic
to a stranger. None of these is a "wrong page" bug. An implementation
**SHOULD** review each classification branch by asking *who is told* rather
than *what loads*.

**11.2 Fail closed, inside the namespace.** A namespace that can be named but
not resolved **MUST** get a handler that refuses without touching the network
(§4.5). The temptation is to leave it unregistered and let something else pick
it up; that is exactly the cross-namespace leak.

**11.3 A malformed address in a sensitive namespace stays in it.** Validity
checks **MUST NOT** be used to route. A `.onion` address is verified properly —
the version byte and the SHA3-256 checksum of `rend-spec-v3` §6, not merely a
length test — so a mistyped address fails instantly and locally instead of
spending a circuit; and that verdict is *reported*, never used to decide the
namespace. This applies beyond `.onion`: any namespace whose addresses are
secrets has the same property.

**11.4 `classify()` is not a navigation-safety filter.** It returns
`javascript:`, `data:` and `file:` inputs untouched with a null namespace,
because L1 says an explicit scheme is authoritative and the classifier does not
get a vote. The decision carries `known: false` for exactly these, so a caller
that navigates can require `known === true`; it **MUST** still apply its own
navigation policy, because `known` says the registry has a row and not that the
scheme is a link target (`navigable: false` is a separate marker, §4.5).

**11.5 One classifier.** The host rule is **one** dependency-free module
(`src/classify-host.cjs`), written in the module system both consumers can
load: the router imports it and re-exports its predicates under their old
names, and the address bar — which is CommonJS and extends `HTMLElement`, and
so cannot import an ES module — requires the same file and carries no host rule
of its own. The two lists the rule consults are each one file read by every
consumer.

One consumer cannot load it: the WebSocket PAC script is a string evaluated
inside the browser's network stack, where there is no URL parser and no module
loader, so it embeds the two lists and an ASCII-only form of the rule. That
copy is held to this module's answers by a test which evaluates the generated
script the way the network stack does and compares its routing decision with
`classifyHost()` across a corpus (RT-7). It is the one remaining copy, and a
test comparing behaviour is a stronger mitigation than a test that reads source
text — but it is still a copy, and two implementations of one rule is precisely
how `.eth` came to mean two different things in the same browser.

**11.6 The namespace marker is a security claim.** `X-Resolution-Namespace` is
the machine-readable proof that a failure stayed where it started. An
implementation **MUST NOT** set it from a value the network controls, and
**MUST** state which vocabulary it speaks (§4.3).

**11.7 The registry table is an anti-drift device, not documentation.** Refusing
to register a scheme with no row is what stops a scheme being wired in without
a verification story. The same row is what the trust model is held to — its
`trust` column names the verdict the scheme may at best reach, and the model is
run against every row and compared with it — so an over-claim cannot be
introduced in one place alone. An implementation **SHOULD** enforce both at
registration time and by test rather than in review.

---

## 12. Conformance

An implementation conforms to this part if:

1. an explicit scheme is never re-classified (§3.1);
2. no failure produces a lookup in a second namespace (§3.2), every routed
   failure carries the namespace it stayed in (§5), and a named scheme keeps
   its namespace even when its URL will not parse (§5);
3. every dispatched scheme has a registry row naming its namespace and its
   verification story (§4.1), and is declared to the URL parser (§4.4);
4. every namespace it can name but not resolve has a fail-closed handler that
   makes no network request (§4.5);
5. bare input is classified in the order of §6.1, with `.onion` first and
   unconditional, a bare NIP-19 identifier decoded before it is claimed,
   special-use labels and IP literals before the label count, and the ICANN
   comparison made against the full IANA root list (§6.2);
6. the same classification is applied at every navigation entry point (§6.4),
   by one implementation of the host rule wherever the runtime permits one
   (§11.5);
7. special-use names are never sent to an alternative-naming resolver (§7);
8. hosts are converted to A-labels before comparison (§8.1), and — where an
   implementation adopts the experimental numeric-TLD form at all — its marker
   is applied before that conversion (§8.2);
9. every namespace reports steps in the vocabulary of §10.1, no dispatched
   scheme returns an empty step list, every registry row's `trust` claim is the
   verdict the model actually produces for that scheme (§4.1), no `partial` row
   reports the trustless state, and the lock follows the weakest link and opens
   on the rule of §10.4 — with a plaintext connection aggregating to `open` in
   the model itself.

The normative test corpus is in [`tests/`](tests/): the classification order and
its worked input table (`classification-order.test.js`), the registry and
dispatch invariants (`scheme-registry.test.js`), the fail-closed handler
(`fail-closed.test.js`), the cross-namespace trust model
(`namespace-trust.test.js`), and the `search://` grammar
(`search-url.test.js`). The Handshake-side classifier tests
(`../../tests/router.test.js`, `../../tests/hns-host.test.js`) and the trust
tests (`../../tests/trust-path.test.js`, `../../tests/lock-semantics.test.js`)
are this part's evidence too, and exercise the same modules from the spine's
side.
