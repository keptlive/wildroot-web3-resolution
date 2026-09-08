# Part II — Namespace selection

**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in this
repository, which ships in the Wildroot browser. Not endorsed by any standards
body. Normative statements below describe what an implementation must do *to
interoperate with this one*; where they are inherited from an existing
standard, that standard is cited and its rule governs.
**Licence:** CC-BY-4.0 (see `../../LICENSE-SPEC`). The reference implementation
is licensed separately.

This part specifies namespace selection, dispatch, and the shared trust model.
Start with the [overview](../../SPEC.md), then use this chapter to determine
which namespace handles an input. Resolution is specified in the corresponding
namespace chapter.

**Review status:** [REVIEW.md](../../REVIEW.md) records unresolved technical
questions. This revision updates documentation only.

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

[Deviations and open questions](DEVIATIONS.md) use the `RT` prefix.
[References](REFERENCES.md) lists the standards and implementation dependencies.

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

A client supporting several naming systems must assign each input to one
namespace before resolution and keep failures within that namespace.

Incorrect classification can disclose a name or send it to a different owner:

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

The registry defines supported schemes (§4); dispatch confines failures (§5);
classification selects the namespace (§6–§8); and trust steps report the result
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

This chapter specifies routing. Namespace handlers perform resolution.

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

L1 and L2 are the routing requirements used throughout this chapter.

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
   ([`src/router.js`](../../src/router.js)).
2. **In the classifier.** The first thing `classify()` does with a non-empty
   input is test for an explicit scheme and return the input untouched
   ([`src/router.js`](../../src/router.js)).

An explicit decision includes `known`, indicating whether the scheme has a
registry row. Navigating callers **SHOULD** require `known === true` and **MUST** apply their
own navigation policy; `javascript:`, `data:` and `file:` return `known: false`
(§11.4).

An implementation **MUST** distinguish a scheme from the `host:port` shape. An
input matching the scheme grammar whose remainder is a bare port number
(`example.com:8080`, `localhost:3000`) is a host, not a scheme, unless the
token is a scheme the registry knows
([`src/router.js`](../../src/router.js)). See RT-4 for the case this
gets wrong.

### 3.2 L2 — no silent cross-namespace fallback

> A failure in one namespace surfaces as *that namespace's* failure. An
> implementation **MUST NOT** retry the same input in a second namespace,
> whatever the first one answered.

This specification adopts the namespace-precedence rule in RFC 9498 §9.10
(originally specified for GNS). For example, an HNS SERVFAIL does not trigger
an ICANN lookup, and an ENS name without a contenthash does not trigger a
Handshake lookup.

L2 is enforced structurally in two ways:

- **The classifier returns one namespace and one reason.** There is no list of
  candidates, no ordering to fall through, and no second guess
  ([`src/router.js`](../../src/router.js)).
- **The dispatcher has no path that calls a second handler.** All four of its
  outcomes (§5) stay inside the scheme that was named.

An implementation **SHOULD** emit a machine-readable marker on every routed
failure naming the namespace it stayed in, so the trust layer can *show* that
no fallback occurred. Ours is the `X-Resolution-Namespace` response header,
which speaks the scheme table's vocabulary (§4.3).

### 3.3 The one allowed "fallback", and why it is not one

Changing transports can stay within the same namespace. The Handshake handler
may retry an eligible chain-path failure through a Handshake-aware DoH resolver
(Handshake §9.1). A synced chain's authoritative `unregistered` result is final
and must not be overridden by DoH.

An implementation MAY offer this transport downgrade. It **MUST** report the
downgraded step as `unverified` and **MUST** identify the resolver it relies on.
The router does not choose transports within a namespace.

## 4. The scheme registry

### 4.1 The table is the single source of truth

Every scheme the implementation serves has exactly one row in a table that
records its **namespace**, its **maturity**, its **verification story** — the
native layer that authenticates the canonical object — and the **trust verdict
it can at best reach**. The router does not perform verification; it *names*
it, so that no scheme can be wired in without one. Registration of a scheme
with no row **MUST** be refused
([`src/router.js`](../../src/router.js)).

The registry description and the trust model are checked together in
`tests/namespace-trust.test.js`. The description must state verification gaps,
including gateway-trusted Arweave bytes and RPC-trusted ENS records.

`trust` states the same fact as a verdict rather than as a sentence, in the
vocabulary of §10.4, so that the claim is machine-checkable:

| `trust` | The verdict a page in this scheme aggregates to |
|---|---|
| `trustless` | `verified` — every step was checked here |
| `trusted` | `partial` — the transport is protected and something in the path is somebody's word |
| `open` | `open` — the connection itself carries no protection |
| `refused` | `partial`, with **no** verified step: a fail-closed stub verifies nothing |
| `builtin` | `verified` — the page came from the application and never touched the network |

The lock-semantics tests compare each registry row with the trust model at a
sample URL. An implementation **SHOULD** apply an equivalent consistency check.

`status` describes implementation maturity:

| Status | Meaning |
|---|---|
| `live` | handler shipped and wired |
| `partial` | handler exists and works, with a named gap in what it verifies |
| `planned` | greenfield; a fail-closed stub registers so dispatch fails *inside* the right namespace (§4.5) |

A `partial` row **MUST NOT** report the trustless lock state (§10.4).

### 4.2 The table

32 rows, 18 namespaces. Reproduced from
[`src/router.js`](../../src/router.js). The **Trust** column is the
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

Two distinctions affect scheme registration:

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

The classifier uses `icann` for an ordinary DNS name, but `https` belongs to
`web` in the scheme table:

```js
classify('example.com').namespace === 'icann'
namespaceForScheme('https') === 'web'
```

`X-Resolution-Namespace` uses the scheme table's vocabulary, so the marker for
that navigation is `web`. An implementation **MUST** document the vocabulary
used by its marker. RT-5 records the unresolved split between classification
and dispatch identifiers.

### 4.4 Scheme privileges

In Chromium (and therefore in Electron, via
[`protocol.registerSchemesAsPrivileged`](https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes)),
a custom scheme is inert until it is declared **before application startup**.
Two properties matter for resolution:

- **`standard: true`** gives the custom scheme Chromium’s standard-scheme
  parsing and origin behavior. This is an Electron extension, not an addition
  to WHATWG’s fixed special-scheme list. Host parsing constrains numeric
  labels (§8.2). Storage, fetch support, and service-worker permissions also
  depend on the applicable privilege flags.
- **`secure: true`** marks the scheme as a secure context. It does not set
  the trust verdict. An implementation **MUST NOT** derive trust from privilege
  flags; `onion` is standard and secure but reports TRUSTED, while plaintext
  `http` reports OPEN.

An implementation **MUST** declare every custom scheme it dispatches before
startup. The browser’s `src/main.cjs` maintains these declarations separately
from the registry; RT-D1 proposes generating them from shared data.

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

`stream` enables streaming behavior needed by media responses, including
range playback.

`hns` and `onion` use persistent origins with service workers disabled. The
`ar` and `ens` registrations use opaque origins and do not opt into secure
contexts. Registration flags are independent of the trust verdict.

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
crosses a namespace ([`src/router.js`](../../src/router.js)):

| Outcome | Response | Namespace marker |
|---|---|---|
| The URL does not parse **and names no scheme** | `400` | none — no scheme was established (RT-12) |
| No handler registered for the scheme | `501`, body naming the scheme | the scheme's namespace, or the scheme itself when it has no row |
| The handler returns — **including a 404 or a 500** | that response, verbatim | whatever the handler set |
| The handler throws | `502`, body carrying the error | the scheme's namespace |

A named scheme keeps its namespace even if WHATWG URL parsing fails. The
dispatcher falls back to reading the scheme prefix. This supports forms such
as `at://did:plc:…/…`, whose authority is not a WHATWG host. An implementation
**MUST** attribute any failure to the named scheme rather than lose the
namespace during error reporting.

A `404` from the Handshake handler is a Handshake `404`. It is **not** retried
as an ICANN lookup, and an implementation **MUST NOT** interpose a "did you
mean" retry at this layer.

The `501` body **SHOULD** state that no other protocol will be attempted.

---

## 6. Classification of bare input

Input: a string with no scheme, as typed. Output: exactly one decision —

```
{ url, scheme, namespace, explicit, reason }
```

with `known` added when `explicit` is true (§3.1) and `validV3` added for a
`.onion` host (§6.1).

An implementation **SHOULD** carry `reason` through to the interface so the
classification can be explained.

### 6.1 The order

The decision is made **once**, in this fixed order; the first match wins and is
final ([`src/router.js`](../../src/router.js)):

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
   ([`src/classify-host.cjs`](../../src/classify-host.cjs)):
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
   7. **an all-numeric final label** → Handshake only when numeric names
      are enabled; otherwise `web`. The feature is off by default (§8.2).
   8. **a final label in the ICANN root** → the ICANN namespace, `https://`.
      `reason: icann-tld`.
   9. **anything else** → Handshake. `reason: hns-tld`.
9. **A single bare label** (step 8.6), and no whitespace anywhere in the input:
   Handshake **unless the label is itself an ICANN top-level domain**, in which
   case search. All-digit labels also select search while numeric names are
   disabled. `reason: hns-bare-label` or `search`.
10. **Anything else** — in practice anything containing whitespace — search.
    `reason: search`.

Ordering constraints:

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
  ([`src/classify-host.cjs`](../../src/classify-host.cjs)).
- **A NIP-19 identifier is decoded before it is claimed, and `nsec` is routed
  on purpose.** The prefix alone is not enough: a Handshake name that merely
  begins `npub` must stay a name, so the branch runs the bech32 decode
  (`decodeNip19`) and only claims the input when the 30-bit checksum holds —
  which makes a false positive a 1-in-2³⁰ event rather than a guess. The one
  exception is `nsec`: a secret key is claimed on its prefix, without waiting
  for a decode that is *designed* to fail, because the alternative is the
  bare-label rule transmitting the secret to a resolver as a name. Routed to
  the Nostr namespace it reaches the handler's "that is a PRIVATE KEY" refusal
  instead ([`src/router.js`](../../src/router.js), and
  [Chapter 6 — Nostr](../nostr/SPEC.md) §5.3).
  The identifier must be the **whole** input: an identifier carrying a path or
  a trailing slash is not matched and falls through to the host rules
  ([Chapter 6's `DEVIATIONS.md`](../nostr/DEVIATIONS.md) `NO-13`).

### 6.2 The host rule, in one sentence

After the exclusions in §6.1, a dotted host belongs to ICANN if its final
label is in the delegated IANA root list; otherwise it belongs to Handshake.

The comparison **MUST** use the full IANA list. The bundled snapshot contains
1,438 A-labels ([`src/icann-tlds.cjs`](../../src/icann-tlds.cjs)) and **SHOULD**
be checked periodically against IANA. An abbreviated list misroutes domains
under omitted TLDs such as `.blog`, `.link`, and country-code TLDs.

ICANN takes precedence even if the same label has been claimed on Handshake.
This product policy differs from Handshake's root model (HS-13, IC-2).

### 6.3 The single bare label

A single label such as `pinner`, `hnshosting`, or `🤝` selects Handshake
unless it is itself an ICANN TLD. An all-digit label such as `14898` selects
search unless numeric names have been enabled. Bare ICANN labels such as `com`,
`org`, and `app` select search.

This is a product decision; another implementation MAY choose a different
default. Mistyped words can become name lookups and be disclosed to a resolver.
An implementation using this rule **SHOULD** offer search as a visible second
choice and **SHOULD** account for that disclosure (RT-3).

Whitespace anywhere in the input **MUST** exclude it from the bare-label rule
([`src/router.js`](../../src/router.js)).

### 6.4 The `http→hns` rewrite

An implementation **MUST** apply host classification at every navigation
entry point: typed input, link clicks, restored tabs, and programmatic loads.
For main-frame HTTP(S) URLs, a Handshake host is rewritten to `hns`, preserving
the other URL components. An ENS or onion host **MUST** be rewritten to its
corresponding carrier scheme. The shared `classifyHost()` function supplies
the decision ([`src/hns-host.js`](../../src/hns-host.js)).

A single label in a URL authority is already a navigation target. Thus
`http://hnshosting/` is treated as a Handshake host, although `classifyHost()`
leaves a bare single label for the input classifier to decide.

This rewrite consults the host of an explicit HTTP(S) URL. The scope of L1
(§3.1), which forbids overriding an explicit scheme, therefore needs
clarification. Both requirements are retained here pending that decision.

### 6.5 Pasted content addresses

The classifier recognises a complete bare CID without a scheme:

- A CIDv0 is converted to CIDv1 base32 before use as a host. CIDv0's
  case-sensitive base58 spelling would be damaged by host lowercasing
  ([`src/router.js`](../../src/router.js)).
- A legacy IPNS key can have the same `Qm…` spelling as a CIDv0. An IPNS name
  **MUST** therefore use `ipns://…` or `/ipns/…`.

## 7. Special-use names

The labels below **MUST NOT** be sent to an alternative-naming resolver.
This prevents local service names from reaching a public namespace operator.

The labels this implementation refuses
([`src/reserved-names.cjs`](../../src/reserved-names.cjs)), and their
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
([`src/reserved-names.cjs`](../../src/reserved-names.cjs)).

The classifier, address bar, and WebSocket PAC generator read the same list.
Reserved hosts select `web` with `http://`; `.onion` is handled earlier and
selects Tor. The additional local-network conventions are documented in RT-1.

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
([`src/classify-host.cjs`](../../src/classify-host.cjs)). What that delivers is
therefore **UTS #46 as the WHATWG URL Standard specifies it**, not IDNA2008 as
RFC 5891 specifies it. The two differ on the deviation characters and on
transitional processing. We have not audited which Handshake labels this can
affect (spine `../../DEVIATIONS.md` D-17).

The conversion **MUST NOT** fail open. Ours does: when the URL parser rejects
the host, the raw final label is used for the ICANN comparison instead. See
RT-11 and RT-D5.

### 8.2 The numeric top-level name — EXPERIMENTAL

Numeric Handshake names are **off by default**. The host classifier exposes
`setNumericNames()`; the documented browser setting is
`hnsOptions.numericNames`. Chapter 10, Part B defines the optional `_` marker
form and its `NT` deviations.

With the feature off, a dotted numeric-final-label host selects `web`, while
a bare all-digit input selects search. With it on, those inputs can select
Handshake. The web classification does not make an invalid HTTP URL valid.

The custom standard-scheme host parser can interpret `14898` as IPv4
`0.0.58.50`, and reject `hello.14898`. When constructing an enabled numeric
Handshake URL, apply the marker **before** the URL parser's IDNA pass
(`src/router.js`, `src/hns-url.cjs`).

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

The host selects one of the metasearch categories: `web` (default),
`academic`, `code`, `wiki`, or `custom`
([`src/search-url.js`](../../src/search-url.js)).

**A standard custom-scheme URL MUST have a host.** The implementation
**MUST NOT** create hostless URLs for these schemes; they are invalid for
the parser and can break history or session restoration.

An implementation **SHOULD** accept legacy spellings and rewrite them rather
than 404 them, since old bookmarks, history rows and saved provider templates
carry them: `search://?q=x&cat=y`, bare `search://`, and `search://<terms>`
with the query in the host position are all read and canonicalised
([`src/search-url.js`](../../src/search-url.js)). An unparseable
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

All namespaces use the following trust states and aggregation rules.

### 10.1 Steps and states

A resolution — in *any* namespace — produces an ordered list of **steps**. Each
step says what was checked, **who told us**, and one of four states:

| State | Meaning |
|---|---|
| `verified` | checked cryptographically, in this process, in this resolution |
| `unverified` | relies on an external resolver, CA, RPC endpoint, gateway, or network service |
| `failed` | checked and did not pass |
| `none` | does not apply, or is absent and *known* to be absent |

An implementation **MUST** expose these steps, or an equivalent structure,
to the interface and **MUST NOT** reduce them to a boolean. The `source`
field identifies the evidence or party each step relies on.

The Handshake step list is specified in the spine's [SPEC §4](../../SPEC.md)
and is not restated here. This section specifies the **cross-namespace**
model — what every *other* scheme reports
([`src/trust-path.js`](../../src/trust-path.js)).

### 10.2 The per-scheme step lists

The model selects a step list by scheme; the default states that no
verification path is available.

The model chooses a step list by scheme, using the prefix when full URL
parsing fails. This keeps forms such as `at://did:plc:…` in their namespace.
Only an unparseable input with no scheme produces an `Address` `failed` step.

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

Requirements for the step lists:

- **A namespace with no verification path gets a step saying so.** An empty
  step list aggregates to "nothing is known", which a naive interface renders
  as neutral; a `none` step with a stated source renders as unverified. An
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
([`src/trust-path.js`](../../src/trust-path.js)).

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
([`src/trust-path.js`](../../src/trust-path.js)):

- no steps at all → **unknown**;
- any step `failed` → **failed**;
- otherwise a step labelled `Connection` in state `none` → **open**;
- otherwise any step `unverified` or `none` → **partial**, and the summary
  names the steps that were not verified;
- otherwise → **verified**.

An implementation **MUST** aggregate a plaintext connection to `open` in
the shared model, so the indicator and detailed panel report the same result.

An implementation that shows a single indicator **SHOULD** distinguish three
states, not two:

| Verdict | Aggregate | Meaning |
|---|---|---|
| **TRUSTLESS** | `verified` | Nobody was believed. Every step was checked on this computer |
| **TRUSTED** | `partial` | It loaded, and something in the path rests on somebody else's assurance — *this is what an ordinary `https://` page is*, and it is also what `ar://`, `ens://` and `onion://` are |
| **OPEN** | `open`, or `failed` | The transport itself carries no protection, or a step did not pass |

The indicator must distinguish local verification from reliance on another party.

The lock is **open** on exactly two conditions: the aggregate is `open`, or it
is `failed`. It is deliberately *not* "any unverified step" — an ordinary
`https://` page has one and is a closed lock. So plaintext `http://` is open,
an unresolvable name under a fail-closed DNS policy is open, and `onion://` —
whose Connection step is `unverified`, not `none` — is closed and never green.

A `failed` step **MUST NOT** aggregate to a closed lock. Where a presentation
layer can paint `partial` in the same colour as `verified`, that is a bug in
the presentation layer and **SHOULD** be pinned by a test.

The registry declares the expected trust verdict; tests compare it with the
model for each scheme (§4.1).

The lock and detailed panel **MUST** use the same step list.

---

## 11. Security considerations

**11.1 Classification and disclosure.** Classification determines who can
learn the input. Misrouting `.onion`, local names, or `.eth` can disclose a
name or send traffic to a different owner. An implementation **SHOULD** review
the recipient of each classification branch.

**11.2 Unsupported namespaces.** A namespace that can be named but not resolved
**MUST** have a handler that refuses without making a network request (§4.5).

**11.3 Malformed sensitive addresses.** Validity checks **MUST NOT** select a
different namespace. Onion validation checks the version byte and SHA3-256
checksum from `rend-spec-v3` §6; an invalid address is refused locally within
Tor. The same isolation applies to other namespaces carrying sensitive input.

**11.4 Navigation policy.** `classify()` preserves explicit schemes, including
`javascript:`, `data:`, and `file:` with `known: false`. A navigating caller
**MUST** apply its own policy. `known` means registered; it does not mean
navigable. `media` and `docview`, for example, have `navigable: false`.

**11.5 Shared classification.** The router and address bar load
`src/classify-host.cjs`, which reads the shared ICANN and reserved-name lists.
The WebSocket PAC script cannot load the module or use its URL parser, so it
contains an ASCII-only copy. Tests compare the generated PAC's decisions with
`classifyHost()` across a shared corpus. Untested host forms remain a drift
risk (RT-7).

**11.6 Namespace marker.** An implementation **MUST NOT** derive
`X-Resolution-Namespace` from a network-controlled value and **MUST** document
its vocabulary (§4.3). The marker identifies the routed failure; it is not
independent proof that no other request occurred.

**11.7 Registry consistency.** An implementation **SHOULD** reject schemes
without a registry entry and test each entry against its trust model. This
keeps the declared verification properties consistent with reported steps.

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
