# Chapter 8 — Tor

**Namespace:** `tor` · **Schemes:** `onion:` · **Addresses:** `<56-char v3>.onion`
**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in
`namespaces/tor/src/`, which ships in the Wildroot browser. Not endorsed by any
standards body, and emphatically not by the Tor Project. Normative statements
below describe what an implementation must do *to interoperate with this one*;
where they are inherited from an existing standard, that standard is cited and
its rule governs.
**Licence:** CC-BY-4.0 (see `../../LICENSE-SPEC`). The reference implementation
is licensed separately.

This chapter is part of the integrated specification whose spine is
[`../../SPEC.md`](../../SPEC.md), where namespace selection — which identifier
belongs to which namespace, and the two routing laws that keep the boundary —
is specified. This chapter adds the namespace whose whole character is that
**its address is a public key and there is no name system underneath it at
all**. Its deviations and open questions are in
[`../../DEVIATIONS.md`](../../DEVIATIONS.md) under the `TO-` prefix, and the
standards it reads are in `REFERENCES.md` beside this file; both are part of
the specification, not appendices to it.

---

## Contents

1. [What this specifies, and why it exists](#1-what-this-specifies-and-why-it-exists) — including [**scope**](#11-scope)
2. [Terminology](#2-terminology)
3. [Namespace selection: `.onion` is decided first](#3-namespace-selection-onion-is-decided-first)
4. [The address](#4-the-address)
5. [The `onion://` URL form](#5-the-onion-url-form)
6. [The resolution algorithm](#6-the-resolution-algorithm)
7. [The circuit: device-local, or nothing](#7-the-circuit-device-local-or-nothing)
8. [Trust state](#8-trust-state)
9. [Security and privacy considerations](#9-security-and-privacy-considerations)

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## 1. What this specifies, and why it exists

Every other chapter in this specification answers the question *"what does this
name mean, and how sure are we?"* — a lookup, a proof, a record, a trust state.
The Tor chapter answers a different question, because it does not have that
one. **An onion address is not a name that resolves to a key. It is the key.**

A v3 onion address is the base32 encoding of an Ed25519 public key, a checksum
over it, and a version byte (Tor rend-spec-v3 §6). Reaching the service means
Tor's rendezvous protocol proves possession of the corresponding private key
inside the circuit; there is no directory to consult, no signature for a client
to check afterwards, and no way for a wrong service to answer. The
authentication is not *verified by the resolver* — it is **structural**, done by
the transport, and it either happens or the connection does not.

So the whole security problem moves. There is nothing to get wrong about the
*answer*. What can be got wrong is the **question**: a DNS lookup containing an
onion address discloses, to a resolver and to everything on the path to it,
which hidden service somebody tried to reach. **No lock state undoes that
disclosure.** It is not a weaker answer; it is a fact about the user that has
already left the machine.

That is why this chapter is mostly a specification of things that MUST NOT
happen, and why the classifier that decides which namespace a host belongs to
is a security boundary here rather than a routing convenience.

The second thing this specifies is a rule that is ours, not Tor's, and is the
reason this chapter is a *design* document and not just a wiring note:

> **An onion address is reached through a Tor client running on the user's own
> device, or it is not reached at all.**

No hosted relay, no operator-run SOCKS endpoint, no `.onion`-to-web gateway,
however convenient. Every one of those substitutes "trust us" for the property
the user came for, and every one of them learns which hidden service was asked
for. A browser that offers the second thing while saying the first is lying, and
this is one of the places we would rather be less capable than dishonest.

### 1.1 Scope

**In scope: turning a `.onion` address into a request that leaves the machine
only inside a device-local Tor circuit, or into an honest refusal.** Precisely:

- **classification** — which inputs belong to this namespace, and the rule that
  nothing in it may ever be handed to a name resolver (§3);
- **address validation** — the four checks rend-spec-v3 §6 specifies, where
  their result is allowed to matter, and where it must not (§4);
- **the URL form** the browser carries an onion address in (§5);
- **the gate** — the policy state under which a request is issued at all, what
  is sent into the service, what comes back out, and what happens to a redirect
  (§6);
- **how a circuit is obtained**, to the extent resolution depends on it: the
  availability states, and the leak-safety property that makes it correct to
  route before the circuit is ready (§7);
- **the trust state** an interface is given, and the claims it must not make
  (§8).

**Out of scope, explicitly:**

| Out of scope | Why it is a different document |
|---|---|
| **The Tor protocol itself** — circuits, the rendezvous handshake, descriptors, the directory system, guard selection, congestion control | Cited (REFERENCES §1), never restated. §9.1 states exactly what an implementation may conclude from a completed circuit, which is the only part a resolver needs. |
| **Tor client management beyond what resolution requires** — packaging and provenance of the binary, supervision, recovery, the bootstrap UI | The parts resolution depends on are the *availability states* and the *SOCKS endpoint* (§7). Everything else is the browser's process management. Included in `src/tor.js` for completeness and marked as such. |
| **Anonymity as a property of the browser** — fingerprinting resistance, tab/circuit isolation, timing defences, the Tor Browser threat model | We do not have it, we say so in the product, and §9.3 says so here. Claiming otherwise would be the most damaging thing in this document. |
| **Publishing an onion service** | The read path only. This implementation is a client and its `torrc` contains no `HiddenService` line. |
| **What the page does once it loads** — rendering, storage, permissions | Except for §8, which specifies the trust state, and §9.4, which is about the origin the content is given. |

A consequence worth stating plainly: an implementation of this chapter is a
**gate and a router**, not a resolver. There is nothing to resolve.

---

## 2. Terminology

Terms are used as in [`../../SPEC.md`](../../SPEC.md), plus:

- **Onion address** — the string `<label>.onion`, where for version 3 `<label>`
  is 56 characters of RFC 4648 base32. Defined by Tor rend-spec-v3 §6.
- **Onion service key** — the Ed25519 public key that *is* the address, modulo
  the encoding of §4.
- **v3** — the current onion service protocol. **v2** (16-character addresses,
  1024-bit RSA) was deprecated in 2020 and removed from Tor in 2021. It is dead;
  an implementation MUST NOT treat a v2 address as valid.
- **Circuit** — a Tor path. Here it always means one built by a Tor client
  process on the user's own device.
- **The gate** — the policy decision, taken before any network activity, of
  whether a request may be issued at all (§6.3).
- **IP Protection** — the state in which the session proxy is the device-local
  Tor SOCKS endpoint (or, when that cannot be had, the blackhole of §7.6). It is
  the gate's only input. It is **not a control of its own**: it is driven by
  **Settings › Content delivery › Mode** — `Private` turns it on, `Fast` turns
  it off — one switch with two handles, the settings page and the Privacy menu,
  both ending in `DeliveryMode.set()` (`../../src/delivery-mode.js`,
  `../../SPEC.md` §4.2). The name leads with what a user gets ("hide my IP")
  rather than with the technology.
- **BLOCKED** — the controller's third state (`MODES.BLOCKED`): protection was
  asked for and Tor cannot be had, so every session is pointed at a loopback
  port nothing listens on (§7.6). Nothing loads; nothing leaks.
- **The blackhole** — that port: `BLACKHOLE_RULES`, `socks5://127.0.0.1:9`.
- **Structural authentication** — authentication a client obtains by
  construction rather than by checking something. §4 and §9.1 turn on this
  distinction.

Note what is *absent* from this vocabulary and present in every other chapter:
there is no record, no zone, no signature, no proof, no anchor, and no NODATA.
Nothing is looked up.

---

## 3. Namespace selection: `.onion` is decided first

`.onion` is a special-use domain name (**RFC 7686**). RFC 7686 §2 requires that
applications and resolvers **not** resolve it in DNS, and that caching resolvers
and authoritative servers answer NXDOMAIN for it. This chapter takes the
application half of that as its first rule, and strengthens it.

> **R1.** A host whose final label is `onion` is in the `tor` namespace. It MUST
> NOT be sent to any name resolver — not DNS, not DoH, not Oblivious DoH, not a
> Handshake chain query, not a search engine.

> **R2.** R1 applies to a **malformed** onion address exactly as it applies to a
> valid one. Validity MUST NOT be a condition of the routing decision.

R2 is the rule that is easy to get wrong and expensive to get wrong. If an
implementation classifies only *well-formed* onion addresses into this namespace
and lets the rest fall through to its default resolver, then a typo, a truncated
paste, a v2 address, or a deliberately malformed link is sent to DNS — and a
typo'd onion address in a query log identifies the intended service just as well
as a correct one. The intent is the disclosure, not the accuracy.

Accordingly the classifier matches `.onion` **first and unconditionally**,
before the ENS suffix check, before the reserved-name list, before the
IP-literal check, and before the ICANN root list is consulted at all:

```js
// ../../src/classify-host.cjs:116-119
// .onion FIRST and unconditionally: a v3 onion goes to Tor and MUST NEVER be
// sent to DNS/ODoH (L1). Even a malformed .onion stays in the Tor namespace
// (it fails as a Tor address, not as a DNS miss) — never leaked to a resolver.
if (isOnionHost(host)) return NAMESPACES.TOR
```

`isOnionHost` is a suffix test and nothing more (`/\.onion$/i`,
`../../src/classify-host.cjs:58-60`). That is deliberate: R2 requires that the guard be
*weaker* than a validity check, not stronger.

`onion` is also a row in the one reserved-name list
(`../../src/reserved-names.cjs:31`, RFC 6761/6762/7686/8375), which the
classifier consults immediately **after** the `.onion` test
(`../../src/classify-host.cjs:128`). Both orderings are load-bearing: the reserved-name
row would otherwise send an onion host to the web namespace as though it were
`nas.local`, and its absence would make `.onion` a Handshake name for any code
path that reaches the list without the suffix test.

### 3.1 Four entry points, one rule

A host reaches the network through more than one door, and R1 has to hold at all
of them. In this implementation there are four, and a miss at any one is a leak:

| Entry point | Mechanism | Result for `<addr>.onion` |
|---|---|---|
| **Typed input** | `classify()` — `../../src/router.js:364` | `onion://<addr>.onion` |
| **Link click / main-frame navigation** on `http(s)://<addr>.onion/` | `rewriteToHns()` via `reservedNamespaceScheme()` — `../../src/hns-host.js:50`, `:85` | rewritten to `onion://…` before the load |
| **Subresource** (`<img>`, `<script>`, `fetch`) on an onion host | `decide()` — `src/subresource-guard.js:35-54` | **cancelled**: zero network, zero DNS |
| **Handshake classification** | `isReservedHost()` — `../../src/reserved-names.cjs:36`, re-exported at `../../src/hns-host.js:30` | never a Handshake name |

`tests/onion-leak-guard.test.js` drives one address through all four.

An implementation **MUST** enumerate its own entry points and cover every one.
The subresource case is the one that is most often missed and is the worst to
miss: a main-frame rewrite is visible to the user, whereas a tracking pixel
pointed at an onion host leaks silently on every page view. In this
implementation the network-layer guard runs before the ad blocker for the same
reason — a filter list must never be able to downgrade a security decision
(`src/subresource-guard.js:22-24`).

**One listener, three gates.** Electron allows exactly one
`webRequest.onBeforeRequest` per session, so everything that must decide before
a request is issued lives in this single listener
(`installSubresourceGuard`, `src/subresource-guard.js:74-110`) or it does not
exist at all. It registers for five URL patterns and dispatches them to three
separate authorities, which do not see each other's traffic:

| Requests | Authority | Enters the ad blocker? |
|---|---|---|
| `ws://`, `wss://` | the injected `websocketPolicy(details)`, first, before anything else (`:82-86`). Chapter 11 §4 specifies it | no |
| `wildroot://` | the Wildroot API gate, answered by the asking WebContents' id rather than by any header (`:87-95`) | no |
| `http://`, `https://` | `decide()` — this chapter's leak guard — then the blocker as `next` (`:96-108`) | yes, and only what the guard passed |

> **R18.** A privacy gate composed into a shared listener **MUST** fail closed
> on its own fault. A `websocketPolicy` that throws yields `{cancel: true}`
> (`src/subresource-guard.js:83-85`): a policy that cannot decide has not
> decided that the request is safe.

The asymmetry with the ad blocker is deliberate and is the rule stated twice: a
blocker fault fails **open** (`:100-108`), because the guard has already had its
say and an allow can only miss an advertisement, while a privacy-policy fault
fails **closed**, because an allow there is a request that leaves the machine.
What the WebSocket policy itself decides is Chapter 11's (`../apps/SPEC.md`
§4), not this chapter's; what is specified here is that it is consulted first,
that it is the only reader of `ws:`/`wss:` in the listener, and that its failure
cancels.

*(`tests/onion-leak-guard.test.js`, "the one listener covers ws:// and wss:// as
well as http(s) and wildroot://", "a WebSocket is answered by the WebSocket
policy alone", "a WebSocket policy that throws fails CLOSED", and "a blocker
fault fails OPEN, and only there".)*

### 3.2 An explicit scheme still wins

R1 governs *classification of a bare host*. It does not override the router's
first law. A user who types `https://<addr>.onion/` has named a protocol, and
that input stays on `https:`; it will simply fail, as HTTPS, without an onion
circuit. An implementation MUST NOT re-sniff an explicit scheme out of the host
— sniffing is how `https://` silently becomes something else, and that is a
worse property than a failed page.

The consequence is honest but worth stating: **R1 does not protect a user who
explicitly asks for an onion address over another scheme.** In this
implementation the subresource guard closes that hole for subresources (it acts
on the host regardless of scheme) but not for a top-level `https://<addr>.onion/`
the user typed themselves. See [`../../DEVIATIONS.md`](../../DEVIATIONS.md)
TO-2.

---

## 4. The address

### 4.1 What rend-spec-v3 specifies

A v3 onion address encodes 35 bytes (rend-spec-v3 §6):

```
onion_address = base32( PUBKEY ‖ CHECKSUM ‖ VERSION ) ‖ ".onion"

  PUBKEY   = the 32-byte Ed25519 master public key of the service
  VERSION  = one byte, 0x03
  CHECKSUM = SHA3-256( ".onion checksum" ‖ PUBKEY ‖ VERSION )[:2]
```

35 bytes is 280 bits, which is exactly 56 base32 characters, so the encoding is
unpadded and every 56-character base32 label decodes cleanly to 35 bytes. The
alphabet is RFC 4648 §6 base32 (`A`–`Z`, `2`–`7`), lower-cased by convention;
addresses are compared case-insensitively.

A complete client-side validation is therefore four checks: **length**,
**alphabet**, **version byte = 3**, **checksum**. The first two are a shape; the
last two are the only ones that can catch a corrupted address.

### 4.2 What this implementation checks

All four (`isValidV3Onion`, `../../src/router.js:240-262`). The shape is one
regular expression; the label is then decoded five bits at a time into the 35
bytes, the version byte is compared against `3`, and the first two bytes of
`SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)` are compared against the
checksum bytes. Case is folded first, so an address typed in capitals is the
same address.

`tests/onion-address.test.js` checks the implementation against a
reference decoder written separately from rend-spec-v3, so that the validator is
compared with the specification rather than with itself: two published v3
addresses pass both, a single flipped character in either one fails both at the
checksum, and `aaaa…a.onion` — 56 legal base32 characters — fails both at the
version byte.

v2 addresses (16 base32 characters, RSA-1024, truncated-SHA-1 addresses) fail
the length check, which is correct: they are removed from Tor and unreachable.

### 4.3 Where validity is and is not used

> **R3.** Address validity MUST NOT gate routing (R2). It **MAY** gate
> *reachability* — refusing to build a circuit for an address that cannot
> possibly exist — provided the refusal stays inside the `tor` namespace.

Both halves are implemented. The classifier reports validity as a fact about a
decision it has already taken on the suffix alone (`classify()` returns
`validV3: isValidV3Onion(host)`, `../../src/router.js:364`), and the handler
consumes it: an address whose version byte or checksum does not match is refused
`400` with a page saying so, **before any circuit is asked for**
(`src/onion-protocol.js:123-127`). Nothing was sent, the refusal carries
`X-Resolution-Namespace: tor`, and no other namespace is tried.

This is a **usability** property, not a security one — §9.2 explains why — and
an implementation of this chapter **SHOULD** do the same, because the checksum
exists precisely to catch the corrupted-address case locally instead of spending
a circuit discovering it.

The check runs **before the gate** (§6.3), so a malformed address is answered
the same way whether IP Protection is on or off. Both answers are generated
locally; neither costs a request.

---

## 5. The `onion://` URL form

An onion address has no natural URL scheme. Tor Browser uses `http://` and
`https://` on the onion host and relies on the whole browser being configured
for Tor. Wildroot is not; it is a general browser in which the Tor path is one
mode among several, so the namespace needs to be visible in the URL itself.

> **R4.** This implementation carries onion addresses in an internal scheme,
> `onion://<host>[:port][/path][?query]`. It is a **carrier**, not a wire
> protocol: nothing outside the browser speaks it, and the request that leaves
> the machine is an ordinary `http://` request to the onion host (§6.4).

> **R16.** `onion://` means **HTTP inside Tor**, and nothing else. The scheme
> has no way to express TLS: there is no `onion+tls`, no flag, and an
> `onion://` URL's port is the HTTP port. An implementation **MUST NOT** encode
> an `https:` target as `onion://` — doing so silently downgrades the transport
> while the address bar goes on showing the same origin — and a transition that
> would remove TLS **MUST** be refused rather than performed (§6.5, R17). The
> consequence is stated rather than hidden: an onion service that serves only
> HTTPS is unreachable in this browser
> ([`../../DEVIATIONS.md`](../../DEVIATIONS.md) TO-8).

Parsing (`parseOnionUrl`, `src/onion-protocol.js:54-74`) uses the WHATWG URL
parser, which is the right tool because `onion:` is registered as a standard
scheme. It returns three fields:

- **host** — `u.hostname`, lower-cased, never carrying the port;
- **port** — `u.port`, empty when the URL names none;
- **path** — `u.pathname` + `u.search`, defaulting to `/`. Because `onion:` is
  not one of WHATWG's *special* schemes, a query-only URL has an empty path and
  the query alone becomes the path — which is what `http://<host>?q=1` means in
  any case.

The **fragment is dropped** before the request is built. This is correct and
worth doing deliberately: a fragment is the client's business and an onion
service has no reason to receive one. The URL parser drops it for free.

A string the parser refuses falls back to a hand split that returns the same
three fields, so a malformed address fails closed inside the handler rather than
throwing out of it.

The scheme is registered with Chromium as `standard` + `secure` (the browser's
`src/main.cjs`, not in this package), which gives an onion page a real,
non-opaque, per-host origin — `localStorage`, `sessionStorage` and
`crypto.subtle` work, so real web applications do not crash. `secure: true`
makes it a secure *context*; it does **not** close the padlock (§8). Service
workers stay disabled.

---

## 6. The resolution algorithm

There is no lookup. The algorithm is an address check, a gate, a proxied
request, a redirect decision, and a response filter.

### 6.1 Step 0 — classification

Per §3. By the time the handler is entered, the input is an `onion://` URL.

### 6.2 Step 1 — the address

The handler re-checks the `.onion` suffix (`src/onion-protocol.js:115`) and then
the full v3 encoding (`:119`, §4.3). A host that is not `.onion` is `400 "Not an
onion address"`; a `.onion` host that is not a valid v3 address is `400 "Not a
valid onion address"`, naming the checksum as the reason. Neither touches the
network.

### 6.3 Step 2 — the gate

```js
// src/onion-protocol.js:38-45
export function decideOnionRoute ({ ipProtectionOn } = {}) {
  return ipProtectionOn ? { action: 'route' } : { action: 'interstitial' }
}
```

> **R5.** An implementation MUST NOT issue a request for an onion address
> unless the connection it would ride is a device-local Tor circuit. If it is
> not, the implementation MUST answer without touching the network.

The gate's single input is whether the session proxy is currently the
device-local Tor SOCKS endpoint (§7). It is a **mode** check, not a
**readiness** check, and that distinction is load-bearing — see §7.2.

When the gate refuses, the handler returns a `200` interstitial page explaining
that the protected path is off, that choosing **Private** under Settings ›
Content delivery › Mode (or its Privacy-menu handle, §2) turns it on — and, in
the same breath, that reaching `.onion` here hides the user's IP but is not full
anonymity, because this browser does not resist fingerprinting the way Tor
Browser does. **No request is made.** The host is escaped before being echoed
into the page.

Answering `200` with a page rather than an error is deliberate: it is a
navigable document a user can read and act on. It also means `did-fail-load`
never fires for it, which is why the "reload when the circuit comes up" rule in
§7.3 keys on the **scheme** rather than on the load status. See
[`../../DEVIATIONS.md`](../../DEVIATIONS.md) TO-1.

### 6.4 Step 3 — the proxied request

```js
// src/onion-protocol.js:140
let target = `http://${host}${port ? ':' + port : ''}${path}`
```

The request is issued through the session-bound fetch, which rides the session
proxy — i.e. the Tor SOCKS5 endpoint, with **proxy-side name resolution**. The
`.onion` host travels to the proxy as a SOCKS5 `DOMAINNAME` address
(**RFC 1928** §4/§5, ATYP `0x03`) and is resolved *inside* Tor. This is the
mechanism by which R1 is satisfied at the transport layer, and it is why the
target URL may safely be a plain `http://` URL: there is no DNS step to leak.

`http://` is also the *only* URL this step builds. The scheme is a carrier for
HTTP inside Tor (R16); the handler never constructs an `https:` target and
never turns one into an `onion://` URL, which is what the redirect refusal of
§6.5 (R17) protects at the one place a service could otherwise ask for it.

> **R6.** The proxy MUST perform the name resolution. A client that resolves the
> host itself and connects to an address has defeated the whole design, whatever
> proxy it then uses.

Two request headers are **pinned**, not forwarded
(`src/onion-protocol.js:228-241`): `User-Agent` is `hns.one-browser`, and
`Accept-Language` is `en-US,en;q=0.5` — the value Tor Browser sends, because
matching the largest existing crowd is what a fingerprint-resistant value is
for. Five headers are forwarded when the request carries them: `content-type`,
`range`, `accept`, `if-none-match`, `if-modified-since`. `Cookie` and `Referer`
are not forwarded by this handler.

> **R7.** An implementation MUST NOT forward the user's language list to an
> onion service. It is a high-entropy passive fingerprinting header, and this
> is the one the handler would otherwise create by itself.

### 6.5 Step 4 — the redirect decision

The request is issued with `redirect: 'manual'`. A `3xx` carrying a `Location`
is classified by `classifyOnionRedirect(location, base)`
(`src/onion-protocol.js:86-101`), which resolves the header against the URL just
fetched and returns exactly one of five kinds:

| Kind | When | What the handler does |
|---|---|---|
| `same-service` | same host **and** same port, on `http:` | follows it internally, up to `MAX_REDIRECTS = 5` hops; beyond that, `502 "Too many redirects"` |
| `other-onion` | a different `.onion` host on `http:`, or the same host on a different port | returns the upstream `3xx` with `Location: onion://<host>[:port]<path>` — a **real navigation**, so the address bar and the origin change as they should |
| `unsupported-transport` | an `https:` target on **any** `.onion` host, the service's own included | **does not fetch it.** Answers `501` naming the HTTPS address and saying the redirect was not followed because doing so would remove TLS (`src/onion-protocol.js:161-168`) |
| `off-tor` | any non-`.onion` target, and any target that is not `http:`/`https:` | **does not fetch it.** Returns a `200` page naming the destination and offering it as a link the user may take deliberately |
| `invalid` | the `Location` will not parse | treated as off-Tor: not fetched, and the raw header is shown |

> **R8.** A redirect out of an onion service MUST NOT be followed into another
> origin's content and returned under the onion origin. A different onion
> service MUST be reached by a navigation the browser performs; a target
> outside Tor MUST NOT be fetched at all.

> **R17.** A redirect that would change the transport MUST NOT be performed.
> Where an implementation's onion carrier is HTTP-only (R16), a `Location` on
> `https:` — even to the same onion service, on the same port — MUST be refused
> and MUST NOT be re-encoded as `onion://`.

The order in which `classifyOnionRedirect` applies those tests is itself
load-bearing: `https://example.com/` is **off-Tor**, not unsupported-transport,
because the host test comes first (`:91`) — a clearnet target is refused for
being clearnet, which is the more important thing to tell the user, and the
transport question never arises.

**Why HTTPS on the onion service is a refusal and not a rewrite.** The onion
address authenticates the *service* structurally (§9.1), so a reader may ask
what TLS would add and whether dropping it costs anything. It costs two things.
The service asked for a **different security context** — its certificate, its
HSTS state, its own view of what is a secure origin — and it is not this
browser's place to decide that the Tor layer is a good enough substitute for
the one the service chose. And the rewrite would be **lossy in a way nobody
sees**: `https://<addr>.onion:443/x` normalises to a URL with no port, so
`onion://<addr>.onion/x` is a request to port 80. A refusal that names the
address is the honest answer; silently fetching a different port over a
different transport is not.

Refusing the `off-tor` case *silently* would be worse than following it, which
is why the answer there is a page rather than an error: the user should learn
that the service they asked for sent them somewhere else, and should be the one
who decides to go. The `unsupported-transport` case is a `501` rather than a
`200` page because it is not a destination the user can choose to take *here*
at all: RFC 9110 §15.6.2 is the status for a request method or capability the
server-side of this exchange does not support, and the capability that is
missing is this browser's, which the page says in as many words.

*(`tests/onion-protocol.test.js`, "classifyOnionRedirect sorts a Location into
exactly one kind" and "a redirect to HTTPS on the same service is refused 501,
not re-encoded as onion://".)*

A followed hop after a `301`, `302` or `303` is re-issued as a `GET` with no
body (RFC 9110 §15.4.4); a `307` or `308` keeps the method and body (§15.4.8,
§15.4.9). The hop is the same service on the same port by construction, so
nothing crosses an origin.

A `3xx` **without** a `Location` is not a redirect and is passed through as an
ordinary response. This is the common case rather than an exotic one, because
`if-none-match` and `if-modified-since` are forwarded and a `304` is what an
onion service answers to them.

### 6.6 Step 5 — the response

The upstream status is passed through `safeStatus` (`../../src/safe-status.js`),
which clamps any code Chromium has no reason phrase for to `502`. The status is
chosen by the far end, so it is a variable rather than a literal, and Chromium
`NOTREACHED`s on a code it does not define.

Response headers are copied through a fixed allow-list
(`src/onion-protocol.js:200-214`), in two groups:

- **what the page needs to render the bytes correctly** — `content-type`,
  `content-length`, `etag`, `cache-control`, `content-disposition`,
  `last-modified`, `content-range`, `accept-ranges`, `vary`;
- **what the service is instructing the browser to do about its own content** —
  `content-security-policy`, `content-security-policy-report-only`,
  `x-content-type-options`, `x-frame-options`, `referrer-policy`,
  `permissions-policy`.

> **R9.** A handler that stands between an onion service and the page MUST pass
> the service's own security headers through. They are not a convenience the
> page wants; they are an instruction the service is giving, and dropping them
> leaves an onion page less defended inside this browser than in one that does
> nothing clever.

Two exclusions are deliberate. `Strict-Transport-Security` is **not** passed
through: there is no TLS inside the tunnel, so it is meaningless here and
forwarding it would poison HSTS state for the origin. `content-length` is
dropped when the response carries a `content-encoding`, because the fetch layer
may have transparently decompressed the body and the upstream length would then
not match the bytes served. Everything not on the list — `Set-Cookie` included —
is dropped. What this handler does *not* determine is whether the injected fetch
attaches the session's own cookie jar; that is unmeasured, and it is
[`../../DEVIATIONS.md`](../../DEVIATIONS.md) TO-4.

Every response, including every refusal, carries `X-Resolution-Namespace: tor`,
which is the machine-readable proof to the trust UI that this answer came from
this namespace and no other.

### 6.7 Step 6 — failure

> **R10.** A failure in this namespace MUST be answered *as* a failure in this
> namespace. There is no fallback, to DNS or to anything else.

A thrown request yields a `502` carrying the underlying error and the honest
note that the circuit may still be building and the first connection can take up
to a minute. A missing `fetchImpl` yields a `500` saying the Tor-routed path is
not wired in this build. Nothing is retried anywhere else.

### 6.8 What is *not* in the algorithm

Stated because their absence is the design: no name lookup of any kind; no
cache, positive or negative — there is no record to cache and nothing to expire;
no certificate validation, chain building, or pin — the connection inside the
tunnel is plain HTTP; no retry across a transport; no second opinion.

---

## 7. The circuit: device-local, or nothing

Resolution depends on exactly two things about the Tor client: **whether there
is a SOCKS endpoint to route to**, and **whether that endpoint is on this
machine**. This section specifies those and stops.

### 7.1 Where the circuit comes from

In preference order (`src/tor.js:149`):

1. a **bundled** `tor` binary the browser ships and supervises, spawned as a
   killable process group with a generated `torrc`;
2. an **external** `tor` the user already runs on `127.0.0.1:9050`;
3. **nothing** — Tor cannot be had. What follows is the controller's
   `failClosed` option. The browser passes it, and the controller enters
   **BLOCKED** (§7.6): the session is pointed at the blackhole and the gate
   keeps refusing. Without it — the library default, for controller-only
   callers — the session stays on a direct connection with a note that says so,
   and the gate refuses.

Both usable sources are on `127.0.0.1`. There is no third source, and adding one
that was not would contradict §1.

The generated `torrc` is client-only, loopback-only, and has **no `ControlPort`**
(`src/tor.js:199-208`): readiness is read from tor's own `Bootstrapped 100%` log
line, so there is no local control socket to authenticate, to have a password
or cookie stolen from, or to leak. It publishes no hidden service. The SOCKS
port is chosen per session rather than fixed at 9050, so the bundled client
coexists with any system Tor instead of fighting it for the port.
`tests/tor-circuit.test.js` pins all of this. It also configures no
`ClientOnionAuthDir`, so a service that requires client authorization is
unreachable — see [`../../DEVIATIONS.md`](../../DEVIATIONS.md) TO-5.

### 7.2 Routing before the circuit is ready is correct

Bootstrapping takes 10–60 seconds on a first run. The controller points the
session proxy at the chosen SOCKS port **immediately**, while tor is still
bootstrapping, and the gate opens at the same moment.

> **R11.** The gate MUST be satisfied by the *mode*, not by circuit *readiness*.

This looks backwards and is the leak-safe order. With the proxy already set, a
request issued during the bootstrap **waits for the circuit**. If the gate
instead waited for readiness, then either the request is refused (and the user
learns to retry, which is a usability tax on the one path where impatience is
dangerous) or — much worse — some other code path takes the request while the
session is still direct, and the `.onion` host goes to a system resolver.

The bootstrap percentage is relayed to the interface purely as display. It never
changes routing (`tests/tor-policy.test.js`).

### 7.3 The order the gate and the proxy change in

> **R12.** The restrictive state MUST be entered before the permissive one, in
> both directions. Turning protection **on** routes the session before it
> announces the mode; turning it **off** closes the gate before it re-routes the
> session.

`isOn()` (`src/anonymize.js:326`) is the gate the onion handler reads. Every
transition into `off` — the user's switch to Fast, an unknown mode, and,
without `failClosed`, an unavailable Tor client or a bootstrap that never
completes — sets `this.mode = MODES.OFF` *before* `await this._applyRules(null)`,
so there is no instant at which the gate says *route* while the session is
already direct. The mirror rule on the way in means there is no instant at
which the mode says *on* while the session is still direct. With `failClosed`
the two Tor failures enter BLOCKED instead (§7.6), a state no less restrictive
than the one before it, so the order is moot there. `tests/tor-policy.test.js`
pins both directions and the two failure paths.

The same rule holds one level up. `DeliveryMode.set()` enters Private by
flipping the mode **before** it routes the session, so every consumer of the
policy is restrictive while the proxy is still being applied, and leaves
Private by routing off — this controller's `setMode('off')`, gate first —
**before** the mode flips back (`../../src/delivery-mode.js`;
`tests/delivery-mode.test.js`: *"entering Private flips the mode BEFORE the
anonymizer routes; leaving it routes off BEFORE the mode flips"*).

The asymmetry is the point, and it is the whole reason to state it as a rule: a
window of a single microtask on the way out is enough to hand a `.onion` host to
a system resolver, and it is invisible when it happens.

**The interval between the two, and who has to know about it.** Turning
protection on is not instantaneous: `setMode('tor')` starts or adopts a Tor
client and applies the session proxy, and there are `await`s in between
(`src/anonymize.js:156-233`). Two different questions are asked across that
interval and they have two different answers.

> **R19.** `isOn()` means *the session's requests are covered*, and it becomes
> true only after the proxy has been applied — the onion gate (§6.3) MUST NOT be
> opened before then. A **raw socket** opened outside the session is not covered
> by the session proxy at all, so it MUST NOT dial directly from the moment the
> user asks for Tor. These are separate questions and an implementation MUST
> answer them separately.

`isSwitchingToTor()` (`src/anonymize.js:331`) is the second question. It is set
**before the first `await`** in `setMode()` (`:160`) and cleared when the proxy
is installed (`:194`, `:221`) or the attempt fails (`:284`), and `torSocks()`
returns `null` while it is true (`:340`). So each of the five raw-socket paths
of §7.5 refuses in words during the interval rather than dialling directly,
while `isOn()` keeps the meaning the onion gate depends on and stays false until
the session really is proxied. A `policy-changing` event carries the requested
mode to anything that needs to hear about the interval as it begins.

Every `await` in `setMode()` is followed by a sequence check against
`_switchSeq` (`:183`, `:192`, `:211`, `:219`), so a slow bootstrap cannot land
after a later switch and route a session the user has since sent back to Fast.
`tests/tor-policy.test.js` pins the interval and the stale-switch case.

### 7.4 When the circuit arrives, and when it fails

When the circuit comes up, tabs that were stuck must load themselves — a user
should never have to know to press reload. The rule
(`src/tor-reload.js:31-35`) is deliberately conservative: reload a tab whose
last main-frame load **errored**, and reload any tab on the `onion://`
**scheme**; leave everything else alone. Scheme rather than load status, because
the interstitial is a successful `200` (§6.3).

If the bootstrap never completes, the controller does not go direct. With
`failClosed` it enters BLOCKED (§7.6) and says so — *"Private mode could not
reach the Tor network. Nothing loads until it can — try again, or switch to Fast
in Settings › Content delivery to connect directly."* — and `isOn()` stays true,
so no onion request is admitted onto a direct session. Without `failClosed` the
controller closes the gate, applies a direct connection, and says *"IP
protection could not reach the Tor network — staying on a direct connection"*;
the next onion navigation gets the interstitial rather than a direct attempt.

A client that bootstrapped and then **died** is the same rule applied later:
the route is revoked at the moment the process ends, and the controller enters
BLOCKED from there exactly as it would from a failed bootstrap (§7.7).

> **R13.** An implementation MUST NOT respond to a Tor failure by attempting the
> onion address over any non-Tor path.

### 7.5 What the mode does to everything else

IP Protection is a **whole-session** proxy, not an onion-only one: when it is on,
page loads, protocol handlers and the search fan-out all ride Tor, and the
bypass rules are set to `<-loopback>`, which *subtracts* the implicit loopback
bypass so even `127.0.0.1` goes through the tunnel rather than around it. On
every switch, existing sockets are torn down (`closeAllConnections`) so an
in-flight direct connection cannot outlive the change.

One SOCKS URL with no credentials is applied, so Tor's `IsolateSOCKSAuth` has
nothing to isolate on and every site in the session can share circuits
([`../../DEVIATIONS.md`](../../DEVIATIONS.md) TO-3).

**Five paths outside the session dial the same port directly.** Electron's
session proxy covers what the network stack sends; it does not cover raw TCP
opened from the main process. Five such paths exist, and while the mode is on
each of them — instead of refusing, and instead of dialling directly — speaks
SOCKS5 to **the port this controller chose** (`torSocks()`, the
`socks5://127.0.0.1:<port>` URL of §7.1) through one shared client,
`../../src/socks-dial.js` (RFC 1928, the "no authentication" method only):

| Path | What it dials, and how | Specified in |
|---|---|---|
| the Handshake resolver's authoritative hop | the nameserver's **address**, `ATYP` IPv4 or IPv6 | Chapter 1 §6.11 |
| an A-record `hns://` site's TLS socket | the resolved **address**, `ATYP` IPv4, with the DANE pin checked on that same handshake (`connectDane`, `../../src/dane-connect.js`) | Chapter 1 §8.1 |
| the `wss://` tunnel's upstream | the origin's resolved **address**, `ATYP` IPv4 or IPv6 | Chapter 11 §4.4 |
| a `gemini://` request's TLS socket | the capsule's **name**, `ATYP` `DOMAINNAME`, so no local lookup happens | Chapter 9 §K.6.2 |
| a Nostr relay's WebSocket | the relay's **name**, `ATYP` `DOMAINNAME`, TLS with the relay's name as SNI layered over the tunnel (`../nostr/src/tor-websocket.js`) | Chapter 6 |

**What they read, and what BLOCKED does to them.** Each path asks the
controller for the port through `torSocks()`, which returns the SOCKS URL only
while the mode is `tor` **and** no switch into Tor is still installing the proxy
(§7.3). While BLOCKED (§7.6), while switching, and once a route has been revoked
(§7.7) it returns `null`, and each path
refuses **in words** — the Handshake handler with `privateRefusal('site')`, the
Nostr handler with `privateRefusal('relay')` (`../../src/delivery-mode.js`),
the tunnel and Gemini with their own refusals — rather than dialling the
blackhole and reporting a network fault. The session's own requests fail at the
proxy instead (TO-7).

Two properties of that are this chapter's, and normative here. First, **it is
still device-local only**: the only SOCKS server any of them may address is the
one this controller chose on `127.0.0.1`, so §1's rule holds unchanged — a
dialer pointed at a hosted SOCKS endpoint would be the escape hatch this chapter
refuses to have (§7.1, DEVIATIONS §2.1). Second, **the address type is the
caller's decision and it matters**: a resolved address is sent as an address so
the proxy learns no name, and a host that has not been resolved is sent as a
name so that Tor resolves it and the operating system never does. An
implementation **MUST NOT** invert either half — resolving locally to send an
address is a leak, and sending a name that was already resolved discloses it for
nothing.

**And TO-3 applies to these dials too.** They send no SOCKS credential either,
so a Handshake nameserver lookup, the site connection that follows it, a
WebSocket to a Handshake origin, a Gemini capsule and a relay query share
circuits with each other and with everything in the session. The
per-origin credential of [`../../DEVIATIONS.md`](../../DEVIATIONS.md) TO-D1
would, unlike the session proxy, be trivial to supply here — these callers
construct their own dialer — which makes them the cheapest place to *measure*
whether Tor isolates on it before the harder question of the session proxy is
answered.

This is what makes onion resolution possible at all: the onion handler does not
build a tunnel, it rides the one the session already has. The cost of that
simplicity is in [`../../DEVIATIONS.md`](../../DEVIATIONS.md) TO-6.

### 7.6 Fail closed: the BLOCKED state

The controller has three states, `MODES`: `off`, `tor` and `blocked`. The third
exists for one promise — Private mode's *"a fresh lookup fails rather than
falling back"* (`../../src/delivery-mode.js`, `DISCLOSURE.private`) — applied to
the proxy itself.

> **R15.** When protection is in force and a device-local Tor cannot be had, an
> implementation MUST NOT route the session directly. It MUST route it somewhere
> that answers nothing.

With `failClosed` (the browser passes it), the two ways a `tor` request can fail
— the Tor client is unavailable (`tor.start()` reports `unavailable`, or no
external `127.0.0.1:9050` answers) and a bootstrap that ends without a circuit —
go through `_cannotRoute()` and enter **BLOCKED**:

- **every session is pointed at the blackhole**, `BLACKHOLE_RULES` =
  `socks5://127.0.0.1:9`: a loopback port nothing listens on, so every
  connection fails at once at the proxy (`ERR_PROXY_CONNECTION_FAILED`) instead
  of going out directly. The PAC decorator folds the same rule in, so a `wss://`
  to a Handshake name is blocked the same way;
- **`isOn()` stays true**, so every gate that reads it — the onion gate, the
  non-proxied-protocol gate, the Handshake handler's route gates — keeps
  refusing;
- **`torSocks()` is `null`**, so every raw-socket path of §7.5 refuses in words
  rather than dialling the blackhole and reporting a network fault;
- **the note names the mode and the switch**: *"Private mode cannot connect — no
  Tor client is bundled or running. Nothing loads until it can; switch to Fast in
  Settings › Content delivery to connect directly."*, or *"Private mode could not
  reach the Tor network. Nothing loads until it can — try again, or switch to
  Fast in Settings › Content delivery to connect directly."*

`setMode('off')` from BLOCKED goes direct exactly as from `tor`, gate first
(§7.3); a later `setMode('tor')` that succeeds routes to the real port and
`torSocks()` reports it again. Without `failClosed` — the library default, kept
for controller-only callers — the same two failures end `off`, direct, with the
honest note of §7.4.

The blackhole is loopback by construction and **MUST** stay so: a routable
address there would turn a refusal into a connection to somebody.
`tests/tor-policy.test.js` pins the state: *"failClosed: bundled tor unavailable
-> BLOCKED on the blackhole, isOn stays true, torSocks is null"*, *"failClosed:
a failed bootstrap -> BLOCKED, not direct"*, *"failClosed: OFF still goes
direct, and a routed TOR still reports its SOCKS URL"*, and *"the blackhole is a
loopback port, never a routable address"*.

What BLOCKED costs is what the mode's disclosure and the note say: nothing
loads. What it does **not** do is change a verdict — there is no page to have
one — or the gate's logic: the gate is a mode check and not a readiness check
(§7.2), so it says *route*, the request dies at the blackhole, and the answer is
the handler's failure page of §6.7, which echoes the proxy error (TO-7).

### 7.7 A route that stops existing is revoked

A Tor client can die under the browser. Until something says so, `socksUrl()`
goes on naming a port nothing is listening on, and the five raw-socket paths of
§7.5 go on dialling it — each one a connection that was supposed to be a Tor
circuit and is now a connection refused, in a mode whose whole promise is that
a failure does not become a fallback.

> **R20.** Availability is not a slow-changing fact. When the route a client
> offered stops existing, the implementation **MUST** revoke it synchronously
> with the event that ended it — not on the next probe, not on the next
> request. A route that has been revoked **MUST NOT** be reported as available
> by anything a caller reads.

`_routeUnavailable(reason)` (`src/tor.js:320-328`) is the one revocation path.
It clears `_ready` and `_available`, flushes every `whenReady()` waiter with
`false` so nothing is left hanging, and emits **`route-unavailable`** — but only
where a route had actually been offered, because startup is still free to try
its external fallback (§7.1) and a client that never offered anything has
nothing to take back. It is called from five places: the child's `error` and
`exit` handlers (`src/tor.js:227-238`), the bootstrap deadline (`:265-267`),
`stopChild()` (`:377`) and `stop()` (`:384`).

Two details make it sound rather than merely present:

- **The handlers are bound to their own child.** Each is registered against the
  specific process object and returns early if `this.child` is no longer it
  (`:226`, `:229`, `:235`), so a superseded process dying after a recovery
  respawn cannot revoke the route the *new* one is providing. The same guard
  covers the `Bootstrapped 100%` line, which is ignored for a superseded or
  stopped child and otherwise sets `_available` alongside `_ready` (`:243-248`)
  — readiness never outruns availability.
- **Revocation reaches the supervisor, rather than switching it off.** The
  30-second probe runs whether or not a route is currently offered: an
  unavailable node counts as having already reached the three-failure threshold,
  so the next tick respawns it (`:339-345`). An implementation whose supervisor
  skips its work while the client is unavailable has built a state the client
  cannot leave — revocation would make the failure permanent instead of
  recoverable.

**What the controller does with it.** `AnonymizeController` subscribes at
construction (`src/anonymize.js:138-145`). While protection is on, a
`route-unavailable` supersedes any in-flight switch, stops the bootstrap
relay, and re-runs `_cannotRoute()` — so with `failClosed` the sessions go to
the blackhole and the state becomes BLOCKED (§7.6), exactly as a bootstrap that
never completes does, with `isOn()` still true and `torSocks()` returning
`null`.
While protection is off it does nothing: a node the user is not routing through
cannot change the session.

*(`tests/tor-circuit.test.js`, "a tor that exits revokes the route it had
offered, once" and "a tor that never offered a route emits nothing when it
stops"; `tests/tor-policy.test.js`, "route-unavailable revokes the route
immediately: failClosed blackholes it".)*

What this does **not** establish is that every way a Tor client can stop being
useful produces one of those five events. A tor that is alive, bootstrapped and
answering its SOCKS port while its circuits are failing looks available here,
and is caught — if at all — by the supervisor's probe and by the request
failing. Revocation closes the window between a process ending and anybody
noticing; it is not a health check.

---

## 8. Trust state

Mapping onto the trust states of [`../../SPEC.md`](../../SPEC.md):

| | |
|---|---|
| **Lock** | **open** — always |
| **What is authenticated** | the *service*, structurally, by Tor's rendezvous protocol |
| **What is not** | the *content*: plain HTTP inside the tunnel — no certificate, no DANE pin, no content address |
| **What is disclosed** | nothing to a resolver; see §9.3 for what is disclosed to the service |

> **R14.** An onion page MUST NOT be presented as verified. The trust state MUST
> be decided by the scheme, and MUST NOT be influenced by anything the service
> sends.

The step an interface is given (`../../src/trust-path.js:412-421`) says, in the
words the user is owed:

> **Connection — unverified — Tor onion service (HTTP inside Tor).** Reached
> only through the Tor client on this device — never a hosted relay. The onion
> address authenticates the service at the Tor layer, but the page itself is
> plain HTTP inside the tunnel, so its contents are not otherwise verified.

Two things this is careful about, and an implementation should be equally
careful:

- **`secure: true` is not a lock.** Registering the scheme as a secure context
  is what makes storage and WebCrypto work for real applications. It is a
  capability decision, not a trust claim, and the two MUST NOT be wired to each
  other. `tests/onion-trust-state.test.js` pins the distinction against a
  genuinely verified scheme.
- **The service cannot talk itself up.** Every onion address yields the
  identical step list, including a malformed one that will never reach a
  service. Nothing in a header, a body or a certificate can change it.

The honest summary a user is given elsewhere in the product is the same one:
this hides your IP; it is not full anonymity.

---

## 9. Security and privacy considerations

### 9.1 What a completed circuit establishes, exactly

An implementation may conclude, from a successfully established connection to
`<addr>.onion`:

- the far end **possesses the private key** for the Ed25519 public key encoded
  in `<addr>` — proven by the rendezvous handshake, not by anything the client
  checks afterwards;
- the traffic between this device and that service was **carried inside Tor**,
  so no observer on the local network, and no name resolver, saw the address.

It may **not** conclude:

- anything about *who* holds that key, or that it is who the user meant. An
  onion address is a key, and a key with a similar-looking base32 encoding is a
  different key belonging to somebody else. **There is no naming layer, so there
  is no name to be wrong about — and equally no name to help the user tell two
  services apart.** This is the namespace's structural strength and its
  structural usability problem, and the two are the same fact.
- anything about the *content*. The tunnel authenticates the endpoint, not the
  bytes. A compromised onion service serves attacker content over a perfectly
  authenticated circuit.
- that the *service* does not know who the user is. Tor hides the network
  address; the page can still identify the user by every other means (§9.3).

### 9.2 What the checksum check is, and what it is not

Verifying the v3 checksum is a **syntax** check, not a security one, and saying
so matters: a reader who believes it closes a hole will look for the wrong bug.
**A wrong address cannot reach a wrong service** with or without it. Tor derives
the directory lookup from the key bytes themselves, so a corrupted address names
a service that does not exist, and the circuit fails.

What the check buys is precision and cost: a mistyped or truncated address fails
**instantly and locally**, with a message that says what is wrong, instead of
hanging while a circuit is built for an address that cannot resolve and then
reporting a generic transport error. The checksum protects against
*transcription error*, which is exactly what it was designed for.

R2 remains the boundary the check must not cross: the routing decision stays on
the suffix test, because an invalid onion address discloses the user's intent to
a resolver exactly as well as a valid one.

### 9.3 What leaks, and when

Stated positively, because "leak" is the whole subject of this namespace.

**With IP Protection off** (Fast mode), an onion navigation makes **no network
request at all**: no DNS, no TCP, no probe. The interstitial is generated locally. This is
pinned by `tests/onion-protocol.test.js` and `tests/onion-leak-guard.test.js`,
and is the single most important behaviour in this chapter.

**With it on**, and the request inside the tunnel:

| Leaked to | What |
|---|---|
| a name resolver | **nothing** — resolution is proxy-side (§6.4) |
| the local network / ISP | that Tor is in use; not which service |
| the Tor network | what Tor's own design exposes; out of scope. Traffic is not isolated per site, so one circuit can carry several of them — and, since the resolver's authoritative hop, the `wss://` tunnel and `gemini://` dial this same port for themselves (§7.5), a circuit can carry those as well (TO-3) |
| **the onion service** | the request line, a pinned `User-Agent` and `Accept-Language`, and the five forwarded headers a request actually carried; and everything the *page* can do once it runs — this browser does not resist fingerprinting the way Tor Browser does, so canvas, fonts, screen metrics, timing and storage are all available to it. **A user who needs anonymity rather than IP-hiding needs Tor Browser, and the product says so in every place this appears.** |

**At the edges:**

- **Switching to Fast** while an onion tab is open: the gate closes first,
  existing sockets are closed, and the next load gets the interstitial (§7.3).
- **A bootstrap that fails**: ends BLOCKED (§7.6) — nothing loads, and the note
  says why — never in a direct onion attempt (R13). Without `failClosed`, it
  ends direct + off + honest.
- **A Tor client that dies mid-session**: the route is revoked as the process
  ends (§7.7), so no raw-socket path keeps a SOCKS URL that no longer answers,
  and the state goes to BLOCKED rather than staying nominally on.
- **The interval while protection is being turned on**: raw sockets are
  withheld from the moment the user asks (§7.3, R19); the onion gate opens only
  once the session proxy is applied.
- **An explicit non-onion scheme on an onion host** typed by the user: not
  protected for a top-level load (§3.2, TO-2).
- **A redirect off Tor**: the destination is named to the user and is never
  fetched (§6.5), so a tracking URL an onion service redirects to is not
  requested at all.
- **A redirect to HTTPS on the onion service itself**: refused `501`, not
  followed and not re-encoded as `onion://` (§6.5, R17). Nothing is sent to the
  HTTPS address, and the page says why. The cost is a real one: such a service
  is unreachable here (TO-8).
- **The 502 page** echoes the underlying transport error, which can name the
  proxy. It is a local page; nothing is sent.

### 9.4 The origin the content is given

Because the scheme is `standard` + `secure`, an onion page gets a real,
persistent, per-host origin with storage. That is what stops real web
applications from crashing, and it means an onion service can persist data on
the user's machine, keyed to its own address, that survives across visits. That
is the same bargain every origin gets and is stated here so it is not a
surprise. Service workers are disabled.

The redirect rules of §6.5 exist to keep that origin honest. Content served
under `onion://<host>` is content `<host>` itself served **over the transport
this origin stands for**: a redirect to another onion service becomes a
navigation, so the origin changes with the content; a redirect off Tor is not
fetched at all; and a redirect to HTTPS is refused rather than folded back into
this origin (R17), because bytes the service chose to serve under TLS are not
bytes this origin may claim. Nothing another origin wrote, and nothing served
under a security context this origin cannot express, is handed to the page
inside this one's storage.

### 9.5 The rule that carries the most weight

Everything above rests on §3's R1/R2 holding at *every* entry point. This
implementation has four (§3.1). The failure mode is silent — a request that
should not have been made looks exactly like one that was allowed — so it cannot
be found by using the browser. It can only be found by enumerating the doors and
testing each one, which is what `tests/onion-leak-guard.test.js` exists to do,
and what an implementer of this chapter is being asked to do for their own tree.
