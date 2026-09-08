# Chapter 8 — Tor

**Namespace:** `tor` · **Schemes:** `onion:` · **Addresses:** `<56-char v3>.onion`
**Version:** 0.1 (draft for public comment)
**Status:** Describes the reference implementation in `namespaces/tor/src/`.
Normative requirements define compatibility with this implementation. Cited
standards govern requirements inherited from them. This is a project
specification, without endorsement from a standards body or the Tor Project.

**Licence:** CC-BY-4.0 (see `../../LICENSE-SPEC`). The reference implementation
is licensed separately.

This chapter follows the namespace-selection and trust rules in
[`../../SPEC.md`](../../SPEC.md). It covers routing to onion services through
a Tor client on the user's device.

See [DEVIATIONS.md](DEVIATIONS.md) for `TO-` deviations and open questions,
and [REFERENCES.md](REFERENCES.md) for sources.

> **Review note:** [REVIEW.md](../../REVIEW.md) records contradictions and
> technical claims awaiting a decision. This rewrite does not resolve them.

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

A v3 onion address encodes an Ed25519 public key, checksum and version byte
(Tor rend-spec-v3 §6). Tor authenticates possession of the corresponding
private key during the rendezvous protocol. The browser delegates that work
to its Tor client.

This chapter specifies address validation, routing, request handling and trust
reporting. A central requirement is to keep onion addresses out of ordinary
name resolution: a DNS query would disclose the requested service. Section 3.2
and TO-2 describe the explicit-scheme exception in the current routing rules.

The implementation also requires a device-local Tor client:

> **An onion address is reached through a Tor client running on the user's own
> device, or it is not reached at all.**

Hosted SOCKS endpoints and onion-to-web gateways are outside this policy
because their operators would learn the requested service.

### 1.1 Scope

**In scope: turning a `.onion` address into a request that leaves the machine
only inside a device-local Tor circuit, or into an local refusal.** Precisely:

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

**Out of scope:**

| Out of scope | Why it is a different document |
|---|---|
| **The Tor protocol itself** — circuits, the rendezvous handshake, descriptors, the directory system, guard selection, congestion control | Cited (REFERENCES §1), never restated. §9.1 states exactly what an implementation may conclude from a completed circuit, which is the only part a resolver needs. |
| **Tor client management beyond what resolution requires** — packaging and provenance of the binary, supervision, recovery, the bootstrap UI | The parts resolution depends on are the *availability states* and the *SOCKS endpoint* (§7). Everything else is the browser's process management. Included in `src/tor.js` for completeness and marked as such. |
| **Anonymity as a property of the browser** — fingerprinting resistance, tab/circuit isolation, timing defences, the Tor Browser threat model | We do not have it, we say so in the product, and §9.3 says so here. Claiming otherwise would be the most damaging thing in this document. |
| **Publishing an onion service** | The read path only. This implementation is a client and its `torrc` contains no `HiddenService` line. |
| **What the page does once it loads** — rendering, storage, permissions | Except for §8, which specifies the trust state, and §9.4, which is about the origin the content is given. |

This chapter specifies the browser gate and transport routing; Tor performs onion-service resolution.

---

## 2. Terminology

Terms are used as in [`../../SPEC.md`](../../SPEC.md), plus:

- **Onion address** — the string `<label>.onion`, where for version 3 `<label>`
  is 56 characters of RFC 4648 base32. Defined by Tor rend-spec-v3 §6.
- **Onion service key** — the Ed25519 public key that *is* the address, modulo
  the encoding of §4.
- **v3** — the current onion service protocol. **v2** (16-character addresses,
  1024-bit RSA) was deprecated in 2020 and removed from Tor in 2021. An implementation MUST NOT treat a v2 address as valid.
- **Circuit** — a Tor path. Here it always means one built by a Tor client
  process on the user's own device.
- **The gate** — the policy decision, taken before any network activity, of
  whether a request may be issued at all (§6.3).
- **IP Protection** — the state in which the session proxy is the device-local
  Tor SOCKS endpoint (or, when that cannot be had, the blackhole of §7.6). It is
  the gate's only input. It is **not a control of its own**: it is driven by
  **Settings › Content delivery › Mode** — `Private` turns it on, `Fast` turns
  it off — one control exposed in two places, the settings page and the Privacy menu,
  both ending in `DeliveryMode.set()` (`../../src/delivery-mode.js`,
  `../../SPEC.md` §4.2). The name leads with what a user gets ("hide my IP")
  rather than with the technology.
- **BLOCKED** — the controller's third state (`MODES.BLOCKED`): protection was
  asked for and Tor cannot be had, so every session is pointed at a loopback
  port nothing listens on (§7.6). Session loads fail at that proxy.
- **The blackhole** — that port: `BLACKHOLE_RULES`, `socks5://127.0.0.1:9`.
- **Structural authentication** — authentication a client obtains by
  construction rather than by checking something. §4 and §9.1 turn on this
  distinction.

The browser does not validate DNS records or perform Tor rendezvous verification itself.

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

A validity-gated classifier could send mistyped, truncated or obsolete onion
addresses to DNS. Those queries still disclose the user's intended service.

Accordingly the classifier matches `.onion` **first and unconditionally**,
before the ENS suffix check, before the reserved-name list, before the
IP-literal check, and before the ICANN root list is consulted at all:

```js
// ../../src/router.js:310-313
// .onion FIRST and unconditionally: a v3 onion goes to Tor and MUST NEVER be
// sent to DNS/ODoH (L1). Even a malformed .onion stays in the Tor namespace
// (it fails as a Tor address, not as a DNS miss) — never leaked to a resolver.
if (isOnionHost(host)) return NAMESPACES.TOR
```

`isOnionHost` is a suffix test and nothing more (`/\.onion$/i`,
`../../src/router.js:216`). That is deliberate: R2 requires that the guard be
*weaker* than a validity check, not stronger.

`onion` is also a row in the one reserved-name list
(`../../src/reserved-names.cjs:31`, RFC 6761/6762/7686/8375), which the
classifier consults immediately **after** the `.onion` test
(`../../src/router.js:322`). Both placements matter: the reserved-name
row would otherwise send an onion host to the web namespace as though it were
`nas.local`, and its absence would make `.onion` a Handshake name for any code
path that reaches the list without the suffix test.

### 3.1 Four entry points, one rule

The implementation applies the rule at four entry points:

| Entry point | Mechanism | Result for `<addr>.onion` |
|---|---|---|
| **Typed input** | `classify()` — `../../src/router.js:416` | `onion://<addr>.onion` |
| **Link click / main-frame navigation** on `http(s)://<addr>.onion/` | `rewriteToHns()` via `reservedNamespaceScheme()` — `../../src/hns-host.js:50`, `:85` | rewritten to `onion://…` before the load |
| **Subresource** (`<img>`, `<script>`, `fetch`) on an onion host | `decide()` — `src/subresource-guard.js:35-53` | **cancelled**: zero network, zero DNS |
| **Handshake classification** | `isReservedHost()` — `../../src/reserved-names.cjs:36`, re-exported at `../../src/hns-host.js:30` | never a Handshake name |

`tests/onion-leak-guard.test.js` drives one address through all four.

An implementation **MUST** enumerate and cover every network entry point.
Subresource requests need a separate guard because they can disclose an onion
address without a visible navigation. This guard runs before the ad blocker
(`src/subresource-guard.js:22-24`).

### 3.2 An explicit scheme still wins

R1 governs *classification of a bare host*. It does not override the router's
first law. A user who types `https://<addr>.onion/` has named a protocol, and
that input stays on `https:`; it will simply fail, as HTTPS, without an onion
circuit. An implementation MUST NOT re-sniff an explicit scheme out of the host
— sniffing is how `https://` silently becomes something else, and that is a
worse property than a failed page.

**The current R1 implementation does not protect an explicitly typed
non-onion scheme on an onion host.** The subresource guard checks the host
regardless of scheme, but the documented top-level exception remains. See TO-2.

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

All four (`isValidV3Onion`, `../../src/router.js:232-252`). The shape is one
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
`validV3: isValidV3Onion(host)`, `../../src/router.js:416`), and the handler
consumes it: an address whose version byte or checksum does not match is refused
`400` with a page saying so, **before any circuit is asked for**
(`src/onion-protocol.js:119-124`). Nothing was sent, the refusal carries
`X-Resolution-Namespace: tor`, and no other namespace is tried.

An implementation **SHOULD** validate the address locally to report mistakes
without waiting for Tor to reject them (§9.2).

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

Parsing (`parseOnionUrl`, `src/onion-protocol.js:54-79`) uses the WHATWG URL
parser, which is the right tool because `onion:` is registered as a standard
scheme. It returns three fields:

- **host** — `u.hostname`, lower-cased, never carrying the port;
- **port** — `u.port`, empty when the URL names none;
- **path** — `u.pathname` + `u.search`, defaulting to `/`. Because `onion:` is
  not one of WHATWG's *special* schemes, a query-only URL has an empty path and
  the query alone becomes the path — which is what `http://<host>?q=1` means in
  any case.

The **fragment is dropped** when constructing the request; it is client-side URL state.

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

The handler re-checks the `.onion` suffix (`src/onion-protocol.js:111`) and then
the full v3 encoding (`:119`, §4.3). A host that is not `.onion` is `400 "Not an
onion address"`; a `.onion` host that is not a valid v3 address is `400 "Not a
valid onion address"`, naming the checksum as the reason. Neither touches the
network.

### 6.3 Step 2 — the gate

```js
// src/onion-protocol.js:38-44
export function decideOnionRoute ({ ipProtectionOn } = {}) {
  return ipProtectionOn ? { action: 'route' } : { action: 'interstitial' }
}
```

> **R5.** An implementation MUST NOT issue a request for an onion address
> unless the connection it would ride is a device-local Tor circuit. If it is
> not, the implementation MUST answer without touching the network.

The gate reads the protection mode, not circuit readiness (§7.2). The mode
controls whether the session is routed through the local SOCKS endpoint or
the BLOCKED proxy (§7.6).

When the gate refuses, the handler returns a local `200` interstitial. It
points to Settings › Content delivery › Mode › Private and states that this
path hides the IP address without providing Tor Browser's fingerprinting
defences. No request is made. The echoed host is HTML-escaped.

The `200` status makes the interstitial a normal navigable document. It does
not trigger `did-fail-load`, so the Tor-ready reload rule checks the `onion://`
scheme as well as load errors (§7.4, TO-1).

### 6.4 Step 3 — the proxied request

```js
// src/onion-protocol.js:136
let target = `http://${host}${port ? ':' + port : ''}${path}`
```

The request is issued through the session-bound fetch, which rides the session
proxy — i.e. the Tor SOCKS5 endpoint, with **proxy-side name resolution**. The
`.onion` host travels to the proxy as a SOCKS5 `DOMAINNAME` address
(**RFC 1928** §4/§5, ATYP `0x03`) and is resolved *inside* Tor. This is the
mechanism by which R1 is satisfied at the transport layer, and it is why the
target URL may safely be a plain `http://` URL: there is no DNS step to leak.

> **R6.** The proxy MUST perform the name resolution. A client that resolves the
> host itself and connects to an address has defeated the whole design, whatever
> proxy it then uses.

Two request headers are **pinned**, not forwarded
(`src/onion-protocol.js:209-219`): `User-Agent` is `hns.one-browser`, and
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
(`src/onion-protocol.js:86-98`), which resolves the header against the URL just
fetched and returns exactly one of four kinds:

| Kind | When | What the handler does |
|---|---|---|
| `same-service` | same host **and** same port | follows it internally, up to `MAX_REDIRECTS = 5` hops; beyond that, `502 "Too many redirects"` |
| `other-onion` | a different `.onion` host, or the same host on a different port | returns the upstream `3xx` with `Location: onion://<host>[:port]<path>` — a **real navigation**, so the address bar and the origin change as they should |
| `off-tor` | any non-`.onion` target, and any target that is not `http:`/`https:` | **does not fetch it.** Returns a `200` page naming the destination and offering it as a link the user may take deliberately |
| `invalid` | the `Location` will not parse | treated as off-Tor: not fetched, and the raw header is shown |

> **R8.** A redirect out of an onion service MUST NOT be followed into another
> origin's content and returned under the onion origin. A different onion
> service MUST be reached by a navigation the browser performs; a target
> outside Tor MUST NOT be fetched at all.

The off-Tor page lets the user inspect the destination before choosing to navigate.

A followed hop after a `301`, `302` or `303` is re-issued as a `GET` with no
body (RFC 9110 §15.4.4); a `307` or `308` keeps the method and body (§15.4.8,
§15.4.9). The hop is the same service on the same port by construction, so
nothing crosses an origin.

The helper converts accepted onion redirect targets to `http://`, including
`https://` locations. It does not preserve an HTTPS upgrade. The same-service
comparison uses hostname and parsed port, without comparing schemes.
[REVIEW.md](../../REVIEW.md) records this transport-policy decision.

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
(`src/onion-protocol.js:182-190`), in two groups:

- **what the page needs to render the bytes correctly** — `content-type`,
  `content-length`, `etag`, `cache-control`, `content-disposition`,
  `last-modified`, `content-range`, `accept-ranges`, `vary`;
- **what the service is instructing the browser to do about its own content** —
  `content-security-policy`, `content-security-policy-report-only`,
  `x-content-type-options`, `x-frame-options`, `referrer-policy`,
  `permissions-policy`.

> **R9.** A handler between an onion service and the page MUST pass the
> service's security headers through, preserving its content restrictions.

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

A request exception returns `502` with the underlying error and a note that
Tor may still be bootstrapping. A missing `fetchImpl` returns `500` stating
that the Tor route is not wired into the build. Neither triggers fallback.

### 6.8 What is *not* in the algorithm

The browser handler has no DNS lookup, resolution cache, certificate or DANE
validation, transport fallback, or independent verification of the Tor circuit.
The initial request inside Tor uses HTTP.

---

## 7. The circuit: device-local, or nothing

The handler needs the Tor client’s availability state and device-local SOCKS endpoint.

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
(`src/tor.js:197-208`): readiness is read from tor's own `Bootstrapped 100%` log
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

Applying the proxy before admitting requests keeps requests on the Tor route
during bootstrap. They can wait or fail at that endpoint instead of entering a
direct connection path.

The bootstrap percentage is relayed to the interface purely as display. It never
changes routing (`tests/tor-policy.test.js`).

### 7.3 The order the gate and the proxy change in

> **R12.** The restrictive state MUST be entered before the permissive one, in
> both directions. Turning protection **on** routes the session before it
> announces the mode; turning it **off** closes the gate before it re-routes the
> session.

`isOn()` (`src/anonymize.js:268`) is the gate the onion handler reads. Every
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

The ordering prevents an asynchronous transition from leaving the gate open on a direct session.

### 7.4 When the circuit arrives, and when it fails

When Tor becomes ready, `src/tor-reload.js:31-35` reloads tabs whose last
main-frame load failed and tabs on the `onion://` scheme. The scheme check
includes the successful `200` interstitial (§6.3). Other tabs are unchanged.

If the bootstrap never completes, the controller does not go direct. With
`failClosed` it enters BLOCKED (§7.6) and says so — *"Private mode could not
reach the Tor network. Nothing loads until it can — try again, or switch to Fast
in Settings › Content delivery to connect directly."* — and `isOn()` stays true,
so no onion request is admitted onto a direct session. Without `failClosed` the
controller closes the gate, applies a direct connection, and says *"IP
protection could not reach the Tor network — staying on a direct connection"*;
the next onion navigation gets the interstitial rather than a direct attempt.

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
while the mode is `tor`. While BLOCKED (§7.6) it returns `null`, and each path
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

The direct dialers also send no SOCKS credentials, so they share the stream
isolation limitation in TO-3. TO-D1 proposes measuring per-origin isolation
with credentials in these dialers before changing the session proxy.

The onion handler uses the session proxy; it does not create a separate tunnel. TO-6 covers the whole-session scope of that choice.

### 7.6 Fail closed: the BLOCKED state

The controller exposes `off`, `tor` and `blocked`. BLOCKED prevents direct
fallback when Private mode requires Tor but no usable client is available.

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
explanatory note of §7.4.

The blackhole is loopback by construction and **MUST** stay so: a routable
address there would turn a refusal into a connection to somebody.
`tests/tor-policy.test.js` pins the state: *"failClosed: bundled tor unavailable
-> BLOCKED on the blackhole, isOn stays true, torSocks is null"*, *"failClosed:
a failed bootstrap -> BLOCKED, not direct"*, *"failClosed: OFF still goes
direct, and a routed TOR still reports its SOCKS URL"*, and *"the blackhole is a
loopback port, never a routable address"*.

BLOCKED prevents loads. The mode-based onion gate still returns `route`
(§7.2), and the session request fails at the blackhole. The handler returns
the 502 page of §6.7; TO-7 tracks its generic proxy-error wording.

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

The interface step (`../../src/trust-path.js`) is:

> **Connection — unverified — Tor onion service (HTTP inside Tor).** Reached
> only through the Tor client on this device — never a hosted relay. The onion
> address authenticates the service at the Tor layer, but the page itself is
> plain HTTP inside the tunnel, so its contents are not otherwise verified.

Two implementation details affect interpretation:

- **`secure: true` is not a lock.** Registering the scheme as a secure context
  is what makes storage and WebCrypto work for real applications. It is a
  capability decision, not a trust claim, and the two MUST NOT be wired to each
  other. `tests/onion-trust-state.test.js` pins the distinction against a
  genuinely verified scheme.
- **The service cannot talk itself up.** Every onion address yields the
  identical step list, including a malformed one that will never reach a
  service. Nothing in a header, a body or a certificate can change it.

The product describes this as IP protection without full anonymity.

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

The v3 checksum detects address transcription errors. Tor handles service
authentication; the browser's checksum check does not replace that protocol.

Local validation reports malformed addresses immediately, with a specific
error, instead of waiting for a transport failure.

R2 remains the boundary the check must not cross: the routing decision stays on
the suffix test, because an invalid onion address discloses the user's intent to
a resolver exactly as well as a valid one.

### 9.3 What leaks, and when

The disclosure depends on the route and the entry point:

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
  ends with the gate closed, a direct session and a status note.
- **An explicit non-onion scheme on an onion host** typed by the user: not
  protected for a top-level load (§3.2, TO-2).
- **A redirect off Tor**: the destination is named to the user and is never
  fetched (§6.5), so a tracking URL an onion service redirects to is not
  requested at all.
- **The 502 page** echoes the underlying transport error, which can name the
  proxy. It is a local page; nothing is sent.

### 9.4 The origin the content is given

Because the scheme is `standard` + `secure`, an onion page gets a real,
persistent, per-host origin with storage. That is what stops real web
applications from crashing, and it means an onion service can persist data on
the user's machine, keyed to its own address, that survives across visits. That
is the same bargain every origin gets and is stated here so it is not a
surprise. Service workers are disabled.

The redirect rules of §6.5 preserve the origin boundary. Content served
under `onion://<host>` is content `<host>` itself served: a redirect to another
onion service becomes a navigation, so the origin changes with the content, and
a redirect off Tor is not fetched at all. Nothing another origin wrote is
handed to the page inside this one's storage.

### 9.5 The rule that carries the most weight

Implementations must test R1/R2 at each network entry point (§3.1), including
subresources and malformed input. `tests/onion-leak-guard.test.js` covers the
shared routing and guard functions. TO-2 records the remaining explicit-scheme
exception.
