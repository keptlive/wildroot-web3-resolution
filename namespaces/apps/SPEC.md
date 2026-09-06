# Chapter 11 — Native applications on a Handshake name

**Namespace:** `hns` (`hns://`) — the application layer above Chapter 1
**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in `src/`
beside this file and in the Wildroot browser tree, and is proven end to end by
one deployed third-party application (`.pxls`). Not endorsed by any standards
body. Normative statements describe what an implementation must do *to
interoperate with this one*; where they are inherited from an existing
standard, that standard is cited and its rule governs.
**Licence:** CC-BY-4.0 (see `../../LICENSE-SPEC`). The reference
implementation is licensed separately.

This chapter is part of the integrated specification whose spine is
`../../SPEC.md`, and **namespace selection — which hosts reach this chapter at
all — is specified there**, not here. Chapter 1 (`../handshake/SPEC.md`)
specifies how a Handshake name resolves and how its DANE pin is checked; this
chapter specifies what an *application* served at such a name may do, which is
the part that decides whether Handshake hosts real software or only static
pages.

Every deviation from a cited standard, and every question we are unsure of, is
in `../../DEVIATIONS.md` under the prefix `AP-`. Every standard cited is listed
with its purpose in `REFERENCES.md` beside this file. **Those two files are
part of this specification, not appendices to it.**

**Paths.** Paths written `src/…` and `tests/…` are this chapter's, under
`namespaces/apps/`. Paths written `../../src/…` are shared modules of the
top-level package. Modules named `browser src/…` are in the Wildroot browser
tree and are **not** extracted into this repository, because they are bound to
Electron and Chromium; where this chapter is normative about them it states the
policy the code enforces and names the module, so the rule can be implemented
against any engine.

---

## Contents

1. [What this specifies, and why it exists](#1-what-this-specifies-and-why-it-exists) — including [**scope**](#11-scope)
2. [Terminology](#2-terminology)
3. [A Handshake name as a web origin](#3-a-handshake-name-as-a-web-origin)
4. [WebSockets to a Handshake name](#4-websockets-to-a-handshake-name)
5. [Signing in with a Handshake name from a native application](#5-signing-in-with-a-handshake-name-from-a-native-application)
6. [Trust states](#6-trust-states)
7. [Operational guidance for the server side (NON-NORMATIVE)](#7-operational-guidance-for-the-server-side-non-normative)
8. [Security considerations](#8-security-considerations)
9. [Conformance](#9-conformance)

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## 1. What this specifies, and why it exists

A Handshake name that serves a static page is a document with a nice address.
A Handshake name that serves an *application* — one that keeps state in the
browser, holds a live socket to its own server, and knows who the user is — is
a different claim entirely, and every part of it fails by default:

- A browser that registers `hns://` as a non-standard scheme gives every page
  at a Handshake name the **opaque origin**. `localStorage`, `sessionStorage`,
  IndexedDB and `crypto.subtle` all throw, and any real web application dies
  on its first line rather than on a feature it could degrade.
- Making the scheme standard and secure fixes that and immediately forbids the
  *other* half: a secure context may not open a plaintext `ws://`, and there is
  no public certificate authority that will issue for a name ICANN does not
  know, so `wss://` has nothing conventional to route to either.
- An application that wants to know which name the user is has no mechanism at
  all. Every capability a Handshake-app standard has defined mediates
  *application → registry*; none mediates *application → the application's own
  server*, which is the one every application with server-side state needs
  first.

This chapter specifies all three: the origin, the socket, and the sign-in. It
is written from an implementation in which a third-party application (`.pxls`,
a shared pixel canvas) loads at `hns://pxls`, holds a DANE-pinned `wss://`
socket to its own host, and signs a player in as a Handshake name its server
independently verifies. Every rule below is one that had to hold for that to
work.

The design rule the whole chapter follows: **the browser routes, and never
terminates.** The tunnel in §4 is a dumb TCP splice precisely so that it cannot
weaken the TLS it carries, and the mediator in §5 signs only what an origin
gate has already confined to the application's own server. A component that
cannot read a secret cannot leak one, and a component that cannot substitute a
certificate cannot break a DANE pin.

### 1.1 Scope

**In scope:** the privileges an `hns://` origin is registered with and what they
cost; the routing of a WebSocket whose host is a Handshake name, including the
local tunnel, its fences, the auto-config script that selects it and the
certificate gate that pins it; the mechanism by which a page at a Handshake
name obtains a proof of control over a Handshake name, what that proof binds,
and what a server must check before believing it; and the trust state of the
resulting connection in the terms of the spine's Part I §4.

**Out of scope:** resolution itself (Chapter 1); the numeric-TLD URL convention
(Chapter 10 Part B); the content of a Handshake-app manifest beyond the fields
this chapter's gates read; the registry operations (`records.propose`,
`names.claim`, `content.publish`) that the reference mediator answers
`OutOfScope`; and the human-facing consent interface, of which this chapter
specifies only the decisions it must obtain, never a rendering.

## 2. Terminology

- **Native name** — a Handshake name reached at its own scheme, `hns://pxls`,
  as opposed to its **gateway mirror**, `https://pxls.hns.one`, an ICANN
  address serving byte-identical content for the same name. The distinction
  runs through the whole chapter: they are two origins for one application.
- **Native application** — a page loaded from a native name that behaves as an
  application: it stores state, opens sockets, and authenticates a user.
- **The tunnel** — the loopback HTTP `CONNECT` proxy of §4.2 (`src/ws-proxy.js`).
- **The PAC** — the proxy auto-config script of §4.6 (`src/ws-proxy-pac.js`),
  which decides, per request, whether a WebSocket goes to the tunnel.
- **The mediator** — the browser-side host of §5 that exposes a capability
  surface to an installed application and holds the user's keys away from it.
- **Provider** — the object the mediator exposes to an installed application's
  page (`window.handshake`).
- **Entry origin** — an origin an application declares in its manifest as its
  own (`ui.entry`), and which the mediator has verified it owns (§5.2).
- **Control key** — the key whose public half a name's `_hns` record anchors;
  the thing a sign-in proves possession of (§5.3).

Trust-state vocabulary (`verified` / `unverified` / `failed` / `none`) is the
spine's, Part I §4.

## 3. A Handshake name as a web origin

### 3.1 The scheme registration

An implementation that intends to host applications at Handshake names **MUST**
register `hns` as a **standard** (in WHATWG URL terms, a *special* scheme) and
as a **secure** scheme, so that a page at `hns://<name>` has a tuple origin
(`hns`, `<name>`, null) in the sense of the HTML Standard and is a **secure
context** in the sense of the W3C Secure Contexts specification.

The reference registration (browser `src/main.cjs:110-120`) is exactly:

| Privilege | Value | Consequence |
|---|---|---|
| `standard` | `true` | a real tuple origin; the URL is canonicalised by the URL Standard's host parser |
| `secure` | `true` | a secure context: storage, `crypto.subtle`, and `wss://` are permitted |
| `allowServiceWorkers` | `false` | no service worker may be registered at a Handshake name (AP-3) |
| `supportFetchAPI` | `true` | `fetch()` inside the page reaches the scheme's handler |
| `bypassCSP` | `false` | a Handshake page is subject to Content Security Policy like any other |
| `corsEnabled` | `true` | cross-origin rules are applied to responses the handler produces |
| `stream` | `true` | the handler may answer with a stream, so large media does not buffer |

This registration **MUST** be performed in the process entry point, before the
engine is ready; a scheme left out of it is unregistered, and in the reference
engine loading such a scheme as a main-frame document terminates the process.

### 3.2 What the origin provides

With the registration above, and only with it:

- **Storage.** `localStorage`, `sessionStorage`, IndexedDB and the Cache API
  are keyed by the tuple origin `hns://<name>`, per the HTML Standard's storage
  model. Two Handshake names are two storage shelves; a name and its gateway
  mirror are also two, and an application that runs at both **MUST NOT** assume
  state carries between them.
- **Secure-context APIs.** `crypto.subtle`, and every API gated on
  `isSecureContext`, are available.
- **`wss://`.** A secure context may open a secure WebSocket; §4 specifies how
  it is routed.
- **Relative and same-origin semantics.** Relative URLs resolve against the
  canonical form of the document URL, and a fetch from the page to its own name
  is same-origin.

The single most important consequence is negative: **an application at a
Handshake name does not have to be written for Handshake.** It is an ordinary
web application whose origin happens to be chain-proven. `.pxls` is a FastAPI
service with a plain browser client; nothing in its client code knows what
Handshake is except the six lines that ask for a name (§5).

### 3.3 What the registration costs

**The host parser.** A standard scheme's host is parsed by the URL Standard's
host parser, which runs the *ends in a number* checker and parses such a host
as IPv4. A Handshake top-level name may legitimately be all digits, so
`hns://14898/` canonicalises to `hns://0.0.58.50/` and `hns://hello.14898/` is
not a valid URL at all. This is not an implementation quirk — it is the URL
Standard applying to the scheme, and `new URL('http://hello.14898')` throws in
every conforming browser for the same reason. The convention that carries such
a name in a URL (a single leading `_` on a final all-digit label:
`hns://hello._14898/`) is specified in **Chapter 10 Part B**, and this chapter
inherits it without restating it. An implementation of this chapter **MUST**
decode that marker before a host is resolved or classified; §4.2 states where.

**Case and canonicalisation.** The host is lowercased and a bare
`hns://pxls` commits as `hns://pxls/`. Nothing may compare a Handshake page URL
as an exact string; every gate parses.

**No service workers.** The reference registration disables them (AP-3), so an
application at a native name cannot be made offline-capable or installable by
the usual means. This is a restriction of the reference implementation, not of
the model.

**No `Origin` on the handler's requests.** In the reference engine a request to
a custom scheme reaches the scheme handler with no `Origin`, no `Sec-Fetch-*`
and no request initiator. Therefore an implementation **MUST NOT** build a
same-origin or CORS gate for a privileged `hns://`-served API out of request
headers: such a gate is a no-op and a page at any origin can read the response.
Where a privileged surface must know its caller, the implementation **MUST**
identify it from the engine's own record of which document made the request
(in the reference implementation, the requesting `webContents` id) and **MUST**
fail closed when there is no identifiable caller.

### 3.4 Requests from a native page

An A-record Handshake site is fetched by the implementation's own code over raw
sockets, outside the engine's HTTP stack (Chapter 1 §8), so the header set that
reaches the origin is chosen by the implementation rather than by the engine.
The reference allowlist (browser `src/hns/index.js:693-729`) forwards
`content-type`, `range`, `accept`, `accept-language`, the conditional
validators, the caller's cache intent (`cache-control`, `pragma`) and
`authorization`.

Two rules in that list are normative for applications:

1. An implementation **MUST** forward `Authorization` from a page's own fetch
   to its own origin. Without it the sign-in of §5 cannot complete: the
   mediator mints a header the page never gets to send. `Authorization` is not
   an ambient credential — no user agent attaches it by itself, and it is
   stripped across a cross-origin redirect — so forwarding it does not breach
   the privacy floor that keeps `Cookie` out of this path.
2. An implementation **MUST** forward the caller's cache intent, and **MUST
   NOT** forward the conditional validators alongside a `no-cache`/`no-store`
   directive. An application that polls its own state with
   `fetch(url, {cache:'no-store'})` is otherwise served a `304` from the very
   cache it asked to bypass.

`Cookie` stays dropped on this path: it *is* ambient, and the authentication
model of §5 is token-based.

## 4. WebSockets to a Handshake name

### 4.1 Why `wss://` and only `wss://`

Because the document is a secure context (§3.1), the W3C Mixed Content
specification forbids it to open a plaintext `ws://`. The reference engine
enforces this **in the renderer, before the network layer**: the request never
reaches the process where a handler, proxy or interceptor could rescue it. No
implementation of this chapter can route a `ws://` from a Handshake page, and
none should try.

Therefore:

- A native application **MUST** connect with `wss://<name>/<path>`, or with the
  protocol-relative form that a secure document upgrades to `wss`.
- An implementation **MUST NOT** silently rewrite a page's `ws://` to `wss://`.
  A silent upgrade is a lie about the security state in the one direction that
  matters least, and it teaches an author that their insecure URL works.

Together with §4.7 this gives the property the whole design exists for: a
WebSocket from a Handshake page is end-to-end TLS to the origin, pinned to the
same on-chain key material as the document.

### 4.2 The tunnel

The routing problem is that Chromium must be made to open a TCP connection to
an address that no name resolver it consults can produce. The mechanism is a
**local HTTP `CONNECT` proxy** (RFC 9110 §9.3.6, framed per RFC 9112) bound to
loopback (`src/ws-proxy.js`).

The property that makes it work is a fact about proxies, not about Handshake:
**a client never resolves the destination of an HTTP proxy itself.** When the
session's PAC points `wss://pxls/ws` at the tunnel, the engine sends
`CONNECT pxls:443` carrying the **literal name**. The tunnel then resolves that
name with the implementation's own Chapter 1 resolver — the same chain-proof
lookup an `hns://` navigation makes — dials the resolved address, answers
`200 Connection Established`, and splices raw TCP in both directions.

An implementation of this chapter:

- **MUST** parse exactly one request head, terminated by a blank line, and
  **MUST** bound it (the reference bound is 8 KiB, `src/ws-proxy.js:76`); an
  oversized or truncated head is dropped without a response.
- **MUST** treat anything that is not a well-formed HTTP/1.x request head as an
  error, not as another protocol. A SOCKS greeting is not an HTTP head
  (`parseConnectHead`, `src/ws-proxy.js:138-151`).
- **MUST** accept only `CONNECT`; any other method is `405` with
  `Allow: CONNECT` (`:281-283`). A proxied `GET` is not a tunnel.
- **MUST** require the target to be exactly `<host>:<port>` with the port in
  1–65535 (`parseAuthority`, `:158-164`), and **MUST** keep an IPv6 literal
  bracketed so that it is refused by the host classifier rather than mistaken
  for a name.
- **MUST** decode the numeric-TLD marker of Chapter 10 Part B from the CONNECT
  host before classifying or resolving it (`decodeHnsHost`, `:287`), because
  the host the engine sends is the *URL* form of the name.
- **MUST** forward, not discard, any bytes that arrive after the blank line
  before the `200` is written (`:334`). A well-behaved client sends none, but
  bytes that do arrive belong to the tunnel.
- **MUST NOT** parse, rewrite or terminate anything after the `200`. The
  WebSocket handshake of RFC 6455 and the TLS handshake are performed by the
  user agent, end to end, through the splice. **A tunnel that cannot see
  plaintext cannot weaken it**, and this is the reason the design is a pipe and
  not a bridge: terminating TLS in the browser process would substitute the
  implementation's certificate for the origin's and destroy the DANE binding
  (§4.7), which is the entire trust story.

### 4.3 The proxy-authentication problem

The obvious fence on a local proxy — require a per-session credential — cannot
be built for this traffic, and the reasons are worth recording because they
constrain any implementation, not just this one.

- **SOCKS5 (RFC 1928) cannot carry it.** Chromium's SOCKS5 client offers only
  the "no authentication" method and does not implement RFC 1929
  username/password at all, so a proxy that demands it answers "no acceptable
  method" and every socket dies in the greeting. Chromium additionally ignores
  a `user:pass@` embedded in a PAC proxy string, so the credential cannot reach
  the proxy by that route either.
- **HTTP proxy authentication (RFC 9110 §11, RFC 7235) is never answered for a
  WebSocket handshake.** The tunnel may send `407 Proxy Authentication
  Required` with a `Basic` challenge, but the engine does not surface a
  proxy-auth challenge to its embedder for a `wss://` CONNECT — the embedder's
  `login` event does not fire — so the challenge is never answered and every
  socket dies.

The reference implementation therefore **ships with no credential**
(browser `src/protocols/index.js:255-261` constructs the tunnel with a resolver
and an anonymization predicate and nothing else), and the credential check is
retained but inert (`src/ws-proxy.js:192`, `:275-278`): a well-formed
`{user, pass}` still enforces `Proxy-Authorization: Basic` in constant time, so
a future platform that *can* authenticate a `wss://` proxy re-enables the gate
with no code change. `tests/ws-proxy.test.js` pins both halves — that a plain
CONNECT is served by default, and that a configured credential still challenges
with `407` and resolves nothing.

The boundary is therefore the loopback bind plus the three fences of §4.4, and
an implementation **MUST NOT** describe proxy authentication as one of its
protections. See AP-2.

### 4.4 The fences

A local listening proxy that resolves names and dials for its caller is a
capability, and the whole of its security boundary is these four rules. Each is
normative, each has a reason, and each is pinned by a test in
`tests/ws-proxy.test.js` or `tests/native-origin.test.js`.

**(0) Loopback only.** The listener **MUST** bind `127.0.0.1` and **MUST NOT**
bind a routable interface (`src/ws-proxy.js:213-219`). *Reason:* a LAN peer must
not be able to reach a proxy that resolves Handshake names and dials for it.
This is what makes the absence of authentication tolerable: a process already
on loopback can resolve a Handshake name over public DoH and open a TCP
connection to its public address by itself, so the tunnel grants it nothing new.
*Pinned by:* `tests/native-origin.test.js`, "FENCE 0: the tunnel binds loopback only".

**(1) Handshake hosts only.** A CONNECT whose target host is not a Handshake
host **MUST** be refused `403`, before any resolution
(`src/ws-proxy.js:300-302`). The classification **MUST** be the implementation's
one host classifier (`isHnsHost` → `classifyHost`, `../../src/hns-host.js`,
`../../src/router.js`), never a second copy of the TLD rules. An IP literal —
dotted-quad or bracketed IPv6 — is refused by the same predicate, because a
Handshake host always arrives as a name. *Reason:* the PAC already sends
ordinary relays DIRECT (§4.6); this is the defence in depth for the case where
one arrives anyway, and it is what stops the tunnel being a general-purpose
open proxy. *Pinned by:* "MITIGATION (b)" (two tests).

**(2) SSRF refusal.** The **resolved** address **MUST** be run through the same
public-address guard as every other fetch in the namespace
(`isPublicAddress`, `../../src/safe-address.js`; `src/ws-proxy.js:321-323`), and
a loopback, private, link-local, CGNAT or cloud-metadata address — v4 or v6 —
**MUST** be refused `403` with no dial. *Reason:* a Handshake name is an
attacker-chosen input (Chapter 1 §11.2). Anyone can register a name and point
its `A` record at `127.0.0.1` or `169.254.169.254`; without this fence a page
could make the browser dial the user's own network from inside. *Pinned by:*
"MITIGATION (c)", which uses the real guard.

**(3) The anonymization gate.** While IP Protection is on, a CONNECT **MUST** be
refused `403` **before the name is resolved** (`src/ws-proxy.js:290-295`).
*Reason:* the tunnel dials directly from the browser process, so completing it
would disclose the user's real address to the origin while the user believes it
is hidden — and resolving first would disclose the name to the network as well.
Refusing is the same posture the raw-socket document path takes. Chaining the
upstream dial through the Tor SOCKS port, so that a WebSocket keeps working
while anonymized, is a design item (AP-D2), not a behaviour to assume.
*Pinned by:* "MITIGATION (d)", which asserts that nothing is resolved and
nothing is dialed.

**The order they are evaluated in** is: the head is parsed and the method and
target validated; the anonymization gate; the Handshake-only check; resolution;
the SSRF guard; the dial (`src/ws-proxy.js:257-336`). The two gates that can be
decided without touching the network are decided first, and the anonymization
gate is first of those, so that while IP Protection is on the request produces
no network activity of any kind — not even a name lookup.

There is one further rule that is not a fence but a failure mode: when
resolution yields no dialable address — an unregistered name, or a name whose
only record is a content pointer with no TCP origin — the tunnel **MUST** refuse
`502` (`:312-317`). A content-addressed Handshake name has no socket to hold.

### 4.5 Refusals

A refusal **MUST** be a complete HTTP response (`Content-Length: 0`,
`Connection: close`) and the socket **MUST** then be half-closed gracefully
rather than destroyed (`src/ws-proxy.js:239-249`). *Reason:* `end` flushes the
response before the FIN, where a bare `destroy` can drop the queued bytes and
leave the page with a transport reset instead of a clean proxy error; the
difference is whether the page reliably gets an `error` event.

The status codes are `400` (malformed head or target), `403` (a fence),
`405` (not CONNECT), `407` (only when a credential is configured) and `502`
(resolution failed, no address, or the dial failed). Note that **none of them
reaches the page**: the WebSocket API surfaces a failed handshake as an
untyped `error` event, so every refusal in this section is indistinguishable to
the application. That is a deliberate property of the web platform, not of this
design, and it is why the reasons live here and in the implementation's own
diagnostics (AP-D8).

### 4.6 The proxy auto-config script

Only WebSocket traffic to Handshake hosts may reach the tunnel, and that
decision is made per request by a **PAC script** in the Netscape/Mozilla format
(`FindProxyForURL(url, host)`), which has no RFC. The generator is
`src/ws-proxy-pac.js`.

**The rule (`_isHns`, `src/ws-proxy-pac.js:44-57`).** Lowercase the host and
strip one trailing dot; `localhost`, an IPv4 literal, and anything containing
`:` or beginning with `[` are not Handshake; a host whose final label is in the
reserved list is not Handshake; a single remaining label **is** Handshake; `eth`
and `onion` are not; an all-digit final label is; otherwise it is Handshake
exactly when the final label is not an ICANN top-level domain.

**The decision (`FindProxyForURL`, `:58-63`).** A URL whose scheme is `wss:` or
`ws:` goes to `PROXY 127.0.0.1:<port>` when the host is Handshake and `DIRECT`
otherwise. **Every other URL returns the base directive** — which is the
anonymizer's own current directive (`DIRECT`, or `SOCKS5 <host:port>` when IP
Protection is on, `rulesToPacDirective`, `:29-33`). So page loads, search,
DNS-over-HTTPS and every protocol fetch keep the routing the privacy controller
chose, and only ws/wss-to-Handshake is diverted.

Normative rules for an implementation:

- The PAC's host rule **MUST** mirror the implementation's single classifier
  rather than reimplement it. The reference generator embeds the ICANN
  top-level list and the reserved-name list *from the same files the classifier
  reads* (`../../src/icann-tlds.cjs`, `../../src/reserved-names.cjs`) so there
  is one source and not three. `tests/native-origin.test.js` asserts the PAC
  and `isHnsHost` agree across a corpus, and the reference tree holds the
  omnibox's third copy to the same answer.
- The PAC directive **MUST NOT** carry a credential (`PROXY 127.0.0.1:<port>`
  and nothing else). Chromium ignores `user:pass@` in a PAC proxy string, so a
  credential written there is silently dropped and gives false assurance.
- Where the engine allows exactly one proxy configuration per session, the PAC
  **MUST** be composed *into* the configuration the privacy controller applies,
  through a single writer, rather than applied by a second caller. In the
  reference implementation the anonymization controller owns `setProxy` and
  takes a decorator (`proxyConfigFor`, browser `src/index.js:1129-1145`; applied
  at browser `src/hns/anonymize.js:243-253`), and the controller is re-applied
  once at startup so the PAC is live from launch rather than from the first
  privacy toggle (`reapply()`, `:264-266`). Two writers is a clobber, and the
  loser is silent.
- The script **MUST** be delivered as a URL, not as text, where the engine's
  API demands one. The reference implementation inlines it as
  `data:application/x-ns-proxy-autoconfig;base64,<base64 of the script>` (RFC
  2397, within the URI syntax of RFC 3986). Passing the script verbatim is
  rejected as an invalid PAC URL and **the entire proxy configuration is then
  dropped**, so every `wss://` falls to DIRECT and fails as an unresolvable
  name — a failure that looks like a resolver bug and is not one.
- The feature **MUST** be inert when disabled: no listener, no PAC diversion, no
  certificate gate (browser `src/protocols/index.js:255`, `src/index.js:1133`,
  `:1322`). A capability that is off must have no surface at all, not a disabled
  one.

Two consequences an implementer should expect. The PAC decides on the
**target** host, not on the initiating origin, so an ordinary `https://` page
that opens `wss://<a handshake name>` is routed through the tunnel too (AP-4) —
which is consistent with the web platform, where a WebSocket is not subject to
the same-origin policy. And the PAC as written routes plaintext `ws:` to the
tunnel as well as `wss:` (AP-1); no secure page can produce one, but a
non-secure page can, and the resulting connection is spliced in the clear with
no certificate gate.

### 4.7 The certificate gate

Routing a `wss://` to a Handshake host would be worthless if the certificate
were checked against the WebPKI, because no public CA issues for a Handshake
name. The connection is instead pinned with **DANE-EE (`3 1 1`)**, exactly as a
document load is (Chapter 1 §8), by a session-wide certificate verification
procedure (browser `src/index.js:1330-1351`):

1. If the hostname is **not** a Handshake host, the procedure **MUST** defer to
   the engine's own WebPKI verification. Ordinary `https://` is verified exactly
   as it would be without this feature; the gate is not a global override.
2. If it is, the implementation resolves the name (Chapter 1) and reads its
   TLSA records.
3. **No TLSA records at all is a failure**, not a permission. There is nothing
   to pin a self-signed certificate to, so the connection is rejected.
4. Otherwise the presented certificate is checked against the pin, and a
   mismatch is rejected.

An implementation **MUST** fail closed at steps 3 and 4, and **MUST** record the
outcome of the whole decision — resolution included — as one measurement, so
that a pin check which fails *slowly* is visible. A DANE check that only times
successes hides the interesting case.

The consequence for publishers is stated as a requirement in §4.8: **a realtime
application on Handshake must publish a TLSA pin**, or its socket fails closed
however well everything else works. This is not a hypothetical: the reference
application's first deployment had no `_443._tcp` TLSA in the served zone, so
even a perfect tunnel would have been refused at this gate.

### 4.8 What an application publisher must do

Normative for the *application*, not the browser:

1. Serve the application at a Handshake name with an `A`/`SYNTH` address **and
   a `3 1 1` TLSA record** for `_443._tcp.<name>`, published in both the signed
   (DO=1) and unsigned views of the zone, signed with the key whose DS is
   committed on chain. Without the pin the socket fails closed (§4.7).
2. Connect with `wss://<name>/<path>`, or the protocol-relative form:
   ```js
   const proto = location.protocol === 'http:' ? 'ws:' : 'wss:'
   const ws = new WebSocket(`${proto}//${location.host}/ws`)
   ```
   `location.host` is already the URL form of the name, including the
   Chapter 10 Part B marker where the top-level name is numeric, and the tunnel
   decodes it (§4.2).
3. Never use `ws://` from a page served over `hns://`. It is blocked in the
   renderer and no browser-side component can route it.
4. Terminate the WebSocket at the application's own TLS endpoint, and see §7
   for the two server-side traps that silently break the upgrade.

## 5. Signing in with a Handshake name from a native application

### 5.1 The provider

An application at a Handshake name learns who the user is through a mediator
that exposes a small capability surface — `window.handshake` — and never a key.
The reference mediator is browser `src/apps/handshake-preload.js` (the content
script), `src/apps/handshake-ops.js` (the Electron wiring) and
`src/apps/handshake-surface.js` (the decisions, which are engine-free and
unit-tested).

The transport rules are normative:

- The provider **MUST** be exposed **only** on a top frame whose origin is an
  **installed** application's own entry origin. A subframe of any origin gets
  nothing. Presence of the provider is therefore itself a statement — *this page
  is an installed application* — and an ordinary site pays one round trip to the
  browser process and receives nothing.
- Every operation **MUST** re-derive the calling origin **in the privileged
  process, from the sender itself**, and never from anything the page supplies.
  In the reference implementation the sender's document URL **and** its frame
  URL must resolve to the same origin and the frame must be a top frame
  (`matchedSenderOrigin`, browser `src/apps/handshake-surface.js:35-41`); a
  frame that has navigated away, or a subframe, is refused. This is the reason
  §3.3's rule about request headers exists: an origin gate built on headers a
  custom scheme never carries is a no-op.
- The origin **MUST** be computed the way the *renderer* computes it. A URL
  parser that does not know `hns` is special returns the string `'null'` for
  `new URL('hns://pxls').origin`, and a mediator that believed it would silently
  refuse every native application. The reference implementation reconstructs
  `<scheme>//<host>` for such a scheme and uses the real `origin` for special
  ones (`appOrigin`, browser `src/protocols/app-manifest.js:82-88`).
- Operations **MUST** answer an envelope rather than throw across the process
  boundary, so that error **codes** are stable (`NotGranted`, `UserDeclined`,
  `RateLimited`, `VaultLocked`, `Unavailable`, `OutOfScope`).

A capability the application did not declare in its manifest is refused
(`NotGranted`), and a capability this host does not implement is refused
(`OutOfScope`) rather than crashing — an application must be able to detect a
host's scope without exception handling.

### 5.2 The manifest and origin ownership

An application is *installed* only after a manifest fetched from its own
discovery URL is validated. One rule in that validation carries the security of
the whole mechanism:

> **Origin ownership.** Every origin an application declares in `ui.entry`
> **MUST** have a host that is exactly the application's own id — the native
> name `<id>` — or that name's gateway mirror `<id>.hns.one`. A single entry
> origin the application cannot prove it owns **MUST** fail the whole manifest;
> a partial install is never created.
> (`validateManifest` / `hostOwnedBy`, browser
> `src/apps/manifest-validate.js:32-71`.)

Without it, an application served at `hns://evil` could declare
`ui.entry: "https://pxls.hns.one/"`, have the mediator inject a provider into
another name's origin, and mint tokens there. The list form of `ui.entry` exists
so that one application can be reached at both its native name and its gateway
mirror (§5.5); this rule is what stops that list from becoming a borrowing tool.

Three further install-time rules:

- Discovery **MUST** be bounded and cached negatively per session, so an
  ordinary site costs exactly one request and never a prompt loop. The reference
  order is `/.well-known/hnsapp.json` then a per-application fallback path.
- Discovery for a native origin is performed at its **gateway mirror over
  https**, because in the reference engine fetching a custom scheme from the
  privileged process is unsafe on one platform; the origin-ownership rule then
  binds the fetched manifest back to the native name. An implementation that can
  fetch its own scheme safely **MAY** discover natively; the ownership rule is
  what makes either route equivalent.
- Grants **MUST** be keyed by application **id**, not by origin, so that a name
  granted at the gateway holds at the native name and the reverse. A user does
  not grant an application twice for one application.
- The manifest **MUST** be pinned by a hash of the fetched bytes, and refusals
  ("not now") **MUST NOT** be persisted — a refusal is not a permanent
  decision, while an install is.

### 5.3 The token

`identity.authenticate` (declared by the reference application under the
extension id `one.hns.auth.nip98`) mints an HTTP `Authorization` header proving
control of a granted name, bound to one request.

**What is signed.** A NIP-98 event: `kind` 27235, empty content, `created_at`,
and tags `u` = the absolute request URL, `method` = the uppercased HTTP method,
`nonce` = 8 random bytes hex, and — when there is a body — `payload` = the
SHA-256 of the exact request body. The event is signed (BIP-340 Schnorr over
secp256k1) with the **control key** of the granted name: the key whose public
half that name's `_hns` record anchors. The header is
`Nostr <base64 of the JSON event>` (browser `src/identity/receipt.js:174-186`).

**What crosses back.** The header string, the name, the URL and the method.
Never a key, never a secret, never the raw event. The control key is read from
the vault inside the privileged function, used, and dropped
(browser `src/identity/app-attest.js:59-86`).

**The gates**, all of which **MUST** hold, and all of which are enforced in the
privileged process:

1. **Transport** — the caller is the application's own installed page (§5.1).
2. **Manifest** — the application declared the capability; absence grants
   nothing (`manifestGrantsAuth`).
3. **Origin** — *the one that matters.* The `url` to be signed **MUST** be under
   one of the application's own entry origins (`originAllowedForAuth`, browser
   `src/protocols/app-manifest.js:115-119`). Without this rule the operation is
   a **signing oracle** over the user's control key: an application could ask
   for a token bound to a registry's mutation endpoint and own every name the
   user holds. A token for someone else's origin is refused in the privileged
   process, not in the page.
4. **Method** — a small allowlist (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`,
   `HEAD`), because NIP-98 binds the method into the event and an exotic verb
   is outside the reviewed shape.
5. **Rate** — a per-application-id token bucket (reference: 30/minute) checked
   **before** any signing, so a runaway page cannot drive the control key
   unbounded.
6. **Name** — the signing name **MUST** be one the user granted to this
   application. An explicit name outside the grants is refused; with no explicit
   name the sole grant is used, else the user's primary name if it is granted,
   else the call is declined as ambiguous.

**Consent is at install, not per call**, for this capability only: it
authenticates to an origin the user is already on and writes nothing anywhere.
Prompting per call would put a dialog in the hot path of an interactive
application and train the user to click through consent, which is the failure
mode consent exists to prevent. Every *mutating* capability keeps its own
consent.

**A locked key store is not a refusal.** An implementation **MUST** distinguish
"the user declined" from "the keys could not be read", and **MUST** say which
(`VaultLocked` with an instruction). Answering a locked store with "no names"
tells an application the user refused — a false statement about the user, with
no mention of the one thing that would fix it.

### 5.4 What the application's server verifies

This is the half a browser cannot enforce and a specification must state
plainly.

> **A provider's answer is a user-interface convenience, never an
> authentication result.** A server **MUST NOT** trust a name because the page
> reported it: the report arrives over the wire from the party it flatters.

The reference application's server (`.pxls`) does exactly what this requires,
and its shape is the recommended one:

1. **Verify the signature.** Check the NIP-98 header against the exact URL,
   method and body actually received, check the kind, and check freshness
   against a bounded window. This proves only *who signed*.
2. **Record the event for single use.** Keep the event id in a replay ledger
   for longer than the freshness window, so an event can never age out of the
   ledger while still being accepted as fresh.
3. **Bind the key to the name, from the name's own record.** Resolve
   `_hns.<name>` and require that its `pubkey` field be the key that signed.
   The record is a TXT of the form
   `v=hns1;pubkey=<64 hex>;epoch=<n>[;receipt=<created_at>.<sig>]`. A record
   that does not parse, or whose receipt does not verify, is treated as **no
   record at all** — never as an unverified-but-usable name.
4. **Only then** treat the session as a named one. The reference server exposes
   this to its own client as `verified: true`, which is true only when a
   binding was established this way.
5. **Issue a session credential** and stop signing per request. One NIP-98
   signature opens a session; a bearer token carries it afterwards. A signature
   per action puts a signing round trip in the hot path, makes every action a
   consent decision, and grows the replay ledger without bound.

Two further properties the reference server documents, and any implementer
should copy: the age of a name (used there as a prize gate) is trustworthy only
because the `_hns` prefix is *managed* — written by the registry at claim time
and not rewritable by the user or the application — so it is a claim about that
registry's behaviour, not a trustless proof; and a name with an apex control key
and no receipt is one bought on chain, which is the one credential in the system
that is expensive to forge in bulk.

### 5.5 The two-origin problem

An application reached at both `hns://pxls` and `https://pxls.hns.one` has two
origins for one identity, and NIP-98 binds a signature to an exact URL. The
reference signer additionally accepts only absolute `http(s)` URLs
(browser `src/identity/receipt.js:175`), so the native origin cannot be the URL
bound in a token at all.

The resolution is on the client, not in the mediator: a page at the native
origin mints its token for the application's **canonical gateway origin** — the
base its server verifies against — while still sending the request to its own
origin. The mediator permits this because the gateway origin is one of the
application's own entry origins (§5.2), and only because of that.

An implementation **MUST NOT** achieve this by rewriting bytes on the wire, and
**MUST NOT** relax the origin gate to a suffix or a "related origins" test. The
consequence — a token whose `u` tag is not the URL the request was sent to — is
recorded as AP-5, with the honest note that what holds the property together is
the server's fixed public base plus its replay ledger, not the URL binding.

### 5.6 What the provider is not

- It is **not** proof of identity to a server (§5.4).
- It is **not** a key. No operation returns a key, a secret, a raw event, or a
  name the user did not grant; an application sees only the names granted to it,
  never the user's portfolio.
- It is **not** a general signer. The only bytes it will ever sign are
  `{url, method, body}` that the origin gate has already confined to the
  application's own server.
- It is **not** a claim of trustworthiness. Manifests are unsigned in the
  reference implementation, `verified` is always false, and the consent copy
  says so (AP-6).

## 6. Trust states

In the spine's Part I §4 terms, a `wss://` upgrade to a Handshake name produces
these steps. They are the document's steps with one addition and one deletion:
the certificate step is performed by the engine's verification procedure rather
than by the fetch path, and there is no content step because a socket has no
bytes to verify.

| Step | State | Who said so |
|---|---|---|
| Namespace | `none` | decided by scheme and host before any lookup (spine Part II); the PAC's classification mirrors it |
| Name → records | `verified` when the Chapter 1 chain path answered; `unverified` when the DoH fallback did, and the resolver that answered **MUST** be named | the chain, or a named DoH resolver |
| Address policy | `none` | not a trust claim: the SSRF guard is a refusal, not an assertion about the address |
| Certificate | `verified` when a `3 1 1` TLSA under a validated zone matched the presented certificate; `failed` on mismatch or on a Handshake host with no pin | the on-chain DS anchoring the zone that published the TLSA |
| Connection | `verified` — TLS end to end from the user agent to the origin, through a splice that never held a key | the TLS session itself |
| Upgrade | `none` | RFC 6455's `Sec-WebSocket-Accept` check is a protocol conformance check performed by the user agent; it adds no trust (DEVIATIONS §2.1) |

Aggregation follows the spine's rule. A socket whose name step is chain-proven
and whose certificate step is verified is **TRUSTLESS**. A socket whose name
came from DoH is **TRUSTED** — the transport is authenticated and pinned, but
the name→address binding was somebody's word, and an interface **MUST NOT**
render the two identically.

There is no **OPEN** state for this path, and that is the point: a `failed`
certificate step, an absent pin, a non-public address or an active
anonymization gate all end with no socket rather than with a degraded one. An
implementation **MUST NOT** offer the user a way to proceed past any of them.

The application-level sign-in of §5 adds no step to the *connection's* trust
state. It is a fact about the user, established by the application's server
against DNS, and an implementation **MUST NOT** let it colour the connection
indicator.

## 7. Operational guidance for the server side (NON-NORMATIVE)

Everything in this section is about the machine serving the application. None
of it is required for conformance; all of it is required for the thing to work,
and each item cost a full diagnosis at least once.

**HTTP/2 silently breaks the upgrade.** The `Upgrade` header is not legal in
HTTP/2, so a WebSocket handshake that arrives over an h2 connection reaches the
application server as a plain `GET /ws` and is answered `404` — with nothing
anywhere saying "WebSocket". On nginx 1.24 and earlier, HTTP/2 is enabled
**per listening socket, not per server block**: a single `listen 443 ssl http2`
anywhere in the configuration turns on h2 (via ALPN) for *every* SNI on that
socket, including virtual hosts that carefully wrote `listen 443 ssl`. The
per-server `http2 off;` directive requires nginx ≥ 1.25.1. The reference
deployment's fix was to strip `http2` from every `listen` directive on the box,
which turns HTTP/2 off host-wide; HTTP/1.1 is universal, so the only loss is h2
multiplexing. Diagnose it with two requests, not with logs:
`curl --http1.1` returns `101` where the default returns `404`, and
`openssl s_client -alpn h2,http/1.1` shows which protocol the socket actually
negotiates for that SNI.

**Serve the application, not the gateway, at the native name.** A name that is
also published through a content gateway usually has two upstreams on the same
box — the gateway that serves published content, and the application itself.
Pointing the native name's virtual host at the gateway produces a page that says
"nothing published yet" while the gateway mirror works perfectly, which reads as
a browser bug and is not one. The native name and the gateway mirror must reach
the *same* upstream.

**Publish the DANE pin, in both views.** The `wss://` upgrade fails closed
without a `3 1 1` TLSA at `_443._tcp.<name>` (§4.7). Two traps: the record must
be served in the signed (DO=1) *and* unsigned views of the zone, and the zone
must be signed with the key whose DS is committed on chain. A separate one,
inherited from Chapter 1: an authoritative server that answers **NXDOMAIN** for
`_443._tcp.<name>` — rather than NODATA — makes the browser unable to conclude
"there is authenticated no pin here", and the same zone therefore cannot serve a
plain HTTP site either. If the server is yours, answer NODATA for an
underscore-prefixed child of a name the zone serves.

**Expect the application's own fetches to carry their cache intent.** The
implementation forwards `no-store` and drops the conditional validators
alongside it (§3.4), so an application polling its own state gets fresh bytes;
a server that answers `304` regardless will pin a live application to stale
state.

**Compress large payloads.** Nothing in this chapter does it for you; the
reference application served a 256 KiB canvas uncompressed on every load.

## 8. Security considerations

**The tunnel is the sensitive component, and its whole boundary is §4.4.** It
is unauthenticated by necessity (§4.3), so the four fences are not defence in
depth — they are the defence. An implementation that relaxes any of them has
built a local open proxy. The two that would be tempting to relax are the
Handshake-only rule (which is what keeps it from proxying the whole internet
for any local process) and the SSRF guard (which is what keeps an
attacker-registered name from pointing the browser at the user's own network).

**Every address in this chapter is attacker-chosen.** Anyone can register a
Handshake name, publish any records under it, and serve any application at it.
The origin-ownership rule (§5.2), the signing-oracle guard (§5.3 gate 3) and
the SSRF guard (§4.4 fence 2) are each written on the assumption that the name
on the other side is hostile.

**A capability that is off must be inert.** Both features here are
configuration-gated, and when off there is no listener, no PAC diversion, no
certificate procedure, no preload and no IPC channel. A disabled-but-present
surface is an attack surface with no owner.

**Ports.** The tunnel dials the port the CONNECT target names, so an
application may be served on a non-default port. The engine's own blocked-port
list applies before the request is routed, and the SSRF guard confines the
destination to public addresses, but an implementation should understand that a
page can cause a connection attempt to an arbitrary permitted port of a public
host that a Handshake name resolves to. That is the same reach an ordinary
`fetch` already has (AP-3).

**Routing is by target, not by initiator.** Any page — including an ordinary
`https://` one — that opens `wss://<handshake name>` is routed through the
tunnel and pinned by the certificate gate (AP-4). This matches the web
platform's treatment of WebSockets, and the consequence is that a page can use
the browser as an oracle for whether a Handshake name is live. It cannot learn
anything the name does not already publish.

**The mediator never holds a decision the page can influence.** Every gate is
re-evaluated in the privileged process from facts the page cannot supply: the
sender's own URL, the stored manifest, the recorded grants. The page supplies
only the request it wants signed, and that request is confined to its own
origin before a key is touched.

**Keys never cross.** No operation returns key material. The control key is
read inside a privileged function, used to sign one event, and goes out of
scope; only the header string crosses back. An implementation that returns a
signature *and* a key has built a different, worse system.

**The user-visible failure of a refused socket is indistinguishable from a
network error.** That is a property of the WebSocket API, and it means an
implementation **MUST NOT** rely on the page to explain a refusal to the user;
the explanation belongs in the browser's own diagnostics (AP-D8).

## 9. Conformance

An implementation conforms to this chapter when:

1. `hns` is registered as a standard, secure scheme, and the numeric-TLD marker
   of Chapter 10 Part B is decoded before any host is classified or resolved
   (§3.1, §3.3).
2. No same-origin or CORS gate on a custom-scheme surface is built from request
   headers; the caller is identified from the engine's own record (§3.3).
3. `Authorization` is forwarded on a page's fetch to its own origin, and cache
   intent is forwarded without the conditional validators (§3.4).
4. A `ws://` from a secure Handshake page is never rewritten or rescued (§4.1).
5. The tunnel parses exactly one bounded CONNECT head, accepts only CONNECT,
   accepts only `<host>:<port>`, and never inspects a byte after the `200`
   (§4.2).
6. All four fences hold — the listener binds loopback only; the anonymization
   gate and the Handshake-only check both refuse *before* the name is resolved;
   the SSRF guard is applied to the resolved address before any dial — and each
   refusal is a complete HTTP response followed by a graceful half-close
   (§4.4, §4.5).
7. Proxy authentication is not claimed as a protection (§4.3).
8. The PAC mirrors the single host classifier, carries no credential, is
   composed into the one proxy authority, and is delivered as a data URL (§4.6).
9. A `wss://` to a Handshake host is pinned to a `3 1 1` TLSA and fails closed
   when the pin is absent or mismatched, while every non-Handshake host defers
   to the engine's own verification (§4.7).
10. The provider is exposed only to an installed application's own top frame,
    every operation re-derives the origin in the privileged process, and the
    origin is computed as the renderer computes it (§5.1).
11. Every declared entry origin is proved to be owned by the application, and
    one that is not fails the whole manifest (§5.2).
12. A token is minted only for the application's own origin, only for a granted
    name, only under a rate limit, and never returns key material (§5.3).
13. A locked key store is reported as locked, never as a user refusal (§5.3).
14. The trust steps of §6 are exposed individually, and no failure of them
    offers the user a way to proceed (§6).
