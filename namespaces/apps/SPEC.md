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
  **MUST** bound it in bytes *and* in time (the reference bounds are 8 KiB,
  `src/ws-proxy.js:92`, and 10 s, `readHead`, `:124-161`); an oversized,
  truncated or slow head is dropped without a response.
- **MUST** count only header bytes against that byte bound. A client may
  coalesce tunnel payload into the same TCP segment as the head, and payload is
  not a header: the reference reader bounds the buffered prefix only (`:131`),
  returns everything after the blank line as `leftover`, and **pauses** the
  client socket the moment the head is complete (`:134`) so that further tunnel
  bytes are retained by the kernel while the resolution and the dial await.
- **MUST** treat anything that is not a well-formed HTTP/1.x request head as an
  error, not as another protocol. A SOCKS greeting is not an HTTP head
  (`parseConnectHead`, `src/ws-proxy.js:168-181`).
- **MUST** accept only `CONNECT`; any other method is `405` with
  `Allow: CONNECT` (`:405-407`). A proxied `GET` is not a tunnel.
- **MUST** require the target to be exactly `<host>:<port>` with the port in
  1–65535 (`parseAuthority`, `:188-194`), and **MUST** keep an IPv6 literal
  bracketed so that it is refused by the host classifier rather than mistaken
  for a name.
- **MUST** decode the numeric-TLD marker of Chapter 10 Part B from the CONNECT
  host before classifying or resolving it (`decodeHnsHost`, `:411`), because
  the host the engine sends is the *URL* form of the name.
- **MUST** forward, not discard, any bytes that arrive after the blank line
  before the `200` is written (`:474`). A well-behaved client sends none, but
  bytes that do arrive belong to the tunnel.
- **MUST** run one listener at most. The reference `start()` refuses a second
  call (`:312`) and binds an ephemeral port when given none (`:313`, `:332`),
  so the port is the operating system's answer rather than a guess that another
  process may already hold.
- **MUST NOT** parse, rewrite or terminate anything after the `200`. The
  WebSocket handshake of RFC 6455 and the TLS handshake are performed by the
  user agent, end to end, through the splice. This is the reason the design is a
  pipe and not a bridge: terminating TLS in the browser process would substitute
  the implementation's certificate for the origin's and destroy the DANE binding
  (§4.7), which is the entire trust story.

The converse is the limit of what the tunnel can promise. **It is an opaque TCP
pipe, not a TLS verifier**: it does not inspect a byte after the `200`, so it
cannot tell TLS from plaintext, cannot check a certificate, and contributes
nothing to the pin. Everything this chapter claims about the *endpoint* is
supplied by the certificate gate of §4.7 — in the reference implementation the
engine's `setCertificateVerifyProc`, which is a property of connections the
engine makes, not of connections the tunnel carries.

### 4.3 The proxy-authentication problem

The obvious fence on a local proxy — require a per-session credential — is not
reachable for this traffic **in the runtime this chapter is written from**, and
the measurements are worth recording because an implementer on another engine
must repeat them rather than inherit the conclusion. Both statements below are
about the tested Electron build and the tested code path (a `wss://` CONNECT
from the web-content session); neither is a property of HTTP, of SOCKS, or of
every version of Chromium, and neither has been re-measured on every engine
version this implementation has since run on. An implementation on another
engine, or another version of this one, **MUST** measure rather than inherit
the conclusion.

- **SOCKS5 (RFC 1928) did not carry it.** In that build Chromium's SOCKS5
  client offered only the "no authentication" method — it does not implement
  RFC 1929 username/password — so a proxy that demanded it answered "no
  acceptable method" and every socket died in the greeting. Chromium
  additionally ignores a `user:pass@` embedded in a PAC proxy string, so the
  credential did not reach the proxy by that route either.
- **HTTP proxy authentication (RFC 9110 §11, RFC 7235) was never answered for a
  WebSocket handshake.** The tunnel sends `407 Proxy Authentication Required`
  with a `Basic` challenge, and on that path the engine surfaced no proxy-auth
  challenge to its embedder for a `wss://` CONNECT — the embedder's `login`
  event did not fire — so the challenge was never answered and the socket died.

The reference implementation therefore **ships with no credential** (the
browser constructs the tunnel with a resolver and the anonymizer's `isOn` and
`torSocks`, and no credential), and the credential check is
retained but inert (`src/ws-proxy.js:228`, `:399-402`): a well-formed
`{user, pass}` still enforces `Proxy-Authorization: Basic` in constant time, so
a platform that *can* authenticate a `wss://` proxy re-enables the gate with no
code change. `tests/ws-proxy.test.js` pins both halves — that a plain CONNECT is
served by default, and that a configured credential still challenges with `407`
and resolves nothing.

The boundary is therefore the loopback bind plus the content fences of §4.4, and
two consequences follow that an implementation **MUST NOT** soften. Proxy
authentication is not one of this feature's protections, and no document,
comment or interface may present it as one. And the loopback bind is not
authentication either: **it limits access to this device, and it does not
identify or authenticate the application making the request.** Any process on
the machine that can open `127.0.0.1:<port>` meets exactly the fences of §4.4
and nothing else. See AP-2.

### 4.4 The fences

A local listening proxy that resolves names and dials for its caller is a
capability, and the whole of its security boundary is these five rules. Each is
normative, each has a reason, and each is pinned by a test in
`tests/ws-proxy.test.js` or `tests/native-origin.test.js`.

**(0) Loopback only.** The listener **MUST** bind `127.0.0.1` and **MUST NOT**
bind a routable interface (`src/ws-proxy.js:311-339`, the bind at `:332`).
*Reason:* a LAN peer must not be able to reach a proxy that resolves Handshake
names and dials for it. State the guarantee at its real width: **loopback limits
access to this device; it does not authenticate the requesting application**
(§4.3). Every other process on the machine is inside this fence, and what
confines it there is fences 1–4 and nothing else.
*Pinned by:* `tests/native-origin.test.js`, "FENCE 0: the tunnel binds loopback only".

**(1) One port, and it is the one this profile looks a pin up at.** A CONNECT
**MUST** name port **443**; any other port **MUST** be refused `403`, before the
name is resolved (`TUNNEL_PORT`, `src/ws-proxy.js:87`; the check at `:416-418`).
*Reason:* this implementation reads a DANE pin at `_443._tcp.<name>` and only
there, whatever port a URL names (Chapter 1 §8, HS-6), so 443 is the only port
for which its certificate gate has a pin to check — a splice on any other port
would carry TLS the gate could not bind to the name. The rule is a **destination
restriction**, and it is worth being exact about what that does and does not
buy. It does not inspect a byte, so it cannot establish that what rides the
splice is TLS at all, and it does not perform the pin check: that is §4.7's, in
the engine. What it does buy is that no splice this tunnel makes falls outside
the range the pin lookup covers, and that the commonest plaintext case is
declined — a `ws://` from a non-secure page arrives as `CONNECT <name>:80` and
is refused here. Refusing *here* rather than excluding `ws:` in the PAC is what
keeps the name out of a system-resolver query: excluded there it would take the
session's base route and, in Fast mode, be handed as a name to the very resolver
this design exists to keep it away from (§4.6). An implementation
**MAY** make the accepted set injectable so a test can stand a TLS origin
elsewhere (the reference constructor takes `ports`, `:219`), and **MUST** ship
with the single port its own pin lookup covers. *Pinned by:* "a CONNECT to any
port but 443 is refused before the name is resolved — a plaintext ws:// is never
spliced".

**(2) Handshake hosts only.** A CONNECT whose target host is not a Handshake
host **MUST** be refused `403`, before any resolution
(`src/ws-proxy.js:437-439`). The classification **MUST** be the implementation's
one host classifier (`isHnsHost` → `classifyHost`, `../../src/hns-host.js` →
`../../src/classify-host.cjs`, re-exported by `../../src/router.js`), never a
second copy of the TLD rules. An IP literal —
dotted-quad or bracketed IPv6 — is refused by the same predicate, because a
Handshake host always arrives as a name. *Reason:* the PAC sends an ordinary
relay along the session's base privacy route and never here (§4.6); this is the
defence in depth for the case where one arrives anyway, and it is what stops the
tunnel being a general-purpose open proxy. *Pinned by:* "FENCE 2" (two tests).

**(3) SSRF refusal.** The **resolved** address **MUST** be run through the same
public-address guard as every other fetch in the namespace
(`isPublicAddress`, `../../src/safe-address.js`; `src/ws-proxy.js:459-461`), and
a loopback, private, link-local, CGNAT or cloud-metadata address — v4 or v6 —
**MUST** be refused `403` with no dial. *Reason:* a Handshake name is an
attacker-chosen input (Chapter 1 §11.2). Anyone can register a name and point
its `A` record at `127.0.0.1` or `169.254.169.254`; without this fence a page
could make the browser dial the user's own network from inside. *Pinned by:*
"FENCE 3", which uses the real guard.

**(4) The Tor rule: dial through it, or refuse.** In Private mode, a direct
dial from the browser process would disclose the user's real address to the
origin while the user believes it is hidden, so the tunnel **MUST NOT** dial
directly in that state. With the device-local Tor's SOCKS port to hand it dials
the upstream **through** it (`torSocks` → `socksDialer`,
`../../src/socks-dial.js`, RFC 1928 — the fence-4 branch of `_handle`); with
no Tor port it **MUST** refuse `403`, before the name is resolved. *Reason:*
the route of the socket is the only thing that changes. The tunnel still
resolves the name itself, so the chain proof, the trust steps of §6 and the SSRF
fence are exactly what they are on the direct route, and the certificate the
origin presents is still pinned end to end (§4.7) because the tunnel is still a
pipe. Two sub-rules are what make that true rather than hoped for:

- The dial through Tor **MUST** use an **address in the SOCKS request** — the
  resolved address is sent to the SOCKS server as an address, `ATYP` IPv4 or
  IPv6 (RFC 1928 §4), never as a name — so the proxy is never asked to resolve
  for the tunnel and the SSRF guard still has an address to inspect. A tunnel
  that let the proxy resolve for it would give up both.
- The resolver the tunnel is given **MUST** itself resolve without leaving the
  anonymized path. In the reference composition it is the one shared Chapter 1
  resolver, whose authoritative queries and whose three ICANN lookups both ride
  the same Tor dial and the implementation's own DoH client. A tunnel whose
  socket rides Tor while its lookups do not has moved the disclosure, not
  removed it.

**What this does not hide is the name.** An address in the SOCKS request means
the SOCKS server performs no lookup for us; it does not mean the name is absent
from the stream. The user agent's TLS handshake runs end to end through the
splice, and its ClientHello carries the server name in the SNI extension
(RFC 8446 §4.2.9; RFC 6066 §3) in the clear, so the exit that carries the stream
— and anything on the path between that exit and the origin — can read which
Handshake name is being reached. An implementation **MUST NOT** describe the
address-form SOCKS request as hiding the name from Tor. Encrypted ClientHello
(RFC 9848) is the mechanism that would close this, and it is not deployed on
this path (Chapter 1, HS-3); until it is, the honest claim is that the anonymized
route hides the **user's address from the origin**, not the **name from the
route**. See AP-8.

The tunnel's two inputs for this fence are the anonymizer's `isOn()` and
`torSocks()` (`namespaces/tor/src/anonymize.js`), and together they name the
three states a CONNECT can meet. The mode is **Settings › Content delivery ›
Mode**, one control whose policy table is `policyFor()` in
`../../src/delivery-mode.js`:

| Mode | Anonymizer | `isAnonymized()` | `torSocks()` | The tunnel |
|---|---|---|---|---|
| Fast | `off` | false | — | dials the resolved address directly |
| Private, Tor connected | `tor` | true | the SOCKS URL | dials through the SOCKS port, with the resolved address in the SOCKS request |
| Private, blocked | `blocked` | true | `null` | refuses `403` before resolving |

The third state is the anonymizer's fail-closed answer to a Tor that cannot be
had — no client bundled or running, or one that could not reach the network.
In it every session's proxy is `BLACKHOLE_RULES`, a loopback port nothing
listens on, so the page that opened the socket is itself loading nothing
through the session; the tunnel, which the session proxy does not cover,
refuses on its own because `torSocks()` is `null`. Neither Private state ever
produces a direct dial, which is the whole of the rule.

*Pinned by:* "with IP Protection on, the dial goes THROUGH the Tor SOCKS port
when there is one, and is refused when there is not", which asserts that the
SOCKS request carried **the resolved address and never the name**; and
"FENCE 4", which asserts that with no Tor port nothing is resolved and nothing
is dialed. Neither test says anything about the TLS that then runs through the
splice, which is where the name reappears — see the paragraph above.

**The order they are evaluated in** is: the head is parsed and the method and
target validated; the port; the Tor decision; the Handshake-only check;
resolution; the SSRF guard; the dial (`src/ws-proxy.js:380-476`). The three
gates that can be decided without touching the network are decided first, and
the port is first of those, so a refused port costs no lookup and a
Private-mode request with no Tor circuit produces no network activity of any
kind — not even a name lookup.

There is one further rule that is not a fence but a failure mode: when
resolution yields no dialable address — an unregistered name, or a name whose
only record is a content pointer with no TCP origin — the tunnel **MUST** refuse
`502` (`:450-454`). A content-addressed Handshake name has no socket to hold.

### 4.5 Refusals, resource limits and route revocation

#### 4.5.1 The shape of a refusal

A refusal **MUST** be a complete HTTP response (`Content-Length: 0`,
`Connection: close`) and the socket **MUST** then be half-closed gracefully
rather than destroyed (`src/ws-proxy.js:358-372`). *Reason:* `end` flushes the
response before the FIN, where a bare `destroy` can drop the queued bytes and
leave the page with a transport reset instead of a clean proxy error; the
difference is whether the page reliably gets an `error` event.

Two rules keep that from becoming a leak of its own. A refusal **MUST NOT** be
written to a client that is already destroyed (`:359`) — there is no socket to
flush and the write is an error, not a diagnostic — and a client that does not
close after the response **MUST** be destroyed on a bounded timer (the reference
timer is 1 s, `:369-371`), so a peer that never reads cannot hold a slot open.

#### 4.5.2 The status a refusal carries

The status codes are `400` (malformed head or target), `403` (a fence), `405`
(not CONNECT), `407` (only when a credential is configured) and the three
gateway statuses, which **MUST** be distinguished as RFC 9110 §15.6 defines
them:

| Status | Meaning here | Where |
|---|---|---|
| `502` Bad Gateway | resolution failed, resolution yielded no dialable address, or the dial failed | `src/ws-proxy.js:447`, `:450-454`, `:469` |
| `503` Service Unavailable | the tunnel is at its pending-operation limit and is refusing work it would otherwise do (§4.5.3) | `:447`, `:469`, from the `EBUSY` of `:279` |
| `504` Gateway Timeout | the resolution or the dial exceeded its own deadline (§4.5.3) | `:447`, `:469`, from the `ETIMEDOUT` of `:293-297` |

An implementation **MUST NOT** answer a timeout or a capacity refusal with
`502`: the three are different facts about the tunnel, and collapsing them makes
the one transient case indistinguishable from the one that means the name is
broken.

Note that **none of them reaches the page**: the WebSocket API surfaces a failed
handshake as an untyped `error` event, so every refusal in this section is
indistinguishable to the application. That is a property of the web platform,
not of this design, and it is why the status is nonetheless normative — it is
what a proxy-aware client, a test, and the implementation's own diagnostics read
(AP-D8).

#### 4.5.3 Limits

A local proxy that resolves names and dials for its caller **MUST** bound the
work one caller can make it hold. An implementation **MUST** state its limits;
the reference set is `WS_LIMITS` (`src/ws-proxy.js:93`), and it is normative in
two directions — the timeouts and counts below are the values this
implementation ships, and they are also the **maximum** a deployment may
configure, because the constructor refuses any limit that is not a positive safe
integer at or below the built-in value (`:237-240`). A limit may be lowered for
a test or a constrained host; it may not be raised.

| Limit | Value | What it bounds |
|---|---|---|
| `headTimeout` | 10 s | reading one CONNECT head (§4.2) |
| `resolveTimeout` | 15 s | one resolution |
| `dialTimeout` | 20 s | one upstream dial, direct or through SOCKS |
| `maxConnections` | 128 | live client sockets; beyond it a new connection is dropped unanswered (`:316`) |
| `maxPending` | 32 | connections still in setup, and separately the resolutions and dials outstanding at once; beyond it the answer is `503` (`:279`) |

Two properties of the pending count are normative, because a reimplementation
that misses either has a bound that does not bind. A cancelled operation
**MUST** keep its slot until the underlying work actually settles (`:305-306`):
shared resolution machinery need not support cancellation, and releasing the
slot at the timeout instead would let a client with a stalled name create
unbounded background work by retrying. And a result that arrives after its
operation was abandoned **MUST** be disposed of, not used — the reference
`_operation` takes a `dispose` callback and the dial passes
`socket => socket?.destroy()` (`:467`), so a late upstream is closed rather than
left open.

#### 4.5.4 Cancellation and route revocation

Every connection **MUST** carry a cancellation scope that a resolution and a
dial both observe. In the reference implementation it is a per-connection
context holding an `AbortController` (`:318`), whose signal is passed into
`readHead`, into `resolver.resolve` and into the dialler
(`../../src/socks-dial.js` takes `{ signal }` and settles once), and which is
aborted when the client socket closes (`:320-325`).

The rule that matters most is about a change of privacy mode:

> **A change of route revokes the sockets made under the old one.** When the
> anonymizer's state changes — Fast to Private, Private to Fast, or the Tor
> port appearing or going away — an implementation **MUST** abort every pending
> resolution and dial and **MUST** destroy every established upstream and client
> stream made under the previous route. It **MUST NOT** leave a connected socket
> running on a route the user has just turned off.

The reference implementation does this with a generation counter
(`policyChanged()`, `src/ws-proxy.js:252-261`): the generation is incremented,
every live context is aborted and both its streams destroyed, and any work that
was already in flight fails its next `_current` check (`:269-272`) and is
refused. A raw CONNECT splice is not in the engine's connection pool, so nothing
else in the browser tears it down; if the tunnel does not, a `wss://` opened in
Fast mode keeps sending over its direct socket after the user has switched to
Private. The transition **MUST** be driven by the controller's own event rather
than by polling — the reference wiring binds the anonymizer's and the delivery
mode's `policy-changing` event to `policyChanged()` and their `change` event to
`refreshPolicy()` (`bindWsProxyPolicy`, browser
`src/hns/ws-proxy-policy.js:25-39`), so revocation happens synchronously, before
the controller awaits its own persistence and proxy work — and a getter check
(`refreshPolicy()`, `:263-267`) **SHOULD** be re-evaluated on accept and before
each step as a defence in depth, not as the primary mechanism. `stop()` is the
same revocation plus the listener (`:341-353`).

Revocation is the one path that writes no status. It destroys the client stream
along with the upstream, so the refusal that the abandoned work then attempts is
skipped as a write to a destroyed client (§4.5.1) and the page sees a transport
failure rather than a proxy response. That is the correct order — the socket
must stop carrying bytes whether or not a courtesy response can still be
delivered — and it is why the reason for a revocation has to be recorded in the
implementation's own diagnostics (AP-D8) rather than inferred from a status.

### 4.6 The proxy auto-config script

Only WebSocket traffic to Handshake hosts may reach the tunnel, and that
decision is made per request by a **PAC script** in the Netscape/Mozilla format
(`FindProxyForURL(url, host)`), which has no RFC. The generator is
`src/ws-proxy-pac.js`.

**The rule (`_isHns`, `src/ws-proxy-pac.js:49-62`).** Lowercase the host and
strip one trailing dot; `localhost`, an IPv4 literal, and anything containing
`:` or beginning with `[` are not Handshake; a host whose final label is in the
reserved list is not Handshake; a single remaining label **is** Handshake; `eth`
and `onion` are not; an all-digit final label is; otherwise it is Handshake
exactly when the final label is not an ICANN top-level domain.

**The decision (`FindProxyForURL`, `:63-68`).** A URL whose scheme is `wss:` or
`ws:` and whose host is Handshake goes to `PROXY 127.0.0.1:<port>`. **Every
other URL — including a `ws:`/`wss:` to a host that is not Handshake — returns
the base directive**, which is the anonymizer's own current directive (`DIRECT`
in Fast mode; `SOCKS5 <host:port>` in Private mode — the Tor port while routed,
the blackhole port while blocked — `rulesToPacDirective`). So page loads, search,
DNS-over-HTTPS and every protocol fetch keep the routing the privacy controller
chose, and only ws/wss-to-Handshake is diverted.

That fall-through is normative, and it is the one rule in this section with a
privacy consequence rather than a routing one:

> A WebSocket to a host this chapter does not claim **MUST** take the session's
> base route, exactly as an `https://` to the same host would. An implementation
> **MUST NOT** answer `DIRECT` for it while the base directive is a proxy: a
> generator that does has written a PAC under which `https://example.com/` rides
> Tor and `wss://example.com/socket` does not, which contradicts the mode the
> user selected and discloses the address the mode exists to hide. *Pinned by:*
> `tests/native-origin.test.js`, "a non-Handshake WebSocket follows the base
> privacy route, never DIRECT".

**Refusal rather than degradation.** The generator **MUST** refuse an input it
cannot represent, and **MUST NOT** substitute a route. `rulesToPacDirective`
accepts only a well-formed `socks5://host:port` — an IPv6 literal bracketed, a
port in 1–65535 — and throws on anything else (`src/ws-proxy-pac.js:26-31`);
`buildWsPac` throws on a port or a `baseDirective` outside the same grammar
(`:35-36`). *Reason:* the failure mode of the alternative is silent. A malformed
rule that becomes `DIRECT` produces a PAC that is valid, installs cleanly, and
routes the traffic of a mode the user believes is on straight out of the
machine. A thrown error is caught by the caller that is composing the proxy
configuration, which can fail closed; a `DIRECT` it did not ask for cannot be
detected anywhere downstream.

Normative rules for an implementation:

- The PAC's host rule **MUST** mirror the implementation's single classifier
  rather than reimplement it. The reference generator embeds the ICANN
  top-level list and the reserved-name list *from the same files the classifier
  reads* (`../../src/icann-tlds.cjs`, `../../src/reserved-names.cjs`) so there
  is one source and not two. The engine's other host-shaped surfaces **MUST NOT**
  carry a rule of their own: in the reference tree the classifier lives in one
  module (`../../src/classify-host.cjs`, re-exported by `../../src/router.js`)
  and the omnibox requires it, so the PAC's ASCII-only form is the single
  remaining copy — and `tests/native-origin.test.js` asserts the PAC and
  `isHnsHost` agree across a corpus, which is what keeps it a copy and not a
  second rule. It exists at all because a PAC sandbox has no URL parser (spine
  Part II).
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

**Reserved names, and the local-network question.** The reserved-name list is
embedded in the generated script from the same file the classifier reads
(`../../src/reserved-names.cjs`, `src/ws-proxy-pac.js:41-45`), and it does two
separable things that **MUST NOT** be conflated:

1. A host whose final label is reserved — `nas.local`, `printer.home`,
   `box.lan`, `localhost` — is **never Handshake**, so it is never sent to a
   Handshake resolver and never reaches the tunnel. That much is absolute.
2. Its *route* is then the base directive, like any other non-Handshake host.
   In Private mode that means the session's proxy, not `DIRECT`. The PAC has no
   loopback branch and **MUST NOT** be given one as a way of implementing a
   local-network policy, for two reasons. A bypass list is not read the way it
   looks: the reference engine applies an implicit bypass for loopback
   destinations, and the `<-loopback>` token *removes* that implicit bypass
   rather than restoring it
   ([Chromium `net/docs/proxy.md`](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md#overriding-the-implicit-bypass-rules)),
   so a PAC written on the opposite reading is a policy that does nothing. And a
   PAC answer is a hint about routing rather than a decision about permission:
   in the reference implementation's integration testing on Electron 43.4.1 /
   Chromium 150 the token was ignored under a PAC configuration and loopback
   stayed direct whatever was configured. That is a measurement of one engine
   version, and an implementation **MUST** repeat it on its own rather than
   assume either behaviour.

An implementation that wants a local-network policy for WebSockets **MUST**
therefore state it as a policy and enforce it where requests can actually be
**cancelled**, not in the PAC. The reference policy is a request-level gate
(`localWsPolicy`, browser `src/hns/ws-proxy-policy.js:8-21`), and this chapter
is normative about its *contract*, not its code: in Private mode a `ws:`/`wss:`
whose host is a non-public IP literal or carries a local-network final label is
cancelled, with one exception — the **exact endpoint** of a Local App the user
has already granted and which is running, where that endpoint is the same origin
as both the requesting document and its frame and carries no embedded
credentials. A WebSocket to a remote host is not touched by the gate: it keeps
the session's base route, with no `DIRECT` fallback anywhere in the path. The
policy object belongs to the application embedding this chapter, because only
that application knows which local services it is itself running; what this
chapter requires is that the decision exists, that it fails closed, and that it
is not inferred from a PAC return value.

Two consequences an implementer should expect. The PAC decides on the
**target** host, not on the initiating origin, so an ordinary `https://` page
that opens `wss://<a handshake name>` is routed through the tunnel too (AP-4) —
which is consistent with the web platform, where a WebSocket is not subject to
the same-origin policy. And the PAC as written routes plaintext `ws:` to the
tunnel as well as `wss:`, when the host is Handshake. That is deliberate, and it
is the reason fence 1 exists: no secure page can produce a `ws://`, a non-secure
one can, and the two ways to decline it are not equivalent. Left to the base
route the name would be handed to whatever resolver that route uses; sent here
it arrives as `CONNECT <name>:80` and is refused on the port before anything is
looked up. Keeping the name away from the resolver is the PAC's job; declining
the connection is the tunnel's.

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

**This is a per-connection verdict, and it is the only thing that binds the
socket.** The document's own trust state is evidence about the document's
connection: the socket is a separate connection, resolved separately, dialled
separately and verified separately, and it may reach a different address of a
multi-homed name or reuse a cached certificate decision. An implementation
**MUST NOT** present the document's result as proof of the socket's, or the
socket's as proof of the document's; what the two share is the policy and the
on-chain key material the policy consults, not an observation. Where a user
interface shows one state for a page and its sockets, it is showing an
aggregate, and §6's rule that no step may be promoted still applies to each
connection on its own.

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
  `RateLimited`, `VaultLocked`, `Unavailable`, `OutOfScope`). The shim that
  turns that envelope back into a rejection **MUST** put the code on the
  rejected `Error` as a `code` **property** and repeat it in the message as
  `"<Code>: <prose>"` — a property alone does not reliably survive every
  engine's page boundary, and a message alone cannot be branched on. The prose
  is a sentence for a person; an application **MUST NOT** parse it, and
  **MUST NOT** show it to a person verbatim as `"<Code>: <prose>"`. An
  implementation **MUST NOT** emit a code it has not published; the full table,
  including per-capability codes, is `plugin-standard/HANDSHAKE-APPS.md` §5.7.

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
- An installed application's manifest **MUST** be re-read: on load at an
  installed entry origin, rate-limited to once per origin per session, and on
  an explicit user action that bypasses that budget. Fetching once at install
  and never again freezes an application at the manifest the user first saw —
  a new version that declares a capability is then never honoured, the
  provider keeps reporting the old set, and the application hides the feature
  it just shipped. Identical bytes are a no-op. A new manifest that asks for
  MORE than was consented **MUST** re-consent the difference and **MUST NOT**
  apply until it is accepted; one that asks for less, or that only changed
  metadata, applies silently and is logged; one that fails validation or no
  longer lists the origin it was served at **MUST** leave the installed
  manifest in place. (Added 2026-09-13, after exactly this froze a live
  application at a superseded manifest.)

**The name picker.** `names.request` is mediator chrome and **MUST** offer every
name in scope with no cap, answer with the **name** chosen rather than a
positional index, re-check that answer against what was offered, mark which
names the application already holds, be keyboard-operable, and be shown even
when the implementation cannot parent it to a window. A host that cannot find a
window **MUST NOT** answer `UserDeclined` on the user's behalf. A message box
whose buttons are the first few names satisfies none of these and is
non-conforming.

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
   else **the name most recently granted to this application**. An
   implementation **MUST NOT** refuse because it could not decide: ambiguity in
   the host is not a refusal by the person, and an implementation that answers
   one with "the user declined" is making a false statement about them. Only an
   application with no grant at all is refused, and the code for that is
   `NotGranted`. (Corrected 2026-09-13: the earlier rule declined an ambiguous
   call, and a user who had granted two names was told they had refused.)

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

**The tunnel adds no trust of its own, on either route.** The steps above are
the same whether the upstream was dialled directly or through the device-local
Tor (§4.4 fence 4). Tor changes which address the origin sees and nothing else:
it does not authenticate the origin — that is still the DANE pin — and it does
not weaken the name step, because the name was resolved by the implementation's
own resolver before the dial rather than by the proxy. An implementation
**MUST NOT** promote any step because a socket rode Tor, and **MUST NOT** demote
one either. What the anonymized route does change is disclosed elsewhere: no
SOCKS credential is sent, so nothing in this path *requests* stream isolation
(Chapter 8, TO-3), and which circuits Tor then uses is its own decision — an
implementation **MUST NOT** state that such sockets share one circuit, or that
they do not, without having observed it. And the TLS that runs through the
splice still names the host in SNI, so the route sees the name whatever the
circuit (§4.4 fence 4, AP-8).

There is no **OPEN** state for this path, and that is the point: a `failed`
certificate step, an absent pin, a non-public address, a port that is not 443,
or a Private-mode session whose Tor is blocked all end with no socket rather
than with a degraded one. An implementation **MUST NOT** offer the user a way to
proceed past any of them.

The application-level sign-in of §5 adds no step to the *connection's* trust
state. It is a fact about the user, established by the application's server
against DNS, and an implementation **MUST NOT** let it colour the connection
indicator.

## 7. Operational guidance for the server side (NON-NORMATIVE)

Everything in this section is about the machine serving the application. None
of it is required for conformance; all of it is required for the thing to work,
and each item cost a full diagnosis at least once.

**An HTTP/2 front end without extended CONNECT silently breaks the upgrade.**
This is a statement about one deployment path, not a prohibition on HTTP/2. The
`Upgrade` mechanism does not exist in HTTP/2 (RFC 9113 §8.5), so the RFC 6455
handshake cannot be carried the way HTTP/1.1 carries it — but RFC 8441 defines
the replacement, an extended `CONNECT` with `:protocol = websocket`, and a front
end and an application server that both implement it carry WebSockets over h2
perfectly well. The trap is a front end that negotiates h2 and does *not*
implement RFC 8441 (`SETTINGS_ENABLE_CONNECT_PROTOCOL` unset, or a proxy module
that does not pass it through): the handshake reaches the application server as
a plain `GET /ws` and is answered `404`, with nothing anywhere saying
"WebSocket".

The reference deployment met this on **nginx 1.24**, where two facts combine.
nginx's own proxying speaks HTTP/1.1 upstream and has no RFC 8441 support on the
client side; and in 1.24 and earlier HTTP/2 is enabled **per listening socket,
not per server block**, so a single `listen 443 ssl http2` anywhere in the
configuration turns h2 on (via ALPN) for *every* SNI on that socket, including
virtual hosts that carefully wrote `listen 443 ssl`. The per-server `http2 off;`
directive requires nginx ≥ 1.25.1.

So make the fix as narrow as the version allows, rather than turning HTTP/2 off
because of a rule that does not exist:

- **nginx ≥ 1.25.1:** `http2 off;` in the server block that terminates the
  WebSocket name, and leave h2 on for the rest of the socket.
- **nginx ≤ 1.24:** the per-socket behaviour gives no per-name switch, so either
  move that name to its own listening socket without the `http2` parameter, or
  strip `http2` from the `listen` directives that share the socket. The
  reference deployment did the latter; HTTP/1.1 is universal, so the loss is h2
  multiplexing for the other virtual hosts on that socket.
- **Any front end:** if it implements RFC 8441 end to end, none of the above
  applies. Check, rather than assume either way.

Diagnose it with two requests, not with logs: `curl --http1.1` returns `101`
where the default returns `404`, and `openssl s_client -alpn h2,http/1.1` shows
which protocol the socket actually negotiates for that SNI.

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
authenticates nothing (§4.3) — not a credential, and not the identity of the
process that connected — so the five fences are not defence in depth; they are
the defence. An implementation that relaxes any of them has built a local open
proxy. The three that would be tempting to relax are the Handshake-only rule
(which is what keeps it from proxying the whole internet for any local process),
the SSRF guard (which is what keeps an attacker-registered name from pointing
the browser at the user's own network), and the single port (which is what keeps
every splice inside the range this implementation's pin lookup covers, and what
declines the commonest plaintext `ws://`).

**Any local process is inside the loopback bind.** The bind is a device
boundary: it keeps a LAN peer out, and it says nothing about *which* program on
this device is asking. A process on the machine can therefore make this browser
resolve a Handshake name with the user's own resolver and open a TCP connection
to its public address on 443 — and, in Private mode, through the user's own Tor
client. Whether that matters is a question about the host system, and an
implementation **MUST NOT** dispose of it with an argument about what a local
process could have done for itself; it is recorded as AP-2 and the fences are
what bound it.

**Every address in this chapter is attacker-chosen.** Anyone can register a
Handshake name, publish any records under it, and serve any application at it.
The origin-ownership rule (§5.2), the signing-oracle guard (§5.3 gate 3) and
the SSRF guard (§4.4 fence 3) are each written on the assumption that the name
on the other side is hostile.

**A capability that is off must be inert.** Both features here are
configuration-gated, and when off there is no listener, no PAC diversion, no
certificate procedure, no preload and no IPC channel. A disabled-but-present
surface is an attack surface with no owner.

**Ports.** The tunnel dials one port and only one (§4.4 fence 1), so it cannot
be used to attempt a connection to an arbitrary port of a public host, and a
realtime application served on a non-default port is not reachable through it at
all. That is the trade, taken deliberately: dialling whatever port the CONNECT
named would give any page the reach to probe every permitted port of every
address a Handshake name resolves to, and would carry a splice outside the range
this implementation's pin lookup covers (§4.4 fence 1).

**The anonymized route is a change of socket, not of trust.** In Private
mode, the upstream is dialled through the device-local Tor (§4.4 fence 4),
which means a local process on loopback can, in that mode, cause a connection
to be made through the user's own Tor client to the public address of a
Handshake name. The port, the Handshake-only rule and the SSRF guard all still
apply to it, the name is resolved by this implementation before the dial rather
than by the proxy, and no SOCKS credential is sent, so nothing asks Tor to
isolate that stream from the session's others (Chapter 8, TO-3). What an
implementation **MUST NOT** do is treat the Tor route as licence to relax
anything else: an anonymized socket that skipped the SSRF guard, or that let the
proxy resolve the name, would be worse than the refusal it replaced.

**The anonymized route hides the address, not the name.** The SOCKS request
carries an address rather than a name, so no lookup is made on our behalf by the
proxy — but the TLS ClientHello that the user agent sends end to end through the
splice carries the server name in SNI in the clear (RFC 8446 §4.2.9; RFC 6066
§3), so the exit relay sees which Handshake name the socket is for. An interface
**MUST NOT** present Private mode as hiding the name from the route, and an
implementation that later deploys Encrypted ClientHello (RFC 9848) may revisit
the claim then and not before. AP-8.

**A route the user turned off must stop carrying bytes.** A spliced CONNECT is
not in the engine's connection pool, so nothing else in the system revokes it: a
mode switch that changed only future connections would leave the socket a page
opened in Fast mode running direct from the user's own address while the
interface says Private. The revocation of §4.5.4 is therefore a security
requirement, not hygiene, and it has to be synchronous with the switch rather
than with the persistence and proxy work that follows it.

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
4. A `ws://` from a secure Handshake page is never rewritten or rescued (§4.1),
   and a `ws://` to a Handshake host from anywhere else is declined by the
   tunnel's port rule rather than sent DIRECT into a system resolver (§4.4,
   §4.6).
5. The tunnel parses exactly one CONNECT head bounded in bytes and in time,
   counts only header bytes against the byte bound, accepts only CONNECT,
   accepts only `<host>:<port>`, and never inspects a byte after the `200`
   (§4.2).
6. All five fences hold — the listener binds loopback only; the port rule and
   the Handshake-only check both refuse *before* the name is resolved; the SSRF
   guard is applied to the resolved address before any dial; and while IP
   Protection is on the upstream is dialled through the device-local Tor using
   an address in the SOCKS request, or refused when there is no Tor port — and
   each refusal is a complete HTTP response followed by a graceful half-close
   (§4.4, §4.5).
7. No claim beyond what each mechanism supports: proxy authentication is not
   presented as a protection, the loopback bind is stated as a device boundary
   and not as authentication of the requesting application, the port rule is
   stated as a destination restriction and not as a TLS or pin guarantee, and
   the address-form SOCKS request is not stated as hiding the name from the Tor
   route (§4.3, §4.4, §8).
8. The tunnel states its limits and does not exceed the built-in maxima,
   refuses beyond them with `503`, answers a timeout with `504` and a failed
   resolution or dial with `502`, and a change of privacy mode aborts pending
   work and destroys established streams made on the old route (§4.5).
9. The PAC mirrors the single host classifier, carries no credential, is
   composed into the one proxy authority, is delivered as a data URL, sends a
   non-Handshake WebSocket along the session's base route rather than DIRECT,
   and throws rather than emitting a substituted route for an input it cannot
   represent (§4.6).
10. A `wss://` to a Handshake host is pinned to a `3 1 1` TLSA and fails closed
    when the pin is absent or mismatched, while every non-Handshake host defers
    to the engine's own verification (§4.7).
11. The provider is exposed only to an installed application's own top frame,
    every operation re-derives the origin in the privileged process, and the
    origin is computed as the renderer computes it (§5.1).
12. Every declared entry origin is proved to be owned by the application, and
    one that is not fails the whole manifest (§5.2).
13. A token is minted only for the application's own origin, only for a granted
    name, only under a rate limit, and never returns key material (§5.3).
14. A locked key store is reported as locked, never as a user refusal (§5.3).
15. The trust steps of §6 are exposed individually, no failure of them offers
    the user a way to proceed, and no step is scored differently because the
    socket was dialled through Tor (§6).
