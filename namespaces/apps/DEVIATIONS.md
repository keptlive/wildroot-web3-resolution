# Chapter 11 — Native applications on a Handshake name: deviations and open questions

Every place this chapter's implementation departs from a standard it cites,
from common practice, or from its own stated design — plus every place we are
not sure we have made the right call, and the design work we know is still to
do.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

A note on proportion before the list. The property this chapter exists to
provide — that a WebSocket from a Handshake page is end-to-end TLS pinned to the
same on-chain key material as the document, through a tunnel that never holds a
key — holds, and the pin is proven through a real spliced connection by
`tests/ws-proxy.test.js` ("e2e: the tunnel preserves end-to-end TLS so a DANE
pin verifies through it"). The five fences hold and each is pinned by a test,
including on the anonymized route, where the upstream is dialled through the
device-local Tor using an address in the SOCKS request, so the proxy performs no
lookup for us. Everything below is about the *other* things: the authentication
that is not reachable, the caller the tunnel cannot identify, the name the TLS
handshake still discloses, the service worker we do not allow, the origin the
token is bound to, the manifest nobody signs, and a long list of what we have not
measured.

Paths written `../../src/…` are shared modules of the top-level package; paths
written `src/…` and `tests/…` are this chapter's, under `namespaces/apps/`.
Paths written `browser src/…` are in the Wildroot browser tree and are not
extracted into this repository (SPEC.md, "Paths").

---

## 1. Deviations

### AP-2. The tunnel authenticates no requesting application

**What.** The tunnel is an unauthenticated local proxy. It accepts a `CONNECT`
from any process on the machine that can reach `127.0.0.1:<port>`, subject only
to the port, Handshake-only, SSRF and Tor fences and to the limits of SPEC
§4.5.3. The `Proxy-Authorization` check is implemented and constant-time
(`src/ws-proxy.js:228`, `:374-378`, `:399-402`) but is skipped because no
credential is passed (browser `src/protocols/index.js:267-277`). Nothing else
identifies the caller: the listener binds `127.0.0.1` (`:332`), and a loopback
bind is a statement about which *device* may reach the port, not about which
*program* on that device did.

**The standard says.** RFC 9110 §11 (with RFC 7235's mechanism) defines exactly
this: a proxy answers `407` with `Proxy-Authenticate` and the client retries
with `Proxy-Authorization`. RFC 1928/1929 define the SOCKS5 equivalent. Both are
available on paper and neither was reachable in the runtime this implementation
targets: in the tested Electron build Chromium's SOCKS5 client offered only the
"no authentication" method, and on the tested path Chromium surfaced no
proxy-auth challenge to its embedder for a `wss://` handshake, so the `407` was
never answered and the socket died instead of retrying (SPEC §4.3). Those are
measurements of one build and one code path, not properties of the protocols,
and they have not been repeated on every engine version this implementation has
since run on: an old experiment is not evidence about a future version.

**Why.** Two implementations were built and neither could connect once. The
choice is between a fence that could not be enforced in that runtime and an
honest statement of what the boundary actually is.

**Consequence.** Any local process can use the tunnel to resolve a Handshake
name with the browser's own resolver and open a TCP connection to that name's
public address on port 443 — in Private mode, through the user's own Tor client;
while Tor is blocked, not at all. The fences bound what it can reach (one port,
Handshake names only, public addresses only) and the limits bound how much of it
it can hold at once, but nothing bounds *who* may ask. A host on which any local
process is assumed benign loses nothing; a host on which it is not has a local
capability here that no user interface shows and no grant covers.

**Status: OPEN.** We would still ship without a proxy credential — there was
none to be had — but we would not again describe the loopback bind as the access
control, and the gap is real rather than notional. Two things would close it and
neither is done: authenticate the peer at the operating-system level (match the
connecting process to this browser's own — `SO_PEERCRED` on Linux,
`LOCAL_PEERPID` on macOS, `GetExtendedTcpTable` on Windows — and refuse every
other caller), or use a platform that can answer a proxy challenge for a
`wss://` CONNECT, for which the credential path is retained and tested
(`tests/ws-proxy.test.js`, "OPTIONAL auth (future platform)") so the gate
re-enables with no code change. Until one exists, no document, comment or
interface may describe proxy authentication, or the loopback bind, as
authenticating the caller.

### AP-3. No service workers at a Handshake name

**What.** `hns` is registered with `allowServiceWorkers: false`
(browser `src/main.cjs:110-120`), while it is otherwise a standard, secure
scheme with a real tuple origin.

**The standard says.** The Service Workers specification requires a secure
context and a supported scheme; a scheme that is standard and secure is
otherwise eligible. Nothing in the specification requires an engine to permit
it for a non-http scheme, so this is a restriction of the reference
implementation rather than a breach of a rule.

**Why.** Chrome pages in the same tree disable service workers deliberately (a
page served from disk must not be able to persist a copy of itself), and the
`hns` registration inherited the value without a stated reason of its own.

**Consequence.** A native application cannot be offline-capable, cannot be
installed as a progressive web app, and cannot use push or background sync at
its Handshake name — while the same application at its `https://` gateway
mirror can. That is a real asymmetry between the two origins of one
application, and it points the ambitious version of an application at the ICANN
address, which is the opposite of what this chapter is for.

**Status: OPEN.** We recommend enabling service workers at `hns://` once two
questions are answered: what a cached, self-persisting copy of a page means for
a name whose records (and therefore its DANE pin) can change under it, and
whether a worker's own fetches take the same header allowlist as the page's
(SPEC §3.4). Both are answerable; neither has been answered, and shipping a
worker that outlives a pin rotation would be worse than not shipping one.

### AP-4. WebSocket routing is decided by the target host, not by the initiating origin

**What.** The PAC receives `(url, host)` and nothing about who is asking, so
`wss://<handshake name>` is routed through the tunnel — and pinned by the
certificate gate — no matter which origin opened it, including an ordinary
`https://` page.

**The standard says.** RFC 6455 §10.2 deliberately does not apply the
same-origin policy to WebSockets; any origin may open a socket to any host, and
the server decides via the `Origin` header. So this is the platform's behaviour,
not an invention.

**Why.** A PAC cannot see the initiator, and building an initiator-sensitive
route would mean holding a second proxy authority (SPEC §4.6) or filtering in
the tunnel on information it does not receive.

**Consequence.** An arbitrary web page can use the browser as an oracle for
whether a Handshake name is live and holds a socket, and can reach a Handshake
application's socket API with whatever credentials that application accepts
cross-origin. It learns nothing the name does not already publish, and the
application's own `Origin` check is the defence the platform intends — but a
Handshake application author should know two things about it. Their socket is
reachable from the whole web, not only from their own origin; and an `Origin`
header is a statement made by the requesting user agent about itself, so it is a
filter against ordinary cross-origin pages and not a proof of who is connecting.
Anything the server must be *sure* of belongs in the authentication of SPEC §5.4,
not in a header.

**Status: DELIBERATE.** Matching the web platform is right here; diverging would
make Handshake sockets behave unlike every other socket, which is a worse trap
than the one it closes. Applications must check `Origin` as they would anywhere.

### AP-5. A native page's sign-in token is bound to a URL the request is not sent to

**What.** NIP-98 binds a signature to an exact URL in the `u` tag. The
reference signer accepts only absolute `http(s)` URLs
(browser `src/identity/receipt.js:175`), so a page at `hns://pxls` cannot mint a
token bound to its own origin at all. It mints one bound to its canonical
gateway origin (`https://pxls.hns.one/api/session`) and then sends the request
to `hns://pxls/api/session`. The mediator permits this only because the gateway
origin is one of the application's own declared entry origins (SPEC §5.2, §5.5).

**The standard says.** NIP-98's whole mechanism is that the `u` tag is the URL
of the request being authorised, and a verifier compares it with the URL it
actually received. Here they differ by scheme and host, and the verifier is
comparing against its own fixed public base rather than against the request's
own URL.

**Why.** One application at two origins is the deployment reality of Handshake
today (native name plus gateway mirror), and a server that accepted a token for
either origin would accept two different URLs for one request — which is the
property NIP-98 exists to remove. Pinning the token to one canonical origin
keeps a single answer to "which URL was signed", at the cost of that answer not
being the URL on the wire.

**Consequence.** The URL binding is no longer doing the work it is defined to
do. What actually prevents a token minted for one endpoint being replayed at
another is the server's fixed public base plus its single-use replay ledger
(SPEC §5.4), and an implementer who copies the client half without the server
half gets neither protection. It also means a third-party server that verifies
NIP-98 strictly, against the URL it received, will reject a native page's
token.

**Status: OPEN.** The clean fix is a canonical-origin concept in the standard —
either an explicit tag naming the origin the token is canonicalised to, or
permission for a verifier to accept a token whose `u` is any of the
application's declared entry origins with the same path. Either makes the
divergence declared rather than conventional. Until one exists, an application
must document which base its server verifies, and a mediator must keep the
origin gate strict: it is what stops the same latitude becoming a signing
oracle.

### AP-6. Manifests are unsigned, so an installed application's identity is only its origin

**What.** An application is installed after its manifest is fetched over https
from its own discovery URL, validated, and hashed; the store records
`verified: false` for every application, always
(browser `src/apps/app-store.js`, `docs/HANDSHAKE-APPS-MEDIATOR.md`).

**The standard says.** The Handshake-Apps standard leaves manifest signing open
(its §12 Q4). Nothing is breached; what is missing is the mechanism that would
let a *third party* host verify a manifest.

**Why.** Signing requires the application's name to be DNSSEC-anchored to an
on-chain DS so a host can find the key, and the reference application's own name
is not yet anchored. Shipping install-with-warning was preferred to shipping
nothing.

**Consequence.** The only thing binding a manifest to an application is that it
was fetched from that application's own origin over https (and, for a native
name, from its gateway mirror). A compromise of the mirror is therefore a
compromise of the application's identity for install purposes, and the
origin-ownership rule (SPEC §5.2) is doing all of the work. The consent copy
says "unverified application", which is honest, and users are known to click
through such copy.

**Status: OPEN.** Sign the manifest with the name's control key, anchored to the
on-chain DS, and let `verified` mean something. The install consent should then
distinguish signed from unsigned rather than warning identically for both, and a
downgrade from signed to unsigned on re-install should be refused rather than
warned about.

### AP-9. Consent is a native dialog; only the name picker is a rendered surface

**What.** The reference implementation renders the *name picker* as a
main-process-owned window over one local page it loads from disk, with the
application's renderer nowhere near it (browser `src/apps/name-picker-sheet.js`,
`src/ui/name-picker.html`). The install consent and the **update** consent are
still native `dialog.showMessageBox` calls (browser
`src/apps/handshake-ops.js` `promptInstall`, `promptUpdate`).

**The standard says.** HANDSHAKE-APPS §5.4 requires consent to be
"main-process-owned chrome … never DOM inside or over the app's renderer". A
native dialog satisfies the security property — the page cannot draw over it,
read it, or click it — but not the rendering requirements around it: a message
box cannot show the disclosure ("show record"), the per-capability layout, or
the distinct treatment §4.2 demands for dangerous capabilities.

**Why.** No mutating capability is implemented yet, so nothing currently needs
the disclosure or the dangerous-capability treatment; a message box states the
effect sentences correctly for the capabilities that exist. The picker was moved
to a rendered surface first because it is where the failure was: as a message
box it could not show the full list, could not mark which names the application
already held, and answered with a positional index (see AP-10).

**Consequence.** When `records.propose` lands, the consent screens have to move
to the rendered surface before it ships, not after — a plan preview cannot be
rendered in a message box at all.

**Status: OPEN.** Move `promptInstall`/`promptUpdate` onto the same sheet
mechanism the picker now uses.

### AP-10. The picker's window is a child window, not an in-window sheet

**What.** Every other overlay in the browser (the hand-off sheet, the publish
sheet, the export sheet) is a `WebContentsView` composited into the window it
belongs to. The name picker is a modal child `BrowserWindow` instead.

**The standard says.** SPEC §5.2 "the name picker" requires mediator chrome the
application cannot reach, shown even when the implementation cannot parent it to
a window. It does not say which kind of window.

**Why.** Two reasons, both about not reproducing the bug this replaced. The
in-window overlay occupies a single per-window slot: a picker opened while a
publish sheet was up would have resolved immediately as "dismissed", which is
the silent decline the whole change exists to remove. And the overlay needs a
window to attach to, while `names.request` can arrive from a tab whose window
the manager cannot resolve — the old code answered `null` there, i.e. told the
application the user declined. A child window has neither problem and is
parentless-capable.

**Consequence.** The picker looks like a small dialog rather than an in-window
sheet, which is a visual inconsistency with the browser's other sheets.

**Status: ACCEPTED.** Revisit if the overlay mechanism grows a second slot and a
parentless mode.

### AP-7. A Handshake WebSocket is reachable on port 443 and nowhere else

**What.** The tunnel accepts a `CONNECT` to 443 and refuses every other port
before resolving (`TUNNEL_PORT`, `src/ws-proxy.js:87`, `:416-418`; SPEC §4.4
fence 1). The PAC still routes `wss://<name>:8443/…` to the tunnel — it decides
on scheme and host, not port — so an application that serves its socket
anywhere but 443 is routed here and then refused with a `403` the page cannot
distinguish from any other failure.

**The standard says.** RFC 6698 gives TLSA records a per-port owner name
(`_<port>._tcp.<name>`), so DANE itself has no objection to a pinned socket on
8443. Nothing in RFC 6455 or in the URL Standard restricts a `wss://` port
either. The restriction is this implementation's.

**Why.** Two links in the chain are fixed to 443, not one. The resolver reads a
pin at `_443._tcp.<host>` and only there, whatever port a URL names — that is
Chapter 1's own deviation HS-6 — and the
engine's certificate-verification request carries a hostname with **no port**
(browser `src/index.js:1330-1351`), so even a resolver that fetched the right
RRset would have nothing to select it with at verification time. Accepting an
arbitrary port would therefore mean splicing TLS that this profile's pin check
could not cover — which is what fence 1 exists to prevent.

**Consequence.** A publisher must terminate its WebSocket on 443 at the
Handshake name (SPEC §4.8), which is what every reference deployment does
anyway, and a non-default port is a dead end with a bad error. The cost is
carried by the deployment, not by the trust story. Two things the port rule is
**not** must be stated with it, because both are easy to assume and neither is
true. It does not guarantee the pin: the pin is checked by the engine's
certificate-verification procedure (SPEC §4.7), and a splice on 443 whose name
publishes no TLSA still fails there, not here. And it does not guarantee TLS:
the tunnel reads no byte after the `200`, so it cannot tell a TLS ClientHello
from a plaintext WebSocket handshake. What the rule actually does is confine
every splice to the one port this implementation's pin lookup covers, and
decline the plaintext case that the web platform can actually produce — a
`ws://` from a non-secure page, which arrives as `CONNECT <name>:80`.

**Status: DELIBERATE**, with a clean fix if a port ever needs to be. Give the
resolution a port parameter, read `_<port>._tcp.<name>`, and thread the port
from the CONNECT through to the certificate check; until the engine's
verification callback carries the port, the honest set is the one port the pin
covers, and refusing is better than splicing unpinned. Both halves must move
together, or the port becomes reachable before it becomes pinned.

### AP-8. On the anonymized route the name is still disclosed to the exit, in SNI

**What.** In Private mode the upstream is dialled through the device-local Tor,
and the SOCKS request carries the **resolved address** (`ATYP` IPv4 or IPv6),
never a name (`socksDialer`, `../../src/socks-dial.js:104-159`; the fence-4
branch at `src/ws-proxy.js:426-432`). That is all it does: the SOCKS server
performs no lookup on our behalf. The stream it then carries is the user agent's
own TLS handshake, spliced end to end (`:473-475`), and that handshake names the
host in the clear.

**The standard says.** [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
§4.2.9 and [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) §3 define
`server_name`: the client **SHOULD** include the server name in the ClientHello,
and the ClientHello is not encrypted, so every hop that carries it can read the
name. RFC 6066 §3 says so itself, and directs a deployment that needs the name
hidden to another mechanism.
[RFC 9848](https://www.rfc-editor.org/rfc/rfc9848) (Encrypted ClientHello) is
that mechanism; it is not deployed on this path (Chapter 1, HS-3: the SVCB
record that would carry the ECH configuration is parsed but not queried, and the
runtime exposes no ECH option).

**Why.** The address-form SOCKS request was chosen for two reasons that both
still hold — it keeps a name out of the proxy's own resolver, and it leaves the
SSRF guard an address to inspect — and neither of them was ever a claim about
the ClientHello. The over-claim ("by address, so Tor learns no name") came from
reading a property of the SOCKS hop as a property of the stream.

**Consequence.** A Tor exit relay carrying a Handshake `wss://` sees which name
the socket is for, and so does anything between that exit and the origin. What
Private mode does hide on this path is the user's own address from the origin,
and the lookup from the local network. An interface that says more than that is
wrong, and a user choosing Private mode to keep *which name they are using*
private is not getting it.

**Status: OPEN.** The fix is ECH, which is blocked on the same two things
Chapter 1 records for the document path — querying SVCB for the ECH
configuration, and a runtime that exposes an ECH option — plus a decision about
what to do when a Handshake name publishes no ECH configuration at all, which
today is all of them. Until then the honest statement is the one SPEC §4.4 and
§8 now make, and the claim must not be restated as "the name never leaves this
device".

---

## 2. Things we are not sure about

These are the ones we would most like other implementers to argue with, and the
claims we could not verify against either the code or a measurement.

### 2.1. Whether the `101` is checked for `Sec-WebSocket-Accept` in our stack

RFC 6455 §4.1 requires a client to compare the server's
`Sec-WebSocket-Accept` against the SHA-1 of the key it sent, and to fail the
connection otherwise. Nothing in this chapter's code does that, and nothing
should: the tunnel is a splice and the handshake is Chromium's. We have observed
a working, DANE-verified `101` in a live browser session, and we have **no test
in this repository or in the browser tree that asserts the accept value is
checked**. So the correct statement is the one SPEC §6 makes — the upgrade step
contributes `none` to the trust state — and the claim "the 101 is verified"
should be read as "the user agent is required to verify it", not as something we
have pinned.

### 2.2. What Chromium actually sends to the tunnel for a plaintext `ws://`

The PAC routes `ws:` to the tunnel (SPEC §4.6). What Chromium then *does* with
that URL through an HTTP proxy — issue `CONNECT <host>:80`, or issue the
WebSocket `GET` through the proxy as an absolute-URI request — we have not
measured. Nothing rests on the answer, because both are refused without a
lookup: a `CONNECT` to 80 by the port fence with `403`, an
absolute-URI `GET` by the method check with `405 Allow: CONNECT`. We record it
because "both branches refuse" is a reason not to measure it, and "we measured
it" would be a different and stronger claim.

### 2.2a. What the anonymized route costs in latency and circuit sharing

The Tor route of SPEC §4.4 fence 4 is pinned by test against a stub SOCKS
server; it has not been measured against a real Tor circuit. Two things are
therefore unquantified: what a WebSocket handshake costs through a circuit that
may still be building (Chapter 8 §7.2 routes before readiness deliberately), and
what a long-lived socket does to the rest of the session, which asks for no
stream isolation and whose actual circuit assignment is Tor's own decision and
not something we have observed (Chapter 8 TO-3). Neither is a correctness
question — the
fences and the pin are the same on both routes — but a realtime application is
the one kind of page for which "it works, slowly, forever" is a different
product from "it works".

### 2.3. What reaches a loopback service in Private mode, and by which rule

Three mechanisms decide this and only one of them is ours, which is why it took
a review to state it correctly.

Chromium applies an **implicit bypass** for loopback destinations, and the
`<-loopback>` token *removes* that implicit bypass rather than restoring it
([`net/docs/proxy.md`](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md#overriding-the-implicit-bypass-rules)).
The privacy controller's own configuration carries
`proxyBypassRules: '<-loopback>'` (`_defaultConfig` in
`namespaces/tor/src/anonymize.js`), so what that configuration asks for is that
loopback *be* proxied; the PAC decorator then replaces the whole configuration
with `{mode: 'pac_script', …}` (browser `src/index.js`) and the bypass list goes
with it. The PAC has no loopback branch, so its non-WebSocket answer for
`http://127.0.0.1:<port>/` in Private mode is the anonymizer's SOCKS directive.

What the token is documented to do and what it did are two different facts, and
the second is version-specific. In the reference implementation's integration
testing on **Electron 43.4.1 / Chromium 150**, `<-loopback>` was **ignored**
under a PAC configuration in the native test: loopback stayed DIRECT whatever
the configuration asked for. That is an observation about one build on one path,
not a rule about Chromium, and an implementation relying on the token should
repeat the measurement on its own engine version rather than inherit ours.

WebSockets therefore do not rest on it at all. They are decided by an explicit
policy at the request level rather than by a proxy return value
(`localWsPolicy`, browser `src/hns/ws-proxy-policy.js:8-21`; SPEC §4.6): a
Private-mode `ws:`/`wss:` to a local host is cancelled unless it is the exact
endpoint of an already-running, granted Local App whose page and frame origins
both match it, while a WebSocket to a remote host keeps the base Tor route with
no DIRECT fallback.

What remains unmeasured is everything that is **not** a WebSocket: whether an
ordinary loopback fetch under this PAC is likewise left DIRECT by the implicit
bypass, or is routed into the session's SOCKS directive — where Tor refuses it —
for as long as Private mode and the tunnel are both on. The two look identical
in the configuration and completely different on the wire. See AP-D1.

### 2.4. Cookie behaviour on an `hns://` origin

SPEC §3.2 claims storage for a tuple origin, and that claim is measured for
`localStorage` only (an application crashed without it and works with it). We
have **not** established whether `document.cookie` works on an `hns://` origin,
whether cookies set there persist across restarts, or whether the behaviour is
stable across Chromium versions — and the reference fetch path deliberately
drops `Cookie` anyway (SPEC §3.4), so an application that relied on cookies for
its own server would find them missing on the wire even if the renderer stored
them. An application should use `Authorization`, which is specified to work.

### 2.5. Storage partitioning inside a native document

The HTML Standard partitions storage for third-party content by top-level site.
What a Chromium build computes as the partition key for a non-http standard
scheme, and therefore what an embedded third-party frame inside an `hns://`
document can reach, is unmeasured here. Nothing in this chapter depends on it;
an application that embeds third-party frames should not assume either answer.

### 2.6. Whether the PAC is applied to every session that can open a WebSocket

The decorator returns the base configuration unchanged for any session that is
not the web-content session (browser `src/index.js:1133`). That is right for the
sessions we know about, and we have not enumerated every session in the
application that could host a document able to open a `wss://`. A session
without the PAC sends `wss://<handshake name>` along that session's own base
route — direct in Fast mode, the session proxy in Private — where it fails as an
unresolvable host, because only the tunnel can resolve a Handshake name. A
failure, not a leak, but an obscure one.

### 2.7. Internationalised hosts in the PAC

The PAC's rule compares the final label against a punycode ICANN list without
punycoding the host itself, where the classifier punycodes first
(`../../src/router.js`). We believe this is safe because Chromium hands a PAC
the already-canonical (ASCII) host from the URL, and the corpus in
`tests/native-origin.test.js` does not test it. If that belief is wrong, an
internationalised ICANN host would be classified Handshake by the PAC and then
refused by the tunnel's own classifier — a broken socket, not a leak.

### 2.8. The numeric-TLD path has never been proven end to end

`tests/native-origin.test.js` shows that the PAC routes `hello._14898` and that
the tunnel strips the marker before resolving. Whether a page actually served at
`hns://hello._14898/` can open a `wss://` and complete a DANE-pinned upgrade has
not been demonstrated in a browser. Chapter 10 Part B is explicit that the whole
numeric-TLD convention is provisional.

### 2.9. `verified: true` is a live observation, not a regression test

The sign-in path of SPEC §5 was proven once, end to end, against a deployed
application: the provider appeared at a native origin, a token was minted for
the canonical gateway origin, the header survived the fetch path, and the
server answered with a verified name. The pieces are unit-tested individually
in the browser tree (the origin gate, the manifest gate, the signature, the
rate limit, the locked-vault cases). The *whole* path has no automated test, and
the memory of one successful run is not one.

---

## 3. Open design items

Work we know is worth doing and have not done. Each names the file and lines to
start from.

### AP-D1. Decide the non-WebSocket loopback policy, and state it somewhere it can be enforced

`FindProxyForURL` has exactly two answers — the tunnel for Handshake
WebSockets, the base directive for everything else
(`src/ws-proxy-pac.js:63-68`) — and installing it discards the
`proxyBypassRules: '<-loopback>'` the privacy controller would otherwise apply
(browser `src/hns/anonymize.js:243-247`, `src/index.js:1142-1145`).

**Not the recommendation.** Adding a `DIRECT` branch for loopback and private
literals is the obvious four lines, and it is the wrong move for two separate
reasons. First, the reasoning it rests on is backwards: `<-loopback>` *removes*
Chromium's implicit loopback bypass
([`net/docs/proxy.md`](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md#overriding-the-implicit-bypass-rules)),
so a PAC branch returning `DIRECT` would not be "restoring the bypass the
controller intended" — the controller asked for the opposite. Second, a PAC
answer is a route hint and not a decision: on **Electron 43.4.1 / Chromium 150**
the reference implementation's integration testing found the token ignored under
a PAC and loopback DIRECT regardless (§2.3), which is precisely why the local
WebSocket rule is a request guard that can *cancel*.

**Recommendation.** Decide the policy as a policy, then enforce it where a
request can be cancelled rather than merely routed. For WebSockets that is done
(`localWsPolicy`, browser `src/hns/ws-proxy-policy.js:8-21`; its contract is
SPEC §4.6). What is left is the non-WebSocket half: measure which rule actually
governs a loopback fetch under a PAC configuration (§2.3), then either extend
the same request-level gate to those requests or state, in the privacy
interface, that loopback services are reachable in Private mode and why.
Whichever way it goes, it should be one written policy with one enforcement
point, not a bypass token in one configuration and a PAC branch in another.

### AP-D4. Decide the service-worker question for `hns://`

See AP-3. `browser src/main.cjs:110-120`. The blocking question is what a
cached page means when the name's DANE pin rotates.

### AP-D5. Sign manifests, and make `verified` mean something

See AP-6. `browser src/apps/app-store.js` (the `verified` field and the hash
pin), `browser src/apps/manifest-validate.js:47-71` (where a signature check
belongs, beside the ownership rule).

### AP-D6. A revoke / manage-applications interface

The store supports `revoke` and `uninstall`
(`browser src/apps/app-store.js`) and nothing in the interface calls them, so a
grant made once at install is, in practice, permanent. **Recommendation.** A
settings page listing installed applications, their entry origins, the names
granted to each and the manifest hash, with revoke and uninstall. Until it
exists the consent at install is a decision the user cannot take back, which is
the strongest possible reason to keep that consent narrow.

### AP-D7. Native discovery for a dotted Handshake name

Discovery maps only a bare native name to its gateway mirror; a dotted native
second-level name (`hns://foo.2url`) is deliberately not mapped
(`browser src/apps/manifest-validate.js:107-117`), so such an application is
discoverable only at its gateway origin. **Recommendation.** Map the dotted case
too once fetching an application's own scheme from the privileged process is
safe on every platform; the origin-ownership rule already handles the binding,
so the change is in the discovery base and its test.

### AP-D8. Surface the tunnel's refusal reason

Every refusal answers a distinct HTTP status that the WebSocket API discards, so
"this is not port 443", "Private mode, and the Tor client is not connected",
"this name has no address", "this name resolves to a private address", "the
origin is down", "we are at capacity" (`503`) and "it timed out" (`504`) are one
untyped `error` event to the page and nothing at all to the user
(`src/ws-proxy.js:358-372`).
**Recommendation.** Record each refusal with its reason and the name, and show
it where the connection's trust state is already shown. The information exists
and is thrown away at the socket boundary.

### AP-D9. Per-name resolution limiting, and the connection that is dropped unanswered

The concurrency bound exists: 128 live client sockets, 32 connections in setup,
32 outstanding resolutions or dials, each with its own deadline, and `503`
beyond the pending limit (`WS_LIMITS`, `src/ws-proxy.js:93`; the accept gate at
`:316`; the pending gate at `:279`; SPEC §4.5.3). Two things around it are not
done.

There is **no per-name limit**: one name that resolves slowly can occupy the
whole pending budget from a page that opens sockets in a loop, and in Private
mode each of those dials costs circuit capacity as well as a resolution (SPEC
§4.4 fence 4). **Recommendation.** A small per-name rate limit on resolutions,
refusing with `503` like the global one, and a shorter deadline for a name
already known to be failing.

And a connection over `maxConnections` is **destroyed without a response**
(`:316`), where every other refusal in this chapter is a complete HTTP response
followed by a graceful half-close (SPEC §4.5.1). RFC 9110 §15.6.4 gives `503`
exactly this meaning and RFC 9110 §10.2.3 gives it a `Retry-After`.
**Recommendation.** Answer the over-cap connection with `503` as the pending
gate does, unless a measurement shows that writing to a client at that point
costs more than it tells anyone.

---

## 4. What this chapter leaves out

- **Resolution.** Every lookup here is Chapter 1's, including the DoH fallback
  and its weaker trust state. This chapter specifies only where a resolution is
  called for and what is done with the answer.
- **The numeric-TLD convention.** Chapter 10 Part B owns it; this chapter states
  only that the marker must be decoded before classification and resolution.
- **Namespace selection.** The spine's Part II. The PAC's host rule is a copy of
  that classifier's and is held to it by test, not an independent rule.
- **The rest of the Handshake-Apps capability surface.** `records.get`,
  `records.propose`, `content.publish` and `names.claim` are answered
  `OutOfScope` by the reference mediator and are not specified here. Only the
  identity and authentication capabilities are.
- **The key store.** How a control key is created, protected, unlocked or backed
  up is out of scope; this chapter specifies only that the key never crosses the
  mediator boundary and that a locked store is reported as locked.
- **The consent interface.** Which decisions must be obtained is normative; how
  they are presented is not.
- **The application's own protocol.** What an application sends over its socket,
  and how it authorises actions once a session exists, is the application's
  business. SPEC §5.4 specifies only what it must not believe.
- **Publishing.** How a TLSA pin, an `_hns` record or a manifest reaches a zone
  is the publishing path's concern; §7 states only what must be true of the
  result.
