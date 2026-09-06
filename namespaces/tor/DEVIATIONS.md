# Chapter 8 — Tor: deviations and open questions

Every place this chapter's implementation departs from a standard it cites,
from common practice, or from its own stated design — plus every place we are
not sure we have made the right call, and the design work we know is still to
do.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

A note on proportion before the list. **The property this namespace exists to
provide — that an onion address never reaches a name resolver — holds, and is
tested at all four entry points** (`namespaces/tor/tests/onion-leak-guard.test.js`).
Everything below is about the *other* things: what is disclosed to the service
once the tunnel is up, the granularity of the mode, an unmeasured cookie jar,
and one exception to the leak rule that lives in the router's first law rather
than in this namespace.

Paths written `../../src/…` are shared modules of the top-level package; paths
written `src/…` and `tests/…` are this chapter's, under `namespaces/tor/`.

---

## 1. Deviations

### TO-1. With Tor off, and off Tor, we answer with a page rather than an error

**What.** Two of this handler's answers are `200` documents where a caller might
expect a failure status. When IP Protection is off, an `onion://` navigation
gets a `200` interstitial explaining what to turn on, where, and what the
limitation is (`src/onion-protocol.js:125-128`, `:228-238`). When an onion
service redirects to a target outside Tor, the answer is a `200` page naming the
destination and offering it as a link (`:167-172`).

**The standard says.** RFC 7686 §2 tells application software that does not
implement the Tor protocol to *generate an error* and not perform a DNS lookup.
This browser does implement it, so it is on the other branch of that
requirement — but with protection off it neither errors nor looks up.

**Why.** The no-lookup half of RFC 7686 is the half that matters, and it is
satisfied absolutely: zero network activity of any kind. The error half exists
so that a user is not silently given the wrong thing. A page that says *"this
browser reaches .onion only through the Tor client on your own device; that path
is off right now; here is how to turn it on"* serves that intent better than an
error code the user cannot act on. The same reasoning covers the off-Tor
redirect: refusing it silently would leave the user believing the onion service
simply failed, when what actually happened is that it tried to send them
somewhere else.

**Consequence.** A script that fetches an `onion://` URL with protection off, or
one whose target redirects to the clearnet, sees a `200` and an HTML body rather
than a failure. That is a real interoperability wart for programmatic callers.
The trade is that the human case — by far the common one — is answered usefully.
There is a second-order effect the design depends on: because the interstitial
is a successful load, `did-fail-load` never fires, which is why the "reload when
the circuit is up" rule keys on the **scheme** and not on the load status
(`src/tor-reload.js`, SPEC §7.4).

**Status: DELIBERATE.** The requirement RFC 7686 is protecting — that the name
is never resolved — is met in full and tested. The status code is the part we
trade, and we trade it for a page a person can act on. An implementation aimed
at programmatic callers rather than at a human navigating should invert this
choice.

---

### TO-2. An explicit non-onion scheme on an onion host is not protected

**What.** `https://<addr>.onion/` typed by a user, or followed as a top-level
link, keeps its explicit scheme. It is not reclassified into the `tor`
namespace, because the router's first law is that an explicit scheme selects the
protocol and is never sniffed (`../../src/router.js:362-376`).

**The standard says.** RFC 7686 §2: software that does not implement the Tor
protocol "should generate an error" for a `.onion` name and "should not perform
a DNS lookup" for it. The requirement is on the *name*, not on the scheme the
name was written under.

**Why.** Sniffing an explicit scheme is how `https://` silently becomes
something else, which is a worse and more general property than one unprotected
input. The law is held hard everywhere else in the router.

**Consequence.** That load goes to Chromium as an ordinary HTTPS request, and
Chromium hands `<addr>.onion` to the system resolver. **This is a real leak
path**, narrower than a classifier miss but real: it needs the user, or a link,
to name a scheme explicitly, which a hostile page can do. Partially mitigated:
the **subresource guard acts on the host regardless of scheme**, so
`<img src="https://<addr>.onion/x">` is cancelled
(`tests/onion-leak-guard.test.js`). The hole is top-level navigation only.

**Status: OPEN.** We recommend refusing it rather than routing it: a `.onion`
host under any scheme other than `onion:` is an unroutable address, and the
answer should be a fail-closed page from the `tor` namespace that names the
address as an onion service and offers the `onion://` form as a link. That is an
error rather than a lookup, which is what RFC 7686 §2 asks of software that will
not use Tor for the name, and it does not require sniffing — the scheme still
selects the protocol, it simply does not select *deanonymisation*. The cost is a
genuine, stated exception to the router's first law in a codebase that otherwise
holds it absolutely, which is why this is a decision to take deliberately rather
than a patch to apply; see §2.2 and TO-D2.

---

### TO-3. No SOCKS stream isolation: everything shares circuits

**What.** One SOCKS proxy URL with no credentials is applied to the whole
session (`src/anonymize.js:243-258`), and the three main-process paths that dial
the same port for themselves — the Handshake resolver's authoritative hop, the
`wss://` tunnel's upstream and a `gemini://` TLS socket, all through
`../../src/socks-dial.js` (SPEC §7.5) — send none either.

**The standard says.** RFC 1929 defines username/password authentication for
SOCKS 5. Tor's `SocksPort` overloads it for *stream isolation* and has
`IsolateSOCKSAuth` on by default (Tor manual, `SocksPort` options), so a client
that supplied distinct SOCKS username/password pairs per first-party origin
would get a separate circuit per origin at no cost. We supply none.

**Why.** For the session the proxy is configured once, as an Electron
session-level `proxyRules` string, and that API has no hook for per-request
SOCKS credentials. For the three direct dialers the reason is different and
weaker: the shared SOCKS client simply does not take a credential, because it
was written for the session's own no-auth port and nothing asked it for one.

**Consequence.** Every onion service, and all clearnet traffic in the same
session, can share exit-side and circuit-level correlation. Tor Browser isolates
by first-party domain precisely to prevent that. It is a genuine anonymity gap,
and it is part of what "hides your IP, is not full anonymity" is paying for. The
direct dialers widen it in a specific and slightly worse way: a Handshake
nameserver query, the WebSocket to that name's origin and an unrelated Gemini
capsule can all traverse one circuit, so a relay that sees the lookup may see
the socket that follows it.

**Status: OPEN**, with a real obstacle for the session half: we do not currently
know how to do this through Electron's session proxy API, and the fix is a piece
of design work rather than a line of code. TO-D1 states the three routes we can
see and why none of them is a one-liner. The three direct dialers are the
exception — they build their own SOCKS connection and could pass a credential
today — which makes them the place to measure whether Tor isolates on one at
all. Until per-site isolation exists anywhere, the product claim must keep
saying it is absent.

---

### TO-4. Whether the session cookie jar reaches the onion fetch is not established

**What.** The handler forwards no `Cookie` header and passes no `Set-Cookie`
back (`src/onion-protocol.js:182-190`, `:209-219`). Whether the injected
session-bound fetch attaches session cookies of its own accord is **not
determined** by this code, and no test in this package or the browser's asserts
either way.

**The standard says.** RFC 6265 §5.4 has a user agent attach cookies for a
request URI from its cookie store; whether one store is shared across origins is
the user agent's decision, and the specification does not make it for us. The
deviation is therefore from our own stated design rather than from the RFC: a
namespace whose whole purpose is non-disclosure should know whether it shares
state with clearnet browsing.

**Why.** It was never measured.

**Consequence.** Unknown, which is the problem. If the session jar is attached,
an onion service shares a cookie space with the rest of the session, which is a
linkability surface exactly the size of the jar. If it is not, some onion sites
will not keep a login. Either answer is defensible; not knowing which one is
true is not.

**Status: OPEN.** This is a measurement we owe, not a design question, and it
has to be an Electron integration test because the behaviour lives in
`net.fetch` rather than in this handler: set a cookie on the session, issue a
request through the handler against a local server, and assert what arrives.
Then pick — we lean towards isolating, because a namespace built for
non-disclosure should not share state with clearnet browsing by default — and
pin the choice. See TO-D3.

---

### TO-5. Onion services with client authorization cannot be reached

**What.** The generated `torrc` configures no `ClientOnionAuthDir`
(`src/tor.js:197-208`), and there is no interface for entering a
client-authorization key.

**The standard says.** rend-spec-v3 specifies client authorization for v3 onion
services — a descriptor encrypted to a set of authorized client keys — and the
Tor manual's `ClientOnionAuthDir` is where a client's keys live.

**Why.** Not implemented.

**Consequence.** A v3 onion service that requires client authorization is
unreachable, and fails with the generic `502` rather than a message naming the
reason. It fails closed and leaks nothing.

**Status: OPEN**, low priority. The `torrc` line and a `0700` directory are
trivial; the real work is the key-entry surface, because a client-authorization
key is a credential and belongs wherever the browser already keeps those, not in
a text box on an error page. Worth doing together with a `502` branch that
recognises the "descriptor requires client authorization" case and says so. See
TO-D4.

---

### TO-6. IP Protection is all-or-nothing for the whole session

**What.** There is one mode for the whole browser session
(`src/anonymize.js:243-258`). Reaching a single onion service means routing
*everything* — every tab, every protocol handler, the search fan-out — through
Tor for as long as the mode is on.

**The standard says.** Nothing directly; this is a deviation from the Tor
Browser design document, whose first-party isolation model is the reference
point every claim about anonymity in this chapter is measured against.

**Why.** It is the honest version of the simple thing. A per-request or
per-origin proxy would be better, but Electron allows one proxy configuration
per session, and a design in which *some* traffic is proxied is a design in
which it is easy to be wrong about which.

**Consequence.** A user who wants one onion page pays Tor latency on everything
else, which is a strong incentive to leave the mode off — and the mode being off
is the condition under which onion addresses are unreachable at all. The design
that is safest is also the one that discourages use. It is also, per TO-3, the
configuration in which everything shares circuits.

**Status: OPEN**, and it is the largest open design question in this chapter. We
do not recommend changing it until one of the routes in TO-D1 is proven, because
every alternative we can see either does not work (a PAC file gives a distinct
proxy string but no distinct SOCKS credentials, so Tor does not isolate on it),
or introduces a new listening socket in a privacy feature (a local SOCKS shim),
or multiplies Electron sessions. A whole-session proxy with no "was this request
proxied?" question in it is worth a great deal, and we would rather keep it than
trade it for a partial answer. See §2.5.

---

## 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each is
a real decision that is currently shipping, and each could be wrong.

### 2.1. Whether "device-local" should have any escape hatch at all

The rule in SPEC §1 is absolute: `127.0.0.1` or nothing. It rules out a hosted
relay, which is the case it was written for and which we would defend without
hesitation — an operator-run SOCKS endpoint learns every hidden service its users
ask for, and offering that while describing it as privacy is the specific
dishonesty this project exists not to commit.

But the same rule also rules out cases that are not that:

- a Tor daemon on another machine **on the user's own LAN** (a home server, a
  router), which many privacy-conscious people actually run;
- a Tor daemon in a container or VM alongside the browser;
- an organisation's own internal Tor instance.

In each of those the user *is* the operator. The rule as written cannot express
"a Tor I control", only "a Tor on this host", and `127.0.0.1:9050` is hard-coded
in two places. We think a configurable endpoint with a loud, non-default,
explicitly-consented-to setting would be strictly better than the current
position — and we are not sure, because the moment such a setting exists it is
the thing a bad tutorial tells people to point at somebody else's server. **We
would like to hear how other clients have drawn this line.** See TO-D5.

### 2.2. Whether an explicit scheme should be allowed to defeat R1 (TO-2)

Two principles collide and only one can win:

- *An explicit scheme selects the protocol, always.* Sniffing is how `https://`
  quietly becomes something else, and we hold this law hard everywhere else.
- *A `.onion` host never reaches a resolver.* Disclosure cannot be undone, and
  this namespace exists for that rule alone.

Currently the first wins for top-level navigation and the second wins for
subresources, which is at least defensible — a subresource is not a user's
expressed intent — but is also two answers to one question. We lean towards
refusing `https://<addr>.onion/` outright, because "the scheme wins" cannot
sensibly mean "the scheme wins the right to deanonymise you". We have not
convinced ourselves that the special case is not the thin end of a wedge, and
the wedge is the thing we are unsure about rather than this instance of it.

### 2.3. Whether routing before the circuit is ready is the right call (R11)

We argue in SPEC §7.2 that opening the gate on the *mode* rather than on
*readiness* is the leak-safe order, because the alternative leaves a window in
which the session is direct and some code path might take the request. We
believe that.

What we are less sure of is the user consequence: with the gate open and the
circuit still building, a first onion navigation can sit for up to a minute with
nothing to show but a progress percentage. The temptation to add a "try
directly" affordance to that screen is exactly the temptation this namespace must
never yield to, and a design that creates the temptation is a design with a
weakness in it. We do not have a better one.

### 2.4. Whether a browser that does not resist fingerprinting should offer `.onion` at all

The strongest argument against everything in this chapter: reaching an onion
service in a browser without Tor Browser's fingerprinting defences may give
users a *feeling* of anonymity that the software does not provide, and a false
sense of protection can be worse than none. Someone who would have used Tor
Browser and instead uses this is worse off.

Our position is that the two things being conflated are separable and that
saying so plainly is the whole job: **hiding your IP** is what this delivers, and
it delivers it properly; **anonymity** is what Tor Browser delivers, and this
does not. Every string on this path pairs them — the interstitial, the mode note,
the trust panel — and `tests/onion-protocol.test.js` asserts the caveat is
present in the interstitial so it cannot be quietly dropped in a copy edit.

We are aware that is a claim about whether users read, and that we have no
evidence for it. **If somebody has run this experiment, we would like to know.**

### 2.5. Whether the mode is at the right granularity (TO-6)

A whole-session proxy is simple, auditable, and has no "was this request
proxied?" question in it — properties we value highly. It also makes the safe
path expensive enough that users will not stay on it, and per-origin circuit
isolation (TO-3) impossible.

The alternatives we can see are a per-request proxy (Electron does not offer
one), a PAC file that routes `.onion` differently from everything else (possible,
and composes badly with the WebSocket PAC the same controller already installs),
or a small local SOCKS shim of our own that fans out to Tor with per-origin
credentials (most capable, most code, most new attack surface). We have not
worked this out.

### 2.6. Whether `onion://` is the right URL form

Tor Browser uses `http://<addr>.onion/`, and so does every link in the wild. We
carry a distinct internal scheme because in a general browser the namespace has
to be visible in the URL — the address bar has to be able to say *which* system
this address belongs to, and the rewrite from a clicked `http://` link is how
those in-the-wild links keep working.

The cost is that a URL copied out of Wildroot's address bar is not a URL anybody
else can use, and a shared `onion://` link is dead outside this browser. That is
the same complaint as the numeric-TLD convention in the Handshake chapter and it
has the same shape: a local convention forced by a real constraint. We would
rather converge with other alt-namespace browsers than defend ours.

### 2.7. What a redirect chain should mean for the address bar

A same-service redirect is followed inside the handler, so the URL the user sees
stays the one they asked for while the bytes come from the path the service
redirected to. That is what an ordinary browser does for a redirect it follows
inside the network stack, and it is what makes a `302` to `/welcome` behave
normally — but here the handler is doing it on the browser's behalf, one layer
further out, and we have not thought through whether the address bar should
learn about the hop. It has no security consequence we can see (the origin is
identical by construction), and we are noting it because "the browser cannot see
the redirect" is the sort of thing that turns out to matter later.

---

## 3. Open design items

Work we believe should happen and have not done. Each states the problem and a
recommendation; none of it is implemented.

### TO-D1. Per-origin SOCKS credentials for circuit isolation

One credential-free `socks5://127.0.0.1:<port>` is applied to the whole session,
so every onion service and all clearnet traffic in it can share circuits, where
Tor's `IsolateSOCKSAuth` would give a separate circuit per origin for free if we
sent distinct credentials. Electron's `session.setProxy` takes a session-wide
`proxyRules` string with no hook for per-request SOCKS credentials, so there is
no small version of this change (TO-3, TO-6).

**Recommendation.** Start where it is nearly free: the three main-process
dialers of SPEC §7.5 construct their own SOCKS connection, so giving
`../../src/socks-dial.js` an optional username/password derived from the
first-party (the Handshake name, the WebSocket origin, the capsule host) is a
parameter and a test, and it answers the question the session-wide routes below
all depend on — *does this Tor isolate on it?* — for the cost of an afternoon. A
positive answer justifies the session work; a negative one saves it. Then take
the three session routes in order of what they would prove, not of effort. **(a)** A PAC script returning a different `SOCKS5` line per host
gets a distinct proxy *string* per origin but still no credentials, so whether
Tor isolates on it is doubtful and must be measured before it is believed; it
also has to compose with the WebSocket PAC the same controller already installs
(`this.proxyConfigFor`), which is a real constraint. **(b)** A tiny local SOCKS
shim that takes the intended first-party from a per-origin listener and opens
the upstream Tor connection with credentials derived from it is the most capable
and needs a security review rather than an afternoon, because it adds a
listening socket to a privacy feature. **(c)** Multiple Electron sessions, one
per first-party, is structurally clean and changes a great deal besides this.
Measure (a) first: it is the only one whose answer is cheap, and a negative
result is what justifies the cost of (b).

### TO-D2. Decide what `https://<addr>.onion/` should do

An explicit scheme wins, so a typed or top-level-linked `https://<addr>.onion/`
goes to Chromium as ordinary HTTPS and the host reaches the system resolver.
Subresources are covered; top-level navigation is not (TO-2, §2.2).

**Recommendation.** Refuse it rather than route it. In `classify()`, before the
explicit-scheme return, recognise a `.onion` host under a non-`onion` scheme and
return a decision marked unroutable in the `tor` namespace, whose handler serves
a fail-closed page naming the address as an onion service and offering the
`onion://` form as a link. Write the exception to the first law into the comment
at the point where it is taken, in the words of the reason: an explicit scheme
selects the protocol, and does not select deanonymisation.

### TO-D3. Establish, then pin, what happens to cookies

Whether the session cookie jar is attached to the onion fetch is unknown, and no
test asserts either way (TO-4).

**Recommendation.** Measure before deciding. An Electron integration test — set
a cookie on the session, issue a proxied request through the handler against a
local server, assert what arrives — turns the unknown into a fact. Then choose
isolation (`credentials: 'omit'`, or a partition of its own) unless the
measurement shows something that argues otherwise, and pin the choice with the
same test. Whichever way it lands, TO-4 stops being an uncertainty.

### TO-D4. Support onion services with client authorization

No `ClientOnionAuthDir` in the generated `torrc` and no way to enter a key, so an
authorized service is unreachable and reports the generic `502` (TO-5).

**Recommendation.** Add `ClientOnionAuthDir <dataDir>/onion-auth` to the `torrc`
and create the directory `0700`; give the `502` page a branch that recognises
tor's "descriptor requires client authorization" and says so. Then design the key
entry properly: it is a credential, and it belongs wherever the browser already
keeps credentials, not in a text box on an error page. Ranked low because the
population of such services is small, not because the failure is graceful.

### TO-D5. Let a user name their own Tor endpoint, loudly

`127.0.0.1:9050` is hard-coded in two modules, so "device-local" is implemented
as "this host" — which correctly excludes a hosted relay and also excludes a Tor
daemon the user runs on their own LAN, in their own container, or in their own
organisation (§2.1).

**Recommendation.** If it is done at all, a single configurable SOCKS endpoint
with three non-optional properties: not discoverable by accident (no
auto-detection beyond the existing `127.0.0.1:9050` fallback); explicitly
consented to once, with text naming the actual risk — *"the operator of this Tor
instance can see which onion services you ask for; only point this at a Tor you
control"*; and visible while it is in use, in the same surface that reports the
mode, so a non-default endpoint is never a silent state. We are genuinely
uncertain this should be built: the moment the setting exists, it is the thing a
bad tutorial tells people to point at somebody else's server. Being talked out
of it is a good outcome.

---

## 4. What this chapter leaves out

Three things are deliberately absent from `src/` and `tests/`:

1. **The Electron privilege registration.** `onion:` is declared `standard: true,
   secure: true, supportFetchAPI: true, corsEnabled: true,
   allowServiceWorkers: false` in the browser's `src/main.cjs`. That is what
   gives an onion page a real, storable, per-host origin and stops real web
   applications from crashing on an opaque one, and SPEC §5 and §8 specify its
   *meaning* — including that `secure: true` is a capability decision and not a
   trust claim. The declaration itself is a literal in the browser's Electron
   entry point and cannot be extracted without Electron. The browser's own
   `tests/hns/onion-origin.test.js` asserts it by reading that source file; that
   half of the test does not travel, and its other half — the trust-state
   assertion — is here as `tests/onion-trust-state.test.js`.

2. **The Tor binary and its supply chain.** No `tor` is vendored here and none
   ever will be. `src/tor.js` is byte-identical to the browser's copy including
   `resolveTorBin()`, which looks for `vendor/tor/<platform>-<arch>/tor` beside
   the source tree; in this package it always returns `null`, so the bundled
   branch is reachable only by injecting `binPath` — which is what every test
   does, deliberately, so that no assertion in this directory depends on the
   machine it runs on. The browser's vendoring step (a pinned GPG signature over
   the Tor Expert Bundle, then a pinned SHA-256) is packaging, not resolution.

3. **The session wiring.** Which Electron sessions the proxy is applied to, how
   `net.fetch` is bound, and how the anonymize controller composes with the
   WebSocket PAC all live in the browser's `src/index.js` and
   `src/protocols/index.js`. `AnonymizeController` takes duck-typed sessions
   (`{ setProxy, closeAllConnections }`) and the onion handler takes an injected
   `fetchImpl`, so both are fully exercised here without Electron — but the
   *wiring* is the browser's, and SPEC §7.5 specifies its policy rather than its
   code.

One thing is included that is arguably out of scope and is flagged rather than
trimmed: **`src/tor.js` contains the whole Tor client lifecycle** — spawning,
the pid-file orphan reap, the 30-second supervision probe and the recovery
respawn. Resolution depends only on the availability states and the SOCKS
endpoint (SPEC §7). It is kept whole because every source file in this
repository is byte-identical to its counterpart in the Wildroot tree, so a fix
in one is provably the same fix in the other, and a trimmed copy of a
security-relevant module is a worse problem than an over-broad one.

`../../src/router.js`, `../../src/reserved-names.cjs`, `../../src/hns-host.js`,
`../../src/safe-status.js` and `../../src/trust-path.js` are **not** copied here
at all — they are the shared modules of the top-level package, and this
namespace's classifier rows, reserved-name row, status clamp and trust-state
case live inside them. That is stated so a reader does not go looking for an
onion-specific copy that would immediately start to diverge.
