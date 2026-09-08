# Chapter 8 — Tor: deviations and open questions

This record separates current departures from proposed work. `DELIBERATE`
identifies a retained implementation choice; `OPEN` identifies unfinished work
or a decision still under review. Section 2 collects design questions, and
section 3 lists proposals. None of those proposals changes current behaviour.

See [the editorial review log](../../REVIEW.md) for contradictions found during
the documentation rewrite.

## 1. Deviations

### TO-1. With Tor off, and off Tor, we answer with a page rather than an error

**Behaviour.** With Tor off, an `onion://` navigation returns a local `200`
interstitial. A redirect outside Tor also returns a `200` page naming the
destination and offering a link. Neither case fetches the destination.

**Standard and effect.** RFC 7686 asks applications that do not use Tor for
an onion name to return an error without querying DNS. These pages provide an
actionable explanation but look like successful responses to programmatic
callers. Because the interstitial does not trigger `did-fail-load`, Tor-ready
reload checks the scheme as well as load errors (SPEC §7.4).

**Status: DELIBERATE.** A programmatic interface may need a failure status
instead.

---

### TO-2. An explicit non-onion scheme on an onion host is not protected

**Behaviour.** The classifier preserves an explicit `https://<addr>.onion/`
scheme instead of selecting the `tor` namespace. The chapter also documents
HTTP(S) link rewriting in SPEC §3.1; the scope of the top-level exception
therefore needs review against the browser wiring.

**Standard and effect.** RFC 7686's no-DNS requirement applies to the onion
name regardless of scheme. The existing deviation records a top-level path
that can reach the system resolver. Subresource guards check the host
regardless of scheme and cancel such requests.

**Status: OPEN.** Decide whether to refuse a non-`onion` scheme on an onion
host and offer the `onion://` form. Preserve explicit protocol selection while
preventing name disclosure. See §2.2 and TO-D2.

---

### TO-3. No SOCKS stream isolation: everything shares circuits

**Behaviour.** The session proxy and the five main-process SOCKS dialers
(SPEC §7.5) send no SOCKS credentials.

**Standard and effect.** Tor's `IsolateSOCKSAuth` can isolate streams with
different SOCKS credentials. This implementation supplies no per-origin
credential, allowing unrelated traffic to share circuits. That limits the
privacy provided by the whole-session Tor route.

**Status: OPEN.** Electron's session proxy interface does not provide the
per-request credential hook used by this design. The raw-socket dialers can
be investigated separately. TO-D1 compares possible integration approaches.

---

### TO-4. Whether the session cookie jar reaches the onion fetch is not established

**Behaviour.** The handler forwards neither `Cookie` nor `Set-Cookie`.
No integration test establishes whether the injected session fetch attaches
cookies from its own jar.

**Standard and effect.** RFC 6265 governs cookie selection, but the relevant
behaviour depends on Electron's session fetch and origin handling. The current
unit tests cannot establish either login persistence or cross-route state
sharing.

**Status: OPEN.** Measure this in an Electron integration test, select an
explicit cookie policy, and preserve it with a test. See TO-D3.

---

### TO-5. Onion services with client authorization cannot be reached

**Behaviour.** The generated `torrc` has no `ClientOnionAuthDir`, and the
browser has no client-authorization key-entry flow.

**Standard and effect.** Tor v3 supports services whose descriptors require
client authorization. Such a service is unavailable through the bundled
configuration and returns a generic 502 rather than an authorization-specific
explanation.

**Status: OPEN.** Add the configuration, credential storage and error reporting
together. See TO-D4.

---

### TO-6. IP Protection is all-or-nothing for the whole session

**Behaviour.** Settings › Content delivery › Mode controls one proxy state
for the entire session. Opening an onion page requires Private mode, which
also affects other tabs, handlers, searches and the policy rows in the
integrated SPEC §4.2.

**Reason and effect.** A single route is straightforward to audit, but users
incur Tor latency and Private-mode refusals across the session. It also does
not provide per-origin stream isolation (TO-3).

**Status: OPEN.** Evaluate session partitions, PAC routing and a local SOCKS
adapter before changing the route scope. TO-D1 and §2.5 describe their costs.

---

### TO-7. While BLOCKED, a session request fails as a proxy error, not as a page that names the mode

**Behaviour.** BLOCKED routes sessions to `socks5://127.0.0.1:9`.
Session requests fail with `ERR_PROXY_CONNECTION_FAILED`; `onion://` turns
that into a 502. The controller's status note explains the mode, but the page
usually does not. Raw-socket handlers have separate explanatory refusals.

**Requirement and effect.** The integrated SPEC §4.2 requires mode-related
failures to name the mode, state what was not done and point to its control.
The generic proxy error does not meet that presentation requirement.

**Status: OPEN.** Preserve the blocking proxy and use the main-frame
`did-fail-load` integration to show the controller's explanation when a proxy
failure occurs in BLOCKED.

---

## 2. Things we are not sure about

The following decisions remain open for review.

### 2.1. Whether "device-local" should have any escape hatch at all

Loopback-only routing excludes hosted gateways, but also excludes Tor instances controlled by the user on another LAN host, VM or organisational server. Review whether to permit an explicitly configured endpoint and how its operator and privacy implications would be disclosed. TO-D5 describes a possible design.

### 2.2. Whether an explicit scheme should be allowed to defeat R1 (TO-2)

Explicit-scheme precedence and the no-DNS rule conflict for onion hosts. The classifier preserves the explicit scheme; subresource guards reject the host. Review a fail-closed top-level refusal that preserves the selected protocol without issuing a DNS request (TO-2).

### 2.3. Whether routing before the circuit is ready is the right call (R11)

The proxy is applied before readiness and the gate follows mode (SPEC §7.2). This avoids a direct-routing transition but can leave the first navigation waiting during bootstrap. Review progress and retry behaviour while retaining the prohibition on direct onion connections.

### 2.4. Whether a browser that does not resist fingerprinting should offer `.onion` at all

The browser provides Tor routing without Tor Browser’s fingerprinting defences. The interface states that limitation, but the project has no usability evidence that users understand it. Review whether the disclosure is sufficient for offering onion navigation.

### 2.5. Whether the mode is at the right granularity (TO-6)

A whole-session proxy simplifies route auditing and increases the latency and policy cost of visiting one onion service. Alternatives include PAC routing, session partitions, or a local SOCKS adapter. They need evaluation alongside per-origin isolation and the existing WebSocket PAC (TO-D1, TO-6).

### 2.6. Whether `onion://` is the right URL form

The internal `onion://` scheme makes namespace selection visible, but a copied URL is not usable in clients expecting HTTP(S) onion URLs. Review how copied and shared links should be represented.

### 2.7. What a redirect chain should mean for the address bar

Same-service redirects are followed inside the handler, leaving the displayed URL at the original path. The origin remains the same, but the browser does not observe each redirect. Review final-URL reporting, relative URL behaviour and navigation history.

## 3. Open design items

Proposed work. These recommendations are not implemented.

### TO-D1. Per-origin SOCKS credentials for circuit isolation

The session proxy and raw-socket dialers send no per-origin SOCKS credentials
(TO-3, TO-6).

**Recommendation.** First test credentials in the five main-process dialers,
using the relevant first-party origin for each connection. Then evaluate the
session options: a PAC configuration, a local SOCKS adapter that assigns
credentials, or separate Electron sessions. A distinct PAC proxy string alone
does not establish isolation; measure the Tor behaviour. Any solution must
compose with the existing WebSocket PAC. A new listening adapter also needs
security review.

### TO-D2. Decide what `https://<addr>.onion/` should do

The explicit-scheme path and no-DNS requirement need one documented policy
(TO-2, §2.2).

**Recommendation.** Refuse non-`onion` requests for an onion host before DNS,
identify the address as an onion service, and offer the `onion://` form as a
link. Document how this exception interacts with explicit-scheme selection
and main-frame link rewriting.

### TO-D3. Establish, then pin, what happens to cookies

The injected fetch's cookie behaviour has not been measured (TO-4).

**Recommendation.** In an Electron integration test, set a session cookie,
make a proxied handler request to a controlled server and inspect the received
headers. Select an explicit policy, such as `credentials: 'omit'` or a separate
partition, and test it. Account for both login persistence and state isolation.

### TO-D4. Support onion services with client authorization

The bundled client has no authorization-key configuration (TO-5).

**Recommendation.** Configure `ClientOnionAuthDir <dataDir>/onion-auth`, create
the directory with mode `0700`, and integrate key entry with credential
storage. Add an authorization-specific explanation where Tor's error can be
identified reliably.

### TO-D5. Let a user name their own Tor endpoint, loudly

The current endpoint policy is loopback-only (§2.1).

**Recommendation for review.** If configurable endpoints are supported, avoid
automatic discovery beyond the existing `127.0.0.1:9050` fallback, require an
explicit selection that explains the endpoint operator can see requested
services, and keep the selected endpoint visible while in use. Whether to
provide this setting remains undecided.

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
   `net.fetch` is bound, how the anonymize controller composes with the
   WebSocket PAC, and how the `DeliveryMode` controller is wired to the
   settings page, the Privacy menu and the stored configuration (the controller
   itself, `../../src/delivery-mode.js`, is in this package; the `failClosed`
   flag the browser passes is set there) all live in the browser's
   `src/index.js` and `src/protocols/index.js`. `AnonymizeController` takes duck-typed sessions
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
