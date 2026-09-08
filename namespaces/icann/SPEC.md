# Chapter 2 — ICANN names

**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the reference implementation in this
repository and in `../../src/`, which ships in the Wildroot browser. Not
endorsed by any standards body. Normative statements describe what an
implementation must do *to interoperate with this one*; where a rule is
inherited from an existing standard, that standard is cited and its rule
governs.
**Licence:** CC-BY-4.0 (see `../../LICENSE-SPEC`). The reference implementation
is licensed separately.

This chapter defines how ICANN names are classified, which DNS transport the
browser requests, and what the trust panel may report. See the
[overview](../../SPEC.md) and [router chapter](../router/SPEC.md) for the shared
model. [Deviations](DEVIATIONS.md) use the `IC` prefix; [references](REFERENCES.md)
list the relevant standards.

**Review status:** [REVIEW.md](../../REVIEW.md) separates stale descriptions from
unresolved technical questions. This revision changes documentation only.

---

## Contents

1. [What this specifies, and why it exists](#1-what-this-specifies-and-why-it-exists) — including [**scope**](#11-scope)
2. [The boundary: which names are ICANN's](#2-the-boundary-which-names-are-icanns)
3. [Collisions: a label that is both](#3-collisions-a-label-that-is-both)
4. [Special-use names](#4-special-use-names)
5. [Transport: encrypted DNS for ICANN lookups](#5-transport-encrypted-dns-for-icann-lookups)
6. [Trust states, and what the lock shows](#6-trust-states-and-what-the-lock-shows)
7. [What an ICANN resolution does not get](#7-what-an-icann-resolution-does-not-get)
8. [The one place we resolve an ICANN name ourselves](#8-the-one-place-we-resolve-an-icann-name-ourselves)
9. [Security considerations](#9-security-considerations)

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

Three path conventions are used. `../../src/…` is a module in this
repository's shared `src/`. A bare `src/dns-policy.js` or
`src/icann-tld-snapshot.js` is this chapter's own `namespaces/icann/src/`.
Every other `src/…` is in the Wildroot browser tree, which is not part of this
package; those are given with line numbers so a claim can be checked against
the code that makes it.

---

## 1. What this specifies, and why it exists

ICANN names use the browser engine's resolver and WebPKI connection path.
Wildroot classifies the name, configures the engine's DNS transport, and
reports the resulting policy and available lookup evidence. Its Handshake
DNSSEC validator, on-chain DS anchors, and DANE transport do not apply to
ordinary ICANN navigation.

Misclassification can send a lookup to the wrong root. Transport reporting can
also overstate privacy if it describes configuration as though it proved how a
particular lookup occurred. Sections 2–4 define the boundary; §5 defines DNS
policy; §6 defines the reporting requirements and their limits.

### 1.1 Scope

**In scope:** how a host is decided to be an ICANN name; how that decision
interacts with Handshake, with other alt-roots, and with special-use names; the
DNS transport policy applied to ICANN lookups (mode, resolver pool, Oblivious
DoH bridge, plaintext fallback, failing closed); and what an implementation may
tell the user about the result.

**Out of scope, explicitly:**

| Out of scope | Why it is a different document |
|---|---|
| **Everything after the address** — the TLS handshake, WebPKI path building, HSTS, the HTTP fetch | This chapter ends where the spine ends: at an address and a trust state. The ordinary web's security model is specified by RFC 5280, RFC 8446 and RFC 9110, and we neither extend nor restrict it. |
| **Handshake resolution** | [`../../SPEC.md`](../../SPEC.md). This chapter says only which names are *not* Handshake's. |
| **The other alt-namespaces** — ENS, Tor, Nostr, AT Protocol | `namespaces/*/`. They are relevant here only because they are matched **before** the ICANN test (§2.2). |
| **The engine's own resolver** — cache behaviour, happy-eyeballs, DoH probing and downgrade heuristics | We configure it; we do not implement it. Where its behaviour matters to a claim we make, §5.5 and `../../DEVIATIONS.md` §2 (what the engine does on each kind of DoH failure) say what we have and have not verified. |
| **DNSSEC validation for ICANN names** | Not performed on this path at all (§7.2). |

This package configures the engine’s ICANN resolver; it does not replace it.
The chapter’s source contains policy and snapshot-generation code.

---

## 2. The boundary: which names are ICANN's

### 2.1 The rule

> **ICANN first.** A host with two or more labels whose final label, expressed
> as an A-label and lowercased, is a delegated ICANN top-level domain **is** an
> ICANN domain, and **MUST** be resolved through the ordinary DNS.

The classifier checks membership in `../../src/icann-tlds.cjs` through
`classifyHost()` in `../../src/classify-host.cjs`. The router and address bar
share that function.

An implementation **MUST NOT** apply any fallback across this boundary in
either direction. An ICANN name that fails to resolve is an ICANN failure; it
is not retried as a Handshake name. A Handshake name that fails is not retried
as an ICANN name. This is law **L2** of the router chapter and it is enforced at
the namespace boundary by the router's dispatcher, which returns a handler's
failure tagged with that handler's own namespace (`X-Resolution-Namespace`) and
never calls a second handler.

### 2.2 Classification order

`classifyHost(host)` decides in this order, and the first match is final:

| # | Test | Result |
|---|---|---|
| 1 | host is empty, or contains whitespace | `null` (the caller treats it as a search query) |
| 2 | final label is `onion` (RFC 7686) | `tor` — **never** a resolver, even when malformed |
| 3 | final label is `eth` | `ens` — no fallback into ICANN or Handshake |
| 4 | the host, or its final label, is a reserved name (§4) | `web`, reached over `http://` |
| 5 | the host is an IPv4 or IPv6 literal, bracketed or not | `web`, reached over `https://` |
| 6 | fewer than two labels | `null` (a bare label; see §2.5) |
| 7 | final label is all ASCII digits | `hns` only with numeric names enabled; otherwise `web` (off by default) |
| 8 | final label ∈ the ICANN set | **`icann`** |
| 9 | otherwise | `hns` |

The onion and ENS rules precede ICANN so lookup failure remains inside the
selected namespace. Onion also precedes the reserved list, preventing a
`.onion` host from selecting the platform web path.

Rows 4 and 5 come before row 6, and an implementation **MUST** order them that
way. Neither test can be expressed as a label count: a reserved name may have
any number of labels (`localhost`, `app.localhost`), and an IPv6 literal has no
dots at all, so `[::1]` would otherwise fall to the bare-label rule and start a
name resolution for an address the user typed in full.

### 2.3 Canonical form before comparison

Before the final label is compared against the set, a host **MUST** be:

- **lowercased** — RFC 4343: DNS owner names compare case-insensitively;
- **stripped of a trailing root dot** — `example.com.` and `example.com` are
  the same name, and must not land in different namespaces;
- **stripped of any `:port`** and of any path, query or fragment. The port is
  stripped only from a host with exactly one colon, or from a bracketed host,
  so that `::1` stays an address rather than becoming a host with a port of `1`
  (`bareHost()`, `../../src/classify-host.cjs`);
- **converted to A-labels** — RFC 5890/5891. In this implementation the
  conversion is done by handing the host to the WHATWG URL host parser and
  reading `hostname` back (`asciiTld()`, `../../src/classify-host.cjs`),
  which is UTS-46 as the URL Standard defines it rather than IDNA2008. The
  bundled set holds IANA's published punycode, so `пример.рф` matches
  `xn--p1ai` and an emoji label matches nothing and is Handshake's. The
  divergence between UTS-46 and IDNA2008 is inherited from the spine's D-17 and
  restated here as IC-12, because on this path it can move a name **across the
  ICANN boundary**, which is a stronger consequence than it has on the
  Handshake path.

If the URL parser throws — which it does for some hosts whose last label is all
digits, under the WHATWG numeric-host rule — the raw final label is
used instead, and row 7 catches it. The `http(s)`→`hns` rewrite has no such
fallback: it returns `null` for a URL it cannot parse, so a literal
`http://hello.14898/` link is left alone rather than rewritten. That URL is one
the engine cannot construct either, so the rewrite is unreachable rather than
skipped: IC-14.

### 2.4 The vendored root-zone snapshot

The set is a **build-time snapshot of the IANA root zone database**, generated
from `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` and committed to the
repository. It holds **1,438 labels** and carries IANA's own provenance line in
its header:

```
// IANA Version 2026090500, Last Updated Sat Sep  5 07:07:01 2026 UTC
```

Requirements on the snapshot:

- It **MUST** carry the source's version and date, in the artefact itself. A
  boundary whose age cannot be read off the file is a boundary nobody can
  reason about.
- It **MUST** hold A-labels, lowercased, one label per entry, exactly as IANA
  publishes them. No second table for Unicode.
- The generator **MUST** refuse to write a list of implausible size. Ours
  refuses fewer than 1,000 entries, so a truncated fetch or an error page can
  never overwrite the boundary.
- It **MUST NOT** be fetched at runtime. A privacy browser does not phone home
  at startup, and the classifier has to answer a keystroke without waiting for
  the network. The cost of that choice is IC-1: the boundary is only as fresh
  as the last release.

`src/icann-tld-snapshot.js` is the parse-and-render half of that pipeline,
extracted so the claim *"the committed file is exactly what the generator
produces"* is checkable offline (`tests/icann-tld-snapshot.test.js`). Wildroot
additionally runs a **live drift alarm** (`tests/hns/icann-tlds-live.test.js`)
that compares the snapshot with IANA on every networked test run and reports
drift in both directions. It is an alarm and never a build gate: a red build
because IANA was unreachable teaches everyone to ignore the alarm.

Both directions of drift are user-visible failures:

- a **delegated TLD missing** from the set → a real domain is resolved as a
  Handshake name, fails, and the user is told the site does not exist;
- a TLD in the set that IANA has **removed** → a name that could be Handshake's
  is sent to https:// and to an ICANN resolver, which both fails and discloses
  the lookup.

New ICANN delegations increase the risk of missing entries in an old
snapshot. Application counts and future delegation dates are not inputs to
the classification rule.

### 2.5 A single bare label is never ICANN

`classifyHost()` returns `null` for a single label. The input classifier
then treats a bare ICANN TLD such as `com`, `org`, or `app` as search, and a
non-ICANN label such as `hnshosting` as Handshake. An implementation **MUST NOT**
turn a bare label into an ICANN lookup under this input policy.

This is a classification rule, not a claim that DNS forbids records at TLD
apexes. Whitespace is excluded from the bare-label rule so multi-word input
selects search.

### 2.6 The rule must be applied on every path

An implementation **MUST** apply the same classification wherever a host is
classified, and **MUST** hold both the rule and each list it depends on in
exactly one place. In this implementation every consumer but one calls the
same function:

| Path | Function | Reads |
|---|---|---|
| typed input / omnibox decision | `classify()` → `classifyHost()` | `classify-host.cjs`, and through it both lists |
| omnibox suggestion rows | `src/ui/omni-box.js` (CommonJS, cannot import the ES-module router) | `require`s the same `classify-host.cjs` |
| `http(s)`→`hns` navigation rewrite | `rewriteToHns()` → `isHnsHost()` → `classifyHost()` | the same module |
| subresource guard (`onBeforeRequest`) | `rewriteToHns()` | the same module |
| session-wide certificate verification | `isHnsHost()` | the same module |
| WebSocket PAC script (runs inside the engine) | `src/hns/ws-proxy-pac.js` — an ASCII-only copy of the rule, held to `classifyHost()`'s answers by test | embeds the two lists |

The CommonJS host-classification module and its two data files can be loaded
by both the ES-module router and the CommonJS address bar.

The PAC environment has no module loader or URL parser. It uses an
ASCII-only version of the rule and the shared lists; tests compare its
decisions with the common classifier (RT-7).

`rewriteToHns()` (`src/hns/hns-host.js`) returns `null` for every ICANN
host, which is the mechanically checkable form of §7: an ICANN name never
enters the Handshake pipeline, and so never meets DANE or the SSRF guard.

---

## 3. Collisions: a label that is both

A label can exist in both roots. A string can be a delegated ICANN TLD and,
simultaneously, a registered Handshake top-level name whose owner has published
records for it.

> **The ICANN answer wins.** Membership of the snapshot is decided first and
> is final. There is no per-name preference, no negotiation, and no prompt.

This differs from Handshake’s model, which lets ICANN holders claim reserved
labels on the chain. Wildroot gives ordinary ICANN navigation precedence
(IC-2, HS-13).

A reserved name (§4) outranks both roots. If one of those labels were ever
delegated, this browser would still route it to the platform.

**The escape hatch is the scheme, and only the scheme.** An explicit
`hns://example.com/` is routed to the Handshake handler and resolved on the
chain, because law **L1** says an explicit scheme selects the protocol and is
never re-sniffed. Nothing in the Handshake handler refuses an ICANN label. So
the collision policy is: *ICANN by default, Handshake on request, never
silently.* An implementation **MUST NOT** make the reverse move — an
unqualified name **MUST NOT** be resolved on the chain because ICANN failed.

Other unreserved, non-ICANN suffixes, including `.crypto`, `.sol`, `.bnb`,
and `.nft`, select Handshake. For example, `brad.crypto` uses the Handshake
`crypto` records rather than Unstoppable’s registry.

---

## 4. Special-use names

A host whose final label is reserved by RFC 6761 (`localhost`, `invalid`,
`test`, `example`), RFC 6762 (`local`), RFC 7686 (`onion`), or RFC 8375 and
adjacent practice (`arpa`, `internal`, `home`, `lan`, `corp`, `intranet`,
`private`) **MUST** be routed to the mechanism that owns it and **MUST NOT** be
sent to a Handshake resolver.

Without the reserved-name branch, local names such as `nas.local`,
`printer.lan`, `gitlab.internal`, and `app.localhost` could be sent to a
Handshake resolver.

The list is `../../src/reserved-names.cjs` (browser:
`src/hns/reserved-names.cjs`), consulted at row 4 of §2.2 and therefore by every
path in §2.6's table. Three details worth copying:

- **`localhost` is a subtree, not a label.** RFC 6761 §6.3 reserves
  `localhost.` and *any name ending in `.localhost.`* to loopback, so
  `app.localhost` is covered as well as `localhost`. `isReservedHost` compares
  both the whole host and its final label, which gives that rule for every
  entry.
- **The result is `web` over `http://`, not a refusal.** A user who types
  `nas.local` means their NAS, and the platform resolver is the mechanism that
  owns the name — the same treatment bare `localhost` gets. Plain `http` rather
  than `https`, because a device on a home network has no public certificate.
- **The list is longer than the RFCs.** `home`, `lan`, `corp`, `intranet` and
  `private` are not reserved by any RFC; they are what home routers and
  corporate networks actually use. Including them is a deviation we would
  defend (IC-5): the alternative is a class of names that resolve to a
  stranger's records on a user's own LAN.

---

## 5. Transport: encrypted DNS for ICANN lookups

Handshake names never use this path: they ride the resolver specified in the
spine's §9. This section is about everything else.

### 5.1 The default is not the platform default

An implementation **SHOULD** configure encrypted DNS. Wildroot uses
`app.configureHostResolver({ secureDnsMode, secureDnsServers })`. This API
accepts RFC 8484 DoH templates; it does not accept DoT, DoQ, or ODoH endpoints.
The loopback bridge translates engine DoH requests to ODoH (§5.3).

`planDnsTransport()` computes the engine configuration and `recordDnsPlan()`
records it for the trust panel (§6).

### 5.2 `dns.mode`

Exactly three values (`src/config.js`):

| `dns.mode` | Meaning | Plaintext possible? |
|---|---|---|
| `off` | no configuration is applied; the platform resolver's default is used | always |
| `automatic` *(default)* | encrypted DNS to the configured servers, **falling back to unencrypted system DNS when none answer** | yes, on failure |
| `secure` | encrypted DNS only; unencrypted DNS is refused | no |

Normalisation is specified, and an implementation **SHOULD** copy it
(`normalizeDnsMode()`, `src/dns-policy.js`):

- **Case and surrounding whitespace are normalised.** `'Off '` becomes `off`.
- **Unknown values are reported** through a warning callback and become
  `automatic`. Missing or empty values use that default without warning.

`dns.mode` is surfaced in the browser's settings page with all three values
explained (`src/pages/settings.html:464-472`) and takes effect on restart. It is
the **Fast-mode** plan: in Private mode (§5.7) the stored value is not consulted
at all — the block is replaced before it is read.

### 5.3 Oblivious DoH, through a loopback bridge

The engine cannot speak RFC 9230. The implementation therefore **runs an RFC
8484 DoH server on loopback** and performs the oblivious exchange behind it:

```
engine ──https──▶ loopback bridge ──HPKE──▶ relay ──▶ target ──▶ resolver
        (127.0.0.1)   (in-process)      (independent)   (ours)
```

Normative requirements on such a bridge:

- It **MUST** bind to loopback only.
- Its endpoint path **MUST** be an unguessable per-launch secret, and it
  **MUST** refuse any request carrying `Origin` or `Sec-Fetch-Site`. Both are
  needed: a page on any origin can reach a loopback listener, and although it
  cannot read the answer, *writing* into the bridge's "recently answered" list
  is by itself enough to make the interface report a name as oblivious that
  went out in the clear (§6.2). Ours does both
  (`../../src/odoh-bridge.js`, `:119`).
- On failure it **MUST** answer SERVFAIL rather than resolving by some other
  route. What happens next is the engine's secure-DNS mode to decide, which
  keeps that decision in one visible place instead of hidden inside the
  component whose whole purpose is privacy.
- Its TLS certificate **MUST** be generated in memory per launch and **MUST
  NOT** be written to disk. The engine is made to trust it by pinning its
  SubjectPublicKeyInfo hash — the RFC 7469 pin construction, base64 of
  SHA-256 over the SPKI — and that pin makes the engine accept that public key
  **for any host**. A key with that power in a profile directory is a standing
  MITM key for the whole browser. Ours is a fresh P-256 self-signed
  certificate naming only `localhost` and `127.0.0.1`
  (`../../src/self-cert.js`).
- The certificate **MUST NOT** be minted for a bridge that is not going to
  run. §9.3.

The ODoH exchange itself is the one specified in the spine's §9.2 and
implemented in `../../src/odoh.js`: RFC 9230 message format, RFC 9180 HPKE
(X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM), RFC 5869 HKDF for the §6.3
response key and nonce. Relays are tried in order; a 401 from the target means
the cached configuration is stale and it is refetched once.

The transport fetches the target’s ODoHConfig from
`https://<target>/.well-known/odohconfigs` and caches it for one hour. The fetch
bypasses the ODoH relay but uses the injected fetch, so Private can carry it
through Tor. The target sees the connecting address, which need not be the
user’s address. The URI’s registration status needs verification (IC-8).

### 5.4 The plan: what replaces what, and what fails closed

The transport decision is a pure function of the configuration and of whether
the bridge started. It returns six facts, and an implementation following this
chapter **MUST** decide each of them consciously:

| Field | Meaning |
|---|---|
| `mode` | the normalised `dns.mode` |
| `servers` | the RFC 8484 templates the engine is given |
| `oblivious` | the bridge is carrying the engine's lookups |
| `configure` | the host-resolver call is made at all; when false the engine keeps its default, which is system DNS |
| `failClosed` | `secure` was asked for and there is no server, so nothing resolves |
| `plaintextFallback` | an ICANN lookup can still leave this machine in the clear |

The bridge and empty-server rules are:

> **When the bridge starts, its loopback template replaces the configured
> resolver pool. It does not join it.** (IC-7.)

Consequences:

- If the bridge **fails to start**, the pool remains and lookups are encrypted
  but not oblivious. The implementation logs exactly that, and the interface
  reports it (§6.2).
- If the bridge **starts and then a lookup fails** — every relay down, the
  target unreachable — the bridge answers SERVFAIL and the engine applies its
  mode. In `automatic` — the Fast-mode default — that means **unencrypted
  system DNS**, not the configured DoH pool, because the bridge replaced it.
  Turning obliviousness on therefore changes the floor beneath a failure from
  *encrypted* to *plaintext*.
- In `secure` mode — configured, or forced by Private mode (§5.7) — there is
  no floor: a relay outage is a total ICANN outage. That is the honest trade
  rather than a defect — the alternative is resolving in the clear after the
  user asked us not to.

> **`secure` with no server to point at fails closed.** The engine is
> configured for secure mode with an **empty** server list, so nothing
> resolves, rather than left on its default, which resolves in the clear.

A setting that says "never plaintext" must not silently mean nothing. A
profile that asks for `secure` with an empty `dns.servers`, or whose bridge
failed to start with `dns.servers` unset, therefore breaks loudly — every
ordinary web address fails, the implementation logs why, and the interface
reports the refusal as a *failed* step rather than as system DNS (§6.2). An
implementation **MUST NOT** treat that configuration as a no-op. Private mode
with no bridge is this case by construction (§5.7).

The plan configures nothing for `off`, or for `automatic` without a resolver.
Both permit the platform default and report `plaintextFallback`.

### 5.5 Captive portals

Fast defaults to `automatic`, which permits system DNS fallback when secure
resolvers are unavailable. This supports networks with captive portals, at the
cost of allowing an attacker to trigger an unencrypted lookup by disrupting
encrypted DNS. Private uses `secure` and permits no plaintext fallback.

An implementation **MUST** report the active mode and **MUST NOT** describe
`automatic` as private without explaining the fallback. The engine's behavior
for each failure type, including an HTTP-successful SERVFAIL response from the
bridge, has not been independently measured (IC-6, IC-D1, DEVIATIONS §2.4).

### 5.6 The bootstrap lookups are not protected

The transport must obtain addresses for relay and target hosts such as
`odoh-relay.numa.rs` and `odoh.hns.one`. The original description attributes
these bootstrap lookups to the runtime/OS resolver and says the same applies
to configured DoH endpoint hosts. The actual lookup path depends on the
injected fetch and its session/proxy configuration; IC-9 records this as a
question requiring runtime evidence.

An implementation **MUST NOT** claim that ODoH leaks nothing to the local
network. Bootstrap resolution can disclose the privacy services in use, even
when it does not disclose the site name being queried.

### 5.7 Private mode: the oblivious bridge, or nothing

`planDnsTransport({ privateMode })` replaces the configured DNS block with
`privateDns()` when Private is enabled:

```
privateDns(dns)  →  { ...dns, mode: 'secure', servers: [] }
```

The result is:

| Mode and bridge | Engine plan |
|---|---|
| Private, bridge running | `secure`; only the bridge template; `oblivious: true`, `plaintextFallback: false` |
| Private, bridge unavailable | `secure`; no servers; `configure: true`, `failClosed: true` |
| Fast | Use the configured DNS plan, including `off` when selected. |

Private overrides configured `off` and `automatic`. It does not use the plain
DoH pool. With no usable bridge—disabled ODoH, no relays, or a startup failure—
the plan refuses lookups and the panel reports a `failed` Domain name step
(§6.2). The limits of inferring a particular lookup from this plan are recorded
in [REVIEW.md](../../REVIEW.md).

The browser's `applyDnsPlan` runs before opening a window and on each
`DeliveryMode` change. It applies and records the new plan. Returning to a
Fast plan that configures nothing explicitly resets `secureDnsMode` to `off`
so the previous secure plan does not persist.

At launch, `wantsObliviousBridge()` is evaluated for both the configured plan
and its Private form. If either needs the bridge, the certificate is prepared
before engine startup and the bridge is started when permitted. A profile with
Fast DNS set to `off` can therefore still switch to Private.

The same delivery mode routes ICANN page fetches through device-local Tor in
Private and directly in Fast (Chapter 8; `DIVERGENCE.md` row 7). The bridge's
relay and configuration requests use the injected session fetch. Bootstrap
lookup behavior remains subject to §5.6. Mode changes do not upgrade DNS
authentication or the page's trust verdict.

`tests/dns-policy.test.js` covers Private with and without a bridge, replacement
of the configured pool, and unchanged Fast-mode planning.

## 6. Trust states, and what the lock shows

### 6.1 The steps

An ICANN page produces exactly two steps, in the four-state vocabulary of the
spine's §4 (`icannNameStep()` and `schemeSteps()`,
`../../src/trust-path.js`):

| Step | State | What it says |
|---|---|---|
| **Domain name** | `unverified`, or `failed` when the lookup was refused | how the address was looked up, and by whom |
| **Connection** | `unverified` for `https:`, `none` for `http:` | a certificate authority vouched, or nothing did |

**No step on this path is `verified`, and an implementation MUST NOT mark
one so under this trust model.** DNS data is accepted from the resolver, and
HTTPS authentication relies on the platform’s WebPKI trust anchors. The engine
still validates the certificate; `unverified` is this model’s category for
reliance on an external authority, not an absence of cryptographic checking.

### 6.2 What the Domain name step may say

**Evidence limit:** the implementation’s ten-minute, parent-name heuristic
does not establish which resolver answered the current navigation. This
conflicts with the event-specific wording below; see [REVIEW.md](../../REVIEW.md)
and DEVIATIONS §2.5. The reporting contract remains a decision for review.

The step is computed from two inputs and nothing else: **the recorded plan**
(§5.4) and whether the live bridge answered *this host*. It **MUST NOT** be
computed from the static configuration, which the bridge may have replaced.
Five mutually exclusive forms, in the order they are tested:

1. **Oblivious** — *"Oblivious DoH — relay `<relay>` → target `<target>`"*, when
   the bridge answered this name. The relay and the target **MUST** both be
   named. It **MUST** still say the answer is the resolver's word.
2. **Oblivious bridge configured, this name not answered by it** — the bridge
   is the only resolver the engine was given and has no record of this host, so
   the honest statement is that we cannot tell how it was resolved. The wording
   depends on the mode, because the possibilities do:
   - `automatic`: *"Resolver not determined — the oblivious bridge did not
     answer this name"*, and the detail says the engine falls back to
     unencrypted system DNS when the bridge fails, so **this lookup may have
     gone out in the clear**;
   - `secure`: *"Oblivious bridge only — this name was not answered by it"*,
     and the detail says unencrypted DNS is refused, so the answer most likely
     came from the engine's cache. It **MUST NOT** suggest plaintext, which
     that mode does not permit. This is the Private-mode wording (§5.7).
3. **Refused** — *"Secure DNS with no server — lookups refused"*, state
   `failed`, when the plan failed closed (§5.4). Reporting this as system DNS
   would describe the exact thing that did not happen. Private mode with no
   bridge lands here (§5.7).
4. **Plaintext** — *"System DNS, unencrypted"*, with the consequence in plain
   words: your router, your ISP and anyone on the path saw the name. This is
   also what is said when the caller has no plan to describe.
5. **Encrypted, not oblivious** — *"Encrypted DNS to `<resolver>` (+n more) —
   NOT oblivious"*. The phrase "NOT oblivious" is load-bearing and is pinned by
   a test in the Wildroot tree that scans every scheme's steps: any step whose
   text contains "oblivious" must also disclaim it unless it is form 1. The
   detail text states the mode's fallback behaviour explicitly.

The reporting requirement is:

> **Obliviousness is claimed for a name the bridge actually answered, never
> because the feature is switched on.**

`icannBridgeState()` returns a claim only when the bridge is running and
`servedRecently(host)` is true. It returns `null` for invalid bridge objects.
This is recent-lookup evidence, not a per-navigation resolver trace.

`servedRecently` matches an exact name or a *sub*domain of a name the bridge
answered, within a ten-minute window. The direction matters: matching the other
way round would let one lookup for `victim-chosen.example.com` vouch for
`example.com`, and even for `com`. We are not confident the ten minutes or the
subdomain rule are right — `../../DEVIATIONS.md` §2 on that window.

### 6.3 Aggregating to a lock

An `https:` ICANN page is **TRUSTED**, never **TRUSTLESS**, in the scheme of
the spine's §4.1. An implementation **MUST NOT** let an oblivious lookup
upgrade the verdict: obliviousness is a privacy property and the lock is an
integrity claim. A refused lookup (form 3) is a `failed` step, and the page
aggregates to `failed`.

An `http:` ICANN page is **OPEN**. `summarize()` checks for a `Connection`
step in state `none` before combining other weak steps. The model’s five
verdicts are `verified`, `partial`, `open`, `failed`, and `unknown`.

An implementation **MUST** apply the plaintext rule in the shared
aggregation model so the indicator and panel agree. It applies equally to a
Handshake site loaded over HTTP. Tor deliberately reports an `unverified`
connection because its HTTP page is inside an authenticated tunnel.

---

## 7. What an ICANN resolution does not get

The following Handshake mechanisms do not apply to ordinary ICANN navigation.

### 7.1 No DANE

The browser installs one session-wide certificate verification hook, and its
**first line defers to the platform's WebPKI for every host that is not a
Handshake host** (`src/index.js`). No TLSA record is queried for an
ICANN name and no pin is applied. `../../src/dane.js` is never reached on this
path.

This path has no local ICANN DNSSEC validation (§7.2), so the browser does
not apply its Handshake DANE mechanism to ICANN HTTPS. Whether to add a
validating ICANN path remains open (IC-3).

### 7.2 No DNSSEC

This path does not locally validate DNSSEC signatures or configure an ICANN
root trust anchor. It accepts the DNS answer from the selected resolver. The
engine separately validates WebPKI certificates for HTTPS (IC-4).

### 7.3 No SSRF guard

`../../src/safe-address.js` — which refuses loopback, RFC 1918 private,
link-local (including `169.254.169.254`), CGNAT, benchmarking, multicast and
reserved addresses — is applied on the Handshake path, on the HIP-5 `_op` path,
and in the WebSocket proxy. It is **not** applied to ICANN names, and cannot
be: the address never passes through our code. `http://localtest.me/` resolving
to `127.0.0.1` behaves exactly as it does in any other browser, subject to the
engine's own private-network protections and nothing of ours. IC-13.

The mechanically checkable form of §7.1 and §7.3 together is that
`rewriteToHns()` returns `null` for every ICANN host: an ICANN name never
enters the pipeline where either mechanism lives. That is asserted in
`tests/icann-boundary.test.js`.

### 7.4 No SVCB/HTTPS use, no DDR

The SVCB/HTTPS parser described in the spine's D-3 is not used here either, and
RFC 9462 Discovery of Designated Resolvers is not implemented: the resolver
list is configuration, never discovered. IC-11.

---

## 8. The one place we resolve an ICANN name ourselves

There is exactly one exception to "we do not resolve ICANN names", and it is
inside a **Handshake** resolution. Three points in a chain walk need the
address of a host whose name is ICANN's: the name of a nameserver the chain
delegated to, the name of a glue-less `NS` target, and the target of a `CNAME`
inside a Handshake zone.

That address comes from **one injected function**. The resolver takes a
`lookup` in its constructor and every one of the three call sites goes through
it (`../../src/resolver.js`, and the three uses at `:370`, `:417`, `:970`).
The browser supplies `DoHResolver.addressOf` (`../../src/doh.js`) — its
own DoH/ODoH client — in
**every** mode, so the lookup rides the same encrypted, and where configured
oblivious, transport as any other name this program resolves. There is no
plaintext lookup left on the chain path.

Integration requirements and limits:

- **The transport is the client's to choose, and the library's default is not
  the good one.** With no `lookup` supplied, `HNSResolver` falls back to the
  runtime's `dns.lookup()` — `getaddrinfo`, in the clear, outside the whole of
  §5. That default exists so the module runs as a library under plain `node`,
  and it means an integrator who takes this code and does not pass a `lookup`
  gets exactly the disclosure the browser's own composition avoids. An
  implementation **MUST** supply its own encrypted resolver here, and
  **SHOULD** make the omission visible rather than silent (IC-16).
- **This is not our oblivious path becoming a general resolver.** The lookup is
  an ICANN name, resolved the way §5 resolves ICANN names; it inherits §5's
  properties and §5's limits, including the bootstrap disclosure of §5.6.
- **The answer is checked against the question.** Every DoH and ODoH message
  the client parses goes through `assertAnswersTo(parsed, name, type)`
  (`../../src/doh.js`, and `../../src/dns-query.js` on the
  authoritative TCP path), which matters most over DoH, where RFC 8484 §4.1
  fixes the message id at zero and the question section is the only thing left
  to match on. The `dns.lookup()` default cannot be checked this way — it
  returns an address, not a message — which is a second reason to replace it.
- Its answer is **unvalidated**. Encrypted is not signed: an address obtained
  this way is the resolver's word, DNSSEC or not, and a `CNAME` to an ICANN
  host makes the Handshake answer unauthenticated from that point. The
  resolution says so, and the trust panel's step says so.
- Its answer **is** SSRF-guarded (`_nameserverFor` and the `CNAME` path,
  `../../src/resolver.js`), because that address is attacker-chosen in exactly
  the way §7.3's is not.

The Handshake chapter specifies this injected lookup; it is repeated here
because its target names belong to ICANN.

---

## 9. Security considerations

### 9.1 The boundary is the attack surface

- A newly delegated TLD missing from the snapshot can still select Handshake.
  The snapshot update process and release cadence therefore affect routing
  security (§2.4).
- Local service names need explicit exclusions before the Handshake default
  (§4).
- `.onion` and `.eth` must select their namespaces before the ICANN test,
  including malformed inputs (§2.2).
- Divergent classifier copies can route the same host differently. Shared
  modules and PAC behavior tests reduce that risk (§2.6).

### 9.2 Fail-open is the default, and it is a choice

Fast-mode `automatic` permits plaintext fallback if encrypted resolution is
unavailable. An attacker can try to trigger it by disrupting secure resolvers.
When the bridge replaces the pool, the configured DoH endpoints are not
available as intermediate fallbacks (§5.4).

`secure`, including Private mode, refuses plaintext. The precise engine
response to each DNS/HTTP failure remains unmeasured (§5.5); policy tests alone
do not establish that runtime behavior.

### 9.3 The any-host trust anchor

The engine's SPKI exception accepts the pinned key for any host. Generate
the bridge key in memory for each launch and never persist it (§5.3).

The certificate must be prepared before engine startup, while the listener
starts later. Both decisions **MUST** use the same `wantsObliviousBridge()`
predicate so an unused bridge does not receive a trusted key. A certificate
that differs from the startup pin causes bridge startup to fail.

### 9.4 Privacy

- A plain DoH resolver can associate names with the address connecting to it.
- ODoH separates the relay and target roles, subject to non-collusion and
  traffic-analysis limits. An implementation **MUST NOT** present it as an
  unconditional privacy guarantee. The original worldwide relay-count claim
  needs evidence (REVIEW.md).
- ODoH adds a relay round trip and configuration-fetch cost. The original
  approximate 200 ms figure has no benchmark context in this chapter.
- Bootstrap lookups may disclose which privacy services are used (§5.6).
- In Private, page and injected-fetch connections use Tor. The documentation
  should not simultaneously claim that these same connections go directly to
  relays; the outstanding bootstrap question is separate.
- DNS privacy alone does not hide later connections. Without ECH on a given
  TLS connection, its ClientHello exposes the server name to an observer on
  that connection. Chromium's ICANN HTTPS path must be assessed independently
  of the raw Handshake TLS transport.
