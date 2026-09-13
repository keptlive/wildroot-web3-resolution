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

This chapter is part of the integrated specification whose spine is
[`../../SPEC.md`](../../SPEC.md), where namespace selection — the rule that
decides which chapter a given host belongs to — is specified. Every deviation
from a cited standard, and every question we are unsure of, is in
[`../../DEVIATIONS.md`](../../DEVIATIONS.md) under the prefix `IC`. Every
standard cited is listed with its purpose in [`REFERENCES.md`](REFERENCES.md).
**Those files are part of this specification, not appendices to it.**

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

A browser that resolves Handshake names is still, overwhelmingly, a browser for
ordinary domains. The Handshake chapters of this specification describe an
elaborate machine — a chain proof, a DNSSEC validation anchored to an on-chain
DS, a DANE pin — and none of it applies to `example.com`. What applies to
`example.com` is: *decide it is not ours, hand it to the platform's resolver,
and be honest about what that means.*

Two things make that worth writing down rather than assuming.

**First, the boundary is the security-critical part of an alt-root browser.**
Everything a Handshake resolver can do wrong at the margin is less damaging
than getting the boundary wrong at the centre. A delegated ICANN top-level
domain classified as Handshake is a working site the browser declares does not
exist. A Handshake name classified as ICANN is a lookup handed to a resolver
that can never answer it — a failure *and* a disclosure. And a special-use name
classified as Handshake (`nas.local`, `printer.lan`) is the name of a machine
on the user's own network, sent to whoever registers the Handshake top-level
name `local`, who may then answer for it. The boundary is one data file, one
list of reserved labels, and about twenty lines of code, and this chapter is
mostly about those.

**Second, "hand it to the platform" is a policy, not an absence of one.** The
platform resolver's default is the user's router, in the clear. This
implementation configures encrypted DNS instead, and — by default — runs
ordinary web lookups through an Oblivious DoH relay so that no single party
sees both who is asking and what. That is a real mechanism with real failure
modes, and the interface makes claims about it. §5 specifies the mechanism and
§6 specifies exactly which claims are permitted.

The honest summary of this whole chapter: **an ICANN resolution in this browser
is ordinary DNS with the transport improved and the trust story stated.**
Nothing about it is verified on the user's computer, and **the browser cannot
observe which resolver answered any particular navigation** — the engine
resolves, and keeps its own cache. §6.2 and §6.3 say both as normative
requirements on the interface, because the temptation to let an oblivious
lookup, or a setting that asks for one, read as a stronger guarantee than it
is is exactly the temptation this project exists to resist.

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

A consequence worth stating plainly: **there is no ICANN resolver in this
package.** `namespaces/icann/src/` contains the boundary's data pipeline and
the transport *policy*; the resolution itself is somebody else's, by design.

---

## 2. The boundary: which names are ICANN's

### 2.1 The rule

> **ICANN first.** A host with two or more labels whose final label, expressed
> as an A-label and lowercased, is a delegated ICANN top-level domain **is** an
> ICANN domain, and **MUST** be resolved through the ordinary DNS.

This is rule 2 of the spine's namespace selection, and it is the whole rule. It
is decided by data — membership of one set — and not by code. The set is
`../../src/icann-tlds.cjs`; the classifier is `classifyHost()` in
`../../src/classify-host.cjs:87-116` — one implementation, loaded by the
router and by the address bar (browser: `src/hns/classify-host.cjs`).

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
| 7 | final label is all ASCII digits | `hns` — ICANN delegates no all-numeric TLD |
| 8 | final label ∈ the ICANN set | **`icann`** |
| 9 | otherwise | `hns` |

Rows 2 and 3 come before row 8 deliberately: a namespace with its own root of
trust must be able to *fail* without its name ever reaching a DNS resolver. For
`.onion` this is not politeness — the query itself is the deanonymising event.
Row 2 also precedes row 4 although `onion` is in the reserved list, so that a
`.onion` host is answered by the Tor namespace rather than by the platform.

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
  (`bareHost()`, `../../src/classify-host.cjs:55-64`);
- **converted to A-labels** — RFC 5890/5891. In this implementation the
  conversion is done by handing the host to the WHATWG URL host parser and
  reading `hostname` back (`asciiTld()`, `../../src/classify-host.cjs:68-76`),
  which is UTS-46 as the URL Standard defines it rather than IDNA2008. The
  bundled set holds IANA's published punycode, so `пример.рф` matches
  `xn--p1ai` and an emoji label matches nothing and is Handshake's. The
  divergence between UTS-46 and IDNA2008 is inherited from the spine's D-17 and
  restated here as IC-12, because on this path it can move a name **across the
  ICANN boundary**, which is a stronger consequence than it has on the
  Handshake path.

If the URL parser throws — which it does for a host whose last label is all
digits, by the "ends in a number" rule (spine §5.1) — the raw final label is
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

The second grows over time: ICANN's 2026 round drew roughly 1,600
applications, and each delegation converts a string that resolves as a
Handshake name today into an ICANN TLD.

### 2.5 A single bare label is never ICANN

A host with one label is not classified by row 8 at all — `classifyHost`
returns `null` and the caller decides. In `classify()`, the ICANN set is
consulted a second time and used **in reverse**: a bare `com`, `org` or `app`
is a word somebody is part-way through typing and becomes a **search**; any
other bare label (`hnshosting`, `14898`, `🤝`) is a Handshake name
(`../../src/router.js:383-409`). An implementation **MUST NOT** turn a bare
label into an ICANN lookup: there is no such name.

The same reversal is what makes whitespace safe. `classifyHost` returns `null`
for a host containing whitespace as well as for a bare label, so the bare-label
rule excludes whitespace explicitly; without that, every multi-word search
would become a Handshake lookup.

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

The rule itself is `../../src/classify-host.cjs`, written in CommonJS precisely
so that the ES-module router and the CommonJS address bar can load the same
bytes rather than each carrying a copy. The two lists it consults are
`../../src/icann-tlds.cjs` and `../../src/reserved-names.cjs`, for the same
reason.

The one exception is the PAC script, which is a string evaluated inside the
engine's network stack: it has no module loader and no URL parser, so it cannot
call the shared rule and carries an ASCII-only form of it, held to the shared
answer by a test that evaluates the generated script
([Part II's `DEVIATIONS.md`](../router/DEVIATIONS.md) `RT-7`). A rule
kept in two places is a rule that disagrees with itself, and on this boundary
the disagreement is a disclosure.

`rewriteToHns()` (`src/hns/hns-host.js:85-98`) returns `null` for every ICANN
host, which is the mechanically checkable form of §7: an ICANN name never
enters the Handshake pipeline, and so never meets DANE or the SSRF guard.

---

## 3. Collisions: a label that is both

A label can exist in both roots. A string can be a delegated ICANN TLD and,
simultaneously, a registered Handshake top-level name whose owner has published
records for it.

> **The ICANN answer wins.** Membership of the snapshot is decided first and
> is final. There is no per-name preference, no negotiation, and no prompt.

This is a deliberate deviation from Handshake's own model, in which ICANN
labels are reserved and claimable by their ICANN holder with a DNSSEC proof,
and a claimed one would make the chain authoritative. We route to ICANN anyway.
The reason is not that Handshake's model is wrong; it is that this rule is what
makes the browser safe to use as somebody's **only** browser. A user who cannot
reach their bank because a chain name shadowed it has been harmed by our
alt-root, and no amount of correctness in the alt-root repairs that. IC-2; the
spine's D-16 states the same decision from the Handshake side.

A reserved name (§4) outranks both roots. If one of those labels were ever
delegated, this browser would still route it to the platform.

**The escape hatch is the scheme, and only the scheme.** An explicit
`hns://example.com/` is routed to the Handshake handler and resolved on the
chain, because law **L1** says an explicit scheme selects the protocol and is
never re-sniffed. Nothing in the Handshake handler refuses an ICANN label. So
the collision policy is: *ICANN by default, Handshake on request, never
silently.* An implementation **MUST NOT** make the reverse move — an
unqualified name **MUST NOT** be resolved on the chain because ICANN failed.

**Every other alt-root is Handshake's.** `.crypto`, `.sol`, `.bnb`, `.nft` and
anything else that is neither delegated by IANA, nor reserved by §4, nor one of
the two namespaces matched at rows 2–3 goes to whoever holds the Handshake
top-level name of that string. `brad.crypto` resolves against the Handshake
`crypto` owner's records, not against Unstoppable's registry. That is the
consistent application of §2.1 rather than a separate policy, and other
implementers may reasonably differ.

---

## 4. Special-use names

A host whose final label is reserved by RFC 6761 (`localhost`, `invalid`,
`test`, `example`), RFC 6762 (`local`), RFC 7686 (`onion`), or RFC 8375 and
adjacent practice (`arpa`, `internal`, `home`, `lan`, `corp`, `intranet`,
`private`) **MUST** be routed to the mechanism that owns it and **MUST NOT** be
sent to a Handshake resolver.

This matters more on the ICANN boundary than anywhere else, because **none of
these labels is in the ICANN set**. Without an explicit carve-out, rule §2.1's
"otherwise, Handshake" catches every one of them: `nas.local`, `printer.lan`,
`gitlab.internal` and `app.localhost` all become Handshake lookups. That breaks
reaching your own devices *and* sends their names to whoever registers the
Handshake top-level name `local`, who can then answer for them.

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

Left alone, every ICANN lookup goes to the local router in the clear. An
implementation **SHOULD** configure encrypted DNS instead. Ours does, at
startup, via the engine's own secure-DNS facility
(`app.configureHostResolver({ secureDnsMode, secureDnsServers })`,
`src/index.js:500`). The engine speaks **RFC 8484 wire-format DoH over HTTPS
templates** and nothing else — no DoT (RFC 7858/8310), no DNS-over-QUIC, and no
ODoH. That constraint is the reason §5.3 exists.

The decision of *what* to tell it is made once, in one place
(`planDnsTransport()`, `src/dns-policy.js`), and the result is **recorded**
(`recordDnsPlan()`). §6 requires the interface to describe that record and
nothing else.

### 5.2 `dns.mode`

Exactly three values (`src/config.js:348-357`):

| `dns.mode` | Meaning | Plaintext possible? |
|---|---|---|
| `off` | no configuration is applied; the platform resolver's default is used | always |
| `automatic` *(default)* | encrypted DNS to the configured servers, **falling back to unencrypted system DNS when none answer** | yes, on failure |
| `secure` | encrypted DNS only; unencrypted DNS is refused | no |

Normalisation is specified, and an implementation **SHOULD** copy it
(`normalizeDnsMode()`, `src/dns-policy.js`):

- **Case and surrounding whitespace are forgiven.** `'Off '` means `off`. A
  configuration file is written by a person, and reading their `'Off'` as
  `automatic` would turn encryption *on*, with a plaintext fallback, for
  somebody who was trying to turn it off.
- **A value that is not a mode is reported**, through a callback the caller
  turns into a warning, and then becomes `automatic`. An absent or empty value
  is the documented default and is *not* reported: a warning that fires for
  every default configuration is a warning nobody reads.

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
  (`../../src/odoh-bridge.js:65`, `:119`).
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

**Binding a reply to its question.** RFC 9230's encryption authenticates the
*bytes* that passed between this process and the target: HPKE says that
whoever holds the target's public key sealed this response in this query's
context, and says nothing whatever about what the plaintext means as DNS. An
empty body, a truncated message and a perfectly well-formed answer to a
*different* question all decrypt equally well. So:

> **An ODoH reply MUST be bound to the question it answers before it is
> treated as an answer**, and a reply that is not so bound **MUST** be handled
> as a failure rather than as evidence that the name was answered.

The bridge parses the DNS envelope of the query on the way in and of the reply
on the way back (`dnsEnvelope()`, `../../src/odoh-bridge.js:253-306`;
`_handle()`, `:135-156`) and requires, of both unless a bullet says otherwise:

- **exactly one question** (RFC 1035 §4.1.2), and a **fully framed** packet —
  every record's name, type, class, TTL and RDLENGTH accounted for, ending
  exactly at the end of the message, with **no trailing bytes**;
- **a name that can be read at all**: RFC 1035 §4.1.4 compression pointers are
  followed, but an offset already visited is a **loop** and is refused, and a
  name over the **255-octet** limit is refused. A parser that can be made to
  spin or to read past the buffer is a denial of service inside the component
  the whole of §5 depends on;
- of a query, **a standard query**: the QR bit clear and the opcode `QUERY`
  (RFC 1035 §4.1.1; the test is `flags & 0xf800`), so a response, or an opcode
  the bridge does not carry, is refused at the door rather than forwarded;
- of a reply, **QR set**, **TC clear** and the reserved header bits clear (RFC
  1035 §4.1.1) — a truncated answer is not an answer;
- of a reply, **the query's id**, and the query's **question name, type and
  class**. The name is compared as case-folded ASCII label **bytes**, because
  DNS case-insensitivity is ASCII-only (RFC 4343): comparing decoded text
  would let a decoding step make two distinct names equal.

A query the bridge cannot parse this way is refused with 400 and never
forwarded. A reply that fails the binding is SERVFAIL to the engine, exactly
as a transport failure is, **and is recorded as a failed exchange for that
name** so that an earlier success cannot stay current for a host whose most
recent lookup did not succeed (§6.2).

The ODoH exchange itself is the one specified in the spine's §9.2 and
implemented in `../../src/odoh.js`: RFC 9230 message format, RFC 9180 HPKE
(X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM), RFC 5869 HKDF for the §6.3
response key and nonce. Relays are tried in order; a 401 from the target means
the cached configuration is stale and it is refetched once.

The target's ODoHConfig is fetched **directly from the target**, over ordinary
HTTPS, at `/.well-known/odohconfigs`, and cached for one hour. Fetching it
through the relay would add nothing: the configuration is public and
authenticated by the target's own TLS, and a relay that tampered with it would
simply break every subsequent decryption. Two honest notes: the direct fetch
means the target learns the client's IP address once per hour, unlinked to any
query; and we believe `/.well-known/odohconfigs` is deployed convention rather
than an IANA-registered well-known URI (IC-8, and `../../DEVIATIONS.md` §2 on
whether that URI is registered — we would like to be corrected).

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

Two of those need stating in prose.

> **When the bridge starts, its loopback template replaces the configured
> resolver pool. It does not join it.** (IC-7.)

Consequences:

- If the bridge **fails to start**, the pool remains: the engine is configured
  for encrypted, not oblivious, DNS. The implementation logs exactly that, and
  the interface names the configuration as configuration (§6.2 form 5).
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
> configured for secure mode with an **empty** server list — asking it to
> refuse new lookups — rather than left on its default, which resolves in the
> clear.

A setting that says "never plaintext" must not silently mean nothing. A
profile that asks for `secure` with an empty `dns.servers`, or whose bridge
failed to start with `dns.servers` unset, is therefore configured exactly so —
the implementation logs it, and the interface reports **the configuration**:
secure DNS configured to refuse new lookups, rather than system DNS (§6.2). An
implementation **MUST NOT** treat that configuration as a no-op. Private mode
with no bridge is this case by construction (§5.7).

What the engine then *does* is the engine's, and is not observed from here.
`failClosed` is a fact about the arguments `app.configureHostResolver` was
given, not a measurement of a lookup that was turned away: a page may still
load from the engine's cache. §6.2 form 3 is written for what is known, and an
implementation **MUST NOT** report a refusal it did not watch happen.

Nothing is configured in two other cases, and neither is a contradiction:
`mode: 'off'`, which asks for exactly that, and `automatic` with no resolver to
point at, which asks to resolve the way the platform would. Both report
`plaintextFallback`, and the interface says so.

### 5.5 Captive portals

`automatic` exists for captive portals and hotel Wi-Fi, which intercept DNS and
would otherwise make the network unusable. This is a genuine
availability-versus-privacy trade and it is resolved in favour of availability
by default, in Fast mode (IC-6). Private mode has no such fallback (§5.7): behind
a portal that intercepts DNS, no ICANN name resolves in Private until the portal
is passed in Fast. An implementation **MUST** state which mode was in force and
**MUST NOT** describe `automatic` as private without the qualification: an
attacker who can make the configured resolvers unreachable can force every
lookup into the clear, and in the bridged case (§5.4) that is one relay outage
away.

We have **not** independently measured what the engine does on each failure
kind — a transport failure, a SERVFAIL, a timeout — and `../../DEVIATIONS.md`
§2 records that as an open question rather than asserting a behaviour we have
not tested. IC-D1 is blocked on the same measurement.

### 5.6 The bootstrap lookups are not protected

The bridge, and the ODoH transport under it, must themselves resolve the relay
and target hostnames (`odoh-relay.numa.rs`, `odoh.hns.one`) and open ordinary
HTTPS connections to them. Those lookups are made by the runtime's own resolver
— the OS resolver — not by the engine's configured secure DNS and not by the
bridge. The same is true of the DoH pool's own hostnames in the non-bridged
case.

So the first lookups of a session, and every configuration refresh, disclose
*which privacy infrastructure this browser uses* to the local network in the
clear. They do not disclose which sites the user visits. An implementation
**MUST NOT** present the oblivious path as leaking nothing to the local
network. IC-9.

### 5.7 Private mode: the oblivious bridge, or nothing

The Fast / Private switch of `../../SPEC.md` §4.2 reaches this chapter through
one argument: `planDnsTransport({ privateMode })`. When it is true the `dns`
block is replaced by `privateDns()` **before anything else reads it**, so every
fact of §5.4 is computed for the configuration the engine is actually given:

```
privateDns(dns)  →  { ...dns, mode: 'secure', servers: [] }
```

- **`secure`, whatever was configured.** `off` and `automatic` are both
  overridden. Nothing plaintext, ever: a name the bridge cannot answer does not
  resolve.
- **The configured pool is dropped.** An encrypted-but-not-oblivious resolver
  still learns every name and the address asking, which is the disclosure the
  mode exists to refuse; so the pool is not a fallback and is not in the list.
  With the bridge up, `servers` is the bridge's template and nothing else
  (`oblivious: true`, `plaintextFallback: false`, `failClosed: false`).
- **No bridge: fail closed.** With the bridge not running — no relays
  configured, `odoh.enabled` or `odoh.icann` false, a start failure — the plan
  is `secure` with an **empty** list (`configure: true`, `failClosed: true`),
  and the engine is configured exactly so. The Domain name step is form 3 of
  §6.2: *secure DNS configured to refuse new lookups*, state `unverified`,
  never *"system DNS"* and never a refusal reported as observed. New lookups
  have nowhere to go until the bridge is up or the mode is Fast; the log says
  which.
- **Fast is the configured plan, untouched.** `planDnsTransport({ privateMode:
  false })` is identical to the call without the argument, including
  `mode: 'off'` configuring nothing.

**Applied on every switch.** The composition (the browser's `src/index.js`,
`applyDnsPlan`) computes the plan for the stored mode at launch, before any
window exists, and recomputes it on every `change` the `DeliveryMode`
controller emits — calling `app.configureHostResolver` with the new `mode` and
`servers` and recording the plan (`recordDnsPlan`), so the panel describes what
the engine was told for *this* mode. A return to a plan that configures nothing
(`dns.mode: off`, in Fast) puts the engine back on its default explicitly
(`secureDnsMode: 'off'`) rather than leaving the last secure plan in force.
Because `DeliveryMode` flips the mode before it routes the session and routes
off before it flips back (`../../src/delivery-mode.js`), the plan is never less
strict than the session is.

**The bridge is started for either mode.** `wantsObliviousBridge()` is asked
twice at launch — for the configured block and for `privateDns()` of it — and
the bridge (and, before the engine is ready, its pinned certificate, §9.3) is
started if **either** wants it. A profile whose `dns.mode` is `off` therefore
still has a bridge to switch to: idle in Fast, the only server in Private.

**Row 7.** The same switch drives the session proxy: in Private every ICANN page
fetch rides the device-local Tor, in Fast none does (Chapter 8 §7.5–§7.6,
`../../DIVERGENCE.md` row 7). The name lookup and the page fetch are therefore
private together or fast together; there is no setting in which one is protected
and the other is not.

**What the mode does, and does not, do to the bridge's own egress.** The
bridge's connections to the relay and the target ride the session's proxied
fetch (`OdohTransport({ fetchImpl })` — the composition injects it exactly as
the Handshake handler's transport receives it), so in Private they leave
through Tor and while BLOCKED the blackhole stops them. The bootstrap *name*
lookups of §5.6 are the runtime's, in both modes (IC-9). And the mode does not
change a verdict: an ICANN page is TRUSTED in both modes (§6.3).

`tests/dns-policy.test.js` pins the plan: *"privateDns: secure, and no pool,
whatever the configured block said"*, *"Private with the bridge up: oblivious
only, nothing plaintext, never a pool server"*, *"Private with NO bridge
configures secure with an empty list, and the panel names the configuration"*,
and *"Fast is the configured plan, untouched"*.

---

## 6. Trust states, and what the lock shows

### 6.1 The steps

An ICANN page produces exactly two steps, in the four-state vocabulary of the
spine's §4 (`icannNameStep()` and `schemeSteps()`,
`../../src/trust-path.js:261-503`):

| Step | State | What it says |
|---|---|---|
| **Domain name** | `unverified`, always | what the engine was configured to do, and what the oblivious bridge has a record of answering |
| **Connection** | `unverified` for `https:`, `none` for `http:` | a certificate authority vouched, or nothing did |

**No step on this path is ever `verified`, and an implementation MUST NOT make
one so.** Nothing here is checked on the user's computer: not the address, not
the binding of the name to it, and not the certificate — a CA is believed, and
so is every other CA the platform trusts.

**No step on this path is ever `failed` either.** `failed` is a report of an
event: something was attempted and did not succeed. Nothing on this path
attempts anything we can watch — the engine resolves, out of its own cache
when it has one — so there is no failure here to report. A configuration that
refuses new lookups is a configuration, and §6.2 form 3 says so in those
words.

### 6.2 What the Domain name step may say

Two facts are available to this step and no others: **the recorded plan**
(§5.4) — what the engine was told — and **the bridge's own record** of the
exact hosts it has answered, with the route that answered each. The step
**MUST** be computed from those two and **MUST NOT** be computed from the
static configuration, which the bridge may have replaced.

A third fact is **not** available and its absence governs everything below:

> **Which resolver answered a given navigation is not observable from here.**
> The engine resolves ICANN names, keeps its own cache, and reports neither.
> An implementation **MUST NOT** state, as a property of *this page*, which
> transport carried its lookup — including that the lookup happened at all.

So the step describes the *configuration* in the language of configuration, and
the *bridge record* in the language of recorded activity, and never lets either
become a claim about this navigation. Five mutually exclusive forms, in the
order they are tested:

1. **Recent oblivious activity** — *"Recent Oblivious DoH lookup — relay
   `<relay>` → target `<target>`"*, when the bridge holds exact-host evidence
   for this host (below). The relay and the target **MUST** both be named, and
   **MUST** be the pair that answered rather than the first configured pair.
   The detail **MUST** say that this is evidence of recent lookup activity and
   **not proof that this page used that answer**, and **MUST** still say the
   answer is the resolver's word. The step re-checks what it was handed — that
   the evidence is of kind `recent-lookup`, that its host **is this host**, and
   that both endpoints are named (`../../src/trust-path.js:462`) — and falls
   through to form 2 if any of that fails. A panel does not take its caller's
   word for what its caller's evidence is about.
2. **Oblivious bridge configured, no evidence for this host** — the bridge is
   the only resolver the engine was given and has no record of this host. What
   answered instead — the engine's cache, or, in `automatic`, the fallback the
   mode permits — is not visible, and the step says so: *"no recent successful
   bridge lookup recorded for `<host>` … this panel cannot establish the
   lookup path"*. The mode is named for what it *permits*, never for what it
   did:
   - `automatic`: *"Resolver not determined — no recent oblivious lookup
     evidence"*, and the detail says automatic DNS permits system fallback
     **and that this does not show that fallback occurred**;
   - `secure`: *"Oblivious bridge configured — no recent lookup evidence"*, and
     the detail says secure DNS is configured to refuse unencrypted fallback.
     It **MUST NOT** suggest plaintext, which that configuration does not
     permit. This is the Private-mode wording (§5.7).
3. **Configured to refuse new lookups** — *"Secure DNS configured to refuse new
   lookups"*, state `unverified`, when the plan failed closed (§5.4). It
   **MUST** say that this is the configured policy and **not an observed
   lookup failure**, and that cached answers may still exist. Reporting it as
   system DNS would describe the opposite of what was asked for; reporting it
   as a `failed` step would report an event nobody watched. Private mode with
   no bridge lands here (§5.7).
4. **Nothing configured** — *"DNS lookup path not observed"*, when the mode is
   `off` or there is no resolver list. The engine keeps its own default; what
   that default did for this page — the operating system's resolver, whatever
   encryption it may have, or the cache — is not observed here, and the step
   says that rather than asserting a plaintext lookup. This is also what is
   said when the caller has no plan to describe.
5. **A configured resolver list, not oblivious** — *"Secure DNS configured:
   `<resolver>` (+n more) — NOT oblivious"*. The detail **MUST** say that this
   names the **configured** list and not an endpoint observed serving this
   page. The phrase "NOT oblivious" is load-bearing and is pinned by a test in
   the Wildroot tree that scans every scheme's steps: any step whose text
   contains "oblivious" must also disclaim it unless it is form 1. The detail
   states what the mode permits on failure.

The governing rule, and the one sentence of this chapter most worth copying:

> **Obliviousness is claimed for the exact name the bridge answered, with the
> route that answered it, never because the feature is switched on and never
> for a name nobody looked up.**

`icannBridgeState()` (`src/dns-policy.js:133-139`) requires a host, returns the
bridge's `recentEvidence(host)` and nothing else, and returns `null` rather
than throwing for any object that misbehaves. `recentEvidence()`
(`../../src/odoh-bridge.js:188-198`) returns `{host, queryType, relay, target,
rcode, at, withinMs, evidence: 'recent-lookup'}` or `null`, under four rules an
implementation **SHOULD** copy:

- **Exact host only.** A lookup for `example.com` does not vouch for
  `a.example.com`, and one for `a.example.com` does not vouch for
  `example.com` or for `com`. Matching either way lets one lookup speak for
  names nobody asked about — in the second direction, for a name an attacker
  chooses.
- **Only an answer or a denial counts.** `rcode` **MUST** be NOERROR (0) or
  NXDOMAIN (3). A SERVFAIL exchange resolved nothing, so it is not evidence
  that anything was resolved — and, because a failure is recorded too, it
  *removes* an earlier success for that host rather than leaving it current.
- **The route recorded is the route that answered.** The relay and target come
  back from the exchange, not from the head of the configured lists. Form 1
  is shown only when both are present.
- **Order is by sequence, not by clock.** Entries are keyed by host and query
  type and carry a monotonic sequence number, so a slow older query completing
  late cannot overwrite a newer result.

Within a ten-minute window. That window is a guess, and what the record means
is narrower than what a reader may want it to mean:
`../../DEVIATIONS.md` IC-18 and §2.5.

### 6.3 Aggregating to a lock

An `https:` ICANN page is **TRUSTED**, never **TRUSTLESS**, in the scheme of
the spine's §4.1. An implementation **MUST NOT** let an oblivious lookup
upgrade the verdict: obliviousness is a privacy property and the lock is an
integrity claim.

Nor may a *configuration* lower it. Every form of §6.2 is `unverified`, so a
fail-closed plan (form 3) aggregates to the same `partial` verdict as any
other ICANN page. A page that loaded — from the engine's cache, or because the
configuration is not what we think it is — must not be shown a broken lock on
the strength of a setting. `summarize()` reaches a `failed` verdict only from a
`failed` step, and this path produces none (§6.1).

An `http:` ICANN page is **OPEN**, and that is a verdict of the aggregation
itself, not of a renderer. `summarize()` tests for a `Connection` step in state
`none` *before* it collapses `none` and `unverified` together as "weak", and
returns `{ state: 'open' }` — one of five verdicts: `verified`, `partial`,
`open`, `failed`, `unknown`. So the padlock and the security panel behind it
read the same verdict for a plaintext page instead of deriving it twice.

An implementation **MUST** put the plaintext rule in the aggregation. Deriving
it beside the indicator instead leaves the model saying that an `http:` page
and an `https:` page have the same standing, and every other consumer of the
model — a panel, an extension API, a log line — inherits that claim. This is
also the reason the rule is stated as a `Connection` step of `none` rather than
as "the scheme is http": an `hns://` name that resolves to an address with no
TLSA pin and is loaded over plain HTTP reaches the same verdict by the same
test, and a Tor onion service, whose page is plain HTTP *inside* an
authenticated tunnel, deliberately reports `unverified` and does not.

### 6.4 The route view answers a different question, and for an ICANN name it cannot

Beside the lock there is a second view, over the same page: not *what was
verified* but **who saw this request**. Its vocabulary is a route per hop —
`local`, `oblivious`, `tor`, `direct`, `refused`, and `unknown`
(`../../src/route-path.js:28`).

For an ICANN name the name-lookup hop is **`unknown`, in every branch**
(`icannNameHop()`, `../../src/route-path.js:234-248`), and an implementation
**MUST NOT** report any other value for it. Both of the alternatives are
measurements nobody made: `direct` asserts that a named party was shown this
computer's address together with this name, and `oblivious` asserts that no
single party saw both. §6.2's third fact — the engine resolves, and does not
say how — makes each of those unavailable.

Two consequences an implementation **MUST** carry through:

- Even with exact-host evidence the hop stays `unknown` and is labelled as
  **recent activity** — *"Recent ODoH activity — relay `<relay>` → target
  `<target>`"*, with the detail saying in as many words that this records a
  lookup and **not the DNS route or cache used by this page**. Form 1 of §6.2
  is the strongest statement available, and it is a statement about the
  bridge, not about this navigation.
- The summary **MUST** lead with the gap. `summarizeRoute()`
  (`../../src/route-path.js:255-274`) tests for an `unknown` hop **before** it
  counts the `direct` ones and says *"Some route details were not recorded;
  this view cannot establish every party that saw this page request."* A count
  of the hops that are known, printed first, reads as a complete accounting of
  a request that was not completely accounted for.

---

## 7. What an ICANN resolution does not get

Stated as requirements because each is a claim an implementer might otherwise
assume in our favour.

### 7.1 No DANE

The browser installs one session-wide certificate verification hook, and its
**first line defers to the platform's WebPKI for every host that is not a
Handshake host** (`src/index.js:1330-1331`). No TLSA record is queried for an
ICANN name and no pin is applied. `../../src/dane.js` is never reached on this
path.

This is deliberate. DANE-for-HTTPS in the ICANN world requires validated
DNSSEC, which §7.2 says we do not have here; a pin taken on a resolver's word
against a name a CA already vouches for adds an availability failure mode and
no security. IC-3, and `../../DEVIATIONS.md` §2 records that we are not certain
it is more than an excuse.

### 7.2 No DNSSEC

Nothing on this path validates a signature. The engine's resolver does not, and
neither do we. An ICANN answer is *the resolver's word*, which is precisely
what the Domain name step says. The spine's entire DNSSEC apparatus is anchored
to an on-chain DS and has no counterpart here — the ICANN root's trust anchor
is not configured anywhere in this browser. IC-4.

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
it (`../../src/resolver.js:226`, and the three uses at `:370`, `:417`, `:970`).
The browser supplies `DoHResolver.addressOf` (`../../src/doh.js:222`) — its
own DoH/ODoH client — in
**every** mode, so the lookup rides the same encrypted, and where configured
oblivious, transport as any other name this program resolves. There is no
plaintext lookup left on the chain path.

Five properties of that path, all of which an implementation should know:

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
  (`../../src/doh.js:71`, and `../../src/dns-query.js:342-400` on the
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

This is a Handshake-side property with an ICANN-side consequence, which is why
it is recorded in both chapters.

---

## 9. Security considerations

### 9.1 The boundary is the attack surface

Every interesting attack in this chapter is a misclassification.

- **A stale snapshot is a live vulnerability**, in the direction that grows.
  As ICANN delegates new TLDs, strings that were Handshake's become ICANN's; a
  browser running an old snapshot keeps sending those names to a Handshake
  resolver, and whoever registered the corresponding Handshake top-level name
  answers for a domain they do not own. The mitigation is the drift alarm
  (§2.4), and it is only as good as the release cadence.
- **A special-use name sent to an alt-root is a LAN disclosure**, and the
  disclosure is the attack: `nas.local` handed to the holder of the Handshake
  name `local` tells them a machine exists and lets them answer for it. §4.
- **A namespace matched after ICANN would be a namespace that can leak.** This
  is why `.onion` and `.eth` are matched first and unconditionally, malformed
  or not.
- **A list held twice is a list that disagrees**, and the path that has the
  older copy is the path that leaks. §2.6.

### 9.2 Fail-open is the default, and it is a choice

`automatic` mode, the plaintext fallback, and the bridge's SERVFAIL-then-defer
policy all resolve availability-versus-privacy in favour of availability. An
attacker who can make the configured resolvers unreachable can therefore force
every ICANN lookup into the clear, and — because the bridge replaces the pool
rather than joining it (§5.4) — needs only to reach the relays to do it.

This is not hidden: `secure` mode exists, it refuses plaintext even when that
means resolving nothing at all, and it is documented in the settings page in
the user's own words. What the interface can add is narrower than it looks —
the plan the engine was given, and the exact hosts the bridge has a record of
answering, neither of which is the path this page's lookup took (§6.2). But
the default is fail-open and an implementation copying this design should copy
that sentence too.

### 9.3 The any-host trust anchor

Pinning the bridge's SPKI into the engine makes the engine accept that public
key for **every** host, not only for `127.0.0.1`. That is why the key is
generated in memory per launch and never written to disk: there is nothing to
steal after the process exits, and the anchor dies with it.

The certificate has to be minted *before* the engine is ready, because the
command-line switch that carries the pin is read once at startup, while the
bridge itself can only be started later. Those are two moments, and they
**MUST** ask one question. `wantsObliviousBridge(config)` is that question, and
both call sites call it (`src/index.js:259-260`, `:461`): a key the engine
trusts for every host is never minted for a bridge that will not run. A bridge
whose certificate does not match the pin the engine was given is treated as
fatal to the bridge rather than silently falling back to an untrusted endpoint,
which would fail every lookup instead.

### 9.4 Privacy

- **Without the bridge**, a resolver that answers directly sees the user's
  address and the name together. The Domain name step says that about direct
  DoH as a property of the transport, and names the configured list as
  configuration — not as the endpoint observed serving this page (§6.2 form
  5).
- **With the bridge**, no single party sees both — subject to the same
  caveat the spine's §9.2 makes and this chapter inherits: **two ODoH relays
  exist worldwide and one is run by a target operator**, so RFC 9230's
  non-collusion assumption does not hold at that scale. The code is worth
  having; the claim is not. An implementation **MUST NOT** present ODoH as a
  privacy guarantee at current deployment scale.
- **The relay hop costs latency** — around 200 ms warm, more on a cold
  configuration fetch — on every cache miss, for every site. That is a trade a
  user should get to make, which is why it is a configuration key. It is
  editable only in the configuration file (IC-15).
- **The bootstrap lookups leak which privacy infrastructure is in use** (§5.6).
- **In Private mode** (§5.7) the bridge is the only resolver the engine is
  given and every page fetch rides Tor, so on the engine's side of the
  configuration the network has a connection to the relay and a connection to
  Tor and no name; the bridge's own connections to the relay and the target
  ride the same proxied fetch. What the engine does with a name it has already
  cached is not part of that, and is not observed here (§6.2). The exception is
  the bootstrap name lookups, which are made by the runtime directly in both
  modes (IC-9).
- **Without ECH** (spine D-3) the server name is in the ClientHello regardless,
  so an oblivious DNS lookup does not by itself hide which site was visited
  from an on-path observer.
