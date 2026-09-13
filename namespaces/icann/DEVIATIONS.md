# Chapter 2 — ICANN names: deviations and open questions

Every place this chapter's implementation departs from a standard it cites,
from common browser practice, or from its own stated design — plus every place
we are not sure we have made the right call, and every change we intend to make
and have not.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

Entries are numbered `IC-n`, and the open design items `IC-Dn`, to keep them
distinct from the spine's `D-n` and from the other chapters'. Every reference in
[`SPEC.md`](SPEC.md) uses those numbers.

Three path conventions are used. `../../src/…` is a module in this
repository's shared `src/`. A bare `src/dns-policy.js` or
`src/icann-tld-snapshot.js` is this chapter's own `namespaces/icann/src/`.
Every other `src/…` is in the Wildroot browser tree; those are given with line
numbers so a claim can be checked against the code that makes it.

---

## 1. Deviations

### IC-1. The ICANN boundary is a build-time snapshot, not a live lookup
*IANA root zone database · `../../src/icann-tlds.cjs`, `src/icann-tld-snapshot.js`*

**What.** The set of delegated ICANN top-level domains is fetched from IANA at
build time, rendered into a committed source file, and shipped. Nothing fetches
it at runtime. The snapshot is IANA version 2026090500 (5 September 2026),
1,438 labels.

**The standard says.** IANA publishes the root zone database and its
machine-readable form (`https://data.iana.org/TLD/tlds-alpha-by-domain.txt`) as
the authoritative list of delegated top-level domains. It is a live registry;
nothing about it is versioned for offline use.

**Why.** A privacy browser does not phone home at startup, and the classifier
has to answer a keystroke without waiting for the network. The same reasoning
governs the ad-filter lists.

**Consequence.** The boundary is only as fresh as the last release, and drift
misroutes names in both directions (SPEC §2.4). The direction that grows is
*missing* delegations: ICANN's 2026 round drew roughly 1,600 applications, and
each delegation turns a string that resolves as a Handshake name today into an
ICANN TLD — so a browser running an old snapshot keeps handing that domain to a
Handshake resolver, where whoever registered the corresponding chain name can
answer for it. A live drift alarm compares the snapshot against IANA on every
networked test run and reports both directions
(`tests/hns/icann-tlds-live.test.js`); it is deliberately an alarm and never a
build gate, because a red build caused by IANA being unreachable teaches
everyone to ignore the alarm. `tests/icann-tld-snapshot.test.js` here adds the
offline half: the committed file is byte-for-byte what the generator produces,
so a hand-edited boundary fails a test that needs no network.

**Status: OPEN.** The bundling itself we would defend and do not intend to
change. What is open is the cadence: nothing forces a refresh before a release
and nothing measures how stale a shipped snapshot was. We recommend a
release-blocking check on the snapshot's age — the `Version` line is a
`YYYYMMDDNN` integer, so "older than N days" is a one-line offline assertion —
together with the offline half of the alarm living in the browser tree (IC-D4).
What N should be is §2.4.

---

### IC-2. ICANN wins a label that is also a Handshake TLD, and every other alt-root is Handshake's
*`../../src/classify-host.cjs:87-116`*

**What.** Two rules, one decision procedure. A dotted name whose final label is
in the IANA snapshot is an ICANN domain, even if the same string is a
registered Handshake top-level name with published records. Any other
non-`.eth`, non-`.onion`, non-reserved label is a Handshake name — including
`.crypto`, `.sol`, `.bnb` and `.nft`, which go to whoever holds the Handshake
name of that string rather than to that alt-root's own registry.

**The standard says.** Handshake's own model reserves the ICANN labels and lets
their ICANN holder claim them with a DNSSEC proof; a claimed name makes the
chain authoritative for it. Following that model would mean consulting the
chain first for a colliding label.

**Why.** This rule is what makes the browser safe to use as somebody's *only*
browser. A user who cannot reach their bank because a chain name shadowed it
has been harmed by our alt-root, and no amount of correctness in the alt-root
repairs that.

**Consequence.** A Handshake registrant of an ICANN string cannot serve that
name to this browser without the user typing `hns://` explicitly, which is the
only escape hatch and is never offered automatically. Conversely, `brad.crypto`
here is not the name Unstoppable's users mean. The second half is a consistent
application of the first, and other implementers may reasonably differ on it.

**Status: DELIBERATE.** The spine's D-16 states the same decision from the
Handshake side. What is *not* settled is whether the escape hatch should be
visible; see §2.1.

---

### IC-3. No DANE for ICANN names
*RFC 6698 · `src/index.js:1330-1331`*

**What.** The session-wide certificate verification hook defers to the
platform's WebPKI (`cb(-3)`) for every host that is not a Handshake host. No
TLSA record is queried for an ICANN name and no pin is applied, although
`../../src/dane.js` is present and is used for Handshake names.

**The standard says.** RFC 6698 defines TLSA records for binding a certificate
or key to a name, and RFC 7671 §4 recommends applying them wherever they are
published. Several ICANN zones (`.se`, `.nl`) publish TLSA records today.

**Why.** DANE-for-HTTPS is only as good as the DNSSEC validation under it, and
there is none on this path (IC-4). A pin taken on a resolver's word, applied to
a name a CA already vouches for, adds an availability failure mode and no
security.

**Consequence.** An ICANN HTTPS page is exactly as authenticated as it is in
any other browser: a CA vouched, and so did every other CA the platform trusts.
The interface says so in those words.

**Status: DELIBERATE**, but see §2.8 — we are not certain a validating ICANN
resolver would change the answer.

---

### IC-4. No DNSSEC validation for ICANN names
*RFC 4033 / 4035 · nothing on this path*

**What.** No signature is validated for an ICANN answer. The ICANN root's
trust anchor is not configured anywhere in this browser; the only anchor it
knows is the on-chain DS of a Handshake name.

**The standard says.** RFC 4033 §3.1 and RFC 4035 describe a validating
security-aware resolver, which a security-aware stub is expected to be able to
rely on or to be.

**Why.** The address comes from the engine's own resolver, which does not
validate either, and the browser never sees the wire response. Adding a
validating resolver of our own for ICANN names would be a second DNS stack for
a namespace we deliberately do not own.

**Consequence.** An ICANN address is the resolver's word. The Domain name step
never reads `verified`, and where it can name a resolver at all — the oblivious
form of SPEC §6.2 — it says in those words that the answer is still that
resolver's word.

**Status: DELIBERATE.** It is a real gap and it is the ordinary web's gap; we do
not think a browser should quietly close it in a way no other browser does.

---

### IC-5. The special-use carve-out is longer than the RFCs
*RFC 6761 / 6762 / 7686 / 8375 · `../../src/reserved-names.cjs`*

**What.** Alongside the reserved labels (`localhost`, `invalid`, `test`,
`example`, `local`, `onion`, `arpa`) the list also refuses `internal`, `home`,
`lan`, `corp`, `intranet` and `private`, none of which is reserved by any RFC.
`localhost` is treated as a subtree, per RFC 6761 §6.3, so `app.localhost` is
covered too — and so is every other entry, because the test compares both the
whole host and its final label.

**The standard says.** RFC 6761 §4 defines the process by which a name becomes
special-use and lists the ones that are; the six extra labels are not on it.
RFC 8375 reserves `home.arpa` precisely *instead of* `.home`, which the IETF
declined to reserve.

**Why.** Those six are what home routers and corporate networks actually use.
None is in the IANA snapshot, so without the carve-out the "otherwise,
Handshake" rule catches every one of them.

**Consequence.** If any of those strings is ever delegated by ICANN, or
registered on Handshake by somebody who intends to serve it, this browser will
not resolve it as a name — it will hand it to the platform resolver, which is
what the user's own network expects. We consider that the right failure: the
alternative is sending the names of machines on a user's own LAN to a stranger
who can answer for them.

**Status: DELIBERATE.**

---

### IC-6. `automatic` falls back to unencrypted system DNS
*`../../src/dns-policy.js`, `src/config.js:348-357`*

**What.** In Fast mode — the configured plan — the default `dns.mode` is
`automatic`: encrypted DNS to the configured resolvers, falling back to
unencrypted system DNS when none answer. The plan reports this as
`plaintextFallback: true`, and the interface says what that configuration
*permits* — "Automatic DNS permits system fallback; this does not show that
fallback occurred" (`../../src/trust-path.js:480`) — because whether any given
lookup took the fallback is not observable from here (IC-17). In Private mode
the block is replaced by `privateDns()` before it is read (SPEC §5.7), so the
fallback is not configured there: `secure`, the bridge alone, or nothing.

**The standard says.** RFC 8484 defines the DoH transport but not a fallback
policy; RFC 8310 §8.2, on the analogous DoT case, distinguishes an opportunistic
profile from a strict one and is explicit that the opportunistic profile gives
no protection against an active attacker. `automatic` is the opportunistic
profile.

**Why.** Captive portals and hotel Wi-Fi intercept DNS and would otherwise make
the network unusable. This is a genuine availability-versus-privacy trade and it
is resolved in favour of availability by default.

**Consequence.** In Fast mode an attacker who can make the configured resolvers
unreachable can force every ICANN lookup into the clear — and, because the
bridge replaces the pool (IC-7), needs only to reach the two relays to do it.
`secure` mode exists, refuses plaintext even when that means resolving nothing
at all, is documented in the settings page in the user's own words, and is what
Private mode forces.

**Status: DELIBERATE** as a default, and stated as a limitation everywhere it
applies (SPEC §5.5, §9.2).

---

### IC-7. The oblivious bridge replaces the resolver pool rather than leading it
*`../../src/dns-policy.js` `planDnsTransport`*

**What.** When the loopback ODoH bridge starts, its template becomes the whole
of `secureDnsServers`. The configured DoH pool is discarded for the life of the
process, so the engine has exactly one secure resolver and, below it, whatever
the mode permits. This is a Fast-mode question: in Private the pool is dropped
by policy before the bridge is consulted (`privateDns()`, SPEC §5.7), so there
the bridge is the only server whether or not it replaces anything.

**The standard says.** Nothing requires either arrangement; RFC 8484 clients
customarily hold a list. This is a deviation from what a reader of the
configuration would expect — `dns.servers` names four resolvers and, with the
default `odoh.icann`, none of them is used.

**Why.** A mixed list is simpler to get wrong than to get right: the engine
would fall from an oblivious template to a plain one silently, and nothing
here would see it happen. The interface's per-name claim (SPEC §6.2) is
narrower than that job needs — it reports the hosts the bridge answered, which
is evidence that the oblivious path was used *for a lookup of that host*, not
evidence about which template served any particular navigation (IC-17).

**Consequence.** Turning obliviousness on changes the floor beneath a failed
lookup from the configured *encrypted* pool to *plaintext* in Fast mode's
`automatic`, and to no floor at all in `secure` mode — configured, or forced by
Private. The second is the honest trade; the first is a downgrade the user did
not ask for by asking for more privacy.

**Status: OPEN.** We think leading the pool with the bridge is strictly better
on privacy and would take it — but only with a measurement first. What is
missing is not the code (`servers = [bridge.template, ...servers]`) but the
evidence: we have not measured what the engine does with a mixed template list,
how it chooses between entries, or how long it remembers a failing one. Until
that is measured, prepending would put a silent downgrade where nothing can
see it, since the panel cannot say which template answered (IC-17). IC-D1, and
the measurement it needs is IC-D5.

---

### IC-8. ODoHConfigs come from a conventional well-known URI, fetched directly from the target
*RFC 9230 · `../../src/odoh.js`*

**What.** The target's `ODoHConfigs` are fetched over ordinary HTTPS from
`https://<target>/.well-known/odohconfigs` and cached for one hour. The fetch
goes straight to the target, not through a relay.

**The standard says.** RFC 9230 defines the `ODoHConfigs` structure and, as we
read it, deliberately defines **no** discovery mechanism.
`/.well-known/odohconfigs` is the convention the deployed implementations use,
and — as far as we can establish — it is not an IANA-registered well-known URI
under RFC 8615.

**Why (the direct fetch).** The configuration is public and authenticated by
the target's own TLS. Fetching it through a relay would add nothing: a relay
that tampered with it could not read anything — decryption would simply fail
for every subsequent query.

**Consequence.** The target learns the client's IP address about once an hour,
unlinked to any query. That is a weaker disclosure than a DoH resolver's, and
it is a disclosure. And every ODoH client depends on a path that is nobody's to
change.

**Status: DELIBERATE** for the direct fetch, which we would defend. The URI's
standing is an uncertainty rather than a decision: §2.2.

---

### IC-9. The lookups that make the private path possible are not themselves private
*`../../src/odoh-bridge.js`, `../../src/odoh.js`*

**What.** Two classes of ICANN lookup escape the whole of SPEC §5:

1. **Bootstrap.** The bridge must resolve the relay and target hostnames
   (`odoh-relay.numa.rs`, `odoh.hns.one`) to open HTTPS connections to them.
   Those go through the runtime's own resolver — `getaddrinfo` — not through
   the engine's configured secure DNS and not through the bridge. The same is
   true of the DoH pool's hostnames in the non-bridged case.
2. **Configuration refresh**, hourly, for the same reason.

A Handshake resolution's own ICANN lookups — a nameserver's name, a glue-less
`NS` target, a `CNAME` target — are **not** in this list: they go through the
resolver's injected `lookup`, which the browser sets to its own DoH/ODoH client
in every mode (SPEC §8). The one thing about that injection which belongs
beside the two entries above is its *library default*, and that is IC-16.

**The standard says.** RFC 9230's privacy analysis assumes the client reaches
the relay without disclosing the query; it says nothing about how the relay's
own name is resolved. RFC 8484 §8.2 warns that a DoH client's bootstrap can
itself be a disclosure.

**Why.** The bridge cannot resolve its own upstream through itself. There is no
chicken-and-egg-free answer at the moment it is needed.

**Consequence.** These disclose *which privacy infrastructure this browser
uses* to the local network in the clear. What bounds it is that they are two
fixed hostnames, asked once a session and once an hour: no name a user typed
is in them, and there is nothing per navigation.

Private mode does not change the lookups themselves (SPEC §5.7): the mode
replaces what the engine is told. The connections that follow them — the
bridge's relay leg and its config fetch — ride the session's proxied fetch
(`OdohTransport({ fetchImpl })`), so in Private they leave through Tor and
while BLOCKED they stop with everything else.

**Status: OPEN**, and not hard: the relay and target addresses can be pinned in
the configuration, or resolved through the engine once it is configured, which
removes the per-session and per-hour disclosure entirely.

---

### IC-11. DoT, DDR, SVCB/HTTPS and ECH are not used
*RFC 7858 / 8310, RFC 9462, RFC 9460, RFC 9848*

**What.**

- **DoT (RFC 7858 / 8310)** and DNS-over-QUIC: not used, and not usable — the
  engine accepts only RFC 8484 HTTPS templates, whatever the configuration
  says.
- **DDR (RFC 9462)**: not implemented. The resolver list is configuration,
  never discovered.
- **SVCB / HTTPS RR (RFC 9460)** is parsed by `../../src/dns-query.js` and
  never queried, on this path or any other; **ECH (RFC 9848)** is therefore
  unreachable, and is also blocked on the runtime exposing no ECH option.

**The standard says.** RFC 9462 §4 specifies how a client discovers a
designated encrypted resolver from the one it already has, which is the
standard answer to "the user's network operator runs a good resolver and we
overrode it". RFC 9460 defines the record that carries it.

**Why.** DoT is the engine's constraint, not our choice, and is recorded so its
absence is not read as an oversight. DDR and SVCB are work nobody has done.

**Consequence.** The resolver list can only be what the configuration file
says, so a network that offers a designated encrypted resolver is ignored — see
§2.9 for the argument that this is the wrong side of a real question. Without
ECH the server name is in the ClientHello regardless, so an oblivious DNS
lookup does not by itself hide which site was visited from an on-path observer.

**Status: OPEN** for DDR, which is the only one of the four that is ours to
take. We recommend implementing the RFC 9462 §4 discovery path — query the
`_dns.resolver.arpa` SVCB record through the configured resolver at startup and
offer any designated encrypted resolver it names as an additional template —
behind a configuration key that is off by default, so that the discovery cannot
silently widen the set of resolvers a user chose. DoT and ECH stay recorded
constraints until the engine offers them.

---

### IC-12. Internationalized names cross the boundary through UTS-46, not IDNA2008
*RFC 5890 / 5891, UTS #46 · `../../src/classify-host.cjs:68-76`*

**What.** A Unicode host is converted to A-labels by handing it to `new URL()`
and reading `hostname` back, which is UTS-46 as the WHATWG URL Standard
specifies it, not IDNA2008 as RFC 5891 specifies it.

**The standard says.** RFC 5891 §4 defines the registration and lookup
protocols for IDNA2008; UTS #46 defines a compatibility processing that differs
from it on a small set of characters (the four deviation characters, and
transitional versus non-transitional processing).

**Why.** The conversion is the URL parser's, and the URL parser is the thing
that will actually carry the name afterwards. Implementing IDNA2008 separately
would mean a host that classified one way and navigated another.

**Consequence.** On the Handshake path the divergence produces a name the chain
has not heard of. **Here it can move a name across the ICANN boundary** — a
host that IDNA2008 would map to an A-label outside the snapshot, and UTS-46
maps to one inside it, is routed to a different root. We have not audited which
labels this can affect.

**Status: OPEN**, and under-examined. The bounded piece of work is to enumerate
the delegated TLDs reachable by a UTS-46/IDNA2008 divergence — the deviation
characters are four, the snapshot is 1,438 labels, and the cross product is
small enough to check exhaustively offline. Until that is done we state the
possibility rather than a consequence (§2.7). The spine's D-17 is the same
deviation with a weaker consequence.

---

### IC-13. The SSRF guard is not applied to ICANN addresses
*RFC 6890 / 1918 / 4193 · `../../src/safe-address.js`*

**What.** `assertPublicAddress()` refuses loopback, private, link-local
(including `169.254.169.254`), CGNAT, benchmarking, multicast and reserved
addresses. It is applied on the Handshake path, on the HIP-5 `_op` path and in
the WebSocket proxy. It is not applied to ICANN names.

**The standard says.** RFC 6890 enumerates the special-purpose ranges; nothing
requires a browser to refuse them, and browsers do not.

**Why.** It cannot be applied: the address never passes through our code. The
engine resolves and connects.

**Consequence.** `http://internal.example/` resolving to `10.0.0.1` behaves
exactly as it does in any other browser, subject to the engine's own
private-network protections and nothing of ours. This is not a regression
against browser norms; it is a place where the Handshake path is *stronger*
than the ICANN path, and a reader should not assume the guard is universal.

**Status: DELIBERATE.**

---

### IC-14. An `http://` link to a numeric-TLD Handshake name is not rewritten
*WHATWG URL Standard · `src/hns/hns-host.js:85-98`*

**What.** `rewriteToHns()` parses its input with `new URL()`. For a host whose
last label is all digits the WHATWG "ends in a number" rule sends the host to
the IPv4 parser, which fails, and the constructor throws — so the function
returns `null` and the URL is left alone. Typed input takes a different path
and does handle the case, via the `_` marker convention
(`hns://hello._14898/`).

**The standard says.** The URL Standard's "ends in a number" checker and IPv4
parser make `http://hello.14898/` an invalid URL. Both the classifier and the
engine are bound by that rule.

**Why.** There is nothing to rewrite. The engine cannot construct that URL
either, so it never becomes a navigation and the rewrite hook is never reached
with it. A rescue path in `rewriteToHns` would be code that no input can
execute.

**Consequence.** `http://hello.14898/` written as a literal link in a page is a
dead end — but it is a dead end in every browser, ours included, before our
code is consulted. The two classification paths disagree on paper about a name
only one of them can be handed. The spine's D-4 is the same URL-parsing rule
seen from the Handshake side, where the `_` convention answers it.

**Status: DELIBERATE.** Recorded because the disagreement is real and a reader
comparing the two paths will find it; the reason it is not repaired is that the
input cannot arrive. See §2.10 for what we have not verified about that.

---

### IC-15. The obliviousness switch and the resolver pool are configuration-file-only
*`src/pages/settings.html:464-472`, `src/config.js:348-357`, `:376-408`*

**What.** `dns.mode` is exposed in the settings page as a free-text field with
all three values explained. `odoh.icann` — the switch that decides whether
ordinary web lookups go through the relay at all, and which costs about 200 ms
per cache miss — is only editable in the configuration file, even though the
code comment beside it calls it "a setting". `dns.servers` is likewise
config-file-only.

**The standard says.** Nothing; this is a deviation from our own stated design,
which is that the user should be able to make this trade.

**Why.** `dns.mode` was the setting with a user-facing question attached
("should ordinary DNS be encrypted?"), and it got a field. `odoh.icann` and
`dns.servers` are the settings with a cost attached, and a cost is harder to
word than a switch — so they stayed where they were written.

**Consequence.** The trade this design most wants the user to make consciously
is the one they are least able to reach. And a free-text field for a
three-valued enumeration is a typo waiting to happen — harmless now that the
value is normalised and a bad one is reported (SPEC §5.2), but still a field
that can be wrong.

The Fast / Private switch (SPEC §5.7) is in the settings page and the Privacy
menu, and it does not expose these two keys either. With `odoh.icann: false`
Private mode leaves the engine with no resolver for ICANN names at all — the
plan fails closed with no bridge — and nothing on the switch says so. The
Domain name step names that configuration after the fact ("Secure DNS
configured to refuse new lookups"), which is the wrong moment and, being a
statement about the configuration rather than about the page, the wrong
sentence to learn it from.

**Status: OPEN.** Add a checkbox for `odoh.icann` in the same DNS privacy
block, with the cost stated in the hint text — including that Private mode
depends on it — and a textarea for `dns.servers`; make `dns.mode` a `<select>`
so the class of error disappears rather than being reported. The plumbing
exists — `dns.mode` is already written through the settings preload. IC-D3.

---

### IC-16. The resolver's default `lookup` is the OS resolver, in the clear
*`../../src/resolver.js:226` · SPEC §8*

**What.** The three places a chain walk needs an ICANN host's address all go
through one injected function, `HNSResolver`'s `lookup`. The browser passes its
DoH/ODoH client, so nothing goes out in the clear. **The constructor's default
does not**: with no `lookup` supplied it is
`(host) => dns.lookup(host, { family: 4 })` — `getaddrinfo`, outside the whole
of SPEC §5.

**The standard says.** Nothing about a library's defaults. RFC 8484 §8.2 is the
nearest: a client that can resolve privately and does not has disclosed the
query.

**Why.** The module has to run as a library under plain `node` — that is how
its own test suite drives it — and a library cannot assume a DoH client. The
default is the one that always works.

**Consequence.** The protection is a property of the **composition**, not of
the module. An integrator who takes `resolver.js` and omits one constructor
argument discloses one ICANN name in the clear for every Handshake resolution
that walks to an ICANN nameserver or follows a `CNAME` out of the zone.
Nothing warns them, and the resolution's own trust reporting cannot tell the
two apart — an address is the resolver's word either way, so the panel's step
reads the same whether the lookup was encrypted or not.

**Status: OPEN.** Two candidate fixes, and we prefer the first: make `lookup`
**required** and let construction fail without it, so the decision is taken
once and visibly; or keep the default and record on each resolution which
transport the lookup used, so the trust step can say "in the clear" when it
was. Either is better than a default whose safety depends on a caller reading
a comment.

---

### IC-17. The browser cannot observe which resolver answered a navigation, so the panel describes configuration
*RFC 8310 §8.2, `app.configureHostResolver` · `../../src/trust-path.js:459-503`, `../../src/route-path.js:234-248`*

**What.** For an ICANN name the engine resolves, from its own cache when it
has an entry, and reports neither the transport it used nor whether it made a
query at all. `app.configureHostResolver` is a one-way call: a mode and a list
of templates go in, and nothing comes back — no event, no readback, no
per-navigation record. So every branch of the Domain name step but one
(`icannNameStep()`) describes the **plan the engine was given** and says the
lookup path was not observed, and the route view's ICANN name hop is
`unknown` in every branch (`icannNameHop()`; SPEC §6.4).

**The standard says.** RFC 8310 §8.2, on the analogous DoT case, distinguishes
an opportunistic profile from a strict one and is explicit that the
opportunistic profile gives no protection against an active attacker: a client
that wants the guarantee **MUST** choose the strict profile. That is a choice
made by *policy*, in advance — which is exactly what `dns.mode` is. Neither
that document, nor RFC 8484, nor RFC 9230 defines any way for a client to
establish **after** the fact which profile carried a particular name; each
assumes the client is the one making the query and therefore already knows.
Here it is not: the engine makes the query, and does not say.

**Why.** We configure the engine's resolver; we do not implement it (SPEC
§1.1). Reimplementing ICANN resolution to gain observability would mean a
second DNS stack for a namespace we deliberately do not own, and would
duplicate the engine's cache with our own.

**Consequence.** The interface's ceiling is lower than a reader expects. It
can say what was asked for and what the bridge has a record of answering; it
cannot say "this page's address came from there". Every sentence in the panel
and the route view is written to that ceiling, which is why a fail-closed plan
is `unverified` rather than `failed` (SPEC §6.1) and why the route summary
leads with what was not recorded (SPEC §6.4). A user reading "Secure DNS
configured" learns a true thing about the browser and nothing about this page.

**Status: OPEN**, and the open part is evidence rather than design. We
recommend capturing the engine's own DNS record in the shipping build — a
`netLog` capture over a scripted navigation, per mode and per failure kind —
and, where that shows a fact the panel could carry per navigation, threading
it through as the resolution events are threaded through on the Handshake
path. Until then the wording stays at the ceiling above. IC-D5, and §2.4 is
the same measurement seen from the failure side.

---

### IC-18. `recentEvidence` is activity, not provenance, and its window is a guess
*RFC 1035 §3.2.1, RFC 8499 · `../../src/odoh-bridge.js:176-200`, `src/dns-policy.js:131-139`*

**What.** The bridge keeps a bounded, in-memory map of the exact hostnames it
has answered: host and query type as the key, and `{host, queryType, relay,
target, rcode, at}` as the value, capped at 512 entries and ordered by a
monotonic sequence number so a slow older query cannot overwrite a newer
result. `recentEvidence(host)` returns the newest entry for that **exact**
host if it is under ten minutes old and its rcode is NOERROR or NXDOMAIN, and
that — labelled `evidence: 'recent-lookup'` — is the only positive claim the
Domain name step can make (SPEC §6.2 form 1).

**The standard says.** RFC 1035 §3.2.1 defines a record's TTL as "the time
interval that the resource record may be cached before the source of the
information should again be consulted", and RFC 8499 defines a cached answer
as one served without a new query. The lifetime of an answer is therefore the
answer's own, published per record; a fixed ten-minute window is unrelated to
it in both directions.

**Why.** It is the strongest true statement available. The engine will not say
what answered a navigation (IC-17), so the bridge's own log of what *it*
answered is the only per-name fact in the system. Ten minutes was chosen to
outlive a page load and little else.

**Consequence.** Three gaps, all of which the wording has to carry and does:

1. **A lookup is not this navigation.** The bridge may have answered
   `example.com` for a subresource, a prefetch, or a page loaded minutes ago,
   while this navigation used a cached address. The step says "evidence of
   recent lookup activity, not proof that this page used that answer"
   (`../../src/trust-path.js:465-469`).
2. **Ten minutes is neither a TTL nor a session.** A one-minute record can be
   re-resolved by some other path inside the window, and a day-long record can
   fall out of it while still being the address in use.
3. **The record is writable by anything that can reach the bridge**, which is
   why the endpoint path is a per-launch secret and `Origin`/`Sec-Fetch-Site`
   are refused (SPEC §5.3): a page that could make the bridge resolve a name
   of its choosing would be writing the interface's evidence.

What it is *not* is a claim about a parent or a child name: one lookup for
`example.com` says nothing about `a.example.com`, in either direction.

**Status: DELIBERATE** as to the shape — the exact-host rule, the rcode rule
and the sequence ordering we would all choose again — and **OPEN** as to the
window, which is a guess we would rather replace with the answer's own TTL.
§2.5.

---

### IC-19. The route view's ICANN name hop has no route
*Our own design · `../../src/route-path.js:28`, `:234-248`, `:255-274`*

**What.** The route view answers "who saw this request", hop by hop, with one
of `local`, `oblivious`, `tor`, `direct`, `refused` — and, for this hop only,
`unknown`. The ICANN name-lookup hop is `unknown` in **every** branch,
including the branch where the bridge holds exact-host evidence, and
`summarizeRoute()` leads with "Some route details were not recorded; this view
cannot establish every party that saw this page request."

**The standard says.** Nothing; this is a deviation from our own stated design,
which is that this view names, for each hop, who was shown this computer's
address and what they were shown.

**Why.** `direct` and `oblivious` are both measurements. `direct` asserts that
a named party saw this address together with this name; `oblivious` asserts
that no single party saw both. Neither is available for a lookup performed by
the engine (IC-17), and a route view that guessed would be making the precise
claim this browser exists to stop making — in the one view a user opens
*because* they want to know who saw them.

**Consequence.** The ICANN row is the only row in the view that never resolves
to a route, and an `https://example.com` page therefore always carries the
"not recorded" summary, however much is known about its other hops. That is
honest and it is also an admission, on the majority of pages, that the most
common navigation in the browser is the one this view can say least about.

**Status: OPEN**, blocked on the same evidence as IC-17. If a `netLog` capture
establishes a per-navigation fact — that a query left through the bridge's
template for this host, say — this hop can carry `oblivious` for that case and
keep `unknown` for the rest. IC-D5.

---


## 2. Things we are not sure about

These are the ones we most want challenged.

### 2.1. Whether "ICANN first" should have a visible escape hatch

The collision rule (IC-2) is settled as a *default*. What is not settled is
that the only way to reach the Handshake answer for a colliding name is to know
that `hns://` exists and type it. A registrant who buys the Handshake name of
an ICANN string cannot serve it to our users at all, and our users are never
told there is another answer. Every design we have sketched for telling them —
a second suggestion row, a one-line notice, a per-name preference — either
teaches users to click through a security-shaped prompt or creates persistent
per-name state an attacker can influence. We do not know the right shape.

### 2.2. Whether `/.well-known/odohconfigs` is standardised

RFC 9230 defines the `ODoHConfigs` structure and, as we read it, deliberately
does not define discovery. The deployed convention is a well-known URI that we
believe is not registered under RFC 8615. If it is registered, we are citing it
wrongly and would like to know. If it is not, then every ODoH client depends on
an unregistered path, which is a thing the working group might want to hear.

### 2.3. Whether replacing the resolver pool is the right failure ordering

In Fast mode, IC-7 means the fallback below a failed oblivious lookup is
plaintext rather than DoH. Prepending the bridge to the pool instead would make the fallback
encrypted-but-not-oblivious, which is strictly better on privacy — but it also
means a *silent* downgrade from oblivious to non-oblivious that the engine
performs without telling us, and the interface's per-name claim (SPEC §6.2)
would then be doing more work than we have tested it for. We think prepending
wins. We have not measured what the engine actually does across a mixed list.

### 2.4. What the engine does on each kind of DoH failure

`automatic` "falls back to system DNS when the secure resolver cannot be
reached" is the documented behaviour, and we repeat it. We have **not**
measured whether a SERVFAIL response — which is what our bridge returns on
failure, and which is a *successful* HTTP exchange — triggers the same fallback
as a transport failure, nor how long the engine remembers a failing resolver.
The bridge's failure policy was chosen on the assumption that it does. If it
does not, a relay outage in Fast mode's `automatic` is a hard failure rather
than a silent downgrade — which would be *better* for privacy and worse for
availability, and either way we should know which one we shipped. In Private
mode we expect the question not to arise, because `secure` is documented to
refuse every fallback and a SERVFAIL from the bridge should then be a failed
lookup whichever way the engine reads it — but that is the same unmeasured
documentation, and the engine's cache sits in front of all of it (IC-17). The
same measurement answers what threshold IC-1's staleness check should use only
by analogy; that one is a separate guess. IC-D5 is the measurement.

### 2.5. The ten-minute window

`recentEvidence()` reports a lookup the bridge answered within ten minutes, for
that exact host. Ten minutes is a guess, and it is a guess about the wrong
quantity: what governs how long an answer stays in use is the record's own TTL
(IC-18), which the bridge does not read — it forwards bytes it does not
interpret beyond the envelope. So the window can outlive the answer, and it can
also expire while the answer is still the one in use. Reading the TTL out of
the reply would make the window the answer's own, at the cost of parsing RDATA
the bridge has no other reason to touch, and would still be a statement about
the bridge's answer rather than about this page's address. We do not know
whether that trade is worth making.

### 2.6. Whether the snapshot cadence is adequate

IC-1's alarm fires on a networked test run. Nothing forces a refresh before a
release, and nothing measures how stale a shipped snapshot was. Against a round
that may delegate hundreds of TLDs over the next two years, "we have an alarm"
may not be enough. We have not decided what the staleness threshold should be,
and the honest reason is that we do not know how quickly a delegation becomes a
name somebody visits.

### 2.7. Whether the IDNA divergence can actually move a name

IC-12 is stated as a possibility because that is exactly what it is: we know
UTS-46 and IDNA2008 differ, we know the difference is applied at the point
where the boundary is decided, and we have not enumerated the labels for which
it changes the answer. It may be that no delegated TLD is reachable by such a
divergence. It may be that several are.

### 2.8. Whether refusing DANE for ICANN names is right

IC-3's argument is that a pin is only as good as the DNSSEC under it, and there
is none. The counter-argument is that this is the only shipping browser that
validates DANE for HTTPS at all, that a validating resolver for ICANN names is
a solved problem, and that a browser willing to build the whole Handshake
apparatus could reasonably offer DANE for the `.se`/`.nl`-style zones that
publish TLSA records today. We did not do it because it is a second DNS stack
for a namespace we deliberately do not own, and because the availability
failure modes of DANE on the open web are notorious. We are not certain that is
more than an excuse.

### 2.9. Whether a browser should be configuring the resolver at all

Every decision in SPEC §5 is made on the user's behalf, at startup, from a
configuration file most people will never open. There is a coherent opposite
position: the operating system owns DNS, a browser that overrides it fragments
the user's threat model across applications, and a corporate or household
resolver that exists for a reason is silently bypassed. We think the plaintext
default is bad enough to justify overriding it, and we say which resolver the
engine was pointed at. We would not call the question settled — and IC-11's
missing DDR is the standard's own answer to it, which we have not taken.

### 2.10. Whether the engine really cannot issue a numeric-TLD http request

IC-14 rests on a claim about the platform: that `http://hello.14898/` never
becomes a navigation, so the rewrite hook is never reached with it. That
follows from the URL Standard, and it matches what the URL constructor does in
our own tests. We have not instrumented the engine's navigation path to confirm
that no code path anywhere constructs such a request by another route — through
a redirect target, say, or a subresource URL assembled relative to a base. If
one does, IC-14 becomes a real gap rather than an unreachable one.

### 2.11. Whether recent bridge activity is worth reporting at all

IC-18's record is the only positive per-name fact in the system, and it is one
step removed from the question the user is asking. There is a coherent position
that a panel should say nothing rather than say something true about a
neighbouring event: "the bridge recently answered a lookup for this host" will
be read as "this page was resolved obliviously" by most people who see it, no
matter how the sentence is worded, and a caveat everybody skips is not a
caveat. The position we shipped is the opposite one — suppressing the single
real observation leaves the user with nothing but settings, which are further
from the truth still — but it is a judgement about how a sentence is read, and
we would rather it were challenged by somebody who tests interfaces on people
than settled by us.

---

## 3. Open design items

Changes we intend or recommend, that are not made. Each names the deviation it
would resolve.

### IC-D1. Lead the resolver pool with the bridge instead of replacing it

The bridge's template becomes the whole of `secureDnsServers`, so in Fast
mode's `automatic` the floor beneath a failed oblivious lookup is plaintext
rather than the configured DoH pool (IC-7); Private mode has no floor by policy
(SPEC §5.7). Prepending would keep an encrypted floor, at the cost of a silent
oblivious-to-non-oblivious downgrade that only the interface's per-name claim
could detect.

**Recommendation.** Do it, but not first. Measure the engine's behaviour on a
mixed template list — how it chooses between entries, whether it falls from the
first to the second on a SERVFAIL as well as on a transport failure, how long
it remembers a failing one — and only then change `planDnsTransport` to
`servers = [bridge.template, ...servers]`. The measurement is also what §2.4
needs, so it pays for itself twice.

### IC-D3. Put the obliviousness switch and the resolver pool in the settings page

`odoh.icann` and `dns.servers` are editable only in the configuration file,
although `odoh.icann` is the setting this design most wants the user to choose
consciously (IC-15). `dns.mode` has a field, but a free-text one.

**Recommendation.** A checkbox for `odoh.icann` with its latency cost in the
hint text ("about 200 ms on the first lookup for each site; Handshake names
stay oblivious either way"), a textarea for `dns.servers`, and a `<select>` for
`dns.mode`. The settings preload already writes `dns.mode`, so the plumbing
exists.

### IC-D4. Give the browser's drift alarm an offline half

`tests/hns/icann-tlds-live.test.js` skips entirely without network, so an
offline run — a release build on a locked-down machine, a contributor on a
plane — checks the ICANN boundary not at all, including the parts that need no
network: that the file is well-formed, that it is what the generator produces,
and that it carries a version line.

**Recommendation.** Lift `tests/icann-tld-snapshot.test.js` from this chapter
into the browser tree, with its imports pointed at `src/ui/icann-tlds.cjs` and
`scripts/fetch-icann-tlds.mjs`; the live comparison stays as it is. Add a
staleness assertion at the same time — `Version` is a `YYYYMMDDNN` integer, so
"this snapshot is more than N days old" is a one-line offline check, and §2.6
is the open question of what N should be.

### IC-D5. Capture what the engine actually does with a name

Four claims in this chapter stop at "configured" because nothing measures the
engine: which resolver answered a navigation (IC-17), whether the route hop can
ever be better than `unknown` (IC-19), what `automatic` does on a SERVFAIL as
against a transport failure (§2.4), and how a mixed template list is used
(IC-D1). They are one measurement.

**Recommendation.** In the shipping browser build, drive a scripted navigation
per mode (`off`, `automatic`, `secure`, Private) and per failure kind (relay
down, target down, bridge-returned SERVFAIL, cold cache, warm cache) with the
engine's own network log capturing, and record for each: whether a query was
made at all, which template carried it, and what happened after a failure.
Publish the table here. Then decide, with evidence: whether any per-navigation
fact can be carried into the Domain name step and the route hop, whether the
bridge should lead the pool rather than replace it, and which of §2.4's two
behaviours we shipped.

---

## 4. What this chapter leaves out

1. **Any ICANN resolver.** There is none in this package, and none in the
   browser: the engine resolves ICANN names. `src/dns-policy.js` here is the
   *policy* the browser's Electron composition layer calls at both of its
   gates, not an implementation of resolution. If you are implementing from
   this specification, the resolver is your platform's and §5 is a description
   of what to tell it. The re-application of the plan on a mode switch
   (`applyDnsPlan`, driven by the `DeliveryMode` controller's `change` event)
   is part of that composition layer; its policy is SPEC §5.7.

2. **The modules this chapter is about that live in the spine's `src/`.**
   `router.js`, `hns-host.js`, `icann-tlds.cjs`, `reserved-names.cjs`,
   `safe-address.js`, `self-cert.js`, `odoh.js`, `odoh-bridge.js`, `doh.js`,
   `dns-query.js` and `trust-path.js` are all in `../../src/`, byte-identical
   to their Wildroot counterparts, and are not duplicated here. Only
   `dns-policy.js` and the snapshot generator's parse-and-render half are in
   this chapter's `src/`.

3. **`src/hns/privacy.js`.** It is named in this chapter's brief and it is
   about something else entirely: Electron permission defaults (camera,
   microphone, clipboard, fullscreen) and tracking-parameter stripping. It has
   no DNS content. The DNS privacy policy lives in `src/hns/dns-policy.js`,
   `src/index.js`, `src/config.js` and `src/hns/odoh-bridge.js`, which is what
   SPEC §5 documents. Recorded so the next reader does not go looking.

4. **The engine's own behaviour.** Cache lifetimes, DoH probing, the downgrade
   heuristics behind `automatic`, and private-network access protections are
   the engine's, not ours. Where a claim we make depends on one of them, §2.4
   says we have not measured it rather than asserting it.
