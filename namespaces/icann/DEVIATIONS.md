# Chapter 2 — ICANN names: deviations and open questions

This file records ICANN routing and transport limitations. `IC-n` identifies
existing behavior; `IC-Dn` identifies proposed work. See
[REVIEW.md](../../REVIEW.md) for claims that require a technical decision or
runtime evidence.

`../../src/` refers to shared code in this repository. `src/dns-policy.js` and
`src/icann-tld-snapshot.js` refer to this chapter's source. Other `src/` paths
refer to the browser composition, which is not included here.

---

## 1. Deviations

### IC-1. The ICANN boundary is a build-time snapshot, not a live lookup

**Behavior.** The build-time snapshot is IANA version 2026090500, dated
2026-09-05, with 1,438 labels. It is committed and not fetched at runtime
(`src/icann-tld-snapshot.js`, `../../src/icann-tlds.cjs`).

**Effect.** New or removed delegations can be misclassified until an update
ships. Browser network tests compare the list with IANA; the chapter's offline
test checks its generated form.

**Status: OPEN.** Keep the bundled snapshot, but define its permitted age at
release and enforce it offline (IC-D4, §2.6).

---

### IC-2. ICANN wins a label that is also a Handshake TLD, and every other alt-root is Handshake's

**Behavior.** ICANN snapshot membership takes precedence for dotted bare
names. Other unreserved suffixes select Handshake, except `.eth` and `.onion`.
An explicit `hns://` request can select Handshake for a colliding name.

**Difference from Handshake.** Handshake permits ICANN holders to claim reserved
labels on chain. Wildroot gives normal web navigation priority rather than
consulting the chain first.

**Status: DELIBERATE.** Whether to expose the explicit-scheme option in the
interface remains open (§2.1).

---

### IC-3. No DANE for ICANN names

**Behavior.** The session certificate hook defers non-Handshake hosts to
platform WebPKI. It does not query or apply TLSA for ICANN navigation.

**Reason.** The browser does not locally validate ICANN DNSSEC (IC-4). The
Handshake DANE implementation therefore has no authenticated ICANN TLSA path.

**Status: DELIBERATE.** Adding a validating ICANN resolver and DANE support
would be separate work (§2.8).

---

### IC-4. No DNSSEC validation for ICANN names

**Behavior.** The browser does not validate ICANN DNSSEC replies locally or
configure an ICANN root trust anchor. The engine handles name resolution;
Wildroot's Domain name step relies on the selected resolver.

**Effect.** DNS transport encryption does not produce a `verified` name step.
This statement concerns DNSSEC, not the engine's WebPKI certificate checks.

**Status: DELIBERATE.** RFC 4033/4035 validation would require additional
integration rather than a change to the trust label alone.

---

### IC-5. The special-use carve-out is longer than the RFCs

**Behavior.** The reserved list includes `internal`, `home`, `lan`, `corp`,
`intranet`, and `private` in addition to the standards-based entries. Matching
the final label covers the entire subtree.

**Effect.** These local-network conventions are kept out of normal Handshake
classification. Their administrative status differs; router SPEC §7 separates
ICANN policy from IETF reservations. RFC 8375 reserves `home.arpa`, not `.home`.

**Status: DELIBERATE.** The list is a client policy broader than the RFC list.

---

### IC-6. `automatic` falls back to unencrypted system DNS

**Behavior.** Fast defaults to `automatic`, which permits fallback from
encrypted resolvers to system DNS. Private replaces the plan with `secure`
and the oblivious bridge alone (`src/dns-policy.js`).

**Effect.** The Fast default favors availability on captive networks. Active
disruption may trigger unencrypted resolution, as in the opportunistic profile
described by RFC 8310 §8.2. The engine's exact SERVFAIL behavior is unmeasured
(§2.4).

**Status: DELIBERATE.** The panel reports the fallback policy. Private permits
no plaintext fallback.

---

### IC-7. The oblivious bridge replaces the resolver pool rather than leading it

**Behavior.** A running bridge replaces the configured secure resolver pool.
The engine receives only its loopback template. In Private the pool is removed
before bridge selection, by policy.

**Effect.** After a bridge lookup fails, Fast `automatic` can use system DNS;
the configured DoH pool is unavailable as an intermediate fallback. `secure`
refuses unencrypted fallback.

**Status: OPEN.** Before prepending the bridge to a mixed pool, measure how
the engine selects and retries templates. It may not use them in simple list
order (IC-D1).

---

### IC-8. ODoHConfigs come from a conventional well-known URI, fetched directly from the target

**Behavior.** The transport fetches `ODoHConfigs` from
`https://<target>/.well-known/odohconfigs` through its injected fetch and caches
the result for one hour. This bypasses the ODoH relay, but the fetch can still
use the session's Tor proxy in Private.

**Effect.** The target sees the address of the connection performing the
configuration fetch; that is not necessarily the user's address. The URI's
IANA registration status was not verified in the original text (§2.2).

**Status: DELIBERATE** for target configuration fetching; discovery provenance
needs verification. RFC 9230 defines the configuration format.

---

### IC-9. The lookups that make the private path possible are not themselves private

**Concern.** Relay and target hostnames must be bootstrapped before encrypted
queries can be made. The original text claims that these names, and DoH pool
hostnames, always use OS `getaddrinfo`, even when fetch is injected through
the browser's proxied session.

**Evidence gap.** This repository's transport delegates requests to `fetchImpl`;
its library code does not establish the browser's bootstrap resolver path.
Runtime measurements are needed for direct, Private, and BLOCKED states.

The ICANN names encountered during a Handshake walk use the injected `lookup`
client and are a separate case (IC-16).

**Status: OPEN.** Identify the actual bootstrap path before choosing pinned
addresses or another resolver. Do not claim zero bootstrap disclosure.

---

### IC-11. DoT, DDR, SVCB/HTTPS and ECH are not used

**Behavior.** The engine configuration API accepts DoH templates, not DoT or
DoQ endpoints. This project does not implement DDR. Its own DNS parser supports
SVCB/HTTPS RDATA, but the Handshake resolver does not query it.

**Scope issue.** That does not establish whether Chromium queries HTTPS records
or uses ECH for ICANN navigation. The original entry applied the raw Node TLS
limitation to both transports, conflicting with HS-3. See REVIEW.md.

**Status: OPEN.** DDR could discover an encrypted resolver through
`_dns.resolver.arpa` (RFC 9462), but policy must decide whether discovery may
change a user-configured pool. Assess ECH against the actual engine version.

---

### IC-12. Internationalized names cross the boundary through UTS-46, not IDNA2008

**Behavior.** Host conversion uses WHATWG UTS #46 rather than a separate
IDNA2008 implementation (`../../src/classify-host.cjs`).

**Potential effect.** The mappings differ for some inputs. Whether any such
difference moves a name across the current ICANN/Handshake boundary has not
been tested.

**Status: OPEN.** Compare affected labels with the snapshot before asserting a
specific collision or changing the mapping (HS-14, §2.7).

---

### IC-13. The SSRF guard is not applied to ICANN addresses

**Behavior.** Handshake and HIP-5 addresses pass through `assertPublicAddress`.
Ordinary ICANN navigation does not; the engine resolves and connects.

**Effect.** ICANN hosts resolving to private or loopback addresses are subject
to the engine's own network protections. Wildroot's Handshake guard adds no
protection on this path.

**Status: DELIBERATE.** The guard is not a universal browser address policy.

---

### IC-14. An `http://` link to a numeric-TLD Handshake name is not rewritten

**Behavior.** `rewriteToHns()` returns `null` if `new URL()` rejects an
HTTP(S) URL, including `http://hello.14898/`. The WHATWG numeric-host parser
does not accept that spelling. Typed numeric-name input uses a separate,
experimental convention.

**Effect.** Such a literal link is not repaired by this helper. The original
claim that no engine navigation path can ever deliver it has not been
instrumented (§2.10).

**Status: DELIBERATE** for the current rewrite behavior; reachability remains
an integration question.

---

### IC-15. The obliviousness switch and the resolver pool are configuration-file-only

**Behavior described by the browser integration.** `dns.mode` has a free-text
settings field. `odoh.icann` and `dns.servers` are configuration-file-only.
The Fast/Private switch does not expose those keys.

**Effect.** Disabling the ICANN bridge can leave Private with no resolver.
The panel reports the resulting failed plan, but the switch does not explain
the dependency in advance.

**Status: OPEN.** Use an enum control for `dns.mode` and expose bridge/pool
settings with their fallback and Private-mode effects. Verify the current
browser UI before implementing IC-D3.

---

### IC-16. The resolver's default `lookup` is the OS resolver, in the clear

**Behavior.** `HNSResolver` accepts an injected `lookup`. Without one it calls
`dns.lookup(host, { all: true })` and applies `preferV4` to the returned
addresses (`../../src/resolver.js`). The earlier IPv4-only code sample
predated the IPv6 improvement.

**Effect.** Wildroot's documented composition supplies DoH/ODoH, but a library
integrator omitting the argument uses the OS resolver. Transport privacy then
depends on that resolver's configuration, and the resolution result does not
identify its transport.

**Status: OPEN.** Make `lookup` required, or record which lookup transport was
used so this choice is visible to callers.

---

## 2. Things we are not sure about

The following decisions or measurements remain open.

### 2.1. Whether "ICANN first" should have a visible escape hatch

Should colliding names offer a visible way to request `hns://`? The current
default is ICANN and the explicit scheme is available, but a prompt or saved
preference could introduce new confusion or persistent per-name state.

### 2.2. Whether `/.well-known/odohconfigs` is standardised

Verify the IANA status and authoritative specification for
`/.well-known/odohconfigs`. The original text cites an unverified recollection
of its registration status (IC-8).

### 2.3. Whether replacing the resolver pool is the right failure ordering

Would a mixed list preserve encrypted fallback without sending queries to
plain DoH unnecessarily? Measure template selection and retry behavior before
replacing the current bridge-only list (IC-7).

### 2.4. What the engine does on each kind of DoH failure

Measure transport errors, timeouts, and HTTP-successful DNS SERVFAIL replies
separately. The documented `automatic` fallback policy does not by itself
establish which of these triggers fallback or how long the engine remembers
a failed resolver. Also test secure mode with an empty template list and
existing cache entries.

### 2.5. The ten-minute window and the subdomain rule

`servedRecently()` accepts an exact name or its subdomain within ten minutes.
That can outlive DNS TTLs and does not prove that the current navigation used
the bridge. A lookup for `example.com` does not prove that `a.example.com`
was resolved obliviously. Review the wording or obtain stronger event-level
evidence before treating this heuristic as proof (SPEC §6.2).

### 2.6. Whether the snapshot cadence is adequate

Choose a maximum snapshot age for releases and an update procedure that
works offline. A network drift alarm alone does not enforce freshness.

### 2.7. Whether the IDNA divergence can actually move a name

Enumerate inputs whose UTS #46 and IDNA2008 behavior differs, and test whether
any changes ICANN-set membership. Until then the cross-root effect is a
possibility, not an observed result.

### 2.8. Whether refusing DANE for ICANN names is right

Would a validating ICANN resolver justify adding DANE to this path? Consider
additional authentication, compatibility, and availability effects. Existing
Handshake support alone does not answer that product decision.

### 2.9. Whether a browser should be configuring the resolver at all

Should the browser override the OS resolver, retain a managed network’s
resolver, or discover an encrypted equivalent through DDR? Each changes who
receives DNS queries. The current configuration policy makes that choice at
browser startup.

### 2.10. Whether the engine really cannot issue a numeric-TLD http request

Instrument redirect, main-frame, and subresource paths to determine whether
the engine ever delivers a numeric-TLD HTTP URL that the helper rejects. URL
constructor tests alone do not establish every browser integration path.

## 3. Open design items

Changes we intend or recommend, that are not made. Each names the deviation it
would resolve.

### IC-D1. Lead the resolver pool with the bridge instead of replacing it

**Proposal.** After measuring mixed-list behavior (§2.3–§2.4), evaluate
`servers = [bridge.template, ...servers]` for Fast mode. Private must retain
its bridge-only policy. Check the per-name reporting before claiming that
fallback remained encrypted.

### IC-D3. Put the obliviousness switch and the resolver pool in the settings page

**Proposal.** Provide a checkbox for `odoh.icann`, a resolver-list editor,
and an enum control for `dns.mode`. Explain the bridge's latency and
Private-mode dependency. Use measurements for latency text rather than an
unqualified fixed estimate.

### IC-D4. Give the browser's drift alarm an offline half

**Proposal.** Add the chapter's snapshot format/generation checks to the
browser test suite. Keep the network comparison separate and add a release
staleness check once §2.6's age limit is chosen. Confirm current browser paths
before copying the tests.

## 4. What this chapter leaves out

- **The engine resolver:** cache policy, probing, address selection, and
  failure handling remain engine responsibilities. This chapter specifies
  the plan supplied to it and records unmeasured behavior.
- **Browser composition:** applying the plan, starting the bridge, and reacting
  to delivery-mode changes occur in browser code outside this package.
- **Shared modules:** classification, bridge, transport, certificate, and trust
  helpers live in `../../src/`; they are not duplicated in this chapter.
- **Permission privacy:** the browser's `src/hns/privacy.js` covers permission
  defaults and tracking-parameter removal, rather than DNS policy.
