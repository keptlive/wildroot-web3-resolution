# Deviations, uncertainties and open decisions

Known departures from cited standards, uncertainties, and design decisions,
organized by chapter. Identifiers use chapter prefixes such as `HS-1` and
`IC-3`; open design items use `<prefix>-Dn`.
**This document is generated from the
chapter files by `scripts/build-docs.mjs`; edit those.**

`DELIBERATE` identifies an intentional departure; `OPEN` identifies an
unresolved issue or proposed change. These labels describe project decisions,
not approval by the authors of the cited standards. Remaining inconsistencies
and proposed improvements are listed in [REVIEW.md](REVIEW.md).

## Contents

- [Part II — Namespace selection](#part-ii-namespace-selection) — [chapter file](namespaces/router/DEVIATIONS.md)
- [Chapter 1 — Handshake](#chapter-1-handshake) — [chapter file](namespaces/handshake/DEVIATIONS.md)
- [Chapter 2 — ICANN names](#chapter-2-icann-names) — [chapter file](namespaces/icann/DEVIATIONS.md)
- [Chapter 3 — IPFS, IPNS and DNSLink](#chapter-3-ipfs-ipns-and-dnslink) — [chapter file](namespaces/ipfs/DEVIATIONS.md)
- [Chapter 4 — Arweave](#chapter-4-arweave) — [chapter file](namespaces/arweave/DEVIATIONS.md)
- [Chapter 5 — ENS and `web3://`](#chapter-5-ens-and-web3) — [chapter file](namespaces/ens/DEVIATIONS.md)
- [Chapter 6 — Nostr](#chapter-6-nostr) — [chapter file](namespaces/nostr/DEVIATIONS.md)
- [Chapter 7 — DID, AT Protocol and ActivityPub](#chapter-7-did-at-protocol-and-activitypub) — [chapter file](namespaces/did/DEVIATIONS.md)
- [Chapter 8 — Tor](#chapter-8-tor) — [chapter file](namespaces/tor/DEVIATIONS.md)
- [Chapter 9 — Key-addressed namespaces](#chapter-9-key-addressed-namespaces) — [chapter file](namespaces/keys/DEVIATIONS.md)
- [Chapter 10 — Experimental: HIP-5 `_op` and numeric Handshake TLDs](#chapter-10-experimental-hip-5-op-and-numeric-handshake-tlds) — [chapter file](namespaces/experimental/DEVIATIONS.md)
- [Chapter 11 — Native applications on a Handshake name](#chapter-11-native-applications-on-a-handshake-name) — [chapter file](namespaces/apps/DEVIATIONS.md)
- [Privacy and transport](#privacy-and-transport) — [source file](DIVERGENCE.md)

---

<a id="part-ii-namespace-selection"></a>

## Part II — Namespace selection

_Source: [`namespaces/router/DEVIATIONS.md`](namespaces/router/DEVIATIONS.md)._

This file records routing limitations, product choices, and proposed changes.
`RT-n` identifies an existing deviation; `RT-Dn` identifies a proposal.
Paths refer to the repository root unless stated otherwise.

See [REVIEW.md](REVIEW.md) for contradictions found during the editorial
review. Proposals below do not change the implementation.

### 1. Deviations

#### RT-1. The reserved-name list is broader than the RFCs reserve

**Behavior.** `src/reserved-names.cjs` excludes thirteen final labels from
Handshake. Seven have the IETF status listed in SPEC §7; the additional labels
are `internal`, `home`, `lan`, `corp`, `intranet`, and `private`.

`internal` was reserved by ICANN for private use in 2024; `home` and `corp`
were deferred from the new-gTLD programme. The remaining labels are local
network conventions. These claims require the source checks listed in §2.7.

**Reason and effect.** The extra exclusions prevent local device names from
being sent to a Handshake resolver. They also make those Handshake labels
unreachable through normal classification.

**Status: DELIBERATE.** This list is a client policy, not an IETF reservation list.

---

#### RT-2. `.eth` and `.onion` are carved out by hard-coded suffix

**Behavior.** Literal `.onion` and `.eth` suffix checks run before the lists
(`src/classify-host.cjs`). RFC 7686 supplies the onion requirement. The ENS
exception is a product choice: a name intended for ENS must not reach the
Handshake holder of `eth`.

**Effect.** The Handshake `eth` name is excluded from normal classification.
Other alternative roots, including `.crypto`, `.sol`, `.bnb`, and `.zil`, have
no equivalent exclusion and select Handshake.

**Status: DELIBERATE.** The policy for adding further exceptions is open (§2.3).

---

#### RT-3. A single bare label is a Handshake name

**Behavior.** Bare labels such as `pinner`, `hnshosting`, `bananas`, and `🤝` select Handshake. Numeric names such as `14898` require
the optional numeric-name setting; they are off by default. Labels that are ICANN TLDs (`com`, `org`, `app`,
`blog`, `link`) and inputs containing whitespace select search
(`src/router.js`). No standard specifies this address-bar behavior.

**Reason and effect.** Bare Handshake names are convenient to enter, but
mistyped words become lookups visible to the selected resolver. The suggestion
list offers search as a second choice.

**Status: DELIBERATE** for Wildroot; suitability for other clients is open (§2.2).

---

#### RT-4. `<known-scheme>:<digits>` is always read as a scheme

**Behavior.** A scheme-like token followed by a bare port number is treated
as a host unless the token is registered (`src/router.js`):

```
hasExplicitScheme('example.com:8080') -> false   (host:port)
hasExplicitScheme('hns:8080')         -> true    (scheme hns, path 8080)
```

RFC 3986 supplies the scheme and authority grammars; the input classifier must
choose an interpretation for this shorthand.

**Effect.** A Handshake label sharing a registered scheme name cannot use the
bare `label:port` form. `hns:8080`, `ar:8080`, `search:8080`, and `media:8080`
are interpreted as explicit schemes.

**Status: DELIBERATE.**

---

#### RT-5. The `icann` namespace has no scheme, so a classification and a dispatch disagree

**Behavior.** ICANN names have different namespace identifiers at
classification and dispatch:

```js
classify('example.com').namespace  === 'icann'
namespaceForScheme('https')        === 'web'
```

The `X-Resolution-Namespace` marker follows the scheme table and therefore uses
`web` (SPEC §4.3).

**Effect.** Consumers cannot compare the classification's namespace directly
with the response marker for an ordinary web navigation.

**Status: OPEN.** RT-D2 proposes returning `web` from classification and retaining
`reason: 'icann-tld'`. A host-aware dispatch vocabulary is another option.

---

#### RT-6. None of the schemes we invented is registered, and none uses `web+`

**Behavior.** The scheme registry contains application-defined names without
IANA registration. The status inventory recorded for the 32 schemes is:

| Status | Count | Schemes |
|---|---|---|
| **Permanent** | 2 | `http`, `https` |
| **Provisional** | 11 | `ipfs`, `ipns`, `ar`, `ens`, `web3`, `nostr`, `at`, `did`, `hyper`, `ssb`, `magnet` |
| **Unregistered** | 19 | `hns`, `ipld`, `pubsub`, `activitypub`, `onion`, `https+raw`, `gemini`, `bittorrent`, `bt`, `wildroot`, `agregore`, `browser`, `search`, `paste`, `editor`, `bluesky`, `mastodon`, `media`, `docview` |

RFC 7595 defines registration. The HTML `web+` convention applies to handlers
registered by web pages, rather than native browser schemes.

**Effect.** Unregistered interoperable schemes have no IANA entry that another
implementer can use to identify their owner or specification.

**Status: OPEN** for `hns` (RT-D4); **DELIBERATE** for application-private
schemes. The inventory's registration statuses need periodic verification.

---

#### RT-7. The PAC script carries a second, ASCII-only copy of the host rule

**Behavior.** The router and address bar share `src/classify-host.cjs`. A
WebSocket PAC script cannot import it or use its URL parser, so it embeds the
shared lists and an ASCII-only version of the rule. Chromium supplies the PAC
with already-parsed hosts.

**Effect.** Tests compare the generated PAC with `classifyHost()` using Unicode,
numeric-TLD, malformed-onion, IP-literal, and reserved-name inputs. An untested
divergence can still send a WebSocket outside the Handshake tunnel or cause the
proxy to refuse it.

**Status: OPEN.** Generate the ASCII rule from a shared representation if the
PAC environment continues to require a separate script.

---

#### RT-8. `classify()` returns `javascript:`, `data:` and `file:` untouched

**Behavior.** L1 preserves explicit schemes, including:

```
classify('javascript:alert(1)') -> { scheme: 'javascript', namespace: null, known: false }
classify('data:text/html,x')    -> { scheme: 'data',       namespace: null, known: false }
classify('file:///etc/passwd')  -> { scheme: 'file',       namespace: null, known: false }
```

**Effect.** `classify()` is not a navigation filter. `known` indicates registry
membership; `navigable` is a separate property. The caller still needs a
navigation policy, consistent with the HTML navigation model.

**Status: DELIBERATE.**

---

#### RT-9. ERC-4804's `w3://` short form is deliberately not offered

**Behavior.** `web3` is registered; ERC-4804's `w3` alias is not.
`namespaceForScheme('w3')` returns `null` and dispatch refuses the scheme with
501. A test checks this behavior.

**Reason.** The existing design cites a possible conflict with the Handshake
TLD `.w3`. Whether scheme syntax actually creates that conflict is a review
question; see [REVIEW.md](REVIEW.md).

**Status: DELIBERATE.** This is an ERC-4804 interoperability limitation.

---

#### RT-10. `agregore://` and `browser://` are permanent silent aliases

**Behavior.** `agregore://` and `browser://` serve the same pages as
`wildroot://` and are rewritten to it during navigation. The aliases remain
available for old sessions and links (`src/router.js`).

**Effect.** Schemes have distinct origins. The navigation rewrite is required
to give these pages consistent storage and origin behavior.

**Status: DELIBERATE.**

---

#### RT-11. The IDNA pass fails open

**Behavior.** `asciiTld` uses the URL parser for A-label conversion and retains
the raw final label when parsing fails (`src/classify-host.cjs`):

```js
try {
  const ascii = new URL('http://' + host).hostname
  tld = ascii.split('.').filter(Boolean).pop()
} catch { /* keep the raw tld */ }
```

**Effect.** Invalid or unnormalised input can still select a namespace. This
does not meet SPEC §8.1's fail-closed requirement. The use of WHATWG UTS #46,
rather than IDNA2008, is a separate compatibility question (HS-14).

**Status: OPEN.** RT-D5 proposes returning `null` on failure, or at minimum
reporting `reason: 'idna-failed'`. Numeric-label handling must be considered
before changing this fallback.

---

#### RT-12. The dispatcher's 400 branch is unreachable through a WHATWG `Request`

**Behavior.** Dispatch returns 400 without a namespace marker only when an
input cannot be parsed and has no scheme. WHATWG `Request` rejects such URLs
during construction, so this branch is reached only through a request-like
object with a `url` property, as used by the runtime and tests.

**Effect.** The dispatch interface is wider than WHATWG `Request`. No namespace
marker is possible when no scheme has been established.

**Status: DELIBERATE.**

---

#### RT-13. `hns:` is a standard scheme, and pays the URL Standard's host rule for it

**Behavior.** Electron registers `hns` with `standard: true` to provide tuple
origins and browser storage APIs. Chromium's host parsing then constrains the
labels that an `hns://` URL can carry.

**Effect.** Numeric final labels need the experimental form in Chapter 10,
Part B. SPEC §8.2 gives the classifier's ordering requirement. The relationship
between Electron's custom standard schemes and WHATWG's fixed special-scheme
set needs more precise wording; see [REVIEW.md](REVIEW.md).

**Status: DELIBERATE.** The numeric convention retains its own `NT` deviations.

---

### 2. Things we are not sure about

The following product and interoperability questions remain open.

#### 2.1. Is "everything non-ICANN is Handshake" a defensible default at all?

Should every unreserved, non-ICANN label default to Handshake? This supports
bare Handshake navigation, but a new ICANN delegation changes a label’s meaning
when the bundled snapshot is updated. Requiring an explicit Handshake scheme
would avoid that default at the cost of more input.

#### 2.2. Whether a bare word should navigate (RT-3)

Bare-label navigation discloses mistyped words to the lookup provider. Is
that acceptable when users rely on DoH rather than a local chain node?

#### 2.3. Where the carve-out list should stop (RT-2)

RFC 7686 supports the `.onion` exception. `.eth` is a product choice. The
project has not defined a general criterion for adding `.crypto`, `.sol`,
`.bnb`, `.zil`, or future alternative roots.

#### 2.4. Should a namespace be identified by classification or by scheme? (RT-5)

Should `namespace` identify the input’s naming system or the dispatched
scheme? The classifier uses `icann` while the scheme table uses `web` (RT-5).

#### 2.5. Whether the three-state lock is comprehensible

The TRUSTLESS, TRUSTED, and OPEN indicator states have not been tested with
users. Would two states plus detailed steps communicate the guarantees better?

#### 2.6. Whether `partial` is doing two jobs in the lock

The `partial` verdict includes WebPKI HTTPS, gateway-trusted Arweave,
RPC-trusted ENS, unchecked Gemini TLS, and incomplete Nostr results. The steps
distinguish them; the single indicator does not. Is that grouping useful?

#### 2.7. Citations we have not verified against the source text

The original reference list did not verify the ICANN board actions for
`internal`, `corp`, and `home` against their resolutions. Those claims should
be linked to primary decisions before they are treated as settled provenance.

#### 2.8. Whether `search://` should be a scheme at all

A `search://` origin gives search pages consistent routing and storage, but
also stores queries in history, bookmarks, and restored sessions. The privacy
comparison with ordinary search URLs has not been measured.

### 3. Open design items

These proposals are not normative and have not been implemented.

#### RT-D1. Derive the privileged-scheme declaration from the scheme table

Store scheme privilege metadata alongside `SCHEME_TABLE` and derive the
Electron declaration from it. The current CommonJS/ES-module split can be
handled by a shared `.cjs` data module. As an interim measure, test that every
registered scheme is declared and every declaration has a registry row.

#### RT-D2. Give `icann` a place in one namespace vocabulary

Choose one namespace vocabulary (RT-5). The current proposal is to return
`web` for ICANN hosts and retain `reason: 'icann-tld'`. An alternative is to
make dispatch host-aware. Neither change is adopted here.

#### RT-D4. Register `hns:` with IANA

Prepare a provisional IANA registration for `hns` under RFC 7595, using
SPEC §5 for syntax and the security considerations for its risks. Review the
other unregistered names individually; RT-6’s list includes more than internal
application pages.

#### RT-D5. Make the IDNA pass fail closed

Make parsing failure explicit in `asciiTld` and `classifyHost` (RT-11).
Returning `null` would allow a search result; an `idna-failed` reason would make
the current fallback visible. Check numeric-TLD input before choosing either.

### 4. What this chapter leaves out

- **Electron wiring:** scheme privilege declarations and dispatcher bindings
  remain in the browser. SPEC §4.4–§5 defines their contract.
- **Address bar and PAC integration:** these remain in the browser. The shared
  classifier and local classification corpus are included here (RT-7).
- **Resolution:** namespace chapters define what happens after classification.
- **ICANN DNS policy:** Chapter 2 defines the resolver plan and bridge. This
  chapter defines the trust-reporting contract.
- **Search backend:** engines, result merging, and bang prefixes are outside
  the `search://` grammar specified here.
- **Numeric-TLD URL form:** Chapter 10, Part B defines the experimental form;
  SPEC §8.2 supplies only its classifier constraint.


---

<a id="chapter-1-handshake"></a>

## Chapter 1 — Handshake

_Source: [`namespaces/handshake/DEVIATIONS.md`](namespaces/handshake/DEVIATIONS.md)._

This file records Handshake limitations, product choices, and proposed work.
Entries retain their `HS-n` and `HS-Dn` identifiers. The implementation is in
`../../src/`; its tests are in `../../tests/`.

[REVIEW.md](REVIEW.md) lists contradictions found during the editorial
review. Proposed changes below are not implementation changes.

---

### 1. Deviations

#### HS-1. TTLs are ignored; a flat 60-second positive cache

**Behavior.** Positive resolutions are cached for 60 seconds, regardless of
RRset TTLs. All failure kinds are retried (`src/resolver.js`).

**Effect.** Short TTLs can be exceeded and long TTLs cause unnecessary queries.
RFC 2181 §5.2 defines the TTL rules. Explicit `forget()` invalidation supports
publishing but does not cover updates made elsewhere.

**Status: OPEN.** Use the minimum relevant TTL with agreed bounds; retain the
rule against caching failures (SPEC §6.8).

---

#### HS-2. IPv6: a dual-stack name is reached over IPv4 (resolved 2026-09-06)

**Behavior.** Since 2026-09-06, resolution reads AAAA, GLUE6, SYNTH6, and
hsd's encoded `_synth` referrals. It selects IPv4 when available, otherwise
IPv6 (`src/resolver.js`, `src/spv.js`, `tests/ipv6.test.js`).

**Remaining limitation.** Address selection does not follow RFC 6724 or race
families as in RFC 8305. An IPv6-only client may therefore fail to reach a
dual-stack site. An unreachable IPv6-only nameserver is tried in NS order.

**Status: DELIBERATE** for now. The current transport and trust report carry
one selected address. The claim that IPv4 works from every network conflicts
with this limitation and is tracked in [REVIEW.md](REVIEW.md).

---

#### HS-3. SVCB / HTTPS records are parsed but never queried, and ECH is not usable

**Behavior.** `src/dns-query.js` parses RFC 9460 SVCB/HTTPS records, including
ECH configuration data, but the Handshake resolver does not query type 65.
The raw Node TLS transport has no ECH option available to this implementation.

**Effect.** Handshake site names appear in TLS ClientHello. Published service
parameters such as `alpn`, `port`, and `ipv4hint` are ignored. The separate
Chromium HTTPS path can have different capabilities; IC-11 currently conflicts
with that distinction.

**Status: OPEN.** ECH requires transport support. Query and service-port work
can be evaluated alongside HS-6. Claims about deployment counts and current
runtime support require versioned evidence.

---

#### HS-5. One DANE profile; an unusable TLSA RRset is refused rather than ignored

**Behavior.** Only TLSA `3 1 1` (DANE-EE, SPKI, SHA-256) is supported.
An RRset with no supported matching pin is refused (`src/dane.js`).

**Difference from RFC 7671 §4.1.** The RFC treats an entirely unusable RRset as
absent and permits PKIX fallback. This transport has no PKIX fallback.

**Status: DELIBERATE.** An unsupported-only RRset causes connection failure.
A mixed RRset can still succeed when a supported `3 1 1` record matches.

---

#### HS-6. The TLSA owner is always `_443._tcp`; a port in the URL is ignored

**Behavior.** TLSA is queried at `_443._tcp.<host>`, and site connections use
443 or 80 regardless of the URL port (`src/resolver.js` and browser handler).
RFC 6698 §3 derives the TLSA owner from the actual connection port.

**Effect.** Non-standard site ports are not supported by `hns://`.

**Status: OPEN.** Define URL-port and HTTPS-record port precedence, then derive
the TLSA owner from the port actually dialled. HS-3 covers service records.

---

#### HS-8. A DoH-resolved TLSA is used as a pin, on the resolver's word

**Behavior.** The DoH fallback queries TLSA and uses its answer as a pin.
NODATA permits plaintext; a failed TLSA lookup refuses the connection
(`src/doh.js`). The report identifies the resolver as the source.

**Difference from DANE.** RFC 6698 expects authenticated DNSSEC data; HTTPS
transport to a resolver does not provide that proof.

**Effect.** This retains pinning when the chain path is unavailable, but a
malicious resolver can replace the pin or claim it is absent.

**Status: DELIBERATE.** Persistent memory that a host was pinned is a separate
open proposal (HS-12).

---

#### HS-9. A CNAME target's own RRset is not validated under the target's owner

**Behavior.** A CNAME RRset in a signed zone is validated, including wildcard
proofs, before following it. The target's address RRset is not then validated
under its own owner, as RFC 4035 §5.3.1 describes (`src/resolver.js`).

**Effect.** An ICANN target is resolved through the injected lookup and the
result is reported as unvalidated. A target inside Handshake is not recursively
chased and validated through a complete CNAME chain. Since the expansion is
not fully secure, TLSA remains at the original name (RFC 7671 §7.2).

**Status: OPEN.** Add target-owner validation without changing the reported
limits of the ICANN-target path.

---

#### HS-10. No RRSIG clock-skew tolerance

**Behavior.** RRSIG inception and expiration are checked against the system
clock without skew tolerance (`src/dnssec.js`). RFC 4034 §3.1.5 defines the
window but does not require tolerance. A clock-guard test checks the shared
time source.

**Effect.** An incorrect local clock can make signed zones fail validation.

**Status: DELIBERATE.** Improve diagnostic wording without silently widening
signature validity windows.

---

#### HS-11. Standards not implemented at all

| Standard or feature | Current treatment |
|---|---|
| RFC 9462 DDR | Not implemented; resolver selection is configured. |
| `draft-ietf-dnsop-deleg` | Not implemented. The original allocation and draft-status claims need rechecking. |
| RFC 5011 anchor rollover | The anchor changes through the Handshake chain. Only the REVOKE-bit rule is used. |
| RFC 6891 extended RCODEs; RFC 8914 EDE | OPT is written for DO but not parsed for extended errors. |
| PKIX on `hns://` | Deliberately absent (HS-5). |

**Status: DELIBERATE** for chain-based anchor updates and no PKIX fallback;
**OPEN** for richer DNS error reporting and the other unsupported features.

---

#### HS-12. A DANE mismatch re-resolves once, then fails closed; there is no "pinned before" memory

**Behavior.** A DANE mismatch invalidates the cached resolution and retries
once. A second mismatch refuses the connection. There is no persistent record
that a host previously had a pin.

RFC 7671 §8.1 recommends publishing a replacement TLSA before rotating the
key. The retry accommodates brief publication delay.

**Effect.** If the chain path fails, a DoH resolver's claim of no TLSA can
permit plaintext for a previously pinned host.

**Status: OPEN.** An HSTS-like rule could require authenticated absence before
removing a remembered pin requirement. Persistence, expiry, recovery, and
attacker-induced unavailability need a design (§2.4).

---

#### HS-13. Product decisions that deviate from what the naming systems themselves say

The following are product policies, rather than shared namespace standards:

- ICANN TLDs take precedence during classification even when Handshake has
  records for the same label. An explicit `hns://` request remains separate.
- Other alternative roots, including `.crypto`, `.sol`, `.bnb`, and `.nft`,
  select Handshake unless a specific exception exists.
- `_op` is the supported HIP-5 pseudo-TLD. Other `_<chain>` targets are removed
  from ordinary nameserver discovery; remaining conventional NS records may
  still resolve the name.
- ODoH is implemented with a warning about relay/target non-collusion. Global
  relay-count claims require evidence (REVIEW.md).
- Registry TLD referrals are followed through the bounded walk in SPEC §6.5.

**Status: DELIBERATE.** Namespace policy is defined in the router chapter.

---

#### HS-14. Internationalized names go through the URL parser, not through our own IDNA

**Behavior.** Host conversion uses `new URL(...).hostname`, which implements
WHATWG's UTS #46 processing rather than a separate IDNA2008 implementation.

**Effect.** IDNA2008 and UTS #46 differ for some input. The effect on registered
Handshake labels has not been audited.

**Status: OPEN.** Compare affected labels before choosing a different mapping
or validation policy.

---

#### HS-15. Nameserver failover at query time (resolved 2026-09-06)

**Behavior.** Since 2026-09-06, `_withFailover` tries a zone's nameservers
lazily in order when a query is unreachable, times out, or answers a different
question. Validation failures are returned without trying another server
(`src/resolver.js`, `tests/nameserver-failover.test.js`). RFC 1034 §4.3.2
describes nameserver retry behavior.

**Status: RESOLVED.** Slow servers still consume their full timeout; there is
no parallel race.

---

#### HS-16. Changing the anonymization mode restarts the SPV node, which re-syncs

**Behavior.** hsd reads its proxy setting at startup. A delivery-mode change
restarts a managed node with the new setting; adopted or external nodes are not
restarted. `_nodeIsProxied` describes the running process, not just the desired
configuration (`src/spv.js`).

**Effect.** While headers resync, requests use DoH and are reported as
`unverified`. Private requires an oblivious answer or returns `unreachable`.
Persisted headers shorten the interval; an in-memory node starts again from
scratch.

**Status: OPEN.** Runtime proxy reconfiguration would avoid the resync. Keeping
the chain directory persistent is a smaller mitigation. The composition
**MUST** report fallback answers as DoH rather than chain-proven.

---

### 2. Things we are not sure about

These questions remain open; no change is adopted here.

#### 2.1. SVCB/HTTPS and ECH (HS-3)

Should every address-record navigation query HTTPS records, or can
authenticated evidence of record presence reduce that cost? The latter has
not been designed or tested.

#### 2.2. Registry TLDs that refer, and NS targets that are themselves Handshake names

The resolver follows registry referrals up to `MAX_DELEGATIONS` and validates
DS at each cut. Nameserver address discovery can require an additional chain
lookup. Review its separate recursion bound, cycle handling, and bailiwick
checks together with the total query budget (HS-D1).

#### 2.3. What the DoH fallback actually promises

Infrastructure failures can force Fast-mode requests onto the weaker DoH
path; Private permits only ODoH or refusal. Should previously pinned hosts
retain a stronger fallback requirement (HS-12)? Authoritative chain
`unregistered` results remain final. The user-facing meaning of TRUSTED also
needs evaluation.

#### 2.4. DANE pin rotation windows (HS-12)

One mismatch retry has not been chosen from measured operator rotation
windows. A persistent pin requirement could resist downgrade, but needs
expiry and recovery rules to avoid locking users out of a recovered site.

#### 2.5. What an SPV proof actually proves

The chain proof is verified by local hsd against its most-work header chain.
SPV assumes that chain is valid, and the browser trusts the local process.
During sync, including after a proxy-mode restart, the browser uses DoH. The
interface needs to make this per-load change of evidence understandable.

#### 2.6. Whether a proven absence should raise the lock as far as it does

A signed address plus authenticated TLSA absence is a validated DNS result
with a plaintext site connection. The trust panel must communicate both facts;
the connection remains OPEN. The earlier wording conflated DNS validation
with the aggregate indicator (REVIEW.md).

#### 2.7. What DNSLink interoperation is worth while the gateways it was for retire

DNSLink remains a record convention independently of any public gateway.
The original text cited retirement dates for `ipfs.io`, `dweb.link`, and
Shipyard bootstrap peers without a supporting source. Those claims require
verification (REVIEW.md). Retrieval and bootstrap policy belong to the content
chapters; this chapter specifies the name-to-pointer mapping.

### 3. Open design items

Items considered and not applied. Each states the problem and what we would do.

#### HS-D1. No per-resolution query budget on NS hops

The depth limit and individual timeouts do not bound the total queries in
one resolution. Each zone can need DNSKEY, TXT, DNSLink TXT, A, AAAA, and TLSA;
nameserver discovery adds work.

**Proposal.** Carry a shared query counter through the resolution, including
nameserver address lookups. A proposed cap is roughly 32 queries. Exhaustion
would return `unreachable`, not `unregistered`. Choose the limit from measured
valid resolutions before adopting it.

#### HS-D2. `hns:` has no IANA URI scheme registration

**Proposal.** Seek provisional registration under RFC 7595, using SPEC §5
for syntax and §11 for security considerations. Registration would give other
implementers a registry entry for the scheme. RT-D4 tracks the same work.

### 4. What this chapter leaves out

- **Browser composition:** `src/hns/index.js` selects chain/DoH paths, injects
  `dial`, `lookup`, and fetch, manages proxy mode, connects sites, applies
  pointer policy, and records trust steps. It is not extracted here. Shared
  transport and policy modules are included in `../../src/`.
- **Content fetching:** IPFS, Arweave, Hyper, and BitTorrent retrieval belong
  to their namespace chapters. This chapter ends at the pointer.
- **HIP-5 `_op`:** Chapter 10 specifies the experimental route; this chapter
  gives its entry point and resulting trust step.
- **Browser interface:** rendering is outside this chapter. SPEC §4 and §11.4
  constrain what the interface may report.


---

<a id="chapter-2-icann-names"></a>

## Chapter 2 — ICANN names

_Source: [`namespaces/icann/DEVIATIONS.md`](namespaces/icann/DEVIATIONS.md)._

This file records ICANN routing and transport limitations. `IC-n` identifies
existing behavior; `IC-Dn` identifies proposed work. See
[REVIEW.md](REVIEW.md) for claims that require a technical decision or
runtime evidence.

`../../src/` refers to shared code in this repository. `src/dns-policy.js` and
`src/icann-tld-snapshot.js` refer to this chapter's source. Other `src/` paths
refer to the browser composition, which is not included here.

---

### 1. Deviations

#### IC-1. The ICANN boundary is a build-time snapshot, not a live lookup

**Behavior.** The build-time snapshot is IANA version 2026090500, dated
2026-09-05, with 1,438 labels. It is committed and not fetched at runtime
(`src/icann-tld-snapshot.js`, `../../src/icann-tlds.cjs`).

**Effect.** New or removed delegations can be misclassified until an update
ships. Browser network tests compare the list with IANA; the chapter's offline
test checks its generated form.

**Status: OPEN.** Keep the bundled snapshot, but define its permitted age at
release and enforce it offline (IC-D4, §2.6).

---

#### IC-2. ICANN wins a label that is also a Handshake TLD, and every other alt-root is Handshake's

**Behavior.** ICANN snapshot membership takes precedence for dotted bare
names. Other unreserved suffixes select Handshake, except `.eth` and `.onion`.
An explicit `hns://` request can select Handshake for a colliding name.

**Difference from Handshake.** Handshake permits ICANN holders to claim reserved
labels on chain. Wildroot gives normal web navigation priority rather than
consulting the chain first.

**Status: DELIBERATE.** Whether to expose the explicit-scheme option in the
interface remains open (§2.1).

---

#### IC-3. No DANE for ICANN names

**Behavior.** The session certificate hook defers non-Handshake hosts to
platform WebPKI. It does not query or apply TLSA for ICANN navigation.

**Reason.** The browser does not locally validate ICANN DNSSEC (IC-4). The
Handshake DANE implementation therefore has no authenticated ICANN TLSA path.

**Status: DELIBERATE.** Adding a validating ICANN resolver and DANE support
would be separate work (§2.8).

---

#### IC-4. No DNSSEC validation for ICANN names

**Behavior.** The browser does not validate ICANN DNSSEC replies locally or
configure an ICANN root trust anchor. The engine handles name resolution;
Wildroot's Domain name step relies on the selected resolver.

**Effect.** DNS transport encryption does not produce a `verified` name step.
This statement concerns DNSSEC, not the engine's WebPKI certificate checks.

**Status: DELIBERATE.** RFC 4033/4035 validation would require additional
integration rather than a change to the trust label alone.

---

#### IC-5. The special-use carve-out is longer than the RFCs

**Behavior.** The reserved list includes `internal`, `home`, `lan`, `corp`,
`intranet`, and `private` in addition to the standards-based entries. Matching
the final label covers the entire subtree.

**Effect.** These local-network conventions are kept out of normal Handshake
classification. Their administrative status differs; router SPEC §7 separates
ICANN policy from IETF reservations. RFC 8375 reserves `home.arpa`, not `.home`.

**Status: DELIBERATE.** The list is a client policy broader than the RFC list.

---

#### IC-6. `automatic` falls back to unencrypted system DNS

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

#### IC-7. The oblivious bridge replaces the resolver pool rather than leading it

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

#### IC-8. ODoHConfigs come from a conventional well-known URI, fetched directly from the target

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

#### IC-9. The lookups that make the private path possible are not themselves private

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

#### IC-11. DoT, DDR, SVCB/HTTPS and ECH are not used

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

#### IC-12. Internationalized names cross the boundary through UTS-46, not IDNA2008

**Behavior.** Host conversion uses WHATWG UTS #46 rather than a separate
IDNA2008 implementation (`../../src/classify-host.cjs`).

**Potential effect.** The mappings differ for some inputs. Whether any such
difference moves a name across the current ICANN/Handshake boundary has not
been tested.

**Status: OPEN.** Compare affected labels with the snapshot before asserting a
specific collision or changing the mapping (HS-14, §2.7).

---

#### IC-13. The SSRF guard is not applied to ICANN addresses

**Behavior.** Handshake and HIP-5 addresses pass through `assertPublicAddress`.
Ordinary ICANN navigation does not; the engine resolves and connects.

**Effect.** ICANN hosts resolving to private or loopback addresses are subject
to the engine's own network protections. Wildroot's Handshake guard adds no
protection on this path.

**Status: DELIBERATE.** The guard is not a universal browser address policy.

---

#### IC-14. An `http://` link to a numeric-TLD Handshake name is not rewritten

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

#### IC-15. The obliviousness switch and the resolver pool are configuration-file-only

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

#### IC-16. The resolver's default `lookup` is the OS resolver, in the clear

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

### 2. Things we are not sure about

The following decisions or measurements remain open.

#### 2.1. Whether "ICANN first" should have a visible escape hatch

Should colliding names offer a visible way to request `hns://`? The current
default is ICANN and the explicit scheme is available, but a prompt or saved
preference could introduce new confusion or persistent per-name state.

#### 2.2. Whether `/.well-known/odohconfigs` is standardised

Verify the IANA status and authoritative specification for
`/.well-known/odohconfigs`. The original text cites an unverified recollection
of its registration status (IC-8).

#### 2.3. Whether replacing the resolver pool is the right failure ordering

Would a mixed list preserve encrypted fallback without sending queries to
plain DoH unnecessarily? Measure template selection and retry behavior before
replacing the current bridge-only list (IC-7).

#### 2.4. What the engine does on each kind of DoH failure

Measure transport errors, timeouts, and HTTP-successful DNS SERVFAIL replies
separately. The documented `automatic` fallback policy does not by itself
establish which of these triggers fallback or how long the engine remembers
a failed resolver. Also test secure mode with an empty template list and
existing cache entries.

#### 2.5. The ten-minute window and the subdomain rule

`servedRecently()` accepts an exact name or its subdomain within ten minutes.
That can outlive DNS TTLs and does not prove that the current navigation used
the bridge. A lookup for `example.com` does not prove that `a.example.com`
was resolved obliviously. Review the wording or obtain stronger event-level
evidence before treating this heuristic as proof (SPEC §6.2).

#### 2.6. Whether the snapshot cadence is adequate

Choose a maximum snapshot age for releases and an update procedure that
works offline. A network drift alarm alone does not enforce freshness.

#### 2.7. Whether the IDNA divergence can actually move a name

Enumerate inputs whose UTS #46 and IDNA2008 behavior differs, and test whether
any changes ICANN-set membership. Until then the cross-root effect is a
possibility, not an observed result.

#### 2.8. Whether refusing DANE for ICANN names is right

Would a validating ICANN resolver justify adding DANE to this path? Consider
additional authentication, compatibility, and availability effects. Existing
Handshake support alone does not answer that product decision.

#### 2.9. Whether a browser should be configuring the resolver at all

Should the browser override the OS resolver, retain a managed network’s
resolver, or discover an encrypted equivalent through DDR? Each changes who
receives DNS queries. The current configuration policy makes that choice at
browser startup.

#### 2.10. Whether the engine really cannot issue a numeric-TLD http request

Instrument redirect, main-frame, and subresource paths to determine whether
the engine ever delivers a numeric-TLD HTTP URL that the helper rejects. URL
constructor tests alone do not establish every browser integration path.

### 3. Open design items

Changes we intend or recommend, that are not made. Each names the deviation it
would resolve.

#### IC-D1. Lead the resolver pool with the bridge instead of replacing it

**Proposal.** After measuring mixed-list behavior (§2.3–§2.4), evaluate
`servers = [bridge.template, ...servers]` for Fast mode. Private must retain
its bridge-only policy. Check the per-name reporting before claiming that
fallback remained encrypted.

#### IC-D3. Put the obliviousness switch and the resolver pool in the settings page

**Proposal.** Provide a checkbox for `odoh.icann`, a resolver-list editor,
and an enum control for `dns.mode`. Explain the bridge's latency and
Private-mode dependency. Use measurements for latency text rather than an
unqualified fixed estimate.

#### IC-D4. Give the browser's drift alarm an offline half

**Proposal.** Add the chapter's snapshot format/generation checks to the
browser test suite. Keep the network comparison separate and add a release
staleness check once §2.6's age limit is chosen. Confirm current browser paths
before copying the tests.

### 4. What this chapter leaves out

- **The engine resolver:** cache policy, probing, address selection, and
  failure handling remain engine responsibilities. This chapter specifies
  the plan supplied to it and records unmeasured behavior.
- **Browser composition:** applying the plan, starting the bridge, and reacting
  to delivery-mode changes occur in browser code outside this package.
- **Shared modules:** classification, bridge, transport, certificate, and trust
  helpers live in `../../src/`; they are not duplicated in this chapter.
- **Permission privacy:** the browser's `src/hns/privacy.js` covers permission
  defaults and tracking-parameter removal, rather than DNS policy.


---

<a id="chapter-3-ipfs-ipns-and-dnslink"></a>

## Chapter 3 — IPFS, IPNS and DNSLink

_Source: [`namespaces/ipfs/DEVIATIONS.md`](namespaces/ipfs/DEVIATIONS.md)._

Known deviations, unresolved questions and proposed changes for IPFS identifiers, content pointers and the experimental `car=` origin hint.

Entries distinguish current behaviour from recommendations. Paths beginning
`src/` or `tests/` are relative to this chapter; `../../src/` names shared
modules. Browser paths refer to the Wildroot source tree. Historical line
references may have moved since extraction.

[Chapter specification](namespaces/ipfs/SPEC.md) · [References](namespaces/ipfs/REFERENCES.md)

---

### 1. Deviations

#### IP-1. Two multibases, not the table

**What.** The CID a pointer or an `ipfs://` host may carry is tested against one
regular expression, `CID_RE` in `../../src/pointers.js:86`:

```js
/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,110})$/
```

That is base58btc CIDv0, or base32 CIDv1, and nothing else.

**The standard says.** The [multibase](https://github.com/multiformats/multibase)
table has a couple of dozen prefixes, and the
[CID specification](https://github.com/multiformats/cid) makes a CIDv1 legal in
any of them.

**Why.** The implementation uses a bounded shape check for the two supported
CID encodings. It does not decode the multihash.

**Consequence.** A CIDv1 written in base36 (`k…`), base16 (`f…`), base58btc
(`z…`) or base64 is refused: as an `ipfs=` pointer, as an `ipfs://` host, as the
CID a `car=` origin is matched against, and as a pasted bare CID. The
inconsistency is inside one file — `IPNS_RE` (line 93) *does* accept base36,
because that is what `ipfs name publish` prints — so the two address spaces of
one namespace disagree about which bases exist.

**Status.** `OPEN`. Decode the address with `CID.parse` inside a `try` and
return its canonical string form, rather than widening the regular expression:
that fixes the inconsistency and the round-tripping in one move, and
`multiformats` is already a dependency (`../../src/contenthash.js` calls
`CID.decode`). Keep a cheap length bound in front of the parse so a hostile
string cannot make the decoder work, and re-run the negative cases in
`tests/ipfs-url.test.js` — a widening must not let the three drift shapes
through. See IP-D4.

#### IP-2. The CID shape exists three times

**What.** `CID_RE` is shared, and two private copies live in the Wildroot tree:
`src/hns/ipfs.js:38-39` and `src/pastebin-url.js:20-21`, each a
`CIDV0_RE`/`CIDV1_RE` pair.

**The standard says.** Nothing — this is an internal consistency requirement,
and it is the mechanism behind SPEC §12.1: one address shape, in one place.

**Why.** History. A guard test exists — `../../tests/publish-pointers.test.js`,
"nobody keeps a private CID regex" — but it looks for the *specific* shape the
copies it was written against had (`[a-z0-9]{46,`), so these two, which are
written differently and are currently equivalent, pass it.

**Consequence.** The copies currently agree, but a future change can leave
modules accepting different forms or lengths.

**Status.** `OPEN`. Have `src/hns/ipfs.js` and `src/pastebin-url.js` import
`CID_RE`, then widen the guard from the one string the last drift happened to
use to the shape of *any* CID matcher — assert that no file outside
`pointers.js` contains a regular-expression literal matching `/Qm\[|\[a-z2-7\]\{/`.
See IP-D3.

#### IP-3. IPNS records are not validated here

**What.** An `ipns://` host and an `ipns=` value are checked for *shape* and
handed to the local IPFS node. The signature check, the sequence-number
comparison and the validity window are the node's; this stack does not implement
them and does not see their results.

**The standard says.** The
[IPNS record specification](https://specs.ipfs.tech/ipns/ipns-record/) defines a
signed record with a value, a sequence number and a validity period, and how a
resolver chooses between two records for the same key.

**Why.** Doing it here means running a libp2p stack, a DHT client and a record
store inside the resolver — which is the daemon this implementation already
ships, twice over.

**Consequence.** Everything an implementation of this chapter can say about an
`ipns://` answer is second-hand. It cannot report which sequence number it got,
whether the record was near expiry, or whether the answer came from a cache. A
stale-but-validly-signed record is indistinguishable here from a fresh one.
*"An IPNS name is a signed pointer"* is true and is the most that can be said.

**Status.** `DELIBERATE`. The node owns record validation. The unresolved
question is how much freshness and cache metadata it exposes (§2.3).

#### IP-5. A URL host is canonicalised; two of our address forms are case-sensitive

**What.** All four schemes are registered as **standard** schemes in the Wildroot
tree (`src/main.cjs`, `P2P_PRIVILEGES.standard = true`), and a standard scheme's
host is lowercased by the URL parser. Meanwhile a CIDv0 (`Qm…`) is base58btc, a
legacy IPNS key (`Qm…`) and a modern peer ID (`12D3Koo…`) likewise, and a
`pubsub://` topic is arbitrary text. A CIDv1 in base32 and an IPNS key in
base32 or base36 are already lowercase and are unaffected.

**The standard says.** The [WHATWG URL Standard](https://url.spec.whatwg.org/#host-parsing)
lowercases the host of a special (registered, standard) scheme.
[draft-msporny-base58](https://datatracker.ietf.org/doc/html/draft-msporny-base58)
defines base58btc as case-sensitive.

**Why.** `standard: true` is what buys origins, `fetch`, service workers and
secure-context features for these schemes. It is the same trade the spine
records for `hns://` in its §5: a standard scheme cannot opt out of the URL
Standard's host handling.

**Consequence.** A *navigated* `ipfs://Qm…`, `ipns://Qm…`, `ipns://12D3Koo…` or
`pubsub://MixedCase` is expected to arrive at the handler with its host
lowercased and therefore broken. A CID is protected on the path that matters
most — a pasted bare CIDv0 is re-spelled as its base32 CIDv1 form before it
becomes a URL (SPEC §3) — and a CID reached through a Handshake `ipfs=` pointer
never becomes a URL host at all. An `ipns=` pointer builds `ipns://<key>` inside
the main process (the Wildroot tree's `src/hns/index.js:443`), where Node's
parser applies and preserves case, so it is probably unaffected. `pubsub://` and
a typed peer-ID IPNS key are the exposed cases, and neither is re-spelled.

**Status.** `OPEN`, and **unmeasured** — the paragraph above is reasoning, not a
measurement, and §2.2 says what would settle it. The fix is not obvious either:
lowercasing is correct behaviour for a standard scheme, so the choices are to
re-spell every address into a case-insensitive multibase before it goes in a
host (which works for a CID and for an IPNS key, and not for a topic), to accept
that a topic containing an uppercase letter is unaddressable, or to carry the
address somewhere other than the host. Measure first (IP-D8).

#### IP-6. No HAMT-sharded directories

**What.** `directoryCid` (`src/cid.js`) refuses a folder whose basic directory
node would exceed kubo's 256 KiB HAMT threshold, with `NOT_SUPPORTED`.

**The standard says.** [UnixFS](https://github.com/ipfs/specs/blob/main/UNIXFS.md)
defines `HAMTDirectory`, and kubo shards a directory past that threshold.

**Why.** `directoryCid` must agree with kubo. An unsharded result would name
a different DAG from the published one.

**Consequence.** A very large folder cannot have its CID computed locally before
it is published.

**Status.** `DELIBERATE`. Unsupported directory layouts are refused.

#### IP-7. The CAR header is decoded by a minimal reader

**What.** The Wildroot tree decodes a CARv1 header with `@ipld/dag-cbor`. That
package is not a dependency of this one, so `src/car-roots.js` carries a
~90-line CBOR reader for the header's fixed shape: unsigned integers, byte
strings, text strings, arrays, maps and tag 42, and a refusal for everything
else including the indefinite-length forms dag-cbor forbids.

**The standard says.** [DAG-CBOR](https://ipld.io/specs/codecs/dag-cbor/spec/)
defines the encoding and requires canonical map ordering on encode.

**Why.** The extracted package does not depend on `@ipld/dag-cbor`; the
small header reader can be tested independently.

**Consequence.** One file is not byte-identical to its Wildroot counterpart,
which is the property this package holds every other source file to. The reader
also does not check dag-cbor's canonical map ordering — neither does
`@ipld/dag-cbor` on decode, so nothing is lost against the original.

**Status.** `DELIBERATE`, and bounded: cross-checked against the real
`@ipld/dag-cbor` encoder over nine header shapes — zero, one, two and three
roots, CIDv0 and CIDv1 roots, `version: 1` and `version: 2`, and a 300-root
header that exercises the two-byte length form — and pinned in
`tests/car-roots.test.js` against the bytes that encoder produced.

#### IP-8. The archive-root check is a claim check

**What.** After a warm fetch, `src/origin-warm.js:179` asserts that the CID being
warmed is among the roots the archive names. Those roots come from the archive's
**own header** (the Wildroot tree's `src/hns/ipfs.js`, `importCar`), not from the
node.

**The standard says.** [CARv1](https://ipld.io/specs/transport/car/carv1/): the
header's `roots` list is written by whoever wrote the archive. It carries no
authentication of its own.

**Why.** It is a cheap, useful check against a misconfigured or confused origin
— the case where a provider hands back the wrong object.

**Consequence.** Nothing, as long as nobody mistakes it for security. A hostile
origin writes the header, so it can claim any root it likes. The actual
protection is elsewhere and is complete: every block is hash-checked on import,
the import is unpinned and bounded, and the page is then served by asking the
node for the resolved CID (SPEC §12.2). The `importCar` docstring in the
Wildroot tree overstates this check (IP-D5).

**Status.** `DELIBERATE`. Section 2.5 considers whether the diagnostic value
justifies the risk of confusing the check with authentication.

#### Experimental: `car=` and origin warming

The three items below are deviations inside SPEC §8, which is marked
EXPERIMENTAL: it ships in the reference browser, it is a local convention with
no standing outside it, and its behaviour may change.

#### IP-9. `car=` accepts more than it writes, and more than the decision allows

**What.** The writer only ever produces the gateway form `<site>/ipfs/<cid>`
(the Wildroot tree's `src/publish.js:515,662`). The reader does not: `parseOrigin`
(`../../src/pointers.js:133`) accepts any absolute `https:` URL under 480 bytes,
and `src/origin-warm.js:203` has a branch for an origin that is not a gateway —
fetch the whole archive or nothing.

**The standard says.** No published standard says how a name announces a
location for a CID; the
[trustless gateway](https://specs.ipfs.tech/http-gateways/trustless-gateway/)
specification gives the URL *shape* and
[IPIP-402](https://github.com/ipfs/specs/blob/main/ipips/ipip-0402.md) gives the
window parameters. The governing decision here is local: **D-P2** in
`STORAGE-PUBLISH-SHARE.md`, as amended, is gateway-form only.

**Why.** The non-gateway branch was written first, for a provider share link — a
bearer URL to one object — before the gateway form was settled on.

**Consequence.** Two things. A name may state an origin that cannot be windowed,
so a large archive behind it is fetched whole or not at all, which is the worst
case for the media seeking the windowing exists to make work. And the published
grammar is looser than the decision, so a third-party implementation reading
this chapter cannot tell which one it must support.

**Status.** `OPEN`. Tighten `parseOrigin` to require the `…/ipfs/<something>`
shape and delete the whole-archive branch that becomes unreachable, or amend the
decision back and state in SPEC §8.1 that a non-gateway origin is
fetch-whole-or-nothing. Either is defensible; the divergence between the two is
not. See IP-D2.

#### IP-10. A vendor gateway is named in a resolution path

**What.** `src/origin-warm.js:42-44` maps `<label>.pinthis` to
`https://pinthis.cloud` — a name-to-provider table in the code.

**The standard says.** Nothing directly; SPEC §8.1 permits such a table and
**SHOULD NOT**s adding entries, because each one names a company in a resolution
path.

**Why.** It predates `car=`. For a `.pinthis` name the browser already knows
where the bytes are, because the same service resolved the name a moment ago, so
no new party learns anything.

**Consequence.** One company's gateway is named in a resolution path, for one
TLD. The general mechanism has since made it unnecessary for any name published
after `car=` existed, and a stated origin already wins over the table when both
are present (`src/origin-warm.js:200`).

**Status.** `OPEN`, and transitional: it is deleted once the names that predate
`car=` have been re-published with a stated origin, and not before — deleting it
first breaks names that have no other way to say where their bytes are. See
IP-D7.

#### IP-11. The windowing policy is ours

**What.** The 2 MiB slice at the seek point, the 16 MiB aligned window completed
in the background, the read-ahead when a read lands in a window's last quarter,
the 64 MiB whole-archive cap and the 45-second first-byte deadline.

**The standard says.**
[IPIP-402](https://github.com/ipfs/specs/blob/main/ipips/ipip-0402.md) says how
to *ask* for a byte range of a DAG. It says nothing about when to, or how much.

**Why.** They are the numbers that make a seek in a large media file answer
promptly without pulling the whole archive, measured against the archives this
implementation serves.

**Consequence.** An implementation that picks different numbers interoperates
fine — the parameters on the wire are IPIP-402's either way — but will feel
different, and nothing in a published standard adjudicates.

**Status.** `DELIBERATE`, inside the EXPERIMENTAL section. The numbers are
engineering. The parts worth defending are normative and stated as such in SPEC
§8.2: never pin a partial DAG, bound the response whether or not the gateway
honoured the range, and every block still arrives hash-checked.

### 2. Things we are not sure about

#### 2.1. Whether a stated origin is the right primitive at all (IP-9)

`car=` announces an HTTPS location for a CID. Its retrieval and verification
boundaries are defined in SPEC §12.2; the unresolved questions concern its
record format:

- Should the record be a full URL, or a provider identifier plus a well-known
  path?
- A gateway-form URL contains the CID, so **the record is rewritten on every
  publish** — exactly the cost DNSLink-over-IPNS exists to avoid. A form naming
  only the gateway (`car=https://host/ipfs/`) would be stable, and a prefix that
  is not a complete URL is a new thing to specify.
- A share capability with an expiry, which is what some providers issue, needs
  renewal, and nothing in the record says when it expires.
- Is `car` the right tag, given the value is a gateway URL and not a `.car` file?

IPIP-402 and the trustless-gateway specification define request URLs but do
not define this name-to-location announcement.

#### 2.2. Whether host canonicalisation actually breaks the case-sensitive forms (IP-5)

The reasoning is in IP-5 and it is only reasoning. What would settle it is one
navigation each to `ipfs://Qm…`, `ipns://12D3Koo…` and `pubsub://MixedTopic` in
the shipping browser, and a look at the URL the handler receives. Until that is
run, IP-5's consequence paragraph is a prediction.

#### 2.3. What delegating IPNS to the node actually gives us (IP-3)

The node's stale-record, expired-record and offline-cache behaviour has not
been established here. Those limits are needed to describe the freshness of a
delegated IPNS result.

#### 2.4. Whether `ipns://<domain>` (DNSLink through the node) works at all

This is the open remainder of the DNSLink story. The resolver reads DNSLink
itself, on both routes, for a name resolved through this stack (SPEC §6.3).
What is unknown is the *node-side* reader: kubo resolves a DNSLink when an IPNS path names a domain rather than a
key, and `ipns://example.com` is a URL a user can type. The reference
implementation sets `DNS.Resolvers: {}` on both daemons, deliberately, because
the "auto" value meant DoH queries to third parties. What that empty value
leaves — the system resolver, or nothing — is untested, and there is no test for
`ipns://example.com` in either tree.

Two outcomes, and we do not know which we have: the scheme resolves domains
through whatever DNS the daemon's host provides (a plaintext query this stack
did not choose and does not report), or it resolves nothing and the URL form is
dead. Both are worth knowing and neither is what a reader of §4.2 would assume.
A third option exists once it is measured — resolve the domain in this stack,
where the record is read under stated rules, and hand the node a key — but there
is no point designing that before the measurement (IP-D8).

#### 2.5. Whether the archive-root check should exist (IP-8)

The CAR-root check detects operator mistakes but does not authenticate the
archive. Removing it would simplify the verification description while losing
a diagnostic for an unrelated archive.

#### 2.6. Whether a pointer's precedence should be fixed at all

Fixed precedence selects `ipfs=` even when an accompanying `ipns=` is newer.
The publisher cannot express a preference for the mutable pointer. It remains
unclear whether this occurs in practice.

---

### 3. Open design items

#### IP-D2. Tighten the `car=` grammar to the decision it implements

`parseOrigin` accepts any absolute `https:` URL under 480 bytes while decision
D-P2 and the writer both say gateway-form only, and `src/origin-warm.js` carries
a whole-archive branch for the difference (IP-9). A published grammar broader
than its decision cannot be implemented from this chapter.

**Recommendation.** Tighten `parseOrigin` to require `…/ipfs/<something>`,
delete the whole-archive branch that then becomes unreachable, and promote the
rule in SPEC §8.1 from a description to a normative **MUST**. If the loose form
is wanted instead, amend D-P2 and say in SPEC §8.1 that a non-gateway origin is
fetch-whole-or-nothing. Either resolves it; leaving the two apart does not.

#### IP-D3. One CID shape, and a guard that catches any copy

`src/hns/ipfs.js` and `src/pastebin-url.js` each keep a private `CIDV0_RE`/
`CIDV1_RE` pair, and the guard test that exists looks for the specific literal
the last drift used, so both pass it while being copies (IP-2).

**Recommendation.** Import `CID_RE` in both files, then widen the guard to the
shape of any CID matcher — no regular-expression literal matching
`/Qm\[|\[a-z2-7\]\{/` outside `pointers.js` — rather than the one string that
happened to appear last time.

#### IP-D4. Decode CIDs instead of shape-matching two multibases

`CID_RE` accepts base58btc CIDv0 and base32 CIDv1 and refuses every other
multibase, while `IPNS_RE` in the same file accepts base36, so the two address
spaces of one namespace disagree about which bases exist (IP-1).

**Recommendation.** Parse with `CID.parse` inside a `try` and return the CID's
canonical string form, so a pointer round-trips to one spelling however it was
written. `multiformats` is already a dependency and `../../src/contenthash.js`
already calls `CID.decode`. Keep a cheap length bound in front of the parse, and
re-run the negative tests in `tests/ipfs-url.test.js`: this is a widening, and
the three drift shapes must still fail.

#### IP-D5. Correct the comment that calls the archive-root check a verification

The Wildroot tree's `src/hns/ipfs.js:1031` says the roots come from the archive's
own header *"so the caller can verify it got the DAG it asked for"*. The header
is written by whoever wrote the archive, so the check catches a confused origin
and not a hostile one; the real protection is stated correctly three lines above
it and in SPEC §12.2 (IP-8).

**Recommendation.** Rewrite it to say what it does: the caller can tell whether
the archive **claims** the DAG it asked for — a check against a confused origin,
not a hostile one — and the hash check on every block is what makes a hostile one
harmless.

#### IP-D6. Correct the error page that tells a user IPFS names work while anonymised

The A-record branch's own refusal page in the Wildroot tree
(`src/hns/index.js`) ends with *"Names served from IPFS or Arweave work
normally."* Arweave does — it rides the proxied session fetch. IPFS does not:
the `ipfs` branch above refuses with `503` under exactly that condition, and so
does the `ipns`/`bittorrent`/`hyper` branch. The sentence is shown to a user at
the moment they are trying to understand what anonymisation blocks, which makes
it worse than a stale code comment: it is a wrong statement about the gate,
delivered by the gate.

**Recommendation.** Say what is true — Arweave and other HTTPS-fetched content
work; anything served over the local node's libp2p connections (IPFS, IPNS,
BitTorrent, Hyper) is blocked, for the reason in SPEC §12.4 — and pin the page's
claim with a test, since it is the only place this policy is explained to
anybody.

#### IP-D7. Delete the hard-coded `.pinthis` gateway table

`src/origin-warm.js:42-44` maps one TLD to one company's gateway (IP-10). `car=`
generalises it, and the code already prefers a stated origin when both exist.

**Recommendation.** Re-publish the names that predate `car=` so they state their
own origin, then delete `ORIGINS` and the `originFor` branch that reads it.
Until those names are re-published, leave it: deleting it first breaks names
that have no other way to say where their bytes are.

#### IP-D8. Two measurements this chapter cannot make

Both need a running browser or a running daemon, which this package deliberately
does not have, so both belong in the Wildroot tree's live suite.

1. **Host canonicalisation (IP-5, §2.2).** Navigate the shipping browser to
   `ipfs://Qm…`, `ipns://12D3Koo…` and `pubsub://MixedTopic` and log the URL the
   handler receives. If the host arrives lowercased, those address forms are
   unreachable as URLs and IP-5 becomes a fact rather than a prediction.
2. **`ipns://<domain>` (§2.4).** With `DNS.Resolvers: {}` set on both daemons,
   does kubo still resolve a DNSLink, and if it does, through which resolver?
   There is no test for it in either tree. The question is not whether this
   stack can read a DNSLink — it reads one directly (SPEC §6.3) — but whether
   the `ipns://<domain>` URL form works and whether it makes a DNS query nobody
   declared.

**Recommendation.** Write both, in that order. The first decides whether SPEC
§4.2 and §4.4 state a hazard or a defect; the second decides whether
`ipns://<domain>` is a supported form, an undeclared plaintext lookup, or a URL
that should be refused.

#### IP-D9. Let a stated-origin name load while anonymised, by stopping the node routing

The `car=` warm is already the private half: it is an HTTPS fetch through the
injected, proxied fetch, and every block it imports is hash-checked, so a name
with a stated origin could be served under anonymisation with no peer-to-peer
traffic at all. What keeps the `ipfs=` gate in place is the **node**, not the
fetch (SPEC §12.4): a kubo holding blocks announces them, publishing provider
records for exactly the content just read from the real address, and serving the
page also means asking that node for the CID.

**Recommendation.** Make the node stop routing while anonymisation is on —
`Routing.Type: none`, kubo's offline routing, in place of the `--routing=dhtclient`
the daemon is started with — so it neither queries the DHT nor announces what it
holds, and then serve a name that has a usable stated origin (and only such a
name) from the imported blocks. Three things have to be settled before it
ships, and none of them is the code: whether the setting can be changed without
respawning the daemon (it is repo configuration, so probably not — which makes
this the same restart-cost question the SPV node has), what a name **without** a
stated origin does in that mode (refuse, as now, is the answer), and
whether a node that has been offline-routing must re-announce afterwards, which
would leak on a delay instead of immediately. A gate removed on the strength of
"the fetch is proxied" alone would be a regression, and the divergence inventory
row that proposes this (`../../DIVERGENCE.md`, row 9) should not be read as
authorising that.

---

### 4. What this chapter leaves out

1. **Retrieval, both daemons.** The `ipfs://` handler
   (`src/protocols/ipfs-protocol.js`) is Electron-bound — it takes a `session`,
   registers a protocol handler and manages an `ipfsd-ctl` daemon lifecycle. The
   `hns://` node (`src/hns/ipfs.js`) spawns and adopts a kubo process, writes its
   config, and streams ranged reads over its HTTP RPC. Neither is resolution.
   Two pure functions are lifted out of the second — `parseByteRange`
   (`src/byte-range.js`) and `carRoots` (`src/car-roots.js`) — because the
   resolution half genuinely depends on them; nothing else is.
2. **`js-ipfs-fetch`'s semantics for `ipld://` and `pubsub://`.** The re-encoding
   an `Accept` header triggers, and the event-stream form of a pubsub
   subscription, are that library's, cited in `REFERENCES.md` and not
   respecified.
3. **The kubo-identity tests.** Four tests in the Wildroot tree spawn the bundled
   kubo binary and compare its `ipfs add` output to `src/cid.js` over fresh
   fixtures, including the 174-link boundary and a depth-3 tree. They need a
   60 MB binary this package does not depend on, so they stay there. What is here
   instead is the pinned vectors those tests produced, which prove agreement on
   the cases someone thought to freeze and not on every input.
4. **Everything after the bytes arrive** — content-type sniffing, directory
   listing pages, media handling, the conversion pipeline. None of it is
   addressing.
5. **The write path.** How an `ipfs=` record is published, an IPNS key created or
   an archive uploaded is a different problem with a different threat model
   (SPEC §1.1).


---

<a id="chapter-4-arweave"></a>

## Chapter 4 — Arweave

_Source: [`namespaces/arweave/DEVIATIONS.md`](namespaces/arweave/DEVIATIONS.md)._

Known deviations, unresolved questions and proposed changes for Arweave identifiers, gateway retrieval and verification limits.

Entries distinguish current behaviour from recommendations. Paths beginning
`src/` or `tests/` are relative to this chapter; `../../src/` names shared
modules. Browser paths refer to the Wildroot source tree. Historical line
references may have moved since extraction.

[Chapter specification](namespaces/arweave/SPEC.md) · [References](namespaces/arweave/REFERENCES.md)

---

### 1. Deviations

<a id="ar-1-the-bytes-are-verified-against-the-transaction-for-a-top-level-transaction-under-8-mib-resolved-2026-09-06-with-a-stated-limit"></a>

#### AR-1. Conditional body checks and the remaining authentication gap

*SPEC §9 · `src/ar.js`, `src/ar-merkle.js`*

**Current behaviour.** Since 2026-09-06, the handler compares eligible response
bodies with a gateway-supplied `data_root`. The header's signature must first
hash to the txid. A body is eligible when the request has no path or range,
the header's declared size is at most 8 MiB, and the buffered body has exactly
that size. A root mismatch returns 502; a match returns
`X-Arweave-Verified: bytes`.

**Limits.** A length mismatch is reported as `header` so gateway-rendered index
pages can be served. Large declared transactions, ranges, manifest paths and
bundled items without a top-level header remain unchecked. The body is buffered
before its length is compared; 8 MiB is a declared-size threshold, not a bound
on a hostile response.

**Authentication gap.** `headerMatchesId()` hashes the signature bytes but does
not verify that the signature covers the supplied header fields. Changing
`owner`, `data_root`, `data_size` or `tags` while preserving `signature`
does not change the result. The conditional body check therefore establishes
agreement with the supplied root, not the complete binding to the Arweave id.

**Status: PARTIALLY IMPLEMENTED.** The small-body comparison is implemented.
Header authentication, bounded response buffering, larger-body verification and
bundled-item verification remain open. The resolution-time trust panel stays
`unverified` / `partial`; the response header reports the fetch check. See
[REVIEW.md](REVIEW.md) and AR-D1.

---

#### AR-2. `ar://` is a de-facto scheme with no registration

*SPEC §4.1 · `src/ar.js`, `../../src/contenthash.js`, `../../src/router.js`*

**What.** We use `ar://<txid>` because ar.io gateways and the Wander (formerly
ArConnect) wallet do. There is no RFC, no IANA URI-scheme registration, and no
normative grammar anywhere for us to conform to.

**The standard says.** RFC 3986 §3.1 defines the syntax of a scheme name;
RFC 7595 §3 sets out the guidelines and the IANA registration procedure for a
new URI scheme, including a provisional registration for exactly this kind of
established-but-unregistered convention. `ar` appears in no IANA registry.

**Why.** The handler follows the existing ecosystem URL form.

**Consequence.** Interoperability depends on convention. A future ecosystem
standard may require updating the URL form. The case-preserving parsing rule
is specified in SPEC §4.2.

**Status: DELIBERATE.** This project follows the ecosystem convention and
does not propose its own scheme registration.

---

#### AR-3. An `arweave` resolution is cached for a flat 60 seconds

*Spine `../../DEVIATIONS.md` D-1 · `../../src/resolver.js` `CACHEABLE`*

**What.** `CACHEABLE` includes `'arweave'`, so a name that resolves to an
Arweave pointer is remembered for 60 seconds and the record's TTL is ignored,
exactly as for every other positive resolution.

**The standard says.** RFC 2181 §5.2 and RFC 1035 §3.2.1: the TTL is the
authoritative server's statement of how long an RRset may be cached, and a
resolver honours it.

**Why.** Inherited from the spine's D-1; no Arweave-specific decision was made.

**Consequence.** The transaction id is immutable, but the name-to-id binding
can change. Caching that binding still needs the authoritative TTL. Local
republishing calls `forget()`; that does not invalidate other clients' caches.

**Status: OPEN in the shared resolver.** The flat positive-cache policy is
tracked as D-1 in the Handshake deviations. Arweave does not define a separate
cache policy.

---

### 2. Things we are not sure about

The questions below remain unresolved.

#### AR-U1. Is delegating manifest resolution to the gateway defensible at all?

SPEC §7: the client never parses a manifest. It appends the path and lets the
gateway map it to a transaction id.

The argument for: gateways implement the manifest specification — including
whatever version and fallback behaviour is current — and a client that
reimplements it will be subtly behind. The argument against: it makes the
**path→id mapping** gateway-trusted on top of the bytes being gateway-trusted,
and it means the multi-gateway failover of §6.1 carries no cross-check
whatsoever, because the client never learns which id a gateway resolved a path
to. This is also exactly why the header check is skipped for a manifest path
(SPEC §9.1.1): there is no single transaction the second gateway could be asked
about, so a site served through a manifest — which is most published sites — gets
the weakest form of every guarantee in this chapter. Even a client that verified
bytes (AR-1) would still be trusting the mapping.

The choice is between client-side manifest parsing and continued delegation
with an explicit trust limit.

#### AR-U2. We have not verified the manifest version 0.2.0 clauses

The canonical Arweave repository schema document specifies
`"version": "0.1.0"`, an `index` object whose `path` must be a key of `paths`,
and a `paths` object of `{ id }` values. Version **0.2.0** — `index.id`, and a
`fallback` — is an ar.io-side extension, and we were unable to retrieve a
document for it. Since the implementation reads neither version, nothing turns
on it; we flag it so that a future manifest reader does not start from this
chapter's summary as though it were checked.

#### AR-U3. What should an `ar://`-adjacent ArNS implementation look like?

SPEC §8: ArNS is not resolved. If it were, it could not simply reuse this
chapter, because the failover rule of §6.2 is safe **only** because an
identifier is immutable. An ArNS name is mutable and its current value lives in
an ANT contract on another chain; two gateways answering differently for a name
is a legitimate state (one is stale), not evidence of tampering, and the client
has no way to tell which. A correct ArNS client probably has to read the ANT
itself, which makes it a chain-reading namespace like HIP-5 `_op` and not a
gateway-fetching one like this.

The documentation should also distinguish ArNS durability claims from the
ordinary DNS and CA authentication used for `<label>_persist.ar.io`.

#### AR-U4. Is one hardcoded gateway list the right shape?

`AR_GATEWAYS` is three hosts, frozen, in a fixed order, with a stated criterion
and a review date (SPEC §6.1). The first still sees nearly every request
(SPEC §11.2, §11.5). Alternatives we have not evaluated: randomizing the order
(spreads disclosure, defeats caching and makes failures non-reproducible);
reading the ar.io gateway registry at runtime (a larger, more current set — and
a new trusted source to bootstrap from); letting the user choose. The
configuration passthrough that would make the list changeable is itself
unfinished — AR-D2.

#### AR-U5. Should an `ar=` pointer close the padlock at all?

What ships: the content step is `unverified`, so the aggregate verdict is
`partial` and never green; and the padlock **closes** in the neutral *trusted*
colour on the chain proof alone, without a DANE pin, on the reasoning that the
bytes arrive over ordinary HTTPS from a TLS-authenticated host — the same
transport an `https://` page has, which this model also calls
*trusted-but-not-trustless* with a closed lock (SPEC §9.2, `../../SPEC.md` §4).

The part we are sure of is the step: `unverified` is not in doubt, and no
Arweave step may borrow the content-addressed sentence. The part we still argue
about is the lock. Against the current choice: the user is being shown the same
lock for "a CA vouched for this host" and for "a chain proved this binding and
then nobody checked the bytes", and the difference lives only in a panel most
people will not open. For it: an open lock would say *less* than the truth,
since the transport really is authenticated HTTPS and the content really is
immutable, and reserving the open lock for genuinely unauthenticated transports
keeps that signal meaningful. We would like other implementers to argue with
us.

---

### 3. Open design items

#### AR-D1. The `data_root` half of the cheap check

The small-body Merkle comparison is implemented (AR-1). The original proposal
for a 4 MB threshold is superseded by `MAX_VERIFY_BYTES = 8 MiB`.

**Remaining work.** Verify the transaction signature over its fields before
treating `data_root` as authenticated. Bound response buffering independently
of the gateway-supplied size. Define verification for larger transactions,
bundled items and manifest mappings.

Cross-gateway byte comparison can detect disagreement, but agreement is not a
cryptographic proof. Keep that distinction in any future response-header or
trust-panel change. [REVIEW.md](REVIEW.md) records the decisions needed.

#### AR-D2. `Config.arOptions` has no schema, default or validation

The composition layer spreads `...(Config.arOptions || {})` straight into
`createArHandler`, so an rc file can replace the gateway list — but there is no
schema, no documented default, no validation and no settings UI. In practice
the list is compiled in, and a typo in an rc key fails silently. Nothing checks
that a configured gateway is `https:`, so a user or a bad rc file can put the
whole fetch in plaintext, which SPEC §6.1 requires against.

**Recommendation.** Declare `arOptions` in the configuration schema with
`AR_GATEWAYS` as its documented default; validate that every entry parses as an
`https:` URL and reject the configuration with an error when one does not; report an
unrecognised key rather than ignoring it. Then either surface the list in
settings or state in the documentation that it is rc-only. AR-U4 is the
question of what the list *should* be; this is only about making the existing
knob real.

---

### 4. What this chapter leaves out

1. **Any Electron dependency.** `src/ar.js` is extracted byte-identical — it
   imports only `isCanonicalTxid` from the shared pointer module, uses
   `Response`, `Headers`, `Request`, `Buffer` and an injected fetch, and runs
   unmodified under `node --test`. Nothing had to be factored or stubbed.

2. **The composition layer**, which is Electron-bound and stays in the browser
   tree: the module that injects the proxied `net.fetch` and registers the
   scheme into the router, the main entry's privilege registration (SPEC §10),
   and the Handshake handler that composes `ar://<txid><path><query>` from a
   resolution (SPEC §5.2). Their *policy* is specified normatively in SPEC
   §5.2, §6.6 and §10; the code is not extracted. If you are implementing from
   this chapter, that layer is yours.

3. **The pointer grammar, the contenthash decoder and the trust panel**, which
   are *not* absent — they are at the repository root
   (`../../src/pointers.js`, `../../src/contenthash.js`,
   `../../src/trust-path.js`) because the spine specifies them and all three
   are shared with the IPFS, BitTorrent, Hyper and ENS chapters. This chapter's
   tests import them from there rather than copying them, so a fix in one is
   provably the same fix here.

4. **Any Arweave write path.** Bundling, signing, chunking, paying, posting: no
   code, no specification, not in this repository. The browser has no Arweave
   publish target either — every `ar=` record this stack reads was written by
   external tooling.

5. **An ArNS client.** SPEC §8, AR-U3.

6. **Manifest parsing.** SPEC §7, AR-U1.


---

<a id="chapter-5-ens-and-web3"></a>

## Chapter 5 — ENS and `web3://`

_Source: [`namespaces/ens/DEVIATIONS.md`](namespaces/ens/DEVIATIONS.md)._

Known deviations, unresolved questions and proposed changes for ENS website resolution, CCIP-Read and the separate `web3://` handler.

Entries distinguish current behaviour from recommendations. Paths beginning
`src/` or `tests/` are relative to this chapter; `../../src/` names shared
modules. Browser paths refer to the Wildroot source tree. Historical line
references may have moved since extraction.

[Chapter specification](namespaces/ens/SPEC.md) · [References](namespaces/ens/REFERENCES.md)

---

### 1. Deviations

<a id="en-1-only-contenthash-is-read-addr-text-and-the-rest-are-not"></a>

#### EN-1. Website resolution with a limited text-record display

**Current behaviour.** Navigation resolves `contenthash`. Since 2026-09-06,
the no-website page also reads seven ENSIP-5 text keys: `url`, `description`,
`avatar`, `email`, `com.twitter`, `com.github` and `org.telegram`.
Those values are displayed as escaped text, capped at 512 characters; only
an HTTPS `url` becomes a link. They are not fetched. See SPEC §5.6a and
`src/ens-protocol.js` (`textRecords`, `textRecordsHtml`).

**Scope.** This remains a browsing client. It does not resolve payment
addresses, multichain address records or primary names. The text display runs
only for a `no-content` result, so successful website navigations do not incur
those additional lookups.

**Status: IMPLEMENTED WITH LIMITED SCOPE.** A name with no website can expose
the selected descriptive records. Each value is read through the same trusted
RPC and Universal Resolver path as the content pointer.

---

#### EN-2. A CCIP resolver's rigour is deliberately not graded

**What.** Every ENS resolution carries the same trust state, whether the
offchain resolver behind it checked an operator's signature or verified a
Merkle storage proof or a DNSSEC chain on chain.

**The standard says.** ERC-3668 is explicit that it is a transport and that
what the callback does with the gateway's answer is the contract's business;
it defines no way to signal, and no obligation to distinguish, the strength of
that check.

**Why.** The RPC endpoint supplies the resolver address, revert and callback
result without a locally verified Ethereum state. The client cannot establish
which callback verification actually ran.

**Consequence.** Stronger checks performed by a resolver do not change this
client's trust verdict.

**Status: DELIBERATE**, conditional on the absence of a light client (§2.2).

---

#### EN-3. Reverse resolution (EIP-181) is not implemented

**What.** `addr.reverse` is never queried; no primary name is ever displayed.

**The standard says.** EIP-181 defines the `.addr.reverse` namespace and the
`name(bytes32)` record so that an address can be shown as the name it claims.

**Why.** Nothing on a browsing path has an Ethereum address to reverse. Reverse
resolution answers "what does this address call itself", which is a wallet's
question.

**Consequence.** Website resolution does not expose reverse names. A future
address-display feature would need this record profile.

**Status: DELIBERATE.**

---

#### EN-4. Two normalisations for one hash function

**What.** `ens://` normalises with ENSIP-15 before `namehash`. The HIP-5 `_op`
route in the Handshake chapter computes `namehash` over a **lowercased
Handshake label with no ENSIP-15 step at all**.

**The standard says.** EIP-137 specifies one hash function over a normalised
name, and ENSIP-15 specifies the normalisation the ENS namespace uses.

**Why.** The inputs are different namespaces. `_op` labels are Handshake
labels, already punycode A-labels and already lowercase, and running them
through an ENS-specific normaliser would map or reject names the Handshake
chain considers valid — a client refusing to resolve a name consensus says
exists.

**Consequence.** The same `namehash` function is fed by two different
pipelines, and a name valid in both namespaces could in principle hash
differently on the two routes. No such name exists today (the label sets do not
overlap in the deployed registries), but an implementer copying one route's
normalisation into the other would be wrong in both directions.

**Status: DELIBERATE.** Each route uses its namespace's normalization rules.

---

#### EN-5. A gateway **hostname** is never resolved before it is fetched

**What.** The CCIP gateway guard rejects `localhost`, `*.localhost`, `*.local`
and `*.internal` by name and checks an **IP literal** against the shared
address registry. A hostname that is not one of those is accepted without
resolution.

**The standard says.** ERC-3668 §Security Considerations puts the burden on the
client: the gateway URL is contract-supplied and the client is responsible for
not being used as a fetching proxy. RFC 6890 / RFC 5737 name the address ranges
that must never be reached from an untrusted URL.

**Why.** A hostname cannot be checked without resolving it, and resolving it in
the guard would be a second lookup the fetch does not use — so a check-then-
fetch is a TOCTOU (DNS rebinding) even when it passes.

**Consequence.** A gateway host whose DNS answer is `127.0.0.1`, an RFC 1918
address, or `169.254.169.254` is fetched. Because the bytes only ever reach the
contract's callback and are never displayed, the exposure is **exfiltration of
an internal HTTP response into a contract**, not display of it. That is a real
capability: an attacker who deploys a resolver contract can read a response
from the user's own network, one contract call at a time, bounded by 4 lookup
rounds and 16 sub-requests per batch.

**Status: OPEN.** The honest fix is not a stricter pre-check but a fetch that
pins the address it resolved — a custom `lookup`/agent that refuses a
non-public result at connect time and connects to the address it checked, so
that rebinding between check and connect is impossible. Until that exists the
guard's comment must say plainly that hostnames are a known hole rather than
merely out of scope, and the limitation belongs in the conformance record.

---

#### EN-6. Nothing is cached; every navigation re-resolves

**What.** There is no cache on the `ens://` path. Each navigation, and each
subresource load that goes through it, performs the full §5 sequence including
any CCIP round trip. The ENS registry's own `ttl(bytes32)` is never read.

**The standard says.** EIP-137 gives every node a TTL, `ttl(bytes32)` on the
registry, for exactly this purpose.

**Why.** A cache has not been implemented.

**Consequence.** Repeated navigations increase latency and the number of
requests observed by RPC endpoints and CCIP gateways.

**Status: OPEN.** A short positive cache keyed by the normalised name,
invalidated the way the Handshake resolver's `forget()` works, is the whole
change. Negative results **must not** be cached — `unreachable` especially,
because caching "we could not ask" turns one outage into a persistent wrong
answer.

---

#### EN-7. Whole areas of ENS are not implemented at all

**What and why**, in one table:

| Thing | Why not |
|---|---|
| **Full ENS text profile** (`text(bytes32,string)`) | Seven keys are read on the no-website page (EN-1). General profile browsing is not implemented. |
| **Multichain address records** (ENSIP-9) | A wallet's job, not a browser's. |
| **`Registry.ttl(bytes32)`** | Nothing caches (EN-6), so there is nothing for a TTL to govern. |
| **ENS on an L2, read natively** | Reached through CCIP-Read (SPEC §6) like every other client without an L2 light client. Reading the L2 directly would swap one trusted RPC for another. |
| **An Ethereum light client** | The single change that would move this namespace out of `unverified`. It is a large piece of work and is not started. Everything in SPEC §7 is conditional on it. |

**The standard says.** Each row's own specification defines behaviour this
implementation does not provide.

**Consequence.** This is an ENS *browsing* client, not an ENS client. Wallet records and general profile browsing remain outside its scope.

**Status: DELIBERATE** for every row except the light client, which is
**OPEN** and is the only one that would change a trust state.

---

### 2. Things we are not sure about

#### 2.1. Is `ens://` TRUSTED, or OPEN?

What ships is TRUSTED, everywhere, consistently: the verdict is `partial`, the
lock closes in the neutral colour, and the scheme table, the handler, the trust
panel, the chapter and the lock test all say the same thing. The question is
whether that is the right verdict.

The case for **TRUSTED**: the honest comparison is with an ordinary `https://`
page, where a CA vouched for the name and the browser believed it. An ENS
resolution is the same *shape* of trust — one third party's word for a
name-to-thing binding — over a connection that is at least encrypted, and the
content at the end is content-addressed, which is more than `https://` offers.
Painting it OPEN puts it in the same bucket as plain `http://`, which is
strictly worse and is a claim of its own.

The case for **OPEN**: the line the rest of the specification draws is "is
there a chain anchor". The `_op` route has one — Handshake consensus proves
*which contract* answers. `ens://` has none: the RPC endpoint is trusted for
the resolver address, the record, and the CCIP callback, with nothing anchoring
any of it. A reasonable implementer could hold that an entirely RPC-trusted
answer should never close a lock.

The current choice is TRUSTED. Any change needs to update the handler,
metadata, trust panel, documentation and tests together.

#### 2.2. Would grading CCIP rigour become right, with a light client?

EN-2 refuses to distinguish a signed-gateway answer from an on-chain proof,
because the difference is not observable. With a light client it is: the
callback's verification runs against state we proved. At that point a
CCIP-Read resolver that verifies a DNSSEC chain on chain is genuinely
**trustless**, and one that checks an operator's signature is genuinely
**trusted**, and showing them identically is the lie. So the rule in EN-2 is
correct *and* temporary, and we do not know how to write it in a way that does
not silently become wrong.

#### 2.3. Revert data is found by the error's shape

The answer/failure decision is structural — is there revert data? — and so is
finding it: `error.data`, or a nested `error.data.data`, counts only when the
whole string is `0x`-prefixed hex; an error *message* is consulted only when it
says the call reverted, and an endpoint that merely echoes a hex value into a
plain error (an address in "invalid argument …") is a transport failure, not an
answer. What remains uncertain is the message path itself: JSON-RPC endpoints
differ in where they put revert data, and a client that only ever saw typed
errors would not need to read messages at all. We have not surveyed enough
endpoints to know whether the "revert" test is too narrow for some of them.

#### 2.4. Should `.eth` be the only alt-root we carve out?

`.eth` and `.onion` are carved out of the Handshake namespace; `.crypto`,
`.sol`, `.bnb` are not, and resolve as Handshake names. The justification is
that ENS and Tor are live systems with real usage and the others are not. That
is a judgement about the market, made once, in a table of one label. It will
age, and there is no mechanism here for noticing when it has.

#### 2.5. Pinning the Universal Resolver address

The Universal Resolver address is pinned and the bundled registry entry is
ignored. Maintaining that pin requires checking future ENS deployments. Options
include a list verified at build time or validating the registry entry against
a known deployment.

#### 2.6. `web3://`'s privilege posture

`ens://` is deliberately opaque-origin and non-secure because its answer is
unverified. `web3://` is standard, secure and service-worker-capable, and its
answer is *equally* unverified. The status and headers a contract returns are
constrained, which removes the sharpest edges, but the origin posture is not. We think the right move is EN-D2 below; we do not know whether any
ERC-4804 site relies on the storage that demotion would take away.

---

### 3. Open design items

The two other open items, EN-5 (pin the resolved gateway address) and EN-6 (a
short positive cache), carry their recommendations in §1 and are not repeated
here.

#### EN-D1. `web3://` has no deadline of its own and no policy over its RPC list

The `ens://` path learned that an RPC without a per-attempt deadline holds a
navigation open forever and makes a two-endpoint list worth one; `web3://` has
no such deadline, because any timeout lives inside the third-party client if it
lives anywhere. ERC-7617 chunking re-enters `web3://` recursively, so one
navigation can become a long chain of contract calls. Separately, a
configuration-supplied `chainList` can point `rpcUrls` at any address including
the user's own network, with no guard — the IP-protection gate blocks the whole
scheme only while anonymisation is on.

**Recommendation.** Put an overall deadline on `fetchUrl` and a bound on the
chunk chain, and run any configured `rpcUrls` through `../../src/safe-address.js`
the way CCIP gateway URLs are, refusing a non-public endpoint at configuration
time rather than at fetch time.

#### EN-D2. `web3://` keeps a stronger privilege posture than `ens://`

`web3` is registered with the peer-to-peer privilege set — standard, secure,
service-worker-capable, fetch-enabled — so an arbitrary contract gets a real,
persistent, secure-context origin keyed by its own address. `ens://` is held at
an opaque origin for a resolution that is better verified, because the content
at the end of an ENS pointer is at least content-addressed. The privilege
gradient runs the wrong way.

**Recommendation.** Demote `web3` to `ens://`'s posture — non-standard,
non-secure, no service workers — until something verifies the read. The
compatibility question in §2.6 is the only thing holding it, and it is
answerable by looking: if no deployed ERC-4804 site uses storage or a service
worker, the demotion costs nothing.

---

### 4. What this chapter leaves out

1. **The Electron wiring.** In Wildroot, the protocol layer constructs the
   handler with the session's proxied `net.fetch` as `fetchImpl` and the live
   IPFS and Arweave handlers as `ipfsFetch`/`arFetch`, and the main process
   registers the scheme's privileges. Both are Electron-bound and are not
   extracted. The *policy* they implement is normative in SPEC §4 (privileges),
   §5.3 (the proxied RPC) and §5.5 (the handoff), but the code is yours to
   write. The handler takes all four as injected options precisely so that it
   is Electron-free, which is why the tests run under plain `node --test`.

2. **The content handlers.** What happens to an `ipfs://` or `ar://` pointer
   once it is produced. This chapter ends at the pointer.

3. **The browser chrome.** The padlock and the security panel that render
   SPEC §7's steps. `../../tests/lock-semantics.test.js` pins the `ens://`
   verdict at the model level, which is the part that belongs to a
   specification.

4. **`web3protocol` itself.** ERC-4804, ERC-5219, ERC-6821 and ERC-7617 are
   implemented by that package, not by this code, and it is not vendored here.
   SPEC §8 specifies what a *host* must do around such a library — constrain
   the status, filter the headers, deadline the call — which is the part we
   own.


---

<a id="chapter-6-nostr"></a>

## Chapter 6 — Nostr

_Source: [`namespaces/nostr/DEVIATIONS.md`](namespaces/nostr/DEVIATIONS.md)._

This record separates current departures from proposed work. `DELIBERATE`
identifies a retained implementation choice; `OPEN` identifies unfinished work
or a decision still under review. Section 2 collects design questions, and
section 3 lists proposals. None of those proposals changes current behaviour.

See [the editorial review log](REVIEW.md) for contradictions found during
the documentation rewrite.

### 1. Deviations

#### NO-1. A NIP-05 address is classified nowhere

**Behaviour.** The omnibox routes valid bare NIP-19 identifiers to Nostr,
but treats `alice@example.com` as a search. The browser's social view instead
classifies this ambiguous shape as `fediverse-or-nip05` and queries both.

**Reason and effect.** Neither NIP-05 nor NIP-21 defines address-bar behaviour.
The search rule prevents URL userinfo parsing from silently turning an address
into a navigation to its host. It also makes NIP-05 lookup unavailable from
the omnibox and sends the input to the search backend.

**Status: OPEN.** Offer explicit NIP-05 and Fediverse lookup suggestions.
`tests/classification.test.js` records the current NO-1 behaviour. See NO-D1.

---

#### NO-2. The `nip05` claim on a protocol page is displayed, but never looked up

**Behaviour.** `renderProfile` displays a kind:0 `nip05` field as
"claims `<handle>` (not verified — the handle was not looked up)". It does not
call `lookupNip05`.

**Standard and effect.** NIP-05 expects a displayed identifier to be checked
against the domain. Here any key can display any handle; the page labels it
as an unresolved claim. Resolving it requires a request to the domain named
in untrusted profile data, subject to SPEC §10.5.

**Status: OPEN.** Use the existing guarded lookup and distinguish a matching
mapping, a contradicted mapping, and an unreachable domain. See NO-D1.

---

#### NO-3. Relay selection is a bundled set plus the link author's hints; NIP-65 is never read

**Behaviour.** The default relays are `wss://social.hns.one`,
`wss://relay.damus.io`, `wss://nos.lol` and `wss://relay.nostr.band`.
The resolver does not read the author's kind:10002 relay list.

**Standard and effect.** NIP-65 defines author-published relay lists. Without
them, authors who publish only outside the defaults need a relay hint to be
found. Every queried relay also learns the target. Unreachable relays produce
502; completed queries without matches produce 404.

**Status: OPEN.** Query `{kinds:[10002], authors:[pubkey]}` for targets with a
pubkey, read the `r` tags and their read/write markers, validate every URL with
the existing guard, and cache the resulting list for the navigation. See NO-D4.

---

#### NO-4. BIP-173's 90-character limit is not enforced, and bech32 is implemented locally

**Behaviour.** The local decoder implements bech32 checksum, case and padding
checks without BIP-173's 90-character cap.

**Reason and effect.** Valid NIP-19 TLV identifiers can exceed that cap. The
bech32 implementations available through the browser's transitive dependencies
enforce it, so this resolver uses its own decoder. BIP-173's bounded-length
error-detection guarantee does not extend to these longer strings. The decoder
has no overall identifier-length limit, though it checks payload lengths by type.

**Status: DELIBERATE.** An independently encoded identifier longer than 90
characters is covered by a test.

---

#### NO-5. `nostr://` is accepted although NIP-21 defines only `nostr:`

**Behaviour.** `parseNostrURI` accepts `nostr://npub1…` as well as
`nostr:npub1…`, and strips a trailing path, query or fragment.

**Standard and reason.** NIP-21 defines the form without an authority component.
The additional form accommodates URLs returned by Chromium's protocol layer.
The remaining identifier still passes through bech32 validation.

**Status: DELIBERATE.** Generated links use `nostr:`. The accepted alias may
not work in clients that parse NIP-21 strictly.

---

#### NO-6. An `nsec` is refused by name, quoting it back to nobody

**Behaviour.** The decoder refuses `nsec` with: "that is a PRIVATE KEY (nsec).
It was not sent anywhere. Never paste it into a browser or share it."
It does not echo the key. The bare-input classifier routes matching `nsec`
prefixes here before name resolution.

**Standard and reason.** NIP-21 excludes secret keys from its URI scheme.
Identifying the secret in the error explains the problem more clearly than an
unsupported-prefix message. Tests check the wording and absence of network
access before parsing.

**Status: DELIBERATE.** The message discloses the type of input, never its value.

---

#### NO-7. No NIP-42 AUTH: a relay that wants sign-in is a relay that answered nothing

**Behaviour.** `AUTH` frames are ignored. A relay that requires authentication
can contribute no events without a report identifying the authentication
requirement.

**Standard and reason.** NIP-42 defines the challenge/response exchange. The
resolver holds no signing key and does not authenticate reads. The social
client has a separate authenticated path and reports "wants sign-in".

**Status: OPEN** for reporting. Recognise the authentication challenge and
report "relay requires sign-in" without signing a response. Authentication
itself remains outside the resolver's scope.

---

#### NO-8. Fixed result limits, no pagination, no time window

**Behaviour.** Profile lookups request at most 5 kind:0 events and 20 kind:1
events; note and addressable lookups request 1. There is no pagination or time
window, and the query option overwrites a filter's `limit`.

**Standard and effect.** NIP-01 provides `limit`, `since` and `until`. These
fixed limits produce a partial view of an author's events. A social client
needs its own paging and can use the existing `matchesFilter` support for
time constraints.

**Status: DELIBERATE** for this resolver.

---

#### NO-9. Three independent NIP-01 implementations, and a trust header nobody reads

**Behaviour.** The browser maintains three NIP-01 implementations: this
resolver, the identity keystore, and a vendored package. Cross-verification
tests and a hash manifest check their agreement. Separately, the handler
emits `X-Nostr-Trust` and `X-Nostr-Pubkey`, but the trust panel derives its
steps from the URL scheme rather than reading those headers.

**Reason and effect.** Packaging boundaries and differing signing/verifying
roles produced the copies. Fixes must be applied consistently. Scheme-based
trust reporting describes the handler contract rather than the checks performed
for an individual response.

**Status: OPEN.** Consolidate signing and verification while preserving packaged
availability. Either connect the response trust metadata to the panel or remove
the unused headers and their misleading comments. See NO-D5 and NO-D6.

---

#### NO-10. The canonical serialisation is delegated to the host's `JSON.stringify`

**Behaviour.** `eventId` serialises
`[0, pubkey, created_at, kind, tags, content]` with `JSON.stringify` and hashes
its UTF-8 bytes.

**Standard and effect.** NIP-01 defines the canonical serialisation. The
implementation relies on the host runtime's escaping behaviour. A
cross-implementation fixture includes quotes, backslash, newline, non-ASCII,
an astral character and U+2028. Non-V8 runtimes have not been compared. A
different byte representation would reject otherwise valid events.

**Status: DELIBERATE.** Runtime serialisation compatibility is an explicit
assumption.

---

#### NO-11. The `_nostr` DNS record is designed and documented but not published

**Behaviour.** Project design documents describe `_nostr.<name>` TXT records
binding Handshake names to Nostr keys. The recorded deployment has `_hns`
records and no `_nostr` records. This chapter does not establish current
deployment state independently.

**Effect.** The proposed chain-anchored name-to-key mapping is not available on
the documented path. NIP-05 supplies the implemented mapping, with the HTTPS
trust limits in SPEC §7.3.

**Status: OPEN.** Specify and publish the record, then read it through the
Handshake chain-proof and DNSSEC path. Until then, describe it as a proposal.
See NO-D3.

---

#### NO-12. On a `.hns.one` NIP-05 address the Handshake guarantees do not apply to the lookup

**Behaviour.** `_@alice.w3.hns.one` is looked up at
`https://alice.w3.hns.one/.well-known/nostr.json?name=_` using platform fetch.
The lookup does not use the Handshake chain-proof, DNSSEC and DANE path.

**Standard and effect.** NIP-05 requires HTTPS and forbids redirects; it does
not select a resolver or trust anchor. The public `.hns.one` form remains
usable by ordinary Nostr clients, but a lookup inside Wildroot currently has
the same WebPKI trust model.

**Status: OPEN.** Consider routing Wildroot's `.hns.one` lookup through the
`hns://` path while retaining ordinary HTTPS access for other clients. That
would require testing both paths.

---

#### NO-14. The `nsec` arm is claimed on its prefix, not on its checksum

**Behaviour.** Public NIP-19 prefixes require a successful decode. The `nsec`
arm instead accepts `nsec1` followed by at least six bech32 characters, even
when the checksum is invalid. `nsec1qqqqqq` therefore reaches the private-key
refusal.

**Reason and effect.** A checksum requirement would allow mistyped secrets to
reach name resolution. The prefix rule also captures Handshake names with that
shape; they require an explicit `hns://` input.

**Status: DELIBERATE.** An implementation **MAY** require the bech32 charset,
as this one does, and **MUST NOT** require a valid checksum for this arm.

---

#### NO-15. Private mode hides who is asking, not what is asked

**Behaviour.** Private mode sends relay connections through device-local Tor
by hostname. Relays see a Tor exit address and still receive the full filter.
NIP-01 provides no oblivious-query mechanism.

**Effect.** Tor hides the device's network address without hiding which key or
event was requested. No SOCKS credentials are sent, so relay queries can share
circuits with other traffic (TO-3). Filters and timing can also link queries.

**Status: DELIBERATE.** The interface must describe this limited protection.
Navigation caching and NIP-65 relay discovery (NO-D4) could reduce disclosure;
stream isolation is tracked in the Tor chapter.

---

#### NO-16. Two WebSocket implementations on two routes

**Behaviour.** Direct connections use the injected or global WebSocket class.
Private connections use `ws`, which accepts an agent and a socket established
through SOCKS. Both expose the events and methods used by `src/relay.js`.

**Effect.** The implementations may differ in timeout, close-code and error
behaviour. A real `wss://` relay behind a loopback SOCKS server tests the Tor
path, but the two client implementations have not been compared across all
scripted-relay cases.

**Status: DELIBERATE.** Run the same relay conformance cases through both
clients to identify differences.

---

### 2. Things we are not sure about

The following decisions remain open for review.

#### 2.1. Whether a lock can ever close for Nostr — and whether a padlock is the right instrument

Completeness keeps the aggregate `partial` under SPEC §4.1 even when every displayed event passes signature verification. Review whether a padlock communicates this clearly, or whether separate event-authorship and relay-coverage indicators would be easier to interpret.

#### 2.2. What "the right event" means, once the answer is bound to the query

Filter matching prevents substitution but does not establish freshness. A relay can return an older valid replaceable event. The interface currently identifies the queried relays and displays the newest timestamp among their answers; a stronger freshness mechanism remains undefined.

#### 2.3. Whether NIP-05 belongs in a resolution specification at all

NIP-05 is a widely used name-to-key mapping with a different trust model from event signatures. Review whether the domain attribution and unresolved-claim wording in SPEC §7.3 communicate that distinction adequately.

#### 2.4. The default relay list is a decision we made for the user

The default set contains four relays, including one operated by the browser publisher. It is a source constant, with no user-facing editing control. Every queried relay learns the target, and in Fast mode the device address. NIP-65 discovery would still require a bootstrap relay. Review configuration and disclosure options.

#### 2.5. Whether `nostr:` should be a standard scheme

`nostr:` currently has no standard origin, fetch support, service workers or secure-context features. That suits static pages. An interactive client would need a storage and origin model, including whether different identifier forms for the same key share an origin.

#### 2.6. Whether a bare `npub` should navigate

A valid bech32 checksum selects Nostr over the bare Handshake-label rule. The secret-key exception uses only a prefix and charset check (NO-14). Review the collision policy while preserving protection against sending a mistyped secret to a name resolver.

#### 2.7. What we should be doing about relay disclosure

Private mode hides the device address through Tor, but relays still learn the query. It adds latency and can encounter relays that block Tor exits. Review whether the current interface adequately explains that narrower privacy benefit.

#### 2.8. Whether a refused relay hint should be silent

The relay report displays rejected hints as escaped text, with no script capability. This makes routing decisions inspectable but gives a link author a place to display chosen text. Review whether the report needs additional presentation limits.

### 3. Open design items

Proposed work, linked to the deviations it addresses.

#### NO-D1. Resolve the `nip05` claim, or say the domain was unreachable

The profile renderer does not resolve its `nip05` claim (NO-2).

**Recommendation.** Call `lookupNip05` with the injected session fetch and a
deadline. Distinguish a matching domain assertion, a conflicting or absent
mapping, and an unreachable domain. A matching assertion remains `unverified`
in this trust model and must name the asserting domain.

#### NO-D3. Publish the `_nostr` record, or stop documenting it

The `_nostr` record is a documented proposal without the corresponding read
and publication path (NO-11).

**Recommendation.** Specify its receipt and publish records for existing keys,
then read them through the Handshake chain-proof and DNSSEC path. Keep the
proposal labelled as such until those parts are implemented.

#### NO-D4. Read NIP-65 relay lists

The resolver uses bundled relays and link hints (NO-3).

**Recommendation.** For a target with a pubkey, first query
`{kinds:[10002], authors:[pubkey]}`. Read `r` tags and read/write markers, then
combine the list with the current relay set. Apply `isSafeRelayUrl`,
`normalizeRelayUrl` and the existing hint limit to every added URL. Cache the
list for the navigation. The initial discovery query still needs bootstrap
relays.

#### NO-D5. Read `X-Nostr-Trust`, or delete it

The trust panel does not read the response headers emitted for it (NO-9).

**Recommendation.** Either provide response metadata to the panel so it can
report the checks performed for that navigation, or remove the unused headers
and comments. Avoid leaving two conflicting sources of trust information.

#### NO-D6. Collapse the three NIP-01 implementations

Three NIP-01 implementations require parallel maintenance (NO-9).

**Recommendation.** Package one module that both signs and verifies, with the
cross-verification tests retained. Resolve the packaging boundary before
replacing the copies.

The proposal does not change the deliberate decisions to accept long NIP-19
identifiers (NO-4) or keep Nostr's aggregate trust partial (SPEC §4.1).

### 4. What this chapter leaves out

1. **The social client.** `src/social.js`, `src/nostr/relay-pool.js`,
   `src/nostr/social-core.js`, `src/pages/social/` and the identity keystore in
   the Wildroot tree are a Nostr *client*: publishing, follow lists, reposts,
   threads, reactions, key custody. None of it is extracted. Two pure functions
   from `social-core.js` (`verificationHost`, `nip05For`/`displayName`) are
   reproduced verbatim inside `src/nip05.js` because they are the NIP-05
   resolution rules and nothing else; that file's header says exactly which
   lines came from where.

2. **The NIP-05 fetch, as it exists in the browser.** There it is a branch of a
   `switch` inside an Electron IPC handler (`src/social.js`, `case 'verify':`).
   There is no function to import, so `lookupNip05` in `src/nip05.js` is that
   branch lifted into one, generalised from the hardcoded `_` local part, with
   `fetch` made injectable so it can be tested without a network. **It is the
   only module here that is not byte-identical to shipping code**, and it is
   labelled as such at the top.

3. **The trust panel and the browser chrome.** `schemeSteps()` in the browser's
   `src/hns/trust-path.js` carries the Nostr arm SPEC §4.1 describes. It is the
   browser's UI, not a resolver, and is specified here as a model rather than
   extracted.

4. **Electron.** Nothing here imports it. `src/nostr-protocol.js` uses only the
   global `Response`, and `src/relay.js` takes its WebSocket implementation
   from an injected seam or the global — so the handler runs, and is tested,
   under plain `node --test`. The Private-mode behaviour is inside the handler
   (SPEC §8.5), behind three injected functions — `isAnonymized`, `torSocks`,
   `torWebSocket`. What stays in the browser is the wiring of the first two to
   the anonymizer's `isOn()` and `torSocks()` (`namespaces/tor/src/anonymize.js`)
   and of the mode to `DeliveryMode` in `../../src/delivery-mode.js`, which is
   a composition concern. `nostr:` is not behind the non-proxied gate of
   Chapter 9 §K.3.6.

5. **Everything the fan-out is not.** No caching, no connection reuse, no
   subscription that stays open, no streaming. A resolution opens sockets, asks
   once, and closes. That is a resolver's shape and it would be the wrong shape
   for a client.


---

<a id="chapter-7-did-at-protocol-and-activitypub"></a>

## Chapter 7 — DID, AT Protocol and ActivityPub

_Source: [`namespaces/did/DEVIATIONS.md`](namespaces/did/DEVIATIONS.md)._

This record separates current departures from proposed work. `DELIBERATE`
identifies a retained implementation choice; `OPEN` identifies unfinished work
or a decision still under review. Section 2 collects design questions, and
section 3 lists proposals. None of those proposals changes current behaviour.

See [the editorial review log](REVIEW.md) for contradictions found during
the documentation rewrite.

### 1. Deviations

#### DI-1. A resolved DID document is served with `Access-Control-Allow-Origin: *`

**Behaviour.** Successful DID responses include
`Access-Control-Allow-Origin: *`, `Allow-CSP-From: *`, and wildcard allowed
headers and methods.

**Reason and effect.** These headers were inherited from other protocol
handlers. `did:` currently lacks fetch support and uses a non-standard origin,
so the headers do not enable `fetch('did:…')`. Changing the scheme privileges
could activate a broader cross-origin read policy. The host guard separately
rejects private address literals and reserved names; SPEC §5.3 records its
DNS-rebinding limitation.

**Status: OPEN.** Align the headers with the intended access model, alongside
the response-format work in DI-3. Tests record the current headers.

---

#### DI-2. `did:plc` is directory-trusted; the operation log is never fetched

**Behaviour.** Both the `did:` handler and `resolvePds` fetch
`https://plc.directory/<did>` and require a matching `id`. Neither fetches
`/<did>/log/audit`.

**Standard and effect.** The PLC identifier commits to its genesis operation.
Verifying the signed operation log and comparing its result with the returned
document would check the method's key history. Without those checks, the
directory is trusted to supply the current keys and services.

**Status: OPEN.** Verify genesis, previous-operation CIDs, authorised rotation
signatures and the resulting document. Include recovery-window semantics.
See DI-D5.

---

#### DI-3. The result is a bare DID document, as `application/json`

**Behaviour.** Successful responses contain a bare DID document with
`Content-Type: application/json; charset=utf-8`.

**Standard and effect.** DID Core §7.1 defines resolution outputs including
`didDocument`, `didResolutionMetadata` and `didDocumentMetadata`.
The current response does not carry structured resolution metadata, so callers
cannot read the performed checks or method limitations from such metadata.

**Status: OPEN.** DI-D6 proposes a resolution-result response and the
`application/did+json` media type. The envelope/media-type pairing needs review
before implementation; the proposal is unchanged by this editorial rewrite.

---

#### DI-4. `did://` is accepted as an alias for `did:`

**Behaviour.** `did://plc:abc` is normalised to `did:plc:abc` before parsing.

**Standard and reason.** DID Core §3.1 has no authority component. The alias
accommodates the form returned by the browser engine. Downstream checks use
the normalised DID, and the implementation does not emit the alias.

**Status: DELIBERATE.** An implementation SHOULD NOT generate `did://` links.

---

#### DI-5. AT Protocol handle resolution is not implemented; the AppView is asked instead

**Behaviour.** `resolveHandle` calls
`com.atproto.identity.resolveHandle` at `https://public.api.bsky.app`.

**Standard and effect.** AT Protocol defines authoritative DNS TXT and HTTPS
well-known lookups, followed by reverse verification against the DID document's
`alsoKnownAs`. This adapter performs none of those checks. It trusts the
AppView's mapping and discloses each requested handle to that operator.

**Status: OPEN.** Implement the DNS method with the validating resolver, the
well-known fallback, and bidirectional verification. Any retained AppView
fallback should be distinguishable and unverified. See DI-D1.

---

#### Experimental: identity anchors

The two deviations below are in the **experimental** part of this chapter
(SPEC §9): record formats that are shipped and signed by the browser's
keystore but are not a proposed standard and may change. They are separated
here so a reader does not weigh them against the stable resolution path.

#### DI-10. Nothing enforces that an identity anchor's `epoch` moves forward

**Behaviour.** Receipts bind `(name, pubkey, epoch, created_at)` but do not
expire. Neither the parser nor its browser consumer remembers the highest
accepted epoch.

**Effect.** A previous holder's receipt still verifies if an old record is
served again. The current defence is publication of the current DNSSEC-signed
record. The format supplies no independent rollback check.

**Status: OPEN.** The resolver MUST report the accepted epoch so callers can
apply their own policy. A persistent epoch floor needs a defined transfer,
reset and recovery policy; §2.4 lists the unresolved cases. Tests preserve
the current behaviour.

---

#### DI-11. `_nostr.<name>` is designed and not published

**Behaviour.** Code comments describe `_nostr.<name>` as a sibling of the
`_hns` control record, but this chapter does not build, publish, parse or verify
that sibling record.

**Reason and effect.** A separate Nostr identity key would let an owner
delegate name control without delegating their social identity. That binding
is not implemented. The current NIP-05 mapping uses the operator's HTTPS
endpoint.

**Status: OPEN.** Specify a separate receipt, such as a `hns:nostr:` `d` tag,
and implement the publication and read paths, or remove present-tense claims
that the record exists.

---

### 2. Things we are not sure about

The following decisions remain open for review.

#### 2.1. Whether "recognised, fail-closed" is a resting state

`at://` and `activitypub:` currently return local refusals. Review whether to retain that state until the requirements in SPEC §10.5 are implemented, or support a clearly labelled unverified result first. The latter would need a defined trust model and must preserve namespace isolation.

#### 2.2. Whether a DID document should be a *page* at all

The `did:` scheme displays JSON in an opaque origin. Internal consumers call adapters directly. Review whether navigation should continue to expose raw JSON or provide a document view listing the subject, keys, services and performed checks.

#### 2.3. Whether a bare atproto handle should be classified as an atproto address

An AT Protocol handle is also a domain name, so treating every domain-shaped input as an AT Protocol address would conflict with website navigation. The current classifier leaves these inputs to the name-routing rules. Review whether an explicit scheme or a selectable suggestion should request identity lookup.

#### 2.4. Whether a client-side epoch memory actually fixes DI-10

A persistent highest-epoch value could reject rollback, but its semantics require decisions about legitimate reset or renumbering, transfer, recovery and fresh devices. The current format does not define those cases. The Handshake chain tracks the TLD, not each second-level identity anchor.

#### 2.5. `did:web:<name>.hns.one` versus `did:plc`

The documented deployment choice is `did:web:<name>.hns.one`; the provisioning worker selects the method outside this chapter. Review the dependency and recovery tradeoffs against `did:plc`: domain-bound identity and operator availability versus PLC directory availability and verifiable operation history. Existing claims about key rotation and network support also require technical review.

#### 2.6. What the AppView path should be *called*

An AppView fallback is `unverified`, but that state alone does not identify the trusted party. Review returning the source alongside the state, as the labelled DoH fallback does for identity anchors.

#### 2.7. Whether this chapter should exist yet

This chapter includes fetched DID documents, an AppView-assisted handle lookup, and unresolved AT-URI and ActivityPub handlers. Keep the supported and refused paths explicit so readers do not infer full client or protocol support from the chapter title.

#### 2.8. Whether a labelled default PDS should exist at all

`resolvePds` returns the default PDS with `assumed: true` and a reason when resolution fails. Review whether the resolver should return a failure instead and leave default selection to sign-in callers. A caller that ignores `assumed` can still mistake the default for the account’s PDS.

### 3. Open design items

Proposed work, ordered by the existing project priorities.

#### DI-D1. Resolve AT Protocol handles locally, not through the AppView

`resolveHandle` trusts the AppView (DI-5).

**Recommendation.** Use the validating resolver for `_atproto.<handle>` TXT,
then the HTTPS well-known fallback. Verify `alsoKnownAs` in the DID document.
Keep any AppView fallback distinguishable and unverified.

#### DI-D5. Verify the `did:plc` operation log

The current PLC lookup checks `id` but does not verify operation history (DI-2).

**Recommendation.** Fetch `/<did>/log/audit`, verify the genesis-derived DID,
previous-operation CIDs, authorised signatures, rotation and recovery semantics,
then compare the document with the resulting state. Cache verified history to
avoid repeating the full work on every navigation.

#### DI-D6. Return a DID resolution result, not a bare document

The current response lacks resolution metadata (DI-3).

**Recommendation.** Return the document with resolution and document metadata,
including which checks were performed. Review the proposed media type and CORS
policy before changing the response contract. See DI-3 and REVIEW.md.

### 4. What this chapter leaves out

**1. The Electron layer.** Two things SPEC describes are engine-bound and are
not extracted:

- **Scheme registration and privileges** (SPEC §3.1, §8) — `did`, `at` and
  `activitypub` are declared non-standard, non-secure, `corsEnabled`, without
  service workers or `fetch`, in the browser's `src/main.cjs`. The *policy* is
  normative here; the declaration is Electron's API.
- **The `_hns` resolution policy** (SPEC §9.2) — the chain-first / DoH-labelled
  algorithm lives in the browser's `src/folders/index.js`, bound to its vault,
  its resolver instances and its dynamic-import wiring. It is specified
  normatively because it is the only security-relevant consumer of `record.js`,
  and a reader who takes the verifier without the policy has taken half of it.

**2. The write half of the anchors.** The browser's
`src/identity/identity-account.js` signs a binding receipt and posts it to the
registry with a NIP-98 header. The *receipt format* is specified (SPEC §9.3)
and extracted (`src/receipt.js`), because a reader verifies it. The endpoint,
the registry's checks and the zone write are the publish path, which this
specification puts out of scope everywhere.

**3. The published `_atproto` record and the `atproto-did` well-known.** Both
are produced by the operator's gateway, outside this tree, and — as SPEC §9.3
says out loud — neither is read by anything in this chapter. This chapter signs
the authorisation for an anchor it never verifies.

**4. The social surface.** `src/bsky.js` is extracted whole and only
`resolveHandle` and `resolvePds` are specified. Everything else in it —
sessions, timelines, posting, follows, likes — belongs to the client, not the
resolver. It is kept whole because byte-identity with the browser tree is worth
more than a tidy package (SPEC, *Layout*).

**5. What is done with the object once resolved.** Signing in to a PDS,
reading or writing a repository, rendering a feed. This chapter ends at "here
is the DID document / here is the PDS / here is the key".

**Dependencies.** Receipt signatures use `@noble/curves`. Local `did:key`
decoding also uses `multiformats/bases/base58`. The handlers otherwise use
platform APIs such as `fetch`, `Response`, `URL` and `AbortSignal`, plus shared
repository modules. `gate.js` uses `../../src/delivery-mode.js` for refusals.

---

<a id="chapter-8-tor"></a>

## Chapter 8 — Tor

_Source: [`namespaces/tor/DEVIATIONS.md`](namespaces/tor/DEVIATIONS.md)._

This record separates current departures from proposed work. `DELIBERATE`
identifies a retained implementation choice; `OPEN` identifies unfinished work
or a decision still under review. Section 2 collects design questions, and
section 3 lists proposals. None of those proposals changes current behaviour.

See [the editorial review log](REVIEW.md) for contradictions found during
the documentation rewrite.

### 1. Deviations

#### TO-1. With Tor off, and off Tor, we answer with a page rather than an error

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

#### TO-2. An explicit non-onion scheme on an onion host is not protected

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

#### TO-3. No SOCKS stream isolation: everything shares circuits

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

#### TO-4. Whether the session cookie jar reaches the onion fetch is not established

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

#### TO-5. Onion services with client authorization cannot be reached

**Behaviour.** The generated `torrc` has no `ClientOnionAuthDir`, and the
browser has no client-authorization key-entry flow.

**Standard and effect.** Tor v3 supports services whose descriptors require
client authorization. Such a service is unavailable through the bundled
configuration and returns a generic 502 rather than an authorization-specific
explanation.

**Status: OPEN.** Add the configuration, credential storage and error reporting
together. See TO-D4.

---

#### TO-6. IP Protection is all-or-nothing for the whole session

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

#### TO-7. While BLOCKED, a session request fails as a proxy error, not as a page that names the mode

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

### 2. Things we are not sure about

The following decisions remain open for review.

#### 2.1. Whether "device-local" should have any escape hatch at all

Loopback-only routing excludes hosted gateways, but also excludes Tor instances controlled by the user on another LAN host, VM or organisational server. Review whether to permit an explicitly configured endpoint and how its operator and privacy implications would be disclosed. TO-D5 describes a possible design.

#### 2.2. Whether an explicit scheme should be allowed to defeat R1 (TO-2)

Explicit-scheme precedence and the no-DNS rule conflict for onion hosts. The classifier preserves the explicit scheme; subresource guards reject the host. Review a fail-closed top-level refusal that preserves the selected protocol without issuing a DNS request (TO-2).

#### 2.3. Whether routing before the circuit is ready is the right call (R11)

The proxy is applied before readiness and the gate follows mode (SPEC §7.2). This avoids a direct-routing transition but can leave the first navigation waiting during bootstrap. Review progress and retry behaviour while retaining the prohibition on direct onion connections.

#### 2.4. Whether a browser that does not resist fingerprinting should offer `.onion` at all

The browser provides Tor routing without Tor Browser’s fingerprinting defences. The interface states that limitation, but the project has no usability evidence that users understand it. Review whether the disclosure is sufficient for offering onion navigation.

#### 2.5. Whether the mode is at the right granularity (TO-6)

A whole-session proxy simplifies route auditing and increases the latency and policy cost of visiting one onion service. Alternatives include PAC routing, session partitions, or a local SOCKS adapter. They need evaluation alongside per-origin isolation and the existing WebSocket PAC (TO-D1, TO-6).

#### 2.6. Whether `onion://` is the right URL form

The internal `onion://` scheme makes namespace selection visible, but a copied URL is not usable in clients expecting HTTP(S) onion URLs. Review how copied and shared links should be represented.

#### 2.7. What a redirect chain should mean for the address bar

Same-service redirects are followed inside the handler, leaving the displayed URL at the original path. The origin remains the same, but the browser does not observe each redirect. Review final-URL reporting, relative URL behaviour and navigation history.

### 3. Open design items

Proposed work. These recommendations are not implemented.

#### TO-D1. Per-origin SOCKS credentials for circuit isolation

The session proxy and raw-socket dialers send no per-origin SOCKS credentials
(TO-3, TO-6).

**Recommendation.** First test credentials in the five main-process dialers,
using the relevant first-party origin for each connection. Then evaluate the
session options: a PAC configuration, a local SOCKS adapter that assigns
credentials, or separate Electron sessions. A distinct PAC proxy string alone
does not establish isolation; measure the Tor behaviour. Any solution must
compose with the existing WebSocket PAC. A new listening adapter also needs
security review.

#### TO-D2. Decide what `https://<addr>.onion/` should do

The explicit-scheme path and no-DNS requirement need one documented policy
(TO-2, §2.2).

**Recommendation.** Refuse non-`onion` requests for an onion host before DNS,
identify the address as an onion service, and offer the `onion://` form as a
link. Document how this exception interacts with explicit-scheme selection
and main-frame link rewriting.

#### TO-D3. Establish, then pin, what happens to cookies

The injected fetch's cookie behaviour has not been measured (TO-4).

**Recommendation.** In an Electron integration test, set a session cookie,
make a proxied handler request to a controlled server and inspect the received
headers. Select an explicit policy, such as `credentials: 'omit'` or a separate
partition, and test it. Account for both login persistence and state isolation.

#### TO-D4. Support onion services with client authorization

The bundled client has no authorization-key configuration (TO-5).

**Recommendation.** Configure `ClientOnionAuthDir <dataDir>/onion-auth`, create
the directory with mode `0700`, and integrate key entry with credential
storage. Add an authorization-specific explanation where Tor's error can be
identified reliably.

#### TO-D5. Let a user name their own Tor endpoint, loudly

The current endpoint policy is loopback-only (§2.1).

**Recommendation for review.** If configurable endpoints are supported, avoid
automatic discovery beyond the existing `127.0.0.1:9050` fallback, require an
explicit selection that explains the endpoint operator can see requested
services, and keep the selected endpoint visible while in use. Whether to
provide this setting remains undecided.

### 4. What this chapter leaves out

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


---

<a id="chapter-9-key-addressed-namespaces"></a>

## Chapter 9 — Key-addressed namespaces

_Source: [`namespaces/keys/DEVIATIONS.md`](namespaces/keys/DEVIATIONS.md)._

Known deviations, unresolved questions and proposed changes for Hypercore, SSB, Gemini and BitTorrent identifiers, dispatch and trust states.

Entries distinguish current behaviour from recommendations. Paths beginning
`src/` or `tests/` are relative to this chapter; `../../src/` names shared
modules. Browser paths refer to the Wildroot source tree. Historical line
references may have moved since extraction.

[Chapter specification](namespaces/keys/SPEC.md) · [References](namespaces/keys/REFERENCES.md)

---

### 1. Deviations

#### KY-1. `gemini://` verifies no certificate and pins none

**What.** A Gemini connection is made with `tlsOpt: { rejectUnauthorized: false }`
and the client's ALPN check overridden to pass (`verifyAlpnId: () => true`).
There is no certificate store: no fingerprint is recorded on a first
connection, and nothing is compared on the next one. The ALPN identifier is
offered but not enforced.

**The standard says.** The Gemini protocol specification §4.2 defines the
trust model as trust-on-first-use: a client records the certificate (or its
public key) presented by a host and refuses a different one on a later visit,
because Gemini servers are expected to be self-signed and there is no CA to
consult.

**Why.** No server-certificate store has been implemented.

**Consequence.** An active attacker can replace the certificate on any visit.
The connection remains encrypted but has no server authentication. The scheme
metadata and trust panel disclose that limit.

**Status: OPEN.** Implement the store: pin the peer's SPKI SHA-256 on first
sight, keyed by `host:port`, persist it, and on a mismatch fail closed with the
wording the DANE path already uses for a pin mismatch — the browser has that
sentence and that UI. `@derhuerst/gemini` takes an injected client-certificate
store with a `get`/`delete` shape, and a server-certificate store is the same
shape and the same injection point, so this needs no fork. Until the store
exists, no document, scheme table or padlock may describe this connection as
TOFU. The engineering item is §3, **KY-D1**.

---

#### KY-2. Only the hex infohash form; BEP-9's base32 magnet is refused

**What.** `INFO_HASH_MATCH` is `/^urn:btih:([a-f0-9]{40})$/i`
(`src/magnet-protocol.js`). A magnet whose `xt` carries a 32-character base32
info-hash is refused with an in-namespace 400 that names the form:
*"This magnet writes its infohash in the base32 form, which this browser does
not read."*

**The standard says.** BEP 9 permits a magnet's info-hash to be written either
as 40 hexadecimal characters or as 32 base32 characters.

**Why.** The implementation uses one canonical hexadecimal key form across
the magnet handler, dispatcher and torrent-input parser (SPEC §K.7.1).

**Consequence.** A valid base32 magnet is refused. Supporting it would require
normalization to the same 20 bytes, without changing downstream semantics.

**Status: OPEN**, low priority. The right fix is to decode base32 to the same
20 bytes at the edge and carry on with the canonical hex string, so that
nothing downstream learns a second spelling: one shared decoder in
`magnet-protocol.js`, applied before `INFO_HASH_MATCH`, and the single
canonical-form argument survives intact. Until then the named refusal is
honest, so this is a completeness gap rather than a correctness one.

---

#### KY-3. BitTorrent v2 is not served, and the URL form cannot express it

**What.** `urn:btmh:` is recognised only to be refused by name; nothing
downstream speaks v2. In the `bittorrent://<key>/` URL form the problem is
sharper: a v2 info-hash is SHA-256 — 32 bytes, **64 hex characters** — which is
byte-for-byte the shape of a BEP-46 Ed25519 public key, and key shape is the
whole of the dispatch (SPEC §K.7.2). There is nothing in the URL to tell them
apart.

**The standard says.** BEP 52 defines the v2 info-hash and the `urn:btmh:`
multihash form a magnet carries it in; BEP 46 defines the `btpk` public key.
Both are 32 bytes.

**Why.** No engine in the tree speaks v2, so serving the URN would only change
which error appears. The URL ambiguity is a property of a form that predates
v2, not a decision.

**Consequence.** Today a v2-only magnet is refused, and the refusal names v2 —
a hybrid magnet carrying a usable v1 info-hash alongside it resolves normally,
in either parameter order. If a v2 engine is added later, a v2 address and a
mutable address are indistinguishable in the URL, and the URL form as it stands
has no room to fix that.

**Status: OPEN.** The identifier syntax has to gain a distinguishing marker
*before* anyone builds on the current one, because every release makes it
harder: either a URN-style host (`bittorrent://btih:<hex>/`), or a
multihash-prefixed key matching BEP 52's own `btmh:` spelling. What must not
happen is disambiguation by trying both engines, which is the cross-engine
fallback SPEC §K.3.3 forbids. We do not have a preferred answer and would
adopt someone else's — see §2.1.

---

#### KY-4. The DNSLink name→key binding is one public resolver's unsigned word

**What.** `hyper://<host-with-a-dot>/` resolves its key from
`TXT _dnslink.<host>`, fetched by `hyper-sdk` with the **DoH JSON** API from
its own default endpoint. `src/config.js` sets only `hyperOptions.storage`, so
that default stands. There is no DNSSEC validation; the answer is cached in
memory and on disk, and the cache answers when a later lookup fails.

**The standard says.** DNSLink defines the record convention and says nothing
about how it is fetched or authenticated. RFC 4033 defines the authentication
that is absent: without DNSSEC, a `TXT` answer is the resolver's assertion.
RFC 8484 defines DNS-over-HTTPS in wire format; the JSON API the engine uses is
a vendor convention outside it, which is why this lookup cannot ride the
browser's own RFC 8484 or RFC 9230 code even if the endpoint were configurable.

**Why.** The engine's default is not overridden.

**Consequence.** Two, and the trust panel states the second.

1. **Privacy.** Every `hyper://<name>/` navigation tells one public resolver
   which hypercore name is being visited, over a path that is neither the
   browser's DoH policy nor its Oblivious DoH — in a browser whose pitch for
   Handshake names is that the lookup is oblivious.
2. **Integrity of the mapping.** A hostile or compromised answer names a
   *different* hypercore, whose contents then verify perfectly against the key
   it supplied. This is said explicitly: a dotted `hyper://` host gets two trust
   steps, the mapping **unverified** and the content **verified**, the verdict is `partial` / TRUSTED, and the scheme table's `verify` string carries the same
   qualification (SPEC §K.4.2, §K.9).

**Status: OPEN.** The privacy half is a configuration change — set
`hyperOptions.dnsResolver` from the browser's own DoH configuration, so the
disclosure goes to the resolver the user already chose rather than to a third
party they did not. The integrity half is not reachable that way: the engine
speaks the DoH JSON API, so a DNSSEC-validating answer would need the lookup
lifted out of the engine entirely and performed by the browser's resolver
before the SDK is constructed. Do the first now and treat the second as a
design question; the claim, which was the security-relevant part, is already
stated correctly. The engineering item is §3, **KY-D2**.

---

#### KY-5. `magnet:` is its own namespace although it only ever redirects

**What.** `magnet` has a namespace of its own, distinct from `bittorrent`
(`../../src/router.js`, `NAMESPACES.MAGNET`), even though every successful
magnet is a 308 into `bittorrent://` and every failing one is a 400.

**The standard says.** Nothing: the namespace is this specification's own unit,
defined in the spine. BEP 9 defines the magnet URI and says nothing about how a
browser tags a failure.

**Why.** The namespace is the unit the routing law L2 is enforced on, and a
magnet failure genuinely is a magnet failure: the URI is malformed, or carries
no URN this browser speaks. Tagging that as a *BitTorrent* failure would say
the swarm was consulted when nothing was.

**Consequence.** A magnet error is reported with
`X-Resolution-Namespace: magnet`, so anything counting failures per namespace
sees two namespaces where a user sees one protocol.

**Status: DELIBERATE.** A redirect is an answer, not a fallback — the same
reasoning that justifies the key-shape split inside the BitTorrent namespace
(SPEC §K.7.2). Stated because a reader comparing the namespace list to the
scheme list will notice the extra row.

---

#### KY-6. A dropped `.torrent` file is shape-checked, not verified

**What.** `validateTorrentFile()` (`src/torrent-input.js`) checks three things:
the bytes are a non-empty `Uint8Array`, they are under 10 MiB, and the first
byte is `0x64` (`d`, a bencode dictionary). Nothing parses the bencode, nothing
reads the `info` dictionary, and nothing computes an info-hash.

**The standard says.** BEP 3 defines the metainfo file and bencoding, and
defines the info-hash as the SHA-1 of the bencoded `info` dictionary.

**Why.** The check exists to refuse an HTML error page or an image the user
dropped by mistake, cheaply, before a multi-megabyte POST. The engine parses
the file properly and derives the info-hash from it, which is the check that
decides the address.

**Consequence.** Any bencoded dictionary passes — `d5:hello5:worlde` passes —
and the user learns that a file is not metainfo from the engine's error rather
than from the browser's. Not a security consequence: the info-hash the engine
derives *is* the address, whatever the file claimed, so a malformed or hostile
`.torrent` cannot make the browser fetch something under the wrong address.

**Status: DELIBERATE.** Pinned by a test that says so explicitly
(`tests/torrent-input.test.js`, "the .torrent check is a SHAPE check and claims
nothing more"), so nobody later reads it as verification.

---

#### KY-7. Every "verified by construction" claim in this chapter is made by a dependency

**What.** The four integrity guarantees this chapter rests on — a hypercore
block against its signed Merkle root, an SSB message against its feed's
signature chain, a torrent piece against the `info` dictionary's piece hashes,
a BEP-46 item against its public key — are performed by `hypercore`,
`ssb-fetch`, the rqbit sidecar and `bt-fetch` respectively. **No verification
code is in this package**, and none of it is tested here.

**The standard says.** The Hypercore protocol, the Scuttlebutt protocol guide,
BEP 3 and BEP 46 each define a check this chapter's trust states depend on.

**Why.** The browser delegates protocol verification to the engines that
retrieve the data.

**Consequence.** The trust states this chapter specifies are only as true as
those libraries are. A silent regression in any of them — a check made
conditional, a verification path skipped on a fast path — is caught by nothing
here, and the padlock keeps saying verified. That is a materially weaker
position than the Handshake chapter, where every signature an answer rests on
is validated by code in this repository and tested against flipped bytes.

**Status: DELIBERATE** architecture. Section 2.3 proposes independent
conformance vectors for the delegated checks.

---

#### KY-8. In Fast mode, a `gemini://` host is resolved by the operating system

**What.** In Fast mode, the Gemini client passes the hostname to Node's
`tls.connect()`, which resolves it with the operating system's resolver: not the
browser's DoH policy, not its Oblivious DoH bridge, not Chromium's secure-DNS
setting, and not the Handshake resolver. In **Private** mode this does not
happen — the handler dials through the device-local Tor by name and no local
lookup is made (SPEC §K.6.1, §K.6.2) — so this deviation is exactly the
Fast-mode case and nothing more.

**The standard says.** RFC 8484 (DoH) and RFC 9230 (Oblivious DoH) are the
transports the rest of this browser uses for exactly this lookup; the Gemini
specification says only that the host is a DNS name.

**Why.** Not a decision — a consequence of a client that opens its own socket.
On the anonymized route the socket has to be built here anyway (a direct dial
would leak the address), and whoever builds the socket chooses who resolves; on
the plain route nobody builds one on the client's behalf, so `tls.connect()`
keeps the choice.

**Consequence.** In a browser that goes to considerable trouble to make name
lookups oblivious, one scheme looks its hosts up in the clear in the mode most
users are in: the router, the ISP and anyone on the path sees which capsule is
being visited. A Gemini host that is a Handshake name does not resolve on either
route, which is a missing feature rather than a leak. The same open-resolver
disclosure applies to SSB's multiserver addresses and to hyperswarm's bootstrap,
but those are peer addresses rather than user-chosen names, so it is less
pointed.

**Status: OPEN**, and confined to one mode. The fix is the same shape as the
one the Private route takes: resolve the host with the browser's own
resolver and pass the resulting **address** to the client with `servername`
still set to the name, so SNI and any future certificate pin (KY-D1) stay keyed
to the name rather than the address. That also opens the door to Gemini over
Handshake names, which do not resolve today. The engineering item is §3,
**KY-D2**.

---

#### KY-9. Engine-reserved host names are reachable: `bt-fetch` petnames and `localhost` drives

**What.** Two engines reserve host names that are not keys.

- `bittorrent://<word>/`, where `<word>` matches `/^[-A-Za-z0-9_]+$/` and is
  not a key, is a **petname**: `bt-fetch` derives a keypair from it *locally*
  and resolves that. `bittorrent://localhost/` is a meta endpoint of the same
  library.
- `hyper://localhost/` is the device's own drive, the one named `default`;
  `GET` answers with its `hyper://<key>/` URL and `GET /path` serves its files.
  Because the handler builds the fetch with `writable: true`, the
  `POST`/`PUT`/`DELETE` routes are live too.

Both are reachable because the `bittorrent://` dispatcher passes anything that
is not a 40-hex info-hash straight through, and because `hypercore-fetch`
reserves the name itself.

**The standard says.** BEP 46 and the Hypercore protocol define an address as a
key. Neither defines a local alias, and nothing in either makes an address mean
different things on different machines.

**Why.** Inherited: these are two engines' local conventions. `hyper://` has no
petname path — `hyper-sdk` rejects a non-key, non-DNS host outright — so this
is not a design of ours in either case.

**Consequence.** A namespace whose entire promise is that the address *is* the
object contains addresses that mean different things on different machines: a
link to `bittorrent://news/` resolves to one thing on the author's computer and
another on the reader's, silently, with the padlock unchanged. And
`hyper://localhost/` names a stable per-device identifier — the user's own
default drive key — from a host name any page in the scheme can ask for.

**Status: OPEN.** Refuse a non-key `bittorrent://` host in the dispatcher,
before `bt-fetch` sees it, with an in-namespace 400 naming the two shapes that
are addresses; if petnames are wanted later they need their own scheme or an
explicit prefix, not the same host position as a key. For `hyper://localhost/`
the first step is to find out whether web content can reach it at all, which
this package cannot determine (§2.5). The engineering items are §3, **KY-D3**
and **KY-D4**.

---

#### KY-10. Every magnet parameter except `xt`, `xs` and `dn` is ignored

**What.** `tr=` (tracker), `ws=` (web seed), `so=` (select file indices),
`x.pe=` (peer address) and everything else are read and discarded. Only the
info-hash or public key and the display name survive the 308 into
`bittorrent://`.

**The standard says.** BEP 9 defines `tr=` and `dn=` alongside `xt=`; BEP 53
defines `so=`.

**Why.** The `bittorrent://` URL form has no room for them: the address is a
key and a path and nothing more. Discovery is the DHT's job (BEP 5), and file
selection is done by the URL path instead (SPEC §K.7.7), which is a better fit
for a browser — a user opens a file by clicking it, not by naming an index.

**Consequence.** A `so=` selection is silently ignored and the browser fetches
what the path asks for, which is equivalent. Dropping `tr=` is not equivalent:
a magnet whose only working trackers are in `tr=`, and which is not findable in
the DHT, does not resolve, and "no peers" and "no trackers" look identical from
the outside.

**Status: OPEN** for `tr=`; the `so=` half is deliberate and settled. Carrying
trackers through means either putting them in the `bittorrent://` URL — which
we do not want, because the address should be the key — or holding them in a
side table keyed by info-hash, which is state the resolution layer does not
have. The second is probably right and is a small store; until it exists, a
thinly-seeded magnet fails silently, which is the worst shape of failure. See
§2.4.

---

#### KY-11. No freshness is pinned for any mutable address

**What.** Three of these namespaces are key-addressed, meaning the content
under a fixed address changes: a BEP-46 item has a sequence number, a hypercore
has a version, an SSB feed has a tip. Nothing records the highest value seen
for any of them.

**The standard says.** BEP 44 defines `seq` and the rule that a node should not
accept an item with a lower sequence number than one it holds; Hypercore
versions and SSB feed tips are the equivalent counters in their protocols.

**Why.** Highest-seen values are not stored. Each protocol needs persistent
state keyed by address and a policy for handling regressions.

**Consequence.** A peer can return an older, validly signed answer without
triggering a rollback warning. The trust steps distinguish integrity from
freshness, but the client does not detect this regression (SPEC §K.9).

**Status: OPEN**, and not planned. The smallest honest version is one store
keyed by address holding the highest sequence number, version or tip seen, a
refusal to render a lower one without saying so, and a trust step that reports
"newest seen" rather than staying silent. Written down because "the address is
the key, so it is verified" is a claim that quietly excludes freshness, and a
reader is entitled to know that.

---

### 2. Things we are not sure about

#### 2.1. Whether key **shape** is a sound basis for dispatch at all

`bittorrent://` splits on the length of a hex string, and it works because
BEP-3 info-hashes are 20 bytes and Ed25519 keys are 32. BEP 52 breaks that: a
v2 info-hash is also 32 bytes. So the dispatch rule is not "this shape means
this kind of object", it is "this shape means this kind of object *among the
two kinds we happen to support*", which is a much weaker statement.

We do not know the right fix. The options we can see are a URN-style host
(`bittorrent://btih:<hex>/`), which breaks every existing link and is a form no
other client emits; a multihash-prefixed key, matching BEP 52's `btmh:` magnet
spelling; or accepting the ambiguity and disambiguating by trying both engines,
which is exactly the cross-engine fallback SPEC §K.3.3 forbids. If anyone has
resolved this for a browser-facing `bittorrent://` scheme, we would rather
adopt their answer than invent a fourth.

#### 2.2. We cannot test the canonicalisation this chapter reasons about

SPEC §K.3.4 argues that registering these schemes as Chromium **standard**
schemes is safe because none of their identifiers is case-sensitive in the host
position, and that the legacy SSB sigil form would be destroyed by the same
canonicalisation. Both claims reason about Chromium's URL parser from its
documented behaviour and from `src/main.cjs`'s own comments.

**Neither can be reproduced in this package.** Node's WHATWG URL parser has no
mechanism for registering a custom standard scheme, so `new URL('ssb://@Abc…')`
under `node --test` does not do what Chromium does. The tests here assert what
our own code does and leave the canonicalisation claims unpinned. An
Electron-hosted test would close this; it is out of this package's scope, and
we would rather say so than leave a reader thinking the claim is tested.

#### 2.3. Whether a dependency's verification should be tested here

KY-7 says plainly that every integrity guarantee in this chapter is a
dependency's. Whether that is acceptable as it stands is the question we cannot
settle.

Delegation avoids duplicate protocol implementations, and live-swarm tests
would be nondeterministic.

Offline negative vectors could still check each engine: a broken Hypercore
signature, a mismatched torrent piece and a tampered SSB message chain. These
would test the guarantees the browser reports without requiring a live swarm.

#### 2.4. Dropping a magnet's trackers

KY-10 discards `tr=`. For public, well-seeded torrents the DHT (BEP 5) finds
peers and nothing is lost. For a private or thinly-seeded one the trackers may
be the only way to find anybody, and the browser simply appears not to work,
with no message saying why.

Carrying trackers through means putting them in the `bittorrent://` URL, which
we do not want to do (the address should be the key), or holding them in a side
table keyed by info-hash, which is state the resolution layer does not have. We
are not sure the second is wrong.

#### 2.5. Whether `hyper://localhost/` is exposed to web content

`hyper://localhost/` answers with the device's default drive key. The schemes
in this chapter are registered with `corsEnabled: true` and
`supportFetchAPI: true`, and `fetch-to-handler.js` sets
`Access-Control-Allow-Origin: *` on every response. That combination reads like
"any page can read this", which would make a stable per-device identifier
available as a fingerprint.

We cannot determine whether it is actually reachable from an `https://` page,
and this package cannot test it: Electron custom schemes carry no `Origin`
header, so a header-based conclusion either way would be wrong — the same trap
that made an earlier CORS gate in this browser a no-op. It needs an
Electron-hosted test with a real cross-origin `fetch`. Until somebody runs it,
this is a suspicion, not a finding.

#### 2.6. Whether Gemini belongs in this chapter at all

Gemini is not key-addressed. It is a DNS name reached over TLS, and it is here
because its *trust* model — TOFU — is the one place a name namespace behaves
like a key namespace: the certificate's key becomes the identity after the
first sight of it.

Gemini could be moved to a separate chapter or grouped with DNS-based
protocols. No other section here depends on it; a move would require updating
cross-references.

---

#### 2.7. What Tor's exit does with a Gemini host name, and whether it has been proven

In Private mode the host is sent to the SOCKS proxy as a domain name and
resolved inside Tor (SPEC §K.6.2), which removes the local disclosure and
moves it: the exit relay's resolver sees which capsule is being visited. That is
the same trade every `.onion`-capable browser makes for clearnet hosts, and we
believe it is right, but we have not thought about it as hard as Chapter 8 has
thought about `.onion` — a capsule with a small readership and a single visitor
is a thinner crowd to hide in than a web host.

Nor has the route been driven against a live capsule through a real circuit:
`tests/gemini-protocol.test.js` proves it against a stub SOCKS5 server that
answers "connected" and never dials, which pins the *wire shape and the address
type* and nothing about latency, exit-policy refusals, or what a capsule that
blocks known exits does. Gemini servers are hobby infrastructure and some of
them will refuse Tor; the honest statement is that the route is correct and
unmeasured.

---

### 3. Open design items

#### KY-D1. A Gemini certificate store

KY-1 records the missing certificate store. Implementing it would add the
persistent identity check required by TOFU.

**Recommendation.** Pin the peer's SPKI SHA-256 on first sight, keyed by
`host:port`, in a persistent store; on a mismatch fail closed with the wording
the DANE pin-mismatch path already uses, and offer the same accept-once
affordance only where that path does. `@derhuerst/gemini` takes an injected
client-certificate store with a `get`/`delete` shape; a server-certificate
store is the same shape at the same injection point, so no fork is needed. When
it lands, the trust step becomes "certificate matches the one first seen" and
the scheme table's `verify` string changes with it — the two must move
together.

#### KY-D2. Give `hyper://` the browser's resolver

`hyper-sdk` resolves DNSLink names from its own default DoH JSON endpoint
because `hyperOptions` sets only `storage` (KY-4), so that scheme looks names up
outside every DNS protection the rest of the browser applies.

**Recommendation.** Set `hyperOptions.dnsResolver` from the browser's own DoH
configuration — a config change that removes the third-party disclosure without
touching the engine. It does not add DNSSEC: the engine speaks the DoH JSON API,
not RFC 8484 wire format, so a validating lookup would have to be performed by
the browser's resolver before the SDK is constructed, which is a larger change
worth costing separately.

Gemini needs no part of this item for the mode that cannot tolerate the gap:
in Private mode, the host is resolved inside Tor and the socket is built by
this handler (SPEC §K.6.2). What is left there is the Fast-mode route, which
is KY-8's own recommendation and the same few lines at the same
injection point — the socket is already constructible at it.

#### KY-D3. Find out whether web content can reach `hyper://localhost/`

`GET hyper://localhost/` answers with the device's default drive key, and the
write routes are live because the fetch is built `writable: true` (KY-9). The
scheme is registered `corsEnabled` and `supportFetchAPI`, and every response
carries `Access-Control-Allow-Origin: *`, which *reads* as available to any
page — but Electron custom schemes carry no `Origin`, so no header-based
conclusion is sound (§2.5).

**Recommendation.** Write the Electron-hosted test first — a real `https://`
page doing `fetch('hyper://localhost/')` — and let the answer decide the fix.
If it is reachable, gate the reserved host on `webContentsId` the way the
browser gates its other main-owned surfaces, never on a header. Either way,
document the reserved host: it currently appears in no document in the tree.

#### KY-D4. Refuse a non-key `bittorrent://` host before the engine sees it

Anything that is not a 40-hex info-hash is passed to `bt-fetch`, which treats a
host matching `/^[-A-Za-z0-9_]+$/` as a petname and derives a keypair from it
locally (KY-9). `bittorrent://news/` therefore names a different object on
every machine, silently, in the one namespace whose promise is that the address
is the object.

**Recommendation.** Refuse a host that is neither 40 nor 64 hex in the
dispatcher, with an in-namespace 400 naming the two shapes that are addresses,
so the refusal teaches the grammar. If device-local names are wanted later they
need their own scheme or an explicit prefix — not the host position a key
occupies.

#### KY-D5. A recognised-but-unserved SSB type answers 418

`ssb-uri2` validates six URI types and `ssb-fetch` serves three; `address`,
`encryption-key` and `identity` parse and then get **418 I'm a teapot**.
Failing closed inside the namespace is right (routing law L2), but 418 signals
nothing to anything, and this browser is otherwise careful that a protocol
handler never returns a status Chromium does not expect.

**Recommendation.** 501 is the code that means "recognised, not implemented",
and it is what the router already returns for a scheme with no handler. Fix it
upstream if the maintainer will take it; otherwise wrap the ssb handler and
rewrite 418 → 501 with a sentence naming the type and saying it is not served.

#### KY-D6. The two BitTorrent key shapes are defined twice

`src/magnet-protocol.js` carries the canonical `INFO_HASH_MATCH` /
`PUBLIC_KEY_MATCH` in their URN forms, and a test asserts that the
`bittorrent://` dispatcher does not fork them. `../../src/pointers.js` defines
the same two shapes again as bare hex (`BT_INFOHASH_RE`, `BT_PUBKEY_RE`) for
the `bt=` Handshake pointer. They agree, in a codebase that has a test whose
whole purpose is to prevent exactly this, and the `bt=` path is where a
divergence would be least visible.

**Recommendation.** Move the two shapes to one module both can import — a bare
hex pair with a one-line URN adapter over it, so the magnet forms and the
pointer forms are provably the same 20 or 32 bytes — and extend the existing
anti-fork test to cover `pointers.js`.

---

### 4. What this chapter leaves out

1. **The three engines.** `hyper-sdk`/`hypercore-fetch`, `ssb-fetch` and
   `bt-fetch` are not extracted and could not be: the first needs a prebuilt
   native addon (`rocksdb-native`, the subject of the diagnostic in SPEC
   §K.3.5), and all of them open real sockets. The Wildroot modules that
   construct them are ten to thirty lines each, and **all of them are the same
   ten lines** — a closure handed to `fetchToHandler()`. That shared wrapper
   *is* extracted, byte-identical, and is tested with a stub engine
   (`tests/engine-lifecycle.test.js`), which pins the two resolution-visible
   behaviours it owns: lazy single construction, and an engine failure
   surfacing as this scheme's own 500. The Gemini client is likewise injected
   rather than extracted (`createHandler({ requestImpl })`), so
   `tests/gemini-protocol.test.js` exercises the handler's own decisions
   without opening a socket.

2. **The rqbit sidecar** (`src/hns/torrent.js` in the browser tree, ~500 lines:
   process supervision, a pid file, orphan reaping, a per-launch loopback
   credential, bounded restarts, the seeding floor). It spawns a vendored
   binary; none of it is resolution. The address decisions it sat next to were
   factored out into `src/torrent-address.js` and are tested without it.

3. **The stream proxy and the torrent listing page.** `Range` forwarding,
   206/`Content-Range` pass-through, content typing and the HTML file listing
   live in `torrent-protocol.js` and stay there. They are retrieval and
   presentation.

4. **The torrents page's view-model** (`src/hns/torrent-manager.js`) apart from
   its two input-validation functions, which are here as
   `src/torrent-input.js`.

5. **The native-addon diagnostic** (`src/protocols/native-addon-check.js`). It
   turns a misleading loader error into a sentence naming the library and the
   package to install. Referenced in SPEC §K.3.5 as a requirement on
   implementations; not extracted, because it is a diagnostic rather than a
   resolution step.

Everything else in `src/` here is either byte-identical to the Wildroot tree
(`gemini-protocol.js`, `magnet-protocol.js`, `fetch-to-handler.js`, `gate.js`)
or a verbatim copy of specific functions with only the module boundary changed
(`torrent-address.js`, `torrent-input.js`) — each of which says so in its own
header. Nothing is rewritten for this package.


---

<a id="chapter-10-experimental-hip-5-op-and-numeric-handshake-tlds"></a>

## Chapter 10 — Experimental: HIP-5 `_op` and numeric Handshake TLDs

_Source: [`namespaces/experimental/DEVIATIONS.md`](namespaces/experimental/DEVIATIONS.md)._

This file records limitations and open questions for the experimental
registry and numeric-name conventions. Remaining questions are
tracked in [the content review](REVIEW.md). The numeric-name default
below reflects the current classifier.

Identifiers are prefixed `OP-` (Part A, HIP-5 `_op`) and `NT-` (Part B, numeric
Handshake TLDs) so they cannot collide with another chapter's. The code is
`../../src/hip5-op.js` and the `_op` step in `../../src/resolver.js` for Part A,
`../../src/hns-url.cjs` and the classification rule in `../../src/router.js`
for Part B.

---

### 1. Deviations

#### OP-1. Two fall-throughs to the seller's nameservers

**What.** When a top-level name delegates to an Optimism registry contract via
an `0x<addr>._op.` NS record, the `_op` route is preferred, and it falls back to
the top-level name's ordinary NS records in two cases the route's own rationale
argues against:

1. **Every RPC endpoint failed or timed out.** Arguably this should be
   `unreachable`, rather than querying the TLD operator's nameserver.
2. **A sub-name of a sold name** (`www.maya.persist`) whose own namehash has no
   resolver in the registry also falls back.

**The standard says.** HIP-0005's premise is that the pseudo-TLD target *is*
the naming system for the names beneath it. ENSIP-10 (wildcard resolution)
describes the second case differently: walk **up** to `maya.persist`'s resolver
and ask it about the sub-name, rather than leaving the registry.

**Why.** Availability. Today the "seller" whose nameservers are fallen back to
is us, so this is a design point rather than a live exposure.

**Consequence.** The exact weakness the registry exists to remove — the
seller's nameserver answering for a name the seller no longer holds — is
reachable by an attacker who can make every Optimism RPC endpoint fail. This depends on the attacker being able to disrupt every configured RPC endpoint.

Not a fallback, deliberately: a **private or link-local address** from the
registry is `blocked`, never retried against DNS.

**Status.** OPEN. Implement ENSIP-10 wildcard resolution for case 2, which is a
strict improvement and removes the case entirely; for case 1, report
`unreachable` rather than falling back, once there is more than one registry
operator and the fallback is no longer to ourselves. The current behaviour is
pinned by a test (`../../tests/hip5-op.test.js`, "every RPC failing falls back
…") so that changing it is a deliberate act.

---

#### NT-1. Numeric Handshake top-level names: off by default, behind a switch

**What.** Numeric-name classification is optional and off by default.
`setNumericNames()` in `../../src/classify-host.cjs` enables it. SPEC Part B
defines the retained `_` marker for explicit URLs.

**The standard says.** Nothing forbids a numeric Handshake label — Handshake
labels are `[a-z0-9-]` and the registry sells them. The WHATWG URL Standard's
host parser is what makes them unwritable as URLs (NT-2).

**Why.** They exist and have been paid for, including the free-name registry
top-level name `14898`, so refusing them strands real registrations. Supporting
them costs a written convention nobody else implements.

**Consequence.** Bare numeric names are not automatically routed to Handshake
unless the option is enabled. Clients using the explicit URL form must
implement the marker convention.

**Status.** DECIDED (Matt, 2026-09-06): pure-number names are excluded by
default for simplicity. The resolution method and the `_` URL form of Part B
stay in the code and in this chapter; `setNumericNames()` in
`../../src/classify-host.cjs` is the one switch (the browser exposes it as
`hnsOptions.numericNames`, Settings › Operator panel). Off, an all-numeric
final label classifies as `web` — what the URL parser makes of it — and a bare
number typed alone is a search; the WebSocket PAC copy of the rule takes the
same answer (`buildWsPac({ numericNames })`). An `hns://hello._14898/` URL
still resolves when reached explicitly. Part B is therefore an OPTIONAL
convention, published, and not a default.

---

#### NT-2. A numeric TLD is written with a leading underscore in a URL

**What.** In an `hns://` URL a final label consisting entirely of ASCII digits
is written with a `_` prefix: `14898` → `hns://_14898/`, `hello.14898` →
`hns://hello._14898/`. The marker is stripped before the name reaches the
resolver and re-added before a URL is built; the address bar displays the
unmarked form. `../../src/hns-url.cjs`.

**The standard says.** The WHATWG URL Standard's
[host parser](https://url.spec.whatwg.org/#host-parsing) runs the
["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker)
for special schemes and parses such a host as an
[IPv4 address](https://url.spec.whatwg.org/#concept-ipv4-parser). It provides no
per-scheme opt-out, and `_` is not a
[forbidden host code point](https://url.spec.whatwg.org/#forbidden-host-code-point),
so the marked form is a conforming host while the unmarked one is not a host at
all.

**Why.** `hns:` is registered as a standard scheme to get a real web origin
(Chapter 1 §5), which is the same decision that subjects the host to that
parser. SPEC B.4 records the alternatives considered.

**Consequence.** Every name under a numeric Handshake top-level name has two
written forms, and any third party writing a link to one must know the
convention or the link is dead on arrival. It is a local convention with no
standing anywhere else, so a link written by this client may be dead in another
Handshake client and vice versa.

**Status.** OPEN. If a different convention gains traction anywhere else we
would rather adopt it than defend this one — a shared convention is needed for interoperable links (§NT-2.1).

---

#### NT-3. The `http://` spelling of a numeric name cannot be rewritten

**What.** The `http(s)→hns` rewrite (Chapter 1 §3) parses its input with
`new URL()`, so `http://hello.14898/` throws before any rewrite is attempted and
the link is simply dead. `../../src/hns-host.js`.

**The standard says.** The same URL Standard rule as NT-2: the host ends in a
number, so it is parsed as IPv4 and the parse fails.

**Why.** There is nowhere to intervene. Chromium refuses to construct the
request, so no navigation hook, protocol handler or rewrite ever runs.

**Consequence.** A third party writing `http://hello.14898/` — the spelling a
person would naturally use — produces a link this browser cannot repair, where
the same name written `hns://hello._14898/` works. Only `hns://` links to
numeric names are reachable.

**Status.** The automatic classification policy is decided in NT-1.
This URL-parser limitation remains: links to supported numeric names need
the marked `hns://` form.

---

### 2. Things we are not sure about

#### OP-2.1. `_op` is chain-pointed and RPC-answered

The Handshake chain proves *which contract* answers for a name. Nothing proves
the contract's *answer*: it is read from a public Optimism JSON-RPC endpoint
over HTTPS with no light client and no Merkle proof against a block header. The
endpoint is trusted for the record and sees which name was asked.

The route is marked `unverified` in the trust panel, naming the registry and
the RPC host in words. The lock follows the DNS route's rule — a content
pointer closes it on the chain proof, an address closes it only on a matched
DANE pin — on the argument that the honest comparison is with the DNS route
(whose unsigned answer is also taken on a nameserver's word, over plaintext
where this hop is HTTPS) and not with `ens://` (which has no chain anchor at
all and never closes better than TRUSTED).

We are not certain that is the right line. A reasonable implementer could hold
that an RPC-trusted answer should never close a lock, full stop.

#### OP-2.2. One deployment is not a specification

`persist` on Optimism mainnet is the registry deployment documented here.
Every property in SPEC A.3 is a property of that contract, verified by reading
it; none of them is enforced by the mechanism. A second registry that behaves
differently — a `resolver(node)` that reverts rather than returning zero, a
`dnsRecord` that returns records under a different owner name — would be
resolved by this client in ways we have not tested.

#### OP-2.3. What the registry read does under an anonymizing proxy

The `_op` read rides the embedder's proxied fetch, so it is private in the sense
that matters — the RPC endpoint sees the proxy, not the user (SPEC §A.6). What we
have not measured is whether it still *answers*: public JSON-RPC endpoints
commonly rate-limit or refuse traffic from anonymizing-network exits, and this
route's behaviour when every endpoint fails is to fall back to the top-level
name's ordinary nameservers (OP-1, case 1). If that is what happens under a
proxy, then the mode a user turns on for privacy is also the mode that quietly
returns them to the seller's nameserver — which is the one outcome the route
exists to avoid. It is a measurement, not an argument, and it has not been made.

#### NT-2.1. The marker is a local invention, and its value depends on being shared

Two interoperability questions remain after the default-off decision:

- Whether the marker belongs on the **numeric label** (`hello._14898`) or as a
  **whole-host** marker. A prefix on the label is minimal and local; a host-wide
  marker would be uglier but would not change meaning depending on which label
  it lands on.
- Whether other Handshake clients will do something different, at which point a
  link written by one is dead in the other. A shared convention would prevent incompatible links.

---

### 3. Open design items

#### OP-D1. The library default fetch is unproxied

The `_op` registry read uses an injected `fetchImpl` when the embedder provides
one, and the browser provides its proxied session fetch, so the shipped
composition never makes this request outside the proxy (SPEC A.6). When no
implementation is injected, the module falls back to the platform's global
fetch — which ignores the session's proxy settings. An embedder that forgets
the injection gets a route that works and leaks the user's address to the RPC
endpoint, with nothing to notice.

This affects privacy because the route runs while anonymization is on and is
not gated (SPEC §A.6), so the default is the one place where a mode the user
turned on for privacy can be defeated by an omission in an embedder rather than
by a decision anybody made.

**Recommendation.** Require it: throw from the constructor when no `fetchImpl`
is given, as the Arweave handler does. A library caller that genuinely wants
the global fetch can pass it explicitly, which makes the choice visible in the
caller rather than invisible in the default.

#### OP-D2. No light-client verification of the registry's answer

A possible next step, also applicable to `ens://`, is to verify the storage slot
against a block header, by a light client or an execution proof, which would allow the record step to report `verified` if that proof validates.

**Recommendation.** Not now — the dependency is large and the route already
degrades honestly. Revisit when a usable Optimism light-client or storage-proof
library exists in a form a browser can load on every navigation; until then,
keep saying `unverified` in words.

#### NT-D1. Numeric top-level names have no test of the whole path

`../../tests/hns-url.test.js` covers the encode/decode/display/rewrite edge
cases, including the trailing-dot case. What is not covered anywhere is the
*path*: a typed `hello.14898`, through the classifier, through the URL
construction, through a resolution, back to a displayed address bar.

**Recommendation.** Add an end-to-end test for both the opt-in classifier
and explicit marked URLs, since both remain supported.

---

### 4. What this chapter leaves out

1. **The chain half of the resolution.** How the `_op` record is proven, how the
   nameserver list is built and how a resolution's trust steps are assembled is
   Chapter 1. This chapter starts from a proven `<registry>._op.` NS record and
   ends at a resolution of Chapter 1's own shape.
2. **The contracts.** The Solidity sources, the minter, the ownership-epoch
   versioning scheme and the operational runbook for the `persist` registry are
   not part of this specification. SPEC A.3 states only the properties a
   *reader* depends on.
3. **The composition layer.** Which fetch implementation is injected, and how a
   browser decides to proxy it, belongs to the embedder; SPEC A.6 states the
   requirement, not the wiring.
4. **Any other `_<chain>` pseudo-TLD.** `_eth` is HIP-5's own shipped example
   and is not implemented; a top-level name delegating through one is resolved
   through its ordinary nameservers (Chapter 1, `HS-13`).


---

<a id="chapter-11-native-applications-on-a-handshake-name"></a>

## Chapter 11 — Native applications on a Handshake name

_Source: [`namespaces/apps/DEVIATIONS.md`](namespaces/apps/DEVIATIONS.md)._

This file records limitations, departures from cited standards, and open
questions about the application integration in [SPEC.md](namespaces/apps/SPEC.md).

The tunnel tests cover its connection restrictions and end-to-end TLS through
the splice. They do not establish every browser behavior discussed below.
The entries distinguish tested behavior, reported observations, and work
that still needs verification.

Paths written `../../src/…` are shared modules of the top-level package; paths
written `src/…` and `tests/…` are this chapter's, under `namespaces/apps/`.
Paths written `browser src/…` are in the Wildroot browser tree and are not
extracted into this repository (SPEC.md, "Paths").

---

### 1. Deviations

#### AP-2. The tunnel cannot require proxy authentication, and ships with none

**What.** The tunnel is an unauthenticated local proxy. It accepts a `CONNECT`
from any process on the machine that can reach `127.0.0.1:<port>`, subject only
to the port, Handshake-only, SSRF and Tor fences. The `Proxy-Authorization`
check is implemented and constant-time (`src/ws-proxy.js:217`, `:276-280`,
`:300-303`) but is skipped because no credential is passed
(browser `src/protocols/index.js:267-277`).

**The standard says.** RFC 9110 §11 (with RFC 7235's mechanism) defines exactly
this: a proxy answers `407` with `Proxy-Authenticate` and the client retries
with `Proxy-Authorization`. RFC 1928/1929 define the SOCKS5 equivalent. The reference browser integration cannot use either mechanism: Chromium's SOCKS5
client offers only the "no authentication" method, and Chromium does not
surface a proxy-auth challenge to its embedder for a `wss://` handshake, so the
`407` is never answered and the socket dies instead of retrying.

**Why.** Two implementations were built and neither could connect once. The reference implementation relies on the loopback bind and the four
connection checks described in the specification.

**Consequence.** Any local process can use the tunnel to resolve a Handshake
name and open a TCP connection to its public address on port 443. That is a real
widening of what this component does compared with an authenticated proxy, and
the argument that it is acceptable is a specific one: a process already on
loopback can resolve the same name over public DoH and dial the same address by
itself, so the tunnel confers no capability it lacked — while the port,
Handshake-only and SSRF fences mean it confers rather *less* than a general
proxy would. In Private mode that connection is made through the user's own
Tor client rather than directly — or, while that Tor is blocked, not at all —
which is a route the local process could also have taken itself.

**Status: DELIBERATE.** The credential path is retained and tested
(`tests/ws-proxy.test.js`, "OPTIONAL auth (future platform)") so that a platform
which can authenticate a `wss://` proxy re-enables the gate with no code change.
Until then, no document, comment or interface may describe proxy authentication
as a protection of this feature.

#### AP-3. No service workers at a Handshake name

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
address, which limits native applications.

**Status: OPEN.** We recommend enabling service workers at `hns://` once two
questions are answered: what a cached, self-persisting copy of a page means for
a name whose records (and therefore its DANE pin) can change under it, and
whether a worker's own fetches take the same header allowlist as the page's
(SPEC §3.4). These questions need answers before changing the registration.

#### AP-4. WebSocket routing is decided by the target host, not by the initiating origin

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
Handshake application author should know that their socket is reachable from
the whole web, not only from their own origin.

**Status: DELIBERATE.** The implementation follows the web platform's target-based routing. Applications must check `Origin` as they would anywhere.

#### AP-5. A native page's sign-in token is bound to a URL the request is not sent to

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

#### AP-6. Manifests are unsigned, so an installed application's identity is only its origin

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

#### AP-7. A Handshake WebSocket is reachable on port 443 and nowhere else

**What.** The tunnel accepts a `CONNECT` to 443 and refuses every other port
before resolving (`TUNNEL_PORT`, `src/ws-proxy.js:90`, `:317-319`; SPEC §4.4
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
arbitrary port would therefore mean splicing TLS that the pin check cannot
cover — which is exactly what fence 1 exists to prevent.

**Consequence.** A publisher must terminate its WebSocket on 443 at the
Handshake name (SPEC §4.8), which is what every reference deployment does
anyway, and a non-default port is a dead end with a bad error. The cost is
carried by the deployment, not by the trust story.

**Status: DELIBERATE.** A broader port policy would require changes in both resolution and certificate verification. Give the
resolution a port parameter, read `_<port>._tcp.<name>`, and thread the port
from the CONNECT through to the certificate check; until the engine's
verification callback carries the port, the supported set remains the one port covered by the pin lookup. Both halves must move
together, or the port becomes reachable before it becomes pinned.

---

### 2. Things we are not sure about

These claims need additional implementation evidence or measurement.

#### 2.1. Whether the `101` is checked for `Sec-WebSocket-Accept` in our stack

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

#### 2.2. What Chromium actually sends to the tunnel for a plaintext `ws://`

The PAC routes `ws:` to the tunnel (SPEC §4.6). What Chromium then *does* with
that URL through an HTTP proxy — issue `CONNECT <host>:80`, or issue the
WebSocket `GET` through the proxy as an absolute-URI request — we have not
measured. Nothing rests on the answer, because both are refused without a
lookup: a `CONNECT` to 80 by the port fence with `403`, an
absolute-URI `GET` by the method check with `405 Allow: CONNECT`. We record it
because "both branches refuse" is a reason not to measure it, and "we measured
it" would be a different and stronger claim.

#### 2.2a. What the anonymized route costs in latency and circuit sharing

The Tor route of SPEC §4.4 fence 4 is pinned by test against a stub SOCKS
server; it has not been measured against a real Tor circuit. Two things are
therefore unquantified: what a WebSocket handshake costs through a circuit that
may still be building (Chapter 8 §7.2 routes before readiness deliberately), and
what a long-lived socket does to a session whose circuits are shared by
everything in it (Chapter 8 TO-3). Neither is a correctness question — the
fences and the pin are the same on both routes — but a realtime application is
the one kind of page for which "it works, slowly, forever" is a different
product from "it works".

#### 2.3. Whether the PAC leaves loopback traffic reachable in Private mode

The privacy controller's own configuration carries
`proxyBypassRules: '<-loopback>'` (`_defaultConfig` in
`namespaces/tor/src/anonymize.js`). The PAC decorator replaces the whole
configuration with `{mode: 'pac_script', …}` (browser `src/index.js`), and the
PAC has no loopback branch: in Private mode, its non-WebSocket answer for
`http://127.0.0.1:<port>/` is the anonymizer's SOCKS directive — the Tor port
while routed, the blackhole port while blocked. Whether Chromium applies an
implicit loopback bypass to a PAC-configured session is exactly the thing we
could not establish from the specification or from a measurement. If it does
not, then every in-process loopback service a page fetches (a content-gateway
port, a media sidecar) is routed into Tor — which refuses it — for as long as
Private mode and the tunnel are both on. See AP-D1.

#### 2.4. Cookie behaviour on an `hns://` origin

SPEC §3.2 claims storage for a tuple origin, and that claim is measured for
`localStorage` only (an application crashed without it and works with it). We
have **not** established whether `document.cookie` works on an `hns://` origin,
whether cookies set there persist across restarts, or whether the behaviour is
stable across Chromium versions — and the reference fetch path deliberately
drops `Cookie` anyway (SPEC §3.4), so an application that relied on cookies for
its own server would find them missing on the wire even if the renderer stored
them. An application should use `Authorization`, which is specified to work.

#### 2.5. Storage partitioning inside a native document

The HTML Standard partitions storage for third-party content by top-level site.
What a Chromium build computes as the partition key for a non-http standard
scheme, and therefore what an embedded third-party frame inside an `hns://`
document can reach, is unmeasured here. Nothing in this chapter depends on it;
an application that embeds third-party frames should not assume either answer.

#### 2.6. Whether the PAC is applied to every session that can open a WebSocket

The decorator returns the base configuration unchanged for any session that is
not the web-content session (browser `src/index.js:1133`). That is right for the
sessions we know about, and we have not enumerated every session in the
application that could host a document able to open a `wss://`. A session
without the PAC sends `wss://<handshake name>` DIRECT, where it fails as an
unresolvable host — a failure, not a leak, but an obscure one.

#### 2.7. Internationalised hosts in the PAC

The PAC's rule compares the final label against a punycode ICANN list without
punycoding the host itself, where the classifier punycodes first
(`../../src/router.js`). We believe this is safe because Chromium hands a PAC
the already-canonical (ASCII) host from the URL, and the corpus in
`tests/native-origin.test.js` does not test it. If that belief is wrong, an
internationalised ICANN host would be classified Handshake by the PAC and then
refused by the tunnel's own classifier — a broken socket, not a leak.

#### 2.8. The numeric-TLD path has never been proven end to end

`tests/native-origin.test.js` shows that the PAC routes `hello._14898` and that
the tunnel strips the marker before resolving. Whether a page actually served at
`hns://hello._14898/` can open a `wss://` and complete a DANE-pinned upgrade has
not been demonstrated in a browser. Chapter 10 Part B is explicit that the whole
numeric-TLD convention is provisional.

#### 2.9. `verified: true` is a live observation, not a regression test

The sign-in path of SPEC §5 was proven once, end to end, against a deployed
application: the provider appeared at a native origin, a token was minted for
the canonical gateway origin, the header survived the fetch path, and the
server answered with a verified name. The pieces are unit-tested individually
in the browser tree (the origin gate, the manifest gate, the signature, the
rate limit, the locked-vault cases). The *whole* path has no automated test, and
the memory of one successful run is not one.

---

### 3. Open design items

Proposed changes and the relevant implementation locations follow.

#### AP-D1. Give the PAC a loopback and private-literal branch

`FindProxyForURL` has exactly two answers — the tunnel for Handshake
WebSockets, the anonymizer's directive for everything else
(`src/ws-proxy-pac.js:58-63`) — and installing it discards the
`proxyBypassRules: '<-loopback>'` the privacy controller would otherwise apply
(browser `src/hns/anonymize.js:243-247`, `src/index.js:1142-1145`). Whether that
matters depends on §2.3, which we could not settle.

**Recommendation.** Return `DIRECT` from the PAC for `localhost`, for IPv4 and
IPv6 loopback and private literals, and for a bracketed literal — before the
WebSocket branch, so it holds for both. It costs four lines, it restores the
bypass the controller intended in the one configuration where the controller no
longer owns it, and it removes the need to answer §2.3 at all.

#### AP-D4. Decide the service-worker question for `hns://`

See AP-3. `browser src/main.cjs:110-120`. The blocking question is what a
cached page means when the name's DANE pin rotates.

#### AP-D5. Sign manifests, and make `verified` mean something

See AP-6. `browser src/apps/app-store.js` (the `verified` field and the hash
pin), `browser src/apps/manifest-validate.js:47-71` (where a signature check
belongs, beside the ownership rule).

#### AP-D6. A revoke / manage-applications interface

The store supports `revoke` and `uninstall`
(`browser src/apps/app-store.js`) and nothing in the interface calls them, so a
grant made once at install is, in practice, permanent. **Recommendation.** A
settings page listing installed applications, their entry origins, the names
granted to each and the manifest hash, with revoke and uninstall. Until it
exists the consent at install is a decision the user cannot take back, so the installation grants should remain limited.

#### AP-D7. Native discovery for a dotted Handshake name

Discovery maps only a bare native name to its gateway mirror; a dotted native
second-level name (`hns://foo.2url`) is deliberately not mapped
(`browser src/apps/manifest-validate.js:107-117`), so such an application is
discoverable only at its gateway origin. **Recommendation.** Map the dotted case
too once fetching an application's own scheme from the privileged process is
safe on every platform; the origin-ownership rule already handles the binding,
so the change is in the discovery base and its test.

#### AP-D8. Surface the tunnel's refusal reason

Every fence answers a distinct HTTP status that the WebSocket API discards, so
"this is not port 443", "Private mode, and the Tor client is not connected",
"this name has no address", "this name resolves to a private address" and "the origin
is down" are one untyped `error` event to the page and nothing at all to the
user (`src/ws-proxy.js:264-274`).
**Recommendation.** Record each refusal with its reason and the name, and show
it where the connection's trust state is already shown. The information exists
and is thrown away at the socket boundary.

#### AP-D9. Bound the tunnel's concurrency

The tunnel accepts and tracks unbounded connections
(`src/ws-proxy.js:230-235`), and every accepted CONNECT to an unresolved
Handshake host costs one resolution. **Recommendation.** A cap on live tunnels
and a small per-name rate limit on resolutions, refusing with `503` beyond it.
The risk today is bounded by the loopback bind, so this is hygiene rather than a
hole — but it is the kind of hygiene that is much easier to add before the
tunnel's dials are, in Private mode, made through the user's own Tor circuit
(SPEC §4.4 fence 4), where every accepted CONNECT costs circuit capacity
as well as a resolution.

---

### 4. What this chapter leaves out

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


---

<a id="cross-cutting-divergence-inventory-where-privacy-and-speed-pull-apart"></a>

## Privacy and transport

_Source: [`DIVERGENCE.md`](DIVERGENCE.md)._

This table compares the routes described for Fast and Private delivery. It
records what a service can learn, which paths are implemented, and which
claims still need verification. Row numbers are retained for existing links
and references.

Private mode uses the device-local Tor client where supported and refuses
some protocols. A Tor route hides the client's IP address from the destination;
it does not hide the requested name, CID, or relay filter from the service
answering it. ODoH separates the client's address from the DNS question across
a relay and target, subject to their non-collusion assumption.

The policy is defined by `policyFor()` in
[`src/delivery-mode.js`](src/delivery-mode.js). The browser supplies session
and content-engine integration. Its current deployment is not established by
this repository.

The table reflects the repository's current policy and separates extracted
modules from browser integration. Remaining questions are listed in
[REVIEW.md](REVIEW.md).

| # | Operation | Fast route and disclosure | Private route | Status and remaining question |
|---|---|---|---|---|
| 1 | Handshake authoritative DNS (§6, Chapter 1) | Local chain proof, then TCP/53 to the authoritative server. The server and network path can see the name and client address. | Keep the chain proof; send authoritative TCP through Tor. | Implemented through `src/socks-dial.js`. Tor adds latency. The documented transition while restarting the SPV node uses DoH and reports its weaker trust state. |
| 2 | SPV peer traffic (§11.5, Chapter 1) | Direct hsd peer connections expose the client address. | Start hsd with its SOCKS proxy option. | Implemented. Changing the proxy restarts the spawned node; sync and availability costs remain. |
| 3 | Handshake DoH/ODoH (§9, Chapter 1) | Try ODoH; plain DoH may answer if relays fail. That endpoint receives the query without the oblivious separation. | Require ODoH; report failure rather than use plain DoH. | Implemented by `strictOblivious`. More independent relays could improve availability. |
| 4 | ICANN NS/CNAME targets during a Handshake walk | Browser integration injects `DoHResolver.addressOf` in both modes. The library default uses the OS resolver. | Use the injected encrypted/oblivious lookup. | Integration requirement. Library embedders must supply the lookup explicitly to avoid the OS default. |
| 5 | ODoH configuration fetch (IC-9) | Fetch `/.well-known/odohconfigs` from the target. It can associate the client with use of the service. | Proposed: bundle a configuration and refresh it through Tor. | Open. The ODoH relay does not provide a general GET proxy for this resource. |
| 6 | ICANN browsing DNS (§5, Chapter 2) | Chromium secure DNS uses the configured pool. | Use the local ODoH bridge in secure mode. | `policyFor('private')` requires secure mode. Plaintext fallback belongs to the configurable automatic policy, not the Private preset. |
| 7 | ICANN page fetches (Chapter 2) | Direct connection; the site sees the client address. | Session fetches through Tor; blocked proxy when Tor is unavailable. | Implemented. Tor latency and sites that reject Tor exits remain limitations. |
| 8 | IPFS DHT and Bitswap (§7, Chapter 3) | Kubo connects to peers, exposing the client address and requested CIDs. | Offline local node plus a proxied, verified content source for named sites. | The repository policy selects `contentNode: offline`. Browser integration implements the Kubo restart and content import; it is not included in this package. Peer discovery remains unavailable in Private. |
| 9 | Stated-origin CAR fetch (§8, Chapter 3) | Fetch a CAR from the published origin; it sees the CID and client address. | Fetch through the proxied session and verify imported blocks. | The origin-fetch module is implemented. Private delivery of named sites requires the offline-node integration in row 8. Bare CIDs without a stated origin need a separate source. |
| 10 | Cooperative delivery | Proposed peer delivery exposes addresses and CIDs to other users' nodes. | Proposed onion-service peers, or refusal. | Not shipped in either mode. Peer identity and performance remain design questions. |
| 11 | Arweave gateways (§6, Chapter 4) | Gateway receives the transaction ID and client address. | Use the same injected fetch through Tor. | Proxied transport is implemented. Header and byte verification are separate trust questions; see REVIEW.md. |
| 12 | ENS resolution (§5, Chapter 5) | Ethereum RPC receives the lookup and client address; CCIP-Read may contact gateways. | Send RPC and CCIP-Read through the proxied fetch. | Implemented. A cache reduces repeated queries; Tor does not conceal the query from the endpoint. |
| 13 | `web3://` RPC (§8, Chapter 5) | The library creates RPC clients using its own fetch. | Refuse with 503 while anonymized. | A proxied path needs an injectable transport in the dependency or a fork. |
| 14 | HIP-5 `_op` RPC (Chapter 10 Part A) | Optimism RPC through the injected fetch. | Use the proxied fetch while the chain path is available. | Implemented by injection. The library's global-fetch default is a separate risk (OP-D1). |
| 15 | Nostr relays (§8, Chapter 6) | Direct WebSockets expose the client address and filter. | Dial relay names through Tor; refuse if no Tor port is available. | Implemented in `namespaces/nostr/src/tor-websocket.js`. Relays still see filters. The handler exposes the injected WebSocket transport required for this route. |
| 16 | DID documents (Chapter 7) | Directory or `did:web` host receives the identifier and client address. | Use the injected proxied fetch. | Implemented for remote DID methods. Locally derived methods do not need this lookup. AT Protocol navigation and ActivityPub remain refused. |
| 17 | Onion services (Chapter 8) | No direct route is defined for this namespace. | Device-local Tor only. | The handler requires IP Protection and otherwise displays an interstitial. Circuit isolation remains open (TO-3). |
| 18 | Gemini (§K.6, Chapter 9) | Direct TLS; the OS resolver sees the hostname. | Dial by name through Tor; refuse without a Tor port. | Tor transport is implemented. Using the browser's resolver in Fast mode remains open. Certificate authentication is a separate issue. |
| 19 | Hyper, SSB, and BitTorrent discovery (Chapter 9) | DHT, swarm, or gossip exposes addresses and discovery requests. | Refuse with 503 and explain the mode restriction. | Refusal is implemented. Stated-origin delivery for a named site is the separate path in rows 8–9. |
| 20 | Hyper DNSLink (KY-4) | The dependency queries a DoH JSON resolver, Cloudflare by default. | The engine is refused in Private mode. | Using the browser's bridge would require a compatible JSON endpoint and certificate handling. |
| 21 | Handshake WebSockets (§4, Chapter 11) | Local CONNECT proxy dials the resolved public address. | The tunnel dials that address through Tor, or refuses without Tor. | Implemented. The same address restrictions and certificate checks apply to either route. |
| 22 | Search | Metasearch receives the query and client address through the configured fetch. | Use the proxied fetch. | Proxied transport is described. The backend still receives the query. |
| 23 | Bootstrap and configuration | Kubo bootstrap features are disabled by policy; the ICANN TLD list is bundled. | Same policy; ODoH configuration is covered by row 5. | The disabled and bundled paths avoid their corresponding startup requests. |
| 24 | Address-based `hns://` document fetch (§8, Chapter 1) | Raw TLS socket to the resolved address, with DANE checking. | Dial the address through Tor and check the pin on that connection. | Implemented in `src/dane-connect.js`. Refuse when Private mode has no Tor route. |

### Reading the comparison

Transport privacy, verification, latency, and availability are separate
properties. A route can preserve its cryptographic checks and still take
longer through Tor. A cache can remove repeated queries without protecting
the first one. A refused request prevents that disclosure but also prevents
the requested operation.

The earlier totals for “no-trade-off” and completed rows were inconsistent
and mixed proposed work with shipped behavior. This table reports status per
operation instead. It makes no general claim that Private is as fast as Fast.

Browser integration details are recorded in the browser's `docs/MODES.md`.
The user-facing disclosure string is `DISCLOSURE` in `src/delivery-mode.js`.

