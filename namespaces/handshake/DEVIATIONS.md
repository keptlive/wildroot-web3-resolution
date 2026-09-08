# Chapter 1 — Handshake: deviations and open questions

This file records Handshake limitations, product choices, and proposed work.
Entries retain their `HS-n` and `HS-Dn` identifiers. The implementation is in
`../../src/`; its tests are in `../../tests/`.

[REVIEW.md](../../REVIEW.md) lists contradictions found during the editorial
review. Proposed changes below are not implementation changes.

---

## 1. Deviations

### HS-1. TTLs are ignored; a flat 60-second positive cache

**Behavior.** Positive resolutions are cached for 60 seconds, regardless of
RRset TTLs. All failure kinds are retried (`src/resolver.js`).

**Effect.** Short TTLs can be exceeded and long TTLs cause unnecessary queries.
RFC 2181 §5.2 defines the TTL rules. Explicit `forget()` invalidation supports
publishing but does not cover updates made elsewhere.

**Status: OPEN.** Use the minimum relevant TTL with agreed bounds; retain the
rule against caching failures (SPEC §6.8).

---

### HS-2. IPv6: a dual-stack name is reached over IPv4 (resolved 2026-09-06)

**Behavior.** Since 2026-09-06, resolution reads AAAA, GLUE6, SYNTH6, and
hsd's encoded `_synth` referrals. It selects IPv4 when available, otherwise
IPv6 (`src/resolver.js`, `src/spv.js`, `tests/ipv6.test.js`).

**Remaining limitation.** Address selection does not follow RFC 6724 or race
families as in RFC 8305. An IPv6-only client may therefore fail to reach a
dual-stack site. An unreachable IPv6-only nameserver is tried in NS order.

**Status: DELIBERATE** for now. The current transport and trust report carry
one selected address. The claim that IPv4 works from every network conflicts
with this limitation and is tracked in [REVIEW.md](../../REVIEW.md).

---

### HS-3. SVCB / HTTPS records are parsed but never queried, and ECH is not usable

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

### HS-5. One DANE profile; an unusable TLSA RRset is refused rather than ignored

**Behavior.** Only TLSA `3 1 1` (DANE-EE, SPKI, SHA-256) is supported.
An RRset with no supported matching pin is refused (`src/dane.js`).

**Difference from RFC 7671 §4.1.** The RFC treats an entirely unusable RRset as
absent and permits PKIX fallback. This transport has no PKIX fallback.

**Status: DELIBERATE.** An unsupported-only RRset causes connection failure.
A mixed RRset can still succeed when a supported `3 1 1` record matches.

---

### HS-6. The TLSA owner is always `_443._tcp`; a port in the URL is ignored

**Behavior.** TLSA is queried at `_443._tcp.<host>`, and site connections use
443 or 80 regardless of the URL port (`src/resolver.js` and browser handler).
RFC 6698 §3 derives the TLSA owner from the actual connection port.

**Effect.** Non-standard site ports are not supported by `hns://`.

**Status: OPEN.** Define URL-port and HTTPS-record port precedence, then derive
the TLSA owner from the port actually dialled. HS-3 covers service records.

---

### HS-8. A DoH-resolved TLSA is used as a pin, on the resolver's word

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

### HS-9. A CNAME target's own RRset is not validated under the target's owner

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

### HS-10. No RRSIG clock-skew tolerance

**Behavior.** RRSIG inception and expiration are checked against the system
clock without skew tolerance (`src/dnssec.js`). RFC 4034 §3.1.5 defines the
window but does not require tolerance. A clock-guard test checks the shared
time source.

**Effect.** An incorrect local clock can make signed zones fail validation.

**Status: DELIBERATE.** Improve diagnostic wording without silently widening
signature validity windows.

---

### HS-11. Standards not implemented at all

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

### HS-12. A DANE mismatch re-resolves once, then fails closed; there is no "pinned before" memory

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

### HS-13. Product decisions that deviate from what the naming systems themselves say

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

### HS-14. Internationalized names go through the URL parser, not through our own IDNA

**Behavior.** Host conversion uses `new URL(...).hostname`, which implements
WHATWG's UTS #46 processing rather than a separate IDNA2008 implementation.

**Effect.** IDNA2008 and UTS #46 differ for some input. The effect on registered
Handshake labels has not been audited.

**Status: OPEN.** Compare affected labels before choosing a different mapping
or validation policy.

---

### HS-15. Nameserver failover at query time (resolved 2026-09-06)

**Behavior.** Since 2026-09-06, `_withFailover` tries a zone's nameservers
lazily in order when a query is unreachable, times out, or answers a different
question. Validation failures are returned without trying another server
(`src/resolver.js`, `tests/nameserver-failover.test.js`). RFC 1034 §4.3.2
describes nameserver retry behavior.

**Status: RESOLVED.** Slow servers still consume their full timeout; there is
no parallel race.

---

### HS-16. Changing the anonymization mode restarts the SPV node, which re-syncs

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

## 2. Things we are not sure about

These questions remain open; no change is adopted here.

### 2.1. SVCB/HTTPS and ECH (HS-3)

Should every address-record navigation query HTTPS records, or can
authenticated evidence of record presence reduce that cost? The latter has
not been designed or tested.

### 2.2. Registry TLDs that refer, and NS targets that are themselves Handshake names

The resolver follows registry referrals up to `MAX_DELEGATIONS` and validates
DS at each cut. Nameserver address discovery can require an additional chain
lookup. Review its separate recursion bound, cycle handling, and bailiwick
checks together with the total query budget (HS-D1).

### 2.3. What the DoH fallback actually promises

Infrastructure failures can force Fast-mode requests onto the weaker DoH
path; Private permits only ODoH or refusal. Should previously pinned hosts
retain a stronger fallback requirement (HS-12)? Authoritative chain
`unregistered` results remain final. The user-facing meaning of TRUSTED also
needs evaluation.

### 2.4. DANE pin rotation windows (HS-12)

One mismatch retry has not been chosen from measured operator rotation
windows. A persistent pin requirement could resist downgrade, but needs
expiry and recovery rules to avoid locking users out of a recovered site.

### 2.5. What an SPV proof actually proves

The chain proof is verified by local hsd against its most-work header chain.
SPV assumes that chain is valid, and the browser trusts the local process.
During sync, including after a proxy-mode restart, the browser uses DoH. The
interface needs to make this per-load change of evidence understandable.

### 2.6. Whether a proven absence should raise the lock as far as it does

A signed address plus authenticated TLSA absence is a validated DNS result
with a plaintext site connection. The trust panel must communicate both facts;
the connection remains OPEN. The earlier wording conflated DNS validation
with the aggregate indicator (REVIEW.md).

### 2.7. What DNSLink interoperation is worth while the gateways it was for retire

DNSLink remains a record convention independently of any public gateway.
The original text cited retirement dates for `ipfs.io`, `dweb.link`, and
Shipyard bootstrap peers without a supporting source. Those claims require
verification (REVIEW.md). Retrieval and bootstrap policy belong to the content
chapters; this chapter specifies the name-to-pointer mapping.

## 3. Open design items

Items considered and not applied. Each states the problem and what we would do.

### HS-D1. No per-resolution query budget on NS hops

The depth limit and individual timeouts do not bound the total queries in
one resolution. Each zone can need DNSKEY, TXT, DNSLink TXT, A, AAAA, and TLSA;
nameserver discovery adds work.

**Proposal.** Carry a shared query counter through the resolution, including
nameserver address lookups. A proposed cap is roughly 32 queries. Exhaustion
would return `unreachable`, not `unregistered`. Choose the limit from measured
valid resolutions before adopting it.

### HS-D2. `hns:` has no IANA URI scheme registration

**Proposal.** Seek provisional registration under RFC 7595, using SPEC §5
for syntax and §11 for security considerations. Registration would give other
implementers a registry entry for the scheme. RT-D4 tracks the same work.

## 4. What this chapter leaves out

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
