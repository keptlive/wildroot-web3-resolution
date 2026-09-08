# Chapter 6 — Nostr: deviations and open questions

This record separates current departures from proposed work. `DELIBERATE`
identifies a retained implementation choice; `OPEN` identifies unfinished work
or a decision still under review. Section 2 collects design questions, and
section 3 lists proposals. None of those proposals changes current behaviour.

See [the editorial review log](../../REVIEW.md) for contradictions found during
the documentation rewrite.

## 1. Deviations

### NO-1. A NIP-05 address is classified nowhere

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

### NO-2. The `nip05` claim on a protocol page is displayed, but never looked up

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

### NO-3. Relay selection is a bundled set plus the link author's hints; NIP-65 is never read

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

### NO-4. BIP-173's 90-character limit is not enforced, and bech32 is implemented locally

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

### NO-5. `nostr://` is accepted although NIP-21 defines only `nostr:`

**Behaviour.** `parseNostrURI` accepts `nostr://npub1…` as well as
`nostr:npub1…`, and strips a trailing path, query or fragment.

**Standard and reason.** NIP-21 defines the form without an authority component.
The additional form accommodates URLs returned by Chromium's protocol layer.
The remaining identifier still passes through bech32 validation.

**Status: DELIBERATE.** Generated links use `nostr:`. The accepted alias may
not work in clients that parse NIP-21 strictly.

---

### NO-6. An `nsec` is refused by name, quoting it back to nobody

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

### NO-7. No NIP-42 AUTH: a relay that wants sign-in is a relay that answered nothing

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

### NO-8. Fixed result limits, no pagination, no time window

**Behaviour.** Profile lookups request at most 5 kind:0 events and 20 kind:1
events; note and addressable lookups request 1. There is no pagination or time
window, and the query option overwrites a filter's `limit`.

**Standard and effect.** NIP-01 provides `limit`, `since` and `until`. These
fixed limits produce a partial view of an author's events. A social client
needs its own paging and can use the existing `matchesFilter` support for
time constraints.

**Status: DELIBERATE** for this resolver.

---

### NO-9. Three independent NIP-01 implementations, and a trust header nobody reads

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

### NO-10. The canonical serialisation is delegated to the host's `JSON.stringify`

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

### NO-11. The `_nostr` DNS record is designed and documented but not published

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

### NO-12. On a `.hns.one` NIP-05 address the Handshake guarantees do not apply to the lookup

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

### NO-14. The `nsec` arm is claimed on its prefix, not on its checksum

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

### NO-15. Private mode hides who is asking, not what is asked

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

### NO-16. Two WebSocket implementations on two routes

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

## 2. Things we are not sure about

The following decisions remain open for review.

### 2.1. Whether a lock can ever close for Nostr — and whether a padlock is the right instrument

Completeness keeps the aggregate `partial` under SPEC §4.1 even when every displayed event passes signature verification. Review whether a padlock communicates this clearly, or whether separate event-authorship and relay-coverage indicators would be easier to interpret.

### 2.2. What "the right event" means, once the answer is bound to the query

Filter matching prevents substitution but does not establish freshness. A relay can return an older valid replaceable event. The interface currently identifies the queried relays and displays the newest timestamp among their answers; a stronger freshness mechanism remains undefined.

### 2.3. Whether NIP-05 belongs in a resolution specification at all

NIP-05 is a widely used name-to-key mapping with a different trust model from event signatures. Review whether the domain attribution and unresolved-claim wording in SPEC §7.3 communicate that distinction adequately.

### 2.4. The default relay list is a decision we made for the user

The default set contains four relays, including one operated by the browser publisher. It is a source constant, with no user-facing editing control. Every queried relay learns the target, and in Fast mode the device address. NIP-65 discovery would still require a bootstrap relay. Review configuration and disclosure options.

### 2.5. Whether `nostr:` should be a standard scheme

`nostr:` currently has no standard origin, fetch support, service workers or secure-context features. That suits static pages. An interactive client would need a storage and origin model, including whether different identifier forms for the same key share an origin.

### 2.6. Whether a bare `npub` should navigate

A valid bech32 checksum selects Nostr over the bare Handshake-label rule. The secret-key exception uses only a prefix and charset check (NO-14). Review the collision policy while preserving protection against sending a mistyped secret to a name resolver.

### 2.7. What we should be doing about relay disclosure

Private mode hides the device address through Tor, but relays still learn the query. It adds latency and can encounter relays that block Tor exits. Review whether the current interface adequately explains that narrower privacy benefit.

### 2.8. Whether a refused relay hint should be silent

The relay report displays rejected hints as escaped text, with no script capability. This makes routing decisions inspectable but gives a link author a place to display chosen text. Review whether the report needs additional presentation limits.

## 3. Open design items

Proposed work, linked to the deviations it addresses.

### NO-D1. Resolve the `nip05` claim, or say the domain was unreachable

The profile renderer does not resolve its `nip05` claim (NO-2).

**Recommendation.** Call `lookupNip05` with the injected session fetch and a
deadline. Distinguish a matching domain assertion, a conflicting or absent
mapping, and an unreachable domain. A matching assertion remains `unverified`
in this trust model and must name the asserting domain.

### NO-D3. Publish the `_nostr` record, or stop documenting it

The `_nostr` record is a documented proposal without the corresponding read
and publication path (NO-11).

**Recommendation.** Specify its receipt and publish records for existing keys,
then read them through the Handshake chain-proof and DNSSEC path. Keep the
proposal labelled as such until those parts are implemented.

### NO-D4. Read NIP-65 relay lists

The resolver uses bundled relays and link hints (NO-3).

**Recommendation.** For a target with a pubkey, first query
`{kinds:[10002], authors:[pubkey]}`. Read `r` tags and read/write markers, then
combine the list with the current relay set. Apply `isSafeRelayUrl`,
`normalizeRelayUrl` and the existing hint limit to every added URL. Cache the
list for the navigation. The initial discovery query still needs bootstrap
relays.

### NO-D5. Read `X-Nostr-Trust`, or delete it

The trust panel does not read the response headers emitted for it (NO-9).

**Recommendation.** Either provide response metadata to the panel so it can
report the checks performed for that navigation, or remove the unused headers
and comments. Avoid leaving two conflicting sources of trust information.

### NO-D6. Collapse the three NIP-01 implementations

Three NIP-01 implementations require parallel maintenance (NO-9).

**Recommendation.** Package one module that both signs and verifies, with the
cross-verification tests retained. Resolve the packaging boundary before
replacing the copies.

The proposal does not change the deliberate decisions to accept long NIP-19
identifiers (NO-4) or keep Nostr's aggregate trust partial (SPEC §4.1).

## 4. What this chapter leaves out

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
