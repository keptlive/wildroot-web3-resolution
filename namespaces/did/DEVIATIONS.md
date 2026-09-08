# Chapter 7 — DID, AT Protocol and ActivityPub: deviations and open questions

This record separates current departures from proposed work. `DELIBERATE`
identifies a retained implementation choice; `OPEN` identifies unfinished work
or a decision still under review. Section 2 collects design questions, and
section 3 lists proposals. None of those proposals changes current behaviour.

See [the editorial review log](../../REVIEW.md) for contradictions found during
the documentation rewrite.

## 1. Deviations

### DI-1. A resolved DID document is served with `Access-Control-Allow-Origin: *`

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

### DI-2. `did:plc` is directory-trusted; the operation log is never fetched

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

### DI-3. The result is a bare DID document, as `application/json`

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

### DI-4. `did://` is accepted as an alias for `did:`

**Behaviour.** `did://plc:abc` is normalised to `did:plc:abc` before parsing.

**Standard and reason.** DID Core §3.1 has no authority component. The alias
accommodates the form returned by the browser engine. Downstream checks use
the normalised DID, and the implementation does not emit the alias.

**Status: DELIBERATE.** An implementation SHOULD NOT generate `did://` links.

---

### DI-5. AT Protocol handle resolution is not implemented; the AppView is asked instead

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

### Experimental: identity anchors

The two deviations below are in the **experimental** part of this chapter
(SPEC §9): record formats that are shipped and signed by the browser's
keystore but are not a proposed standard and may change. They are separated
here so a reader does not weigh them against the stable resolution path.

### DI-10. Nothing enforces that an identity anchor's `epoch` moves forward

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

### DI-11. `_nostr.<name>` is designed and not published

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

## 2. Things we are not sure about

The following decisions remain open for review.

### 2.1. Whether "recognised, fail-closed" is a resting state

`at://` and `activitypub:` currently return local refusals. Review whether to retain that state until the requirements in SPEC §10.5 are implemented, or support a clearly labelled unverified result first. The latter would need a defined trust model and must preserve namespace isolation.

### 2.2. Whether a DID document should be a *page* at all

The `did:` scheme displays JSON in an opaque origin. Internal consumers call adapters directly. Review whether navigation should continue to expose raw JSON or provide a document view listing the subject, keys, services and performed checks.

### 2.3. Whether a bare atproto handle should be classified as an atproto address

An AT Protocol handle is also a domain name, so treating every domain-shaped input as an AT Protocol address would conflict with website navigation. The current classifier leaves these inputs to the name-routing rules. Review whether an explicit scheme or a selectable suggestion should request identity lookup.

### 2.4. Whether a client-side epoch memory actually fixes DI-10

A persistent highest-epoch value could reject rollback, but its semantics require decisions about legitimate reset or renumbering, transfer, recovery and fresh devices. The current format does not define those cases. The Handshake chain tracks the TLD, not each second-level identity anchor.

### 2.5. `did:web:<name>.hns.one` versus `did:plc`

The documented deployment choice is `did:web:<name>.hns.one`; the provisioning worker selects the method outside this chapter. Review the dependency and recovery tradeoffs against `did:plc`: domain-bound identity and operator availability versus PLC directory availability and verifiable operation history. Existing claims about key rotation and network support also require technical review.

### 2.6. What the AppView path should be *called*

An AppView fallback is `unverified`, but that state alone does not identify the trusted party. Review returning the source alongside the state, as the labelled DoH fallback does for identity anchors.

### 2.7. Whether this chapter should exist yet

This chapter includes fetched DID documents, an AppView-assisted handle lookup, and unresolved AT-URI and ActivityPub handlers. Keep the supported and refused paths explicit so readers do not infer full client or protocol support from the chapter title.

### 2.8. Whether a labelled default PDS should exist at all

`resolvePds` returns the default PDS with `assumed: true` and a reason when resolution fails. Review whether the resolver should return a failure instead and leave default selection to sign-in callers. A caller that ignores `assumed` can still mistake the default for the account’s PDS.

## 3. Open design items

Proposed work, ordered by the existing project priorities.

### DI-D1. Resolve AT Protocol handles locally, not through the AppView

`resolveHandle` trusts the AppView (DI-5).

**Recommendation.** Use the validating resolver for `_atproto.<handle>` TXT,
then the HTTPS well-known fallback. Verify `alsoKnownAs` in the DID document.
Keep any AppView fallback distinguishable and unverified.

### DI-D5. Verify the `did:plc` operation log

The current PLC lookup checks `id` but does not verify operation history (DI-2).

**Recommendation.** Fetch `/<did>/log/audit`, verify the genesis-derived DID,
previous-operation CIDs, authorised signatures, rotation and recovery semantics,
then compare the document with the resulting state. Cache verified history to
avoid repeating the full work on every navigation.

### DI-D6. Return a DID resolution result, not a bare document

The current response lacks resolution metadata (DI-3).

**Recommendation.** Return the document with resolution and document metadata,
including which checks were performed. Review the proposed media type and CORS
policy before changing the response contract. See DI-3 and REVIEW.md.

## 4. What this chapter leaves out

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