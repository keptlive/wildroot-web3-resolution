# Chapter 7 — DID, AT Protocol and ActivityPub

This chapter is part of the integrated Wildroot resolution specification whose
spine is `../../SPEC.md`, and namespace selection — which address space an
input belongs to, before any resolution — is specified there.

Everything below describes the behaviour of the reference implementation in
`namespaces/did/src/`, which ships in the Wildroot browser. Normative
statements describe what an implementation must do *to interoperate with this
one*; where a rule is inherited from an existing standard, that standard is
cited and its text governs. Every departure from a cited standard, and every
question we are unsure of, is in `../../DEVIATIONS.md`. Every standard cited is
listed with its purpose in `REFERENCES.md`.

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## Contents

1. [What this specifies, and why it exists](#1-what-this-specifies-and-why-it-exists) — including [**scope**](#11-scope)
2. [Terminology](#2-terminology)
3. [Namespace selection](#3-namespace-selection)
4. [Trust states](#4-trust-states)
5. [`did:` — identifier to DID document](#5-did--identifier-to-did-document)
6. [AT Protocol — handle to DID to PDS](#6-at-protocol--handle-to-did-to-pds)
7. [ActivityPub](#7-activitypub)
8. [The fail-closed contract](#8-the-fail-closed-contract)
9. [Experimental: identity anchors under a Handshake name](#9-experimental-identity-anchors-under-a-handshake-name)
10. [Security considerations](#10-security-considerations)

---

## 1. What this specifies, and why it exists

Three naming systems in this family answer the same question — *given a string
a human typed, who is that, and where does their data live?* — and answer it in
three incompatible ways:

- a **DID** (`did:plc:…`, `did:web:…`) is an identifier that resolves to a
  **DID document**: a JSON object listing the subject's keys and services;
- an **AT Protocol handle** (`alice.bsky.social`) resolves to a DID, which
  resolves to a **PDS**, which holds the repository an `at://` URI addresses;
- an **ActivityPub actor** (`@alice@example.social`) resolves through
  **WebFinger** to an actor document URL.

All three share one structural property that this chapter exists to exploit and
to be honest about: **the identifier is anchored in a domain name, and
therefore in whatever authenticates that domain name.** `did:web` is a domain
plus a well-known path. AT Protocol handle resolution is a DNS `TXT` record or
a well-known path on the handle's own domain. WebFinger is a well-known path.
In every case the identity is exactly as strong as the DNS answer and the TLS
certificate underneath it — which, on the ordinary internet, means "as strong
as the ICANN root plus every CA your system trusts".

That is why this chapter sits inside a Handshake resolution specification
rather than beside it. A Handshake name resolved the way `../../SPEC.md`
specifies — from a chain proof, DNSSEC-validated against an **on-chain** DS,
TLS pinned with DANE — is a domain anchor with a *different and stronger* root
of trust. A client that can resolve one can make a `_atproto.<hns-name>` TXT
record mean something no stock client can check.

**This chapter describes an implementation that does not yet do that.** What it
does is:

- resolve `did:plc` and `did:web` to a DID document, over HTTPS, with the
  document **checked to be about the identifier asked for** and otherwise
  unproven (§5);
- resolve an AT Protocol handle to a DID by **asking Bluesky's public AppView**,
  and a DID to a PDS from its DID document (§6);
- **recognise and refuse** `at://` and `activitypub:` — a visible 501 inside
  their own namespace, with no network request of any kind (§7, §8);
- read a **`_hns.<name>`** control record, DNSSEC-validated against the chain,
  to learn which key controls a Handshake name, and sign the receipt that
  authorises an **`_atproto.<name>`** binding (§9, experimental).

Saying which of those is a proof and which is somebody's word is most of the
work, and §4 and §10 are where it is said.

### 1.1 Scope

**In scope: turning an identifier in this family into the object it names, and
stating what was verified.** Precisely: how a `did:`, an AT Protocol handle, an
`at://` URI, an `activitypub:` address or a Handshake identity anchor becomes
one of

- a **DID document** (or the PDS endpoint read out of one),
- a **control key** for a Handshake name, with the strength of the answer,
- an **authorisation receipt** binding a name to a DID, or
- a **failure**, distinguished by kind and tagged with its namespace,

together with what an implementation may and may not conclude from it.

**Out of scope, explicitly:**

| Out of scope | Where it belongs |
|---|---|
| **Handshake name resolution itself** — the chain proof, DNSSEC against the on-chain DS, DANE, the authoritative walk | `../../SPEC.md`. §9 here consumes a validated TXT answer and says what it must have been validated *for*; it does not restate how. |
| **What is done with the object once resolved** — signing in to a PDS, reading or writing a repository, rendering a feed, the embedded Bluesky and Fediverse clients | This chapter ends at "here is the DID document / here is the PDS / here is the key". `src/bsky.js` carries the whole read/write surface because it is kept byte-identical to the browser's copy (see [Layout](#layout)); only `resolveHandle` and `resolvePds` are specified. |
| **Publishing an anchor** — how `_hns.<name>` or `_atproto.<name>` gets into a zone, who may write it, what the registry checks | The read path and the write path are different problems with different threat models. §9.3 specifies the **receipt** a writer must produce, because a reader verifies it; the endpoint that accepts it is the registry's. |
| **Key management** — where a control key is generated, how it is stored, backed up or delegated | `src/keys.js` is extracted only because `record.js` and `receipt.js` import it. |
| **The user interface** — the padlock, the security panel, the address bar | §4 specifies the model an interface must be given and the claims it must not make. It does not specify a rendering. |
| **Other naming systems** — Handshake, ENS, Nostr, Tor, IPFS, the ICANN DNS path | Each has its own chapter and its own trust model. |

A consequence worth stating plainly: an implementation of this chapter is an
**identity resolver**, not a social client. It answers "who is this, and how
sure are we?" and stops there.

---

## 2. Terminology

DID terms are used as defined in **W3C DID Core 1.0**: *DID*, *DID subject*,
*DID method*, *method-specific identifier*, *DID document*, *DID resolution*,
*verification method*, *service*. AT Protocol terms are used as defined in the
AT Protocol specifications: *handle*, *DID*, *PDS*, *repository*, *AppView*,
*XRPC*, *AT-URI*. Where this document uses one of those words it means what
those documents say it means.

Terms specific to this document:

- **Namespace** — an address space with its own root of trust, as in
  `../../SPEC.md`. `did`, `atproto` and `activitypub` are three of them.
- **Recognised-but-unresolved namespace** — a namespace this implementation can
  *name* but cannot *resolve*. It answers inside itself and makes no network
  request (§8).
- **Identity anchor** — a record under a Handshake name that binds the name to
  a key or to an account in another system: `_hns.<name>` (§9.1) and
  `_atproto.<name>` (§9.3).
- **Control key** — the per-name secp256k1 key that authorises operations on a
  Handshake name. Published as the `pubkey=` field of the `_hns` record; not a
  social identity, and not a chain key.
- **Claim receipt** — a signed statement by a control key that it claimed a
  given name at a given epoch (§9.1).
- **Binding receipt** — a signed statement by a control key that authorises a
  given DID to hold the name's handle (§9.3).
- **Epoch** — a monotonic counter in an identity anchor, incremented when the
  key changes. Signed into both receipt kinds.

---

## 3. Namespace selection

Namespace selection is specified in `../../SPEC.md`. This section states only
what is specific to this family, because a DID's method-specific identifier
routinely *looks like* something else.

### 3.1 An explicit scheme is authoritative

An input that names a scheme MUST be routed to that scheme's handler and MUST
NOT be reclassified from its authority, path or anything else:

| Input | Namespace | Never |
|---|---|---|
| `did:plc:ewvi7nxzyoun6zhxrhs64oiz` | `did` | a host called `plc` on port… anything |
| `did:web:alice.hns.one` | `did` | an ICANN lookup of `alice.hns.one` |
| `at://foo.14898/app.bsky.feed.post/3k…` | `atproto` | a Handshake lookup of `foo.14898` |
| `at://did:plc:abc/app.bsky.feed.post/3k…` | `atproto` | a 400 for an unparseable URL |
| `activitypub:@alice@example.social` | `activitypub` | a search |
| `@alice@example.social` | `activitypub` | `https://@alice@example.social` |

Five syntactic points make this work and MUST be implemented:

1. **A DID has no authority component.** `did:plc:abc` is a scheme followed by
   an opaque path, with no `//`. A classifier that requires `://` before it
   will believe a scheme was named reads `did:plc:abc` as a host and a port.
   The reference implementation's `hasExplicitScheme` accepts any `scheme:`
   prefix and applies its `host:port` exception **only to schemes it does not
   know**, so `example.com:8080` stays a host while `did:plc:abc` stays a DID.
2. **`did://` is accepted as an alias for `did:`.** Some hosts (Electron's
   protocol layer among them) hand a registered scheme back in authority form.
   A resolver MUST normalise `did://<rest>` to `did:<rest>` before parsing.
   This is a compatibility measure, not a URL form: an implementation SHOULD
   NOT emit `did://` (`../../DEVIATIONS.md` DI-4).
3. **The canonical AT-URI is not a WHATWG URL.** `at://did:plc:abc/…` carries a
   colon in its authority that is not a port, so the URL parser refuses it. A
   named scheme's failure is still that scheme's failure, so a dispatcher MUST
   read the scheme by prefix when the URL will not parse and hand the request
   to that scheme's handler — which is how the canonical form reaches the
   refusal of §8 rather than a generic parse error. With no scheme at all there
   is no namespace to fail inside, and a bare `400` is correct.
4. **`@user@host` is an address, not a host.** The URL parser reads the second
   `@` as a userinfo separator, so `https://@alice@example.social` navigates to
   the instance's home page with a stray credential. The canonical Fediverse
   address form MUST classify to `activitypub`, which is what makes the
   refusal written for it (§8) reachable from the one input a Fediverse user
   would actually type.
5. **A classifier's returned decision says whether the scheme is known.** An
   input naming a scheme the table does not carry (`javascript:`, `data:`,
   `file:`) comes back explicit, with a null namespace and marked unknown, so a
   caller that navigates can tell a link target from a decision.

An implementation MUST NOT register `did:` as a *standard* (special) URL scheme.
A standard scheme's authority is run through the WHATWG host parser, which
lowercases, IDNA-maps and — for an all-digit final label — parses as IPv4. A DID
method-specific identifier is case- and byte-sensitive and MUST survive intact.
The reference implementation registers `did`, `at` and `activitypub` as
non-standard, non-secure, `corsEnabled` schemes for exactly this reason; the
cost is that they are opaque origins, which §5.4 discusses.

### 3.2 The deliberate non-conflation: a name is not an identifier

A **bare name** — `alice.wildroot`, `alice.hns.one` — is classified by the
rules of `../../SPEC.md` (Handshake or ICANN) even when the name is a social
identity. The `did:`, `at:` and `activitypub:` schemes address the **native
objects** directly.

This is not a cosmetic split. It is the layering the whole design rests on:

> **The name system authenticates the mapping. The native layer authenticates
> the object.**

`alice.wildroot` publishing `_atproto.alice.wildroot TXT "did=did:plc:…"` is a
Handshake resolution, and its strength is the chain's. What that DID then
*is* — which keys, which PDS — is a DID resolution, and its strength is §5's.
An implementation MUST NOT let one stand in for the other, and MUST NOT report
the stronger of the two as the strength of the whole.

### 3.3 A failure stays in its namespace

An implementation MUST surface a failure in one of these namespaces as *that
namespace's* failure. Specifically:

- an unregistered scheme MUST fail as itself (HTTP 501), and MUST NOT be
  reinterpreted as a bare host, a name in another system, or a search;
- a handler that throws MUST surface as that scheme's failure (HTTP 502);
- a handler that answers for itself MUST tag its own response, so that a `400`
  for a bad DID and a `404` from a directory carry the same proof as a
  router-generated failure;
- every one of those MUST carry a machine-readable namespace tag. The reference
  implementation uses the response header
  `X-Resolution-Namespace: <namespace>`, which is the trust interface's
  evidence that no fallback occurred.

The reason is a real cross-namespace hijack, which is why §8 exists: before
`.eth` and `.onion` had handlers, an input whose TLD was not in the ICANN root
was assumed to be Handshake, so `vitalik.eth` was resolved on-chain (handing
the traffic to whoever owns the Handshake TLD `eth`) and an onion address left
the machine in a DNS query. A namespace that can be *named* but not *resolved*
must fail inside itself.

---

## 4. Trust states

This chapter uses the four-valued per-step model of `../../SPEC.md`:
**verified** (this client checked it), **unverified** (someone's word, stated
as such), **failed** (checked and did not pass), **none** (no verification
exists for this step). The lock closes only if **every** step is verified.

The honest assignment for this family, as implemented:

| Step | State | Because |
|---|---|---|
| `did:plc` → DID document | **unverified** | `plc.directory` is asked, and the document it returns must be about the DID asked for — a check that catches a wrong answer but proves nothing about a consistent lie. The PLC operation log that would make the method self-certifying is not fetched (`../../DEVIATIONS.md` DI-2). |
| `did:web` → DID document | **unverified** | The document is whatever the domain served over WebPKI TLS, from a public host, without redirects, within a deadline — and it must be about the DID asked for. WebPKI is the ICANN root plus every CA (§10.3). |
| handle → DID | **unverified** | Bluesky's public AppView is asked (§6.1). Neither authoritative method from the AT Protocol handle specification is used. |
| DID → PDS | **unverified** | Read out of an unverified document; and an unresolvable document silently becomes `bsky.social` (§6.2). |
| `at://` → record | **none** | Not resolved. Refused (§7, §8). |
| `activitypub:` → actor | **none** | Not resolved. Refused (§7, §8). |
| `_hns.<name>` → control key, via the chain | **verified** | DNSSEC-validated to the on-chain DS, *and* the embedded receipt verified against the name, key and epoch (§9.2). |
| `_hns.<name>` → control key, via DoH | **unverified** | The record's signature still verifies, but the resolver chose which record to show. Labelled `via: 'doh'` and never silently substituted (§9.2). |

An implementation MUST NOT report a closed lock for any resolution in the
`did`, `atproto` or `activitypub` namespaces as specified here. The `did:`
step has one real check and no proof, so the lock it earns is **TRUSTED**,
never green.

An implementation SHOULD give the interface a `did`-specific step rather than a
generic "no verification path for this scheme". The reference implementation
does: the panel names the identifier step, marks it unverified, and says in
words that the document was checked to be about the identifier asked for and
that for `did:plc` the operation log which would prove it was not audited — so
this is that server's word.

---

## 5. `did:` — identifier to DID document

### 5.1 The identifier

Input is parsed as **DID Core §3.1**: `did:<method-name>:<method-specific-id>`.

```
did = "did:" method-name ":" method-specific-id
```

An implementation MUST:

- normalise a leading `did://` to `did:` (§3.1);
- split on `:` and refuse anything with fewer than three components, with an
  empty component, or whose first component is not exactly `did`, with a
  **400** and no network request;
- refuse a method it does not implement with a **400** and no network request.

The reference implementation supports exactly two methods: `plc` and `web`.
Everything else — `did:key`, `did:ion`, `did:ethr`, `did:pkh` — is refused, and
the refusal names the supported set so a user sees why.

**Refusing before the network is normative, not an optimisation.** A malformed
or unsupported DID that reaches `fetch` is a request an attacker chose the
shape of; refusing it locally is the same discipline §8 applies to a whole
namespace.

### 5.2 `did:plc`

`did:plc` is Bluesky's **Public Ledger of Credentials** method. The identifier
is derived from the genesis operation — base32 of a truncated hash of the
signed operation — so the DID *commits to* its own creation, and the directory
publishes the full signed operation log at `/<did>/log/audit`. That is what
makes the method verifiable in principle.

The reference implementation resolves it by asking the directory for the
current document:

```
GET <plcDirectory>/<did>
default plcDirectory: https://plc.directory
```

The directory URL is configurable, which matters for two reasons: a self-hosted
or mirrored directory is a supported deployment, and a test can drive every
path with no network.

An implementation that wants the method's actual guarantee MUST fetch the audit
log and verify the operation chain to the genesis operation, checking that the
DID equals the hash of that operation and that each subsequent operation is
signed by a rotation key valid at that point. This implementation does not
(`../../DEVIATIONS.md` DI-2). Until it does, `plc.directory` is a trusted third
party, and §4 says so.

### 5.3 `did:web`

`did:web` locates a DID document by an HTTPS `GET` on the domain named in the
identifier. The **did:web method specification §3.2** gives the read algorithm,
and its order is load-bearing:

1. Replace every `:` in the method-specific identifier with `/`, producing a
   fully qualified domain name and an optional path. This happens **before**
   any percent-decoding — otherwise a port's `%3A` would decode into a colon
   and then be turned into a path separator.
2. Percent-decode the port. Percent-encoding is case-insensitive
   (**RFC 3986 §2.1**), so `%3A` and `%3a` are the same octet.
3. Prepend `https://`.
4. Append `/.well-known` **only if no path was specified**.
5. Append `/did.json`.

From the specification's own examples, which the reference implementation's
`didWebUrl` is checked against in `tests/did-protocol.test.js`:

| DID | Document URL |
|---|---|
| `did:web:w3c-ccg.github.io` | `https://w3c-ccg.github.io/.well-known/did.json` |
| `did:web:w3c-ccg.github.io:user:alice` | `https://w3c-ccg.github.io/user/alice/did.json` |
| `did:web:example.com%3A3000` | `https://example.com:3000/.well-known/did.json` |
| `did:web:example.com%3A3000:user:alice` | `https://example.com:3000/user/alice/did.json` |

**The host is a stranger's choice.** A `did:web` names any host on the
internet, and a link to one is written by whoever wants this browser to fetch
it. Before any request an implementation MUST establish that the host is a
public web host, and MUST answer **400** without connecting if it is not. The
reference implementation's `isSafeDidWebHost` refuses, in this order: an empty
host; a reserved name (`localhost`, `.local`, `.internal`, and the rest of the
reserved-name list `../../SPEC.md` shares with the classifier); and any IPv4 or
IPv6 literal that is not a public address (loopback, private, link-local
including `169.254.169.254`, CGNAT, multicast, reserved — RFC 6890, RFC 5737).
A port is stripped before the test and brackets are removed from an IPv6
literal, so neither smuggles a private address past it.

A hostname that *resolves* to a private address is not caught, because that
needs a connect-time check; the limitation is stated here and in the browser's
conformance record beside the ERC-3668 row that shares it.

**There is one `did:web` reader.** The other caller that needs a DID document
— `resolvePds` in `src/bsky.js`, §6.2, which is looking for a PDS rather than
publishing the document as a page — imports `didWebUrl` and `isSafeDidWebHost`
from this module rather than building a URL of its own. An implementation MUST
have one reader: two implementations of a three-line read algorithm in one
program produce a DID that resolves one way for an identity panel and another
way for a sign-in path, which is the class of inconsistency nobody can
reproduce.

### 5.4 The response

The transport is **injected**, not global. `createHandler({ fetchImpl })` takes
the function that makes the request, so the browser hands it the proxied
session fetch and a test hands it a fake. An implementation SHOULD do the same:
it is what lets DID resolution ride the user's configured proxy (§10.4) and
what lets every path in this section be exercised without a socket.

Every request an implementation makes here MUST carry:

- `redirect: 'error'` — a redirect is a second, unchecked choice of host made
  by the first one, and a document that is not where the DID says it is, is not
  that DID's document;
- a deadline. The reference implementation aborts after 10 seconds, so a
  hostile host cannot hold the handler open.

On a successful upstream `200`, the body is parsed as JSON and **checked to be
about the identifier asked for**: the document MUST be an object whose `id`
equals the DID (DID Core §7.1.3 — a resolver answers with the document *for*
the input DID). A directory or host answering with somebody else's document,
with a body that is not an object, or with no `id` at all, is a wrong answer
and MUST be refused. The reference implementation answers **502** naming both
the DID asked for and the `id` received.

That check is the strongest cheap check DID resolution has, and it is the only
one made. It catches a wrong answer; it does not prove a consistent lie
(§5.5, §10.3).

On success the document is re-serialised and answered:

```
200 OK
Content-Type: application/json; charset=utf-8
X-Resolution-Namespace: did
Access-Control-Allow-Origin: *
Allow-CSP-From: *
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: *
```

On an upstream non-`200` the answer carries **the upstream status**, clamped to
a status the rendering engine knows, and a `text/plain` body naming the DID,
the status and the URL tried. Clamping is not cosmetic: a protocol handler's
status goes straight into Chromium's reason-phrase lookup, which is
`NOTREACHED` on a code it does not have — so an upstream `523` from a CDN
becomes a `502`, not a crash. On a transport error the answer is **502**
carrying `e.message` and nothing else: a stack would disclose this
installation's filesystem paths to whoever caused the navigation.

**Every response carries `X-Resolution-Namespace: did`** — the successful one,
the `400` refusals, the upstream-status failure and the `502`. A handler's own
responses pass through the router verbatim, so a handler that does not tag
itself leaves a hole in the L2 evidence chain exactly where the commonest
failures are (§3.3).

Two things a conforming implementation SHOULD do that this one does not:

- The media type SHOULD be `application/did+json`, and the body SHOULD be a
  **DID resolution result** as DID Core §7.1 defines it — `didDocument`
  alongside `didResolutionMetadata` and `didDocumentMetadata` — so that
  "resolved, and here is what was and was not checked" is expressible in the
  data rather than only in the interface (`../../DEVIATIONS.md` DI-3).
- The wildcard CORS headers SHOULD say what is intended. A document no page can
  read does not need `*`. They are inert while `did:` is a non-standard scheme
  with no `fetch` support, and a decision to make `did:` standard would make
  them live with no other edit (`../../DEVIATIONS.md` DI-1).

### 5.5 What is and is not verified

An implementation of this chapter MUST NOT claim that a resolved DID document
is authentic. What the reference implementation establishes:

- **the document is about the identifier asked for** — its `id` equals the DID,
  and a mismatch is a failure rather than a warning (§5.4);
- **the request went where the identifier said**, to a public host, with no
  redirect and a deadline (§5.3);
- **nothing else.**

Both hold for the PDS lookup of §6.2 as well: it reads a document through the
same URL builder and the same host guard, and makes the same `id` comparison.
The two callers establish the same things because they run the same code.

Specifically it does **not**:

- **verify the `did:plc` operation log** (§5.2), so a `did:plc` document is the
  directory's word;
- **prove anything about a `did:web` document beyond WebPKI**, which is the
  ICANN root plus every CA the system trusts (§10.3);
- **catch a hostname that resolves to a private address**, which needs a
  connect-time check (§5.3);
- **validate the document's structure** beyond `id`. Any other JSON the host
  returns with a `200` is passed through.

---

## 6. AT Protocol — handle to DID to PDS

AT Protocol identity is two hops. A **handle** (a domain name) resolves to a
**DID**, which is the stable identifier; the DID resolves to a **DID document**
which names the account's **PDS** and its signing key. The handle is mutable
and the DID is not, which is why the reference implementation signs in by DID
whenever it has one.

### 6.1 Handle → DID

The **AT Protocol handle resolution specification** gives two authoritative
methods, either of which a client may use, with DNS preferred:

1. **DNS TXT.** `_atproto.<handle>` `TXT` `"did=did:plc:…"`. Exactly one such
   record must exist.
2. **HTTPS well-known.** `GET https://<handle>/.well-known/atproto-did`,
   answering the DID as `text/plain`, no redirects.

The specification further requires **bidirectional verification**: the DID
document reached from the handle MUST list `at://<handle>` in its
`alsoKnownAs`, or the handle is not valid for that account.

**The reference implementation implements neither method and does not perform
bidirectional verification.** `resolveHandle` calls
`com.atproto.identity.resolveHandle` on Bluesky's public AppView:

```
GET https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=<handle>
```

This is `../../DEVIATIONS.md` DI-5, and it is the largest single gap in this
chapter. Why it costs more here than elsewhere: the AppView is a free service
run for the whole network and a perfectly ordinary thing for a client to use,
but it is *a third party being trusted for a mapping the client could check
itself* — and in a browser that already resolves Handshake names from a chain
proof and validates DNSSEC, the DNS method is not merely implementable, it is
the one thing this client can do that no stock client can (§9.4). An
implementation of this chapter SHOULD implement the DNS TXT method against its
own validating resolver, fall back to the well-known method, and perform
bidirectional verification; and MUST report the AppView path, if it keeps one,
as **unverified**.

### 6.2 DID → PDS

Given a DID, the reference implementation fetches the DID document and reads
the PDS out of it:

- `did:plc:…` → `GET https://plc.directory/<did>`
- `did:web:…` → the URL `didWebUrl()` builds from the method-specific
  identifier, by the read algorithm of §5.3 and through the host guard of
  §5.3: a loopback, private, reserved or non-public host is never fetched
- any other method → not resolved

The fetch sets `redirect: 'error'` and a 10-second deadline, so a redirect
cannot become a second, unchecked choice of host and a hanging host cannot
become a hanging sign-in.

Four rules decide whether what comes back is an answer, and an implementation
**MUST** apply all four. Each is pinned in `tests/atproto-identity.test.js`:

1. **The document must be about the DID asked for.** `doc.id` is compared to
   the DID, and a document naming a different subject is not a resolution —
   W3C DID Core §7.1.3. This is the same check the `did:` handler makes
   (§5.4), made by the same rule here rather than left to the caller: without
   it, a directory or a `did:web` host answering with somebody else's document
   hands back that document's PDS under the asked-for DID.
2. **The service is identified by `id` *and* `type`.** The PDS is the
   `serviceEndpoint` of the first `service` entry whose `id` **ends with**
   `#atproto_pds` and whose `type`, when present, is
   `AtprotoPersonalDataServer`. The suffix match on `id` is deliberate — a
   service `id` may legitimately be a relative fragment or an absolute URL
   carrying that fragment — and the `type` is what the AT Protocol DID
   requirements name alongside it.
3. **The endpoint must be `https://`.** A plaintext or non-HTTP endpoint is
   not accepted.
4. **A fallback is never presented as a resolution.** On **every** path that
   does not end in a PDS read out of a valid document — the host guard refused
   it, the fetch failed, the document is not about this DID, it names no
   `https` PDS, or the DID method is not supported — the return value is
   `{ did, pds: DEFAULT_PDS, assumed: true, reason }`. `assumed` is the
   distinct state; `reason` says which path it was, in words.

Rule 4 is the one that needs stating as a rule. The AT Protocol DID
specification makes an unresolvable DID a resolution **failure**, and this
implementation keeps a default (`https://bsky.social`) for the sign-in path it
was written for, where a wrong host fails loudly and the default is right for
almost everyone. That argument does not survive contact with the question
"where does this account live", which is the question a self-hoster's page is
answering. So an implementation **MUST NOT** present a substituted PDS as the
account's own: a caller signing in may ignore `assumed`, and a caller
answering for the account, or rendering it, **MUST NOT**. Silently naming the
network's largest operator when a self-hoster's document is momentarily
unreachable is the one substitution that must never be silent.

### 6.3 `at://` is recognised and refused

The `at://` scheme — an AT-URI addressing a record in a repository,
`at://<did-or-handle>/<collection>/<rkey>` — is **recognised, and refused**,
per §8. The refusal states what resolving it would need: *the DID document for
the repository and a signature check on the record.* The canonical
`at://did:plc:…` form reaches that refusal even though it is not a WHATWG URL
(§3.1).

That is the right requirement and worth stating normatively, because it is what
makes `at://` resolution meaningfully different from asking an AppView:

> An implementation that resolves `at://` MUST obtain the record from the
> repository named by the identifier's own DID document, and MUST verify the
> record against the repository's signed commit — the MST proof and the
> repository signature — using the signing key from that DID document. An
> implementation that fetches the record from an aggregator and renders it
> unverified MUST report the step as **unverified** and MUST NOT present it as
> a resolution of the AT-URI.

---

## 7. ActivityPub

The `activitypub:` scheme is **recognised, and refused**, per §8, and a bare
`@user@host` classifies into it (§3.1) so that the refusal is reachable from
the address form a Fediverse user types. The refusal states what resolving it
would need: *a WebFinger lookup and an actor signature check.*

Normatively, for an implementation that enables it:

- An `@user@host` address MUST be resolved by **WebFinger (RFC 7033)**:
  `GET https://<host>/.well-known/webfinger?resource=acct:<user>@<host>`,
  taking the `self` link with type `application/activity+json` as the actor URL.
  The `.well-known` path is registered per **RFC 8615**.
- The actor document MUST be fetched from that URL and MUST be checked for
  consistency with the address that led to it — the actor's `preferredUsername`
  and host, and its own WebFinger back-reference. WebFinger is a redirection,
  not an authentication: any host can publish a WebFinger record pointing at
  any actor URL, so the actor document is the authority for its own identity
  and the WebFinger answer is not.
- An implementation MUST NOT present an actor as verified on the strength of
  the WebFinger hop alone. **ActivityPub** itself specifies no client-side
  object authentication; HTTP Signatures authenticate *delivery* between
  servers, not a document a client fetched. So the honest trust state for a
  fetched actor is **unverified**, and an implementation MUST report it as such.

`REFERENCES.md` lists these as *what an implementation must do*; nothing in
`src/` reads them.

---

## 8. The fail-closed contract

A namespace an implementation can **name** but cannot **resolve** MUST fail
*inside itself*. This is the contract the reference implementation's
`unimplemented-protocol.js` provides for `at` and `activitypub`, and it is
normative for any namespace added in this state.

Such a handler MUST:

1. **Make no network request of any kind.** Not a DNS lookup, not a well-known
   fetch, not a telemetry ping. This is its entire security value. In the
   reference implementation it is a structural property — the module imports
   nothing and calls nothing — and it is pinned by a test that replaces the
   global `fetch` with a counter and asserts it stays at zero.
2. **Answer `501 Not Implemented`** (RFC 9110 §15.6.2). Not a redirect, not a
   404, not a search.
3. **Carry `X-Resolution-Namespace: <its own namespace>`**, so the trust
   interface has machine-readable proof the failure did not cross a boundary.
4. **Say what it recognised and what resolving it would need**, in the user's
   words. The reference implementation echoes the address back so the user can
   see the input was understood — and MUST escape it: the echoed string is
   attacker-controlled and lands in HTML. `&`, `<`, `>`, `"` and `'` are all
   escaped.
5. **Never throw.** Including when the request object's `url` getter itself
   throws. A URL that cannot be read is still not a reason to fail differently.
6. **Be an opaque, unprivileged origin.** `Access-Control-Allow-Origin: null`,
   and the scheme registered without `standard`, `secure`, service workers or
   `fetch`. A page that serves one static error message must never become an
   origin worth attacking.

One point that is easy to read as bureaucracy and is not: **the scheme MUST be
registered with the browser engine even though it resolves nothing.** A scheme
the engine does not know is not merely unhandled — loading one as a main-frame
document has hard-crashed this application on Windows. Registration is what
makes "recognised and refused" a state the engine can be in.

---

## 9. Experimental: identity anchors under a Handshake name

**This section is EXPERIMENTAL.** The `_hns` control record and the claim and
binding receipts are shipped: the browser's keystore builds and signs them, and
`src/record.js` and `src/receipt.js` verify them. The `_nostr` sibling record
is designed and not published (`../../DEVIATIONS.md` DI-11). None of it is a
proposed standard, none of it has been reviewed outside this project, and the
record formats **may change** — a field may be added, renamed or given
different semantics, and the version tag `v=hns1` exists so that a change is a
refusal rather than a misparse. Read this section as a description of what is
running, not as a format to build an interoperating implementation against yet.
Everything in §§3–8 is stable by comparison.

This section is also the seam with `../../SPEC.md`. It specifies records
**published under a Handshake name** that bind that name to a key or to an
account in another system. Their resolution is Handshake resolution: an
implementation MUST obtain them by the algorithm of `../../SPEC.md` and MUST
NOT accept one that did not validate to the on-chain DS, except as §9.2 allows
and labels.

### 9.1 `_hns.<name>` — who controls this name

A second-level Handshake name has no on-chain existence of its own: the chain
knows `wildroot`, not `alice.wildroot`. "This key controls `alice.wildroot`" is
therefore **mutual attestation** — the zone publishes a record naming the key,
and the *keyholder* signs a receipt naming the name. Either half alone is weak:
DNSSEC alone proves only that the zone operator said so; a receipt alone proves
only that somebody wanted the name.

**Owner name.** `_hns.<name>`, where `<name>` is the normalised name:
lowercased, trailing dot removed, LDH labels, at least two labels. `_hns` is a
legal DNS owner label and cannot collide with a Handshake label, which may not
contain `_` (RFC 1123 §2.1).

**Type.** `TXT`.

**Value.** One RFC 1035 `<character-string>`, semicolon-separated
`key=value` fields:

```
v=hns1;pubkey=<64 lowercase hex>;epoch=<integer ≥ 1>;receipt=<created_at>.<base64url sig>
```

- `v` — format version. MUST be exactly `hns1`; anything else is refused
  outright rather than best-effort parsed.
- `pubkey` — the control key, x-only secp256k1, 64 lowercase hex (BIP-340).
- `epoch` — integer ≥ 1, incremented on key change.
- `receipt` — the compact claim receipt: the decimal `created_at` of the claim
  event, a `.`, and the raw 64-byte BIP-340 signature in **base64url**
  (RFC 4648 §5). This is the whole point of the compact form: the signed event
  is *reconstructible* from `(name, pubkey, epoch, created_at)`, so a 255-byte
  TXT record can carry an offline-verifiable proof.

The record carries no variable-length field — `pubkey` is 64 hex, `receipt` is
a fixed-width base64url signature after a decimal timestamp, and the name is
not in the record at all — so its length is a fact, not a risk: the longest
string any accepted `(epoch, created_at)` pair can produce fits one
`<character-string>` with room to spare.

Parsing rules an implementation MUST follow:

- Unknown fields are **ignored** — forward compatibility.
- A **duplicated** field is **tampering, not merging**: the record is refused.
  Two records each carrying `pubkey=` is an attempt to have a validator pick
  one, and there is no safe pick.
- A string longer than **255 bytes**, the maximum of a TXT
  `<character-string>` (RFC 1035 §3.3.14), is refused. It is input no
  nameserver could have served.
- Each TXT *record*'s `<character-string>`s are concatenated into one value
  before parsing (RFC 1035 §3.3.14). Separate records are separate values, and
  a field is **never** merged across two records — merging would let anyone who
  can add a record complete somebody else's.
- Malformed input MUST return a negative result, never throw. This parser runs
  on zone data an attacker may have chosen.

**The claim receipt.** The signed object is an ordinary NIP-01 event —
deliberately not a new signature format, so any Nostr library can verify it:

```
kind:       30078            (NIP-78 application-specific data)
pubkey:     <the control key>
created_at: <the receipt's created_at>
content:    ""
tags:       [["v","hns1"], ["d","hns:<name>"], ["epoch","<epoch>"]]
```

The `v` tag is **first and load-bearing**. Kind 30078 is a generic
application-data kind, and users are encouraged to carry these keys into other
Nostr apps; without an explicit version tag in the preimage, any app that will
sign a kind-30078 event with a chosen `d` tag could be walked into producing a
valid claim receipt for an attacker's name. The `d` tag makes the event
parameterised-replaceable per name, so a relay keeps only the newest claim —
which is the semantics a transfer wants.

Verification is: rebuild the event from `(name, pubkey, epoch, created_at)`,
recompute its id as sha256 of the canonical NIP-01 serialisation, and check the
BIP-340 signature over that id. It requires no relay and no network.

### 9.2 Resolving a control record

Given a name, an implementation resolving `_hns.<name>` MUST:

1. Query `TXT` at `_hns.<name>` through the Handshake resolution algorithm of
   `../../SPEC.md` — chain proof, then the authoritative walk, DNSSEC validated
   to the on-chain DS.
2. Distinguish the outcomes, and MUST NOT collapse them:
   - **the chain could not be asked** (node down, still syncing) — §9.2a;
   - **the name is unregistered** — but "the name exists and has no `_hns`
     record" and "there is no such name" are different answers and MUST be told
     apart. The reference implementation asks the apex to separate them;
   - **an answer arrived but is not `TXT`**, or **is not DNSSEC-validated** —
     refuse; the result is *unverified*, not *absent*.
3. Verify the receipt embedded in the record against the name, the key and the
   epoch (§9.1). A record that validated by DNSSEC but whose receipt does not
   verify MUST be treated as **no record**, not as a binding.
4. Report the strength of the answer alongside it.

**9.2a The DoH downgrade.** A Handshake SPV node cannot answer at all until it
reaches the chain tip, which takes about an hour on a fresh install. Being
locked out of a product for an hour is not an acceptable way to be secure, so
when the **chain could not be asked** — and only then — an implementation MAY
re-read the same record over DoH/ODoH. If it does:

- it MUST label the answer as the weaker one (`via: 'doh'`,
  `dnssecValidated: false`) and MUST NOT silently substitute it;
- the caller, not the resolver, MUST decide what a weakly-resolved key is
  allowed to do, and the user MUST be told in words before anything is sent;
- a DoH answer MUST NOT be allowed to be the reason a name is declared **not to
  exist**. The resolver that could not answer is exactly the one that would be
  wrong about that. Only `ok` or nothing may come back from this path.
- Anything the **chain did answer** stands. A name the chain says does not
  exist is not re-litigated over DoH.

This algorithm is implemented in the browser's `src/folders/index.js`
(`resolveRecipient` / `resolveOverDoh`) and is **not extracted** into this
chapter: it is bound to the browser's vault, its resolver instances and its
dynamic-import wiring. It is specified here because it is the only
security-relevant consumer of `record.js`, and a reader who takes `record.js`
without it has taken the verifier and left the policy behind.

**What is not specified, because it is not implemented.** Nothing anywhere
enforces that `epoch` moves forward. A receipt for epoch 1 verifies for ever,
so a record from a previous holder, if it is ever served again, verifies again.
The defence is entirely that the registry publishes the current record under
DNSSEC. A resolver SHOULD report the epoch it accepted alongside the key, so a
caller with durable memory can apply a floor; `../../DEVIATIONS.md` DI-10 and
§2.4 there explain why a client-side floor is not obviously the right fix.

### 9.3 The atproto binding, and `_atproto.<name>`

Handing a name's **handle** to an AT Protocol account is a stronger statement
than naming a key: whoever answers `_atproto.<name>` / `/.well-known/atproto-did`
**owns that handle on the network**. So it is authorised the same provable way,
with a second receipt.

```
kind:       30078
pubkey:     <the control key>
created_at: <the receipt's created_at>
content:    ""
tags:       [["v","hns1"], ["d","hns:atproto:<name>"], ["epoch","<epoch>"], ["did","<did>"]]
```

Two properties are normative:

- **The `d` tag prefix is `hns:atproto:`, not `hns:`.** That single difference
  is what makes a claim receipt and a handle grant non-interchangeable, so
  neither can be replayed as the other. `tests/identity-anchor.test.js` pins
  both directions.
- **The `did` tag binds the exact account**, lowercased and trimmed before
  signing so the preimage is canonical. The signature can only mean "this
  control key authorised *this* DID".

The receipt is signed in the client, by a key that never leaves it; what
crosses the network is the name, the DID, `created_at` and the signature. A
registry that accepts the binding can therefore prove it was authorised by the
key that holds the name, and a stray write to the registry's own store cannot
forge it.

**The published record is out of scope.** `_atproto.<name>` `TXT` `"did=…"` is
written by the registry and served by the gateway; its exact form is the AT
Protocol handle specification's (§6.1), and neither the record nor the
`/.well-known/atproto-did` endpoint is produced or **read** by anything in this
chapter. The asymmetry is worth stating plainly rather than leaving implied:
**this implementation signs the authorisation for an anchor it never verifies.**
Closing that loop is §6.1's requirement (`../../DEVIATIONS.md` DI-D1).

### 9.4 `did:web:<name>.hns.one`

The design decision this section records: a Handshake name's AT Protocol
identity is a **`did:web` on the operator's ICANN subdomain** for that name —
`did:web:alice.hns.one`, resolving at
`https://alice.hns.one/.well-known/did.json`.

The reasoning, and its cost, both belong in a specification because an
implementer will face the same choice:

- `<name>.hns.one` is an *ICANN* label served over public-CA TLS, so
  `did:web:<name>.hns.one` resolves for Bluesky's relay and AppView and for
  every stock client — **not only inside a Handshake-aware browser**. The
  browser's bonus is that it *also* addresses the bare Handshake name; the
  universal anchor is the dotted ICANN form.
- The cost is real and irreversible per account: `did:web` is self-certifying
  only in the sense that the domain vouches for it. It is **not portable off
  the domain**, and it has none of `did:plc`'s in-document key rotation. A user
  who loses the domain loses the identity.
- `did:plc` costs no infrastructure, works today, and is what most of the
  network uses. Which of the two should be the *default* is an open decision,
  recorded as such in `../../DEVIATIONS.md` §2.5.

Both methods are implemented on the resolution side (§5), and the binding
receipt (§9.3) is method-agnostic: a `did:plc` binding needs nothing from the
operator's infrastructure at all.

A note on display, which is an interoperability question and not only a
cosmetic one: inside a Handshake-aware client the name is shown in its native
form (`alice.wildroot`), and the dotted ICANN form is the one handed to the
outside world. An implementation MUST NOT let the two forms diverge into two
identities — they are one name with two spellings, and the handle upgrade path
in §6 exists to move an account from a temporary spelling to the canonical
dotted one without ever changing its DID.

---

## 10. Security considerations

### 10.1 Fail closed, and inside your own namespace

Every refusal in this chapter is *inside* the namespace that was named. That is
not politeness. The concrete failure it prevents was live: an input whose TLD
was not in the ICANN root was assumed to be a Handshake name, so an address
meant for another naming system was resolved on-chain and its traffic delivered
to whoever owned the colliding Handshake TLD. The general rule (§3.3) and the
specific contract (§8) are the same rule at two altitudes.

An implementation MUST NOT "helpfully" retry a failed identity resolution as
something else. There is no safe fallback from "I could not resolve this DID"
to "perhaps it is a website".

### 10.2 Every host in a DID resolution is attacker-chosen

`did:web:<anything>` names a host. So does an AT Protocol handle. An
implementation MUST treat the resulting URL as hostile input:

- it MUST refuse to connect to a special-purpose address (loopback, private,
  link-local including `169.254.169.254`, CGNAT, multicast, reserved — the
  registry in RFC 6890 / RFC 5737) or to a reserved name. `isSafeDidWebHost`
  applies that test over the shared guard in `../../src/safe-address.js` and
  the shared reserved-name list, **before** any request;
- it MUST NOT follow redirects, because a redirect is a second, unchecked
  choice of host made by the first one;
- it MUST bound the request in time.

Both readers do all three, and they do it with the **same** code: `didWebUrl`
builds the URL and `isSafeDidWebHost` guards the host for the `did:` handler
and for the PDS lookup alike. That is the structural form of the fix, and it is
the form to insist on — a guard that has to be remembered at each call site is
a guard that will be missed at one of them.

A hostname that resolves to a private address remains uncaught by an
address-literal test; catching it needs a check at connect time, and the same
limitation applies to every URL-level guard in this tree.

### 10.3 What a DID document establishes

A DID document fetched over HTTPS and checked against the DID asked for
establishes exactly this: **at this moment, the party who controls that
domain's TLS (or that directory's database) served these bytes, and they are
about this identifier.** It does not establish that the keys in it are the
subject's, that it has not been rolled back, or that the same document would be
served to anyone else. The `id` check catches a wrong answer; it cannot catch a
consistent lie by the party being asked.

For `did:plc` there is a stronger claim available and not taken: the operation
log makes the current document verifiable against the DID itself, because the
DID *is* a hash of the genesis operation. Until that log is checked, "did:plc
resolved" means "plc.directory said so".

For `did:web` no stronger claim is available at all. The method's security is
the domain's security, and the domain's security is WebPKI — which is exactly
the trust model this project exists to offer an alternative to. §9.4 accepts
that trade deliberately, for reach; a specification should say so rather than
let a reader assume a self-certifying identifier is self-certifying.

### 10.4 Privacy: asking is a disclosure

Resolving an identity discloses an interest in that identity, to a party who
can log it:

- `did:plc` tells `plc.directory` which account you are looking at. It is one
  operator seeing every `did:plc` lookup this client makes.
- `did:web` tells the subject's own host that someone is resolving them, and
  tells the network which host that is.
- The AppView handle lookup (§6.1) tells Bluesky which handle you asked about,
  even for accounts you never interact with. The DNS method would put that
  question into DNS, where this client already has an oblivious transport for
  it — another reason §6.1's gap costs more than it looks.

Because the `did:` handler's transport is **injected** (§5.4), the browser
gives it the proxied session fetch, so DID resolution rides the user's
anonymizing proxy and stays available while IP Protection is on. That is the
posture an implementation SHOULD adopt, and it is why `did:` needs no gate.

The rule the gate encodes is still normative for anything that cannot be
proxied: a handler that opens its own transport — a p2p overlay dialling peers,
a raw socket in the main process — MUST refuse rather than resolve while an
anonymizing mode is on, because it would reveal the real address. The reference
implementation's `createNonProxiedGate` answers **503** with a plain
explanation and does not run the handler. The status code matters — some
engines treat an unknown HTTP status from a protocol handler as a fatal
condition — so a gate MUST use a status the engine knows.

The recognised-but-unresolved handlers (§8) need no gate either: they make no
request under any condition.

### 10.5 Before enabling `at://` or `activitypub:`

A conforming implementation MUST NOT change a namespace from *recognised,
fail-closed* to *resolving* until it can state, for each step, which of §4's
four states applies and why. Concretely, the minimum bar for each:

**`at://`**

1. Resolve the identifier's handle by the DNS or well-known method (§6.1), not
   by asking an aggregator; verify bidirectionally against the DID document's
   `alsoKnownAs`.
2. Resolve the DID, checking `id`, and — for `did:plc` — the operation log.
3. Read the record **from the PDS named in that document**, and verify it
   against the repository's signed commit using the `#atproto` signing key from
   that document.
4. Report anything obtained from an AppView instead as **unverified**, and
   never as a resolution of the AT-URI.

**`activitypub:`**

1. WebFinger the address (RFC 7033, RFC 8615) and treat the answer as a
   *redirection*, never as an authentication.
2. Fetch the actor document from the `self` link and check it is
   self-consistent with the address that led to it.
3. Report the actor as **unverified**: ActivityPub gives a client no way to
   authenticate a fetched object, and an implementation MUST NOT borrow HTTP
   Signatures' server-to-server delivery guarantee to imply one.

Until then, the refusal is the honest answer, and it is a better answer than a
rendered page with a lock nobody can justify.

---

## Layout

```
SPEC.md          this chapter
REFERENCES.md    what it is built on
../../DEVIATIONS.md  where it departs, and what we are unsure of (DI-n)
src/
  did-protocol.js            the did: handler — did:plc, did:web (§5)
  unimplemented-protocol.js  the fail-closed contract for at:/activitypub: (§7, §8)
  gate.js                    the anonymization gate for non-proxied handlers (§10.4)
  bsky.js                    the AT Protocol adapter; resolveHandle/resolvePds are §6
                             (it imports did-protocol.js for the one did:web reader)
  xrpc.js                    its transport (imported by bsky.js)
  record.js                  the `_hns.<name>` control record (§9.1, experimental)
  receipt.js                 the claim and atproto binding receipts (§9.1, §9.3)
  keys.js  nostr-event.js    the signature primitives those two import
tests/
  did-protocol.test.js       §5, with the transport injected
  unimplemented.test.js      §8, including "no network request of any kind"
  atproto-identity.test.js   §6
  identity-anchor.test.js    §9.1, §9.3
  namespace-routing.test.js  §3, against the shared classifier at ../../src/router.js
```

Every file in `src/` is **byte-identical** to its counterpart in the Wildroot
tree modulo import paths. A fix in one is provably the same fix in the other.

**Two files reach past the scope line, and are kept whole rather than trimmed
for that reason.** `bsky.js` is the entire Bluesky adapter, of which §6
specifies two functions; `xrpc.js` is there only because `bsky.js` imports it.
`bsky.js` also imports `did-protocol.js`, which is the point of §5.3's one
reader — the dependency edge is what makes the single reader structural rather
than a convention.
Forking either to make the package tidier would break byte-identity, and a
divergent copy of a security-relevant module is a worse problem than an
over-broad dependency. `keys.js` and `nostr-event.js` are the signature
primitives `record.js` and `receipt.js` import; their own design is out of
scope (§1.1). `gate.js` is extracted because §10.4 specifies the rule it
encodes; the `did:` handler itself does not use it.

**Nothing here is Electron-bound.** Two things this chapter describes *are*,
and are therefore specified but not extracted: the scheme registration and
privilege declaration (§3.1, §8, in the browser's `src/main.cjs`), and the
`_hns` resolution policy of §9.2 (in the browser's `src/folders/index.js`).
If you are implementing from this chapter, those two layers are yours to write.
