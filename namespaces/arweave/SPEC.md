# Chapter 4 — Arweave

This chapter is part of the integrated Wildroot web3 resolution specification
whose spine is `../../SPEC.md`, where namespace selection — how a URL or a name
comes to be handled here rather than somewhere else — is specified.

**Namespace:** `arweave` (`ar://`)
**Status:** Describes the behaviour of the reference implementation in
`namespaces/arweave/src/`, which ships in the Wildroot browser. Not endorsed by
any standards body, and not endorsed by the Arweave project or by ar.io.
Normative statements describe what an implementation must do *to interoperate
with this one*; where a rule is inherited from an existing specification, that
specification is cited and its text governs.
**Licence:** CC-BY-4.0 (see `../../LICENSE-SPEC`). The reference implementation
is licensed separately (Apache-2.0).

This chapter specifies what happens **after** a Handshake resolution (or an ENS
resolution, or a typed URL) has produced an Arweave transaction id. It does not
restate the Handshake part.

Every deviation from a cited specification, and every question we are not sure
about, is in `../../DEVIATIONS.md` under the `AR-` prefix. Every specification
cited is listed with its purpose in `REFERENCES.md`. **Those files are part of
this specification, not appendices to it.**

---

## Contents

1. [What this specifies, and its scope](#1-what-this-specifies-and-its-scope)
2. [Terminology](#2-terminology)
3. [The Arweave identifier](#3-the-arweave-identifier)
4. [The `ar://` URL form](#4-the-ar-url-form)
5. [How an identifier is reached](#5-how-an-identifier-is-reached)
6. [Retrieval: gateways and failover](#6-retrieval-gateways-and-failover)
7. [Path manifests](#7-path-manifests)
8. [ArNS and ar.io names](#8-arns-and-ario-names)
9. [What is verified, and what is not](#9-what-is-verified-and-what-is-not)
10. [Origin and privilege](#10-origin-and-privilege)
11. [Security considerations](#11-security-considerations)

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## 1. What this specifies, and its scope

Arweave is the only content network in this browser whose addresses are
**bought once and never renewed**. That makes it the natural backstop behind a
Handshake name's live pointers, and it is where this stack puts it: a name's
`ar=` record is consulted last, after `ipfs=`, `ipns=`, `bt=` and `hyper=`
(`../../SPEC.md` §10, `../../src/pointers.js` `POINTER_PRECEDENCE`).

**In scope.** Three questions:

1. **What is a valid Arweave identifier**, and what URL form carries one (§3,
   §4).
2. **How an identifier is arrived at** — typed as `ar://`, read from an `ar=`
   TXT record on a Handshake name, or decoded from an `arweave-ns` EIP-1577
   contenthash on the HIP-5 `_op` or ENS routes (§5).
3. **What an implementation may claim about the bytes** it gets back, and what
   it must not claim (§9). This is the part that matters, and it is the part
   where this implementation is weakest — see §9.2 and `../../DEVIATIONS.md`
   AR-1.

**Out of scope, explicitly.**

| Out of scope | Where it lives instead |
|---|---|
| **Handshake resolution itself** — how `ar=` was proven to belong to the name | `../../SPEC.md` §6 (the chain proof and the authoritative walk), §7 (`_op`), §10 (the pointer grammar) |
| **The pointer record grammar** — the `ar=<txid>` TXT syntax, precedence, and `txtStringsFrom` | `../../SPEC.md` §10, implemented in `../../src/pointers.js`. Referenced here (§5.2), not duplicated. |
| **HTTP transfer mechanics beyond what verification requires** — connection reuse, caching policy, TLS to the gateway | ordinary HTTPS; the gateway is an ordinary HTTPS host, which is precisely the problem §9 describes |
| **Writing to Arweave** — bundling, signing, posting, paying | not in this repository at all. The browser has no Arweave publish target; every `ar=` record this stack reads was written by external tooling. |
| **ArNS name resolution** | **not implemented** — §8 says what happens instead, which is nothing special |
| **Rendering** — how HTML, video or a PDF fetched from Arweave is displayed | the browser's content layer |

A consequence worth stating plainly: an implementation of this chapter is a
**fetcher with a strict address grammar**, not a verifier. §9 is the honest
accounting of that.

---

## 2. Terminology

Arweave terms are used as the Arweave protocol documentation and the Arweave
Standards (ANS) series define them:

- **Transaction** — the signed unit posted to the Arweave network. Its
  identifier is derived from its signature (§3.1).
- **Data item** — an ANS-104 bundled item. It has its own identifier, derived
  the same way, and a gateway serves it at the same URL shape as a
  transaction. An implementation of this chapter **cannot and need not tell
  the two apart** (§3.3).
- **`data_root`** — the Merkle root over a format-2 transaction's data chunks,
  committed inside the signed transaction header. Verifying bytes against a
  transaction id means verifying chunk proofs against `data_root` and then
  verifying `data_root`'s membership in the signed header. This implementation
  does **neither**.
- **Gateway** — an HTTP service that indexes the Arweave network and serves
  `GET /<id>` and `GET /<id>/<path>`. `arweave.net` is the Arweave project's
  own gateway; ar.io gateways are an independent operator network.
- **Path manifest** — a transaction whose data is a JSON document with
  `"manifest": "arweave/paths"`, mapping subpaths to transaction ids. §7.
- **ArNS / ANT / undername** — the ar.io name system, the Arweave Name Token
  contract that holds a name's records, and the `<label>_<name>` sub-record
  form. §8.

Terms specific to this chapter:

- **Arweave identifier** (or **txid**) — the 43-character base64url string
  that names a transaction or a data item. §3.
- **Content pointer** — as in `../../SPEC.md` §2: a record naming content by a
  self-authenticating address. `ar=<txid>` is one.
- **Gateway-trusted** — a trust state in which bytes were obtained from a host
  authenticated only by its TLS certificate, and were **not** checked against
  the address they were requested by. Every byte this implementation returns
  for `ar://` is gateway-trusted.

---

## 3. The Arweave identifier

### 3.1 How the identifier is derived

An Arweave transaction id is the **SHA-256 digest of the transaction's
signature**, encoded base64url. ANS-104 states the same rule for a bundled
data item verbatim: *"The id of the DataItem, is the SHA256 digest of this
signature."* Thirty-two bytes, base64url-encoded without padding (RFC 4648
§5), is **43 characters**.

This derivation is what makes an identifier *immutable*: the id commits to the
signature, the signature commits to the transaction header, and the header
commits to `data_root`. Nothing about that chain is checked by this
implementation (§9); it is stated because it is what a conforming
implementation *could* check, and because it is the reason failover across
gateways (§6) is safe in principle.

### 3.2 The rule this implementation applies

One function decides, and both the `ar://` handler and the `ar=` pointer parser
import it from `../../src/pointers.js`:

```js
export function isCanonicalTxid (id) {
  if (!ARTX_RE.test(String(id || ''))) return false      // /^[A-Za-z0-9_-]{43}$/
  const bytes = Buffer.from(id, 'base64url')
  return bytes.length === 32 && bytes.toString('base64url') === id
}
```

An implementation **MUST** require exactly 43 characters from the base64url
alphabet (RFC 4648 §5: `A-Z a-z 0-9 - _`), **MUST** require the **canonical**
spelling of those 32 bytes (§3.3), and **MUST** reject anything else before any
network request is made.

That ordering is not cosmetic: it is the guard that confines every URL this
handler can construct to `<gateway>/<43-char-id>…`, so no `ar://` URL can be
steered at a gateway's API endpoints (`/tx`, `/chunk`, `/price`, `/graphql` —
none of which is 43 characters). The test *"failover does not weaken the txid
rule"* in `tests/arweave-gateways.test.js` asserts it: a rejected id reaches
**no** gateway.

An implementation **MUST NOT** keep a second, private copy of this rule. One
rule read by both the fetcher and the pointer parser is what stops a name
publishing an identifier the fetcher refuses, or the reverse; the browser tree
pins that with a test asserting no module declares its own txid regex.

### 3.3 What the rule does and does not distinguish

**Canonical encoding is enforced.** A 43-character base64url string encodes 258
bits, of which only 256 are the identifier; the final character therefore
carries two bits that MUST be zero in a canonical encoding (RFC 4648 §3.5), and
only 16 of the 64 alphabet characters have them zero. Decoding to 32 bytes and
re-encoding is the check. Measured against the reference implementation:

```
ar://W-9rj7LCX-1kRs8Edf4UmJvzCHYBCnZN_13dh0Y7xq8   200
ar://W-9rj7LCX-1kRs8Edf4UmJvzCHYBCnZN_13dh0Y7xq9   400, and reaches no gateway
                                                    (it decodes to the same 32
                                                     bytes; it is not the one
                                                     spelling of them)
```

One transaction therefore has one URL, one cache entry and one origin. The
same rule applies to an `ar=` record: a non-canonical spelling is **not a
pointer** (§5.2).

**A transaction is not distinguished from a data item.** ANS-104 data-item ids
have the same derivation, the same length and the same alphabet. This is
correct behaviour rather than a gap — a gateway resolves both at `GET /<id>` —
but an implementation **MUST NOT** report to a user that an `ar://` URL names
"a transaction" when it may name a bundled item.

### 3.4 Case

An identifier is **case-sensitive**. `W-9rj…` and `w-9rj…` are different
identifiers, and only one of them exists. An implementation **MUST NOT** apply
a host-style case fold. §4.2 states the parsing consequence.

---

## 4. The `ar://` URL form

### 4.1 Grammar

```
ar-URL = "ar://" txid [ "/" path ] [ "?" query ] [ "#" fragment ]
txid   = 43( ALPHA / DIGIT / "-" / "_" )       ; canonical — §3.2
path   = segment *( "/" segment )
```

`ar://` is a **de-facto scheme**, not a registered one. It is the form used by
the ar.io gateway network and by the Wander (formerly ArConnect) wallet
extension, and this implementation adopts it unchanged rather than inventing
another. There is no RFC and no IANA registration — see `../../DEVIATIONS.md`
AR-2.

### 4.2 Parsing MUST be from the raw string

```js
const raw = String(request.url).replace(/^ar:\/\//, '').split('#')[0]
```

An implementation **MUST NOT** obtain the identifier from a WHATWG-URL host
accessor (`URL.hostname` or equivalent). Host parsing lowercases, and §3.4
makes lowercasing destructive: it silently turns a valid id into a different,
non-existent one. The identifier is read from the raw URL text.

This also means the scheme **SHOULD NOT** be registered as a *standard* scheme
in a Chromium-based browser, because standard-scheme host canonicalization
performs exactly that fold. The browser registers `ar` with `standard: false`
(§10).

### 4.3 Path

Everything after the first `/` and before the first `?` is a path *within* the
identifier. Three rules:

- **Segments are passed on as they were received.** They arrive already
  percent-encoded from the URL parser, and an implementation **MUST NOT**
  re-encode them: `encodeURIComponent` applied to an encoded segment turns
  `%20` into `%2520`, which addresses a manifest path that does not exist.
  `ar://<txid>/my%20file.html` is requested as `…/<txid>/my%20file.html`.

- **A segment that decodes to a separator or a dot-segment MUST be refused**
  with **400**, before any request. Because segments are forwarded rather than
  re-encoded, this check — not the encoding — is what confines the path:

  ```js
  function isSafeSegment (segment) {
    if (segment === '.' || segment === '..') return false
    try {
      const decoded = decodeURIComponent(segment)
      return !decoded.includes('/') && !decoded.includes('\\') &&
             decoded !== '.' && decoded !== '..'
    } catch { return false }
  }
  ```

  A segment that cannot be decoded at all is refused too. `ar://<txid>/../x`
  must never become `<gateway>/x`, which would escape the identifier's scope
  and address the gateway's own namespace, and neither may
  `ar://<txid>/a%2F..%2Fb`.

  Note precisely what the dot-segment half of this guard is and is not. When
  the URL arrives through a WHATWG `Request`, dot segments — including
  percent-encoded ones — have **already** been collapsed by URL normalization,
  so that half is unreachable on that path. It is real defence for a raw
  string, which is what a non-`Request` caller or another runtime's URL
  handling can present. The test *"a path cannot escape the txid, whichever
  gateway answers"* asserts the outcome on the URL actually requested rather
  than on the guard, which is the assertion that stays true either way.

- **Empty segments are dropped.** `ar://<txid>/`, `ar://<txid>/a//b` and
  `ar://<txid>/dir/` are requested as `…/<txid>`, `…/<txid>/a/b` and
  `…/<txid>/dir`. A gateway that wants a trailing slash for an index answers
  with a redirect, which §6.3 follows.

### 4.4 Query and fragment

The **fragment is split off first and dropped** — it is never sent on the wire,
and dropping it first is what stops a `#` in a URL smuggling itself into the
query. The **query string is carried through unchanged** to the gateway:
`ar://<txid>/app?route=x` is requested as `<gateway>/<txid>/app?route=x`, and
`ar://<txid>?dl=1` as `<gateway>/<txid>?dl=1`. A manifest-hosted single-page
application that reads `location.search` therefore behaves at an `ar://` URL as
it does at the gateway's own URL for the same transaction.

---

## 5. How an identifier is reached

Three entry points converge on the same handler. All three produce
`ar://<txid>[<path>][<query>]` and hand it to §6.

### 5.1 A typed or linked `ar://` URL

An explicit scheme is authoritative: it selects the handler and nothing
re-classifies it (`../../SPEC.md` §3's law, implemented in
`../../src/router.js` `classify`, `reason: 'explicit-scheme'`). A failure
inside this namespace **MUST** surface as an Arweave failure and **MUST NOT**
be re-dispatched into another namespace — a bad `ar://` URL never becomes a
search or a DNS lookup.

There is **no** bare-identifier classification: a 43-character base64url string
typed alone in an address bar is not treated as an Arweave id (it goes to
search). This is deliberate — the shape collides with too much else — and it
means `ar://` must always be written out.

### 5.2 An `ar=` pointer on a Handshake name

The record grammar, the concatenation rule for a TXT record's
`<character-string>`s, and the precedence between pointer kinds are specified
in `../../SPEC.md` §10 and implemented **once**, in `../../src/pointers.js`:

```js
if (tag === 'ar') return isCanonicalTxid(id) ? { kind: 'arweave', txid: id } : null
```

with `isCanonicalTxid` the same function §3.2 gives the `ar://` handler, and
`arweave` **last** in `POINTER_PRECEDENCE`. Three rules from that module bear
repeating here because they are Arweave-specific in effect:

- A pointer whose address fails the identifier rule is **not a pointer** — it
  is `null`, not a half-trusted record. A name carrying only a malformed or
  non-canonical `ar=` resolves as though it carried no pointer at all.
- Because the rule is the canonical one, an `ar=` record round-trips
  byte-for-byte through a republish, and a name cannot publish an identifier
  the fetcher would refuse.
- Precedence is decided by the table, never by DNS answer order, so a name
  carrying both `ipfs=` and `ar=` resolves to IPFS on **every** path — SPV,
  DoH and `_op`.

The Handshake handler then composes the URL (`src/hns/index.js` in the browser
tree, not extracted here — it is Electron-bound):

```js
const target = `ar://${resolution.txid}${path === '/' ? '' : path}`
```

where `path` is the `hns://` URL's `pathname + search`. The query component is
carried this far and, by §4.4, all the way to the gateway.

If no `ar://` handler is registered, the Handshake handler answers **501** and
names Arweave. It **MUST NOT** fall through to an address record: a name that
says its content is on Arweave has not said anything about an A record.

### 5.3 An `arweave-ns` contenthash

On the HIP-5 `_op` route (`../../SPEC.md` §7) and on the ENS route, the name's
content pointer is an EIP-1577 / ENSIP-7 `contenthash` byte string.
`../../src/contenthash.js` decodes multicodec `arweave-ns` = **`0xb29910`**:

```js
if (code === CODEC.ARWEAVE) {
  const txid = Buffer.from(rest).toString('base64url')
  return { protocol: 'arweave', supported: true, id: txid, url: `ar://${txid}`, code }
}
```

The value is the **raw 32 bytes**, base64url-encoded here into the 43-character
form of §3.1, which is canonical by construction — this route has nothing for
§3.3's canonicality check to catch. The multicodec code is read as an unsigned
varint (`readVarint`), which is why `0xb29910` occupies four bytes on the wire
(`90 b2 ca 05`).

An implementation **MUST NOT** guess at an unrecognised codec, and **MUST NOT**
fall through to the seller's nameservers when it decodes a codec it recognises
but cannot fetch. `../../src/hip5-op.js` returns `{ unusable: true, protocol }`
for those cases; the ENS handler answers **501** naming the protocol.

---

## 6. Retrieval: gateways and failover

### 6.1 More than one operator, on a stated criterion

```js
export const AR_GATEWAYS = Object.freeze([
  'https://arweave.net',
  'https://permagate.io',
  'https://ar-io.dev'
])
```

An implementation **SHOULD** carry more than one gateway, under more than one
operator. A scheme whose entire promise is that content outlives everyone is
poorly served by a single host, and `arweave.net` is the Arweave project's own
gateway rather than a member of the ar.io gateway network (it does not answer
`/ar-io/info`). The other two are independent ar.io nodes with their own
operators and wallets.

An implementation **SHOULD** state the criterion for membership of the list and
the date it was last reviewed, so that the list is maintainable by someone who
did not write it. Ours does, in the module: *an independent operator answering
`/ar-io/info`, reachable on the review date; a host that stops answering is
removed rather than kept for sentiment.* Every entry **MUST** be `https:` — an
`http:` gateway would put the whole fetch in plaintext and nothing downstream
re-checks the scheme.

A caller **MAY** pin exactly one gateway (`{ gateway }`, singular), and when it
does there **MUST** be no failover: silently reaching for two more hosts
defeats the purpose of pinning one. Pinning one also gives up the header check
(§9.1.1), which has nobody independent to ask — so a caller that pins a single
gateway is choosing to trust that operator for both the bytes and the
transaction's identity, and an implementation **SHOULD** say so where the option
is offered.

### 6.2 When to move on — the normative rule

```
for each gateway in order:
    attempt the request (following at most one in-scope redirect, §6.3)
    if the host could not be REACHED and another gateway remains: continue
    if the response status is >= 500 and another gateway remains: continue
    otherwise: return this response as it came
if no gateway was ever reached: raise the last transport error
```

**A 404 is an answer.** The transaction is not there, and three more gateways
saying so costs three round trips and tells the user nothing new. Only a
failure to *reach* a host, or a 5xx, is worth another attempt. An
implementation **MUST NOT** retry a 4xx across gateways.

*Failure to reach* is decided by **structure first**: the error's `code`, or
its cause's, matched against `ENOTFOUND`, `ECONNREFUSED`, `ECONNRESET`,
`ETIMEDOUT`, `EAI_AGAIN`, `EHOSTUNREACH`, `ENETUNREACH` and undici's
`UND_ERR_*` family, then the error's `name` (`AbortError`, `TimeoutError`), and
only then the message text as a last resort. An implementation **SHOULD NOT**
rest this decision on message text alone: a runtime that rewords or localizes
its errors would silently turn failover off, and no test would go red.

**Every gateway failing MUST raise**, not return an empty success. A blank page
with a 200 is indistinguishable from content that legitimately is blank.

### 6.3 Redirects

The request is made with `redirect: 'manual'`: a gateway **MUST NOT** be able
to bounce an `ar://` fetch to an arbitrary host. That is load-bearing, and it
means the implementation decides for itself what a 3xx means.

A redirect is followed **only** when all of the following hold, and at most
**one** hop is taken:

1. the `Location` resolves to an `https:` URL,
2. on the **same gateway** as the one that answered — its own host, or a
   **subdomain** of it (`hostname.endsWith('.' + gateway)`, so a host that
   merely ends in the gateway's name is not one), and
3. whose first path segment is the **same identifier**.

Rule 2 admits the sandbox that arweave.net and every ar.io gateway answer
`GET /<txid>` with: a 302 to `https://<label>.<gateway>/<txid>[/path]`, where
`<label>` is the transaction id re-encoded in lowercase unpadded base32
(RFC 4648 §6; `sandboxLabel()`, 52 characters for a 32-byte id), so that each
transaction is its own origin in the renderer. The identifier in the path is
the load-bearing check — a sandbox label is derivable from the id, but the
path is what names the transaction the gateway is about to serve. The header
check of §9.1.1 runs after the hop, against the other gateway, and the
response says so.

Anything else — another host, a subdomain of another host, another
transaction, a downgrade to `http:`, or a second redirect — is refused with
**502** and a body naming the gateway that tried it. The 502 **MUST NOT** carry a `Location`: handing the redirect back to
the renderer would restore the open redirect that `redirect: 'manual'` exists
to close. `location` is accordingly absent from the response safelist of §6.4.

This is what makes ordinary gateway operation work — index normalization when a
manifest is fetched without a trailing slash is a redirect within the same
transaction — without giving a gateway a way to steer the client.

A 3xx with **no** `Location` is not a redirect and is returned as it came,
which is how a `304 Not Modified` answering an `If-None-Match` survives.

### 6.4 Headers

Request headers are filtered to a **fixed safelist**, and one header is added:

```js
const FORWARDED = ['range', 'if-none-match', 'if-modified-since', 'accept']
// plus 'user-agent: hns.one-browser'
```

The **header** request of §9.1.1 is not a caller's request and carries none of
the caller's headers: it is a `GET <gateway>/tx/<txid>` with `user-agent` and
`accept: application/json` and nothing else, whatever method or headers the
original request had. It is issued for a `HEAD` too, because a `HEAD` that
answered `200` made the same claim about the same identifier.

Response headers are filtered to a fixed safelist too:

```js
const RETURNED = ['content-type', 'content-length', 'etag', 'cache-control',
                  'content-range', 'accept-ranges', 'last-modified', 'vary']
```

The list being **fixed** is the point. Nothing the caller chose beyond a known
set reaches the gateway, so an `ar://` fetch cannot be fingerprinted by
whatever headers a page happened to set and no cookie or credential can leak to
a gateway that sees every request (§11.2) — while the conditional and range
mechanisms of RFC 9110 that a browser actually needs keep working. `Range`
reaches the gateway and `Content-Range` and `Accept-Ranges` come back, so media
served from `ar://` seeks; `If-None-Match` reaches the gateway, so the `ETag`
that comes back can be revalidated.

One header is *added* on the way out and is this implementation's own, not a
gateway's: `X-Arweave-Verified` (§9.1.1). It is set on every response a gateway
answered — whatever the status, so a `404` or a `304` carries it too — and it is
absent only from the refusals this implementation generates itself (a bad
identifier, a bad path, a bad method, a refused redirect), which have no
transaction to say anything about. It is not in the response safelist, so a
gateway cannot supply it.

An implementation **MAY** choose a different safelist, but **MUST NOT** forward
caller-chosen headers wholesale, **MUST NOT** return `location` (§6.3), and
**MUST NOT** let a gateway supply the verification header itself.

### 6.5 Method

Only **GET** and **HEAD** are accepted. Any other method is answered **405**
with `Allow: GET, HEAD` and reaches no gateway: there is nothing under a
transaction id to write to, so the surface is removed rather than confined.

The upstream request carries the same method, so a `HEAD` is answered by a
`HEAD` of the gateway and transfers no body. No request body
is ever read or forwarded.

### 6.6 Transport privacy

Where the fetch is proxied — an anonymizing proxy, Tor, a VPN — the
implementation **MUST** use a fetch that honours the proxy. A runtime's global
`fetch` frequently does not: in this build, Node's global `fetch` (undici)
ignores Electron's `session.setProxy` entirely, so using it would disclose the
real client address to the gateway with anonymization visibly on.

The handler therefore takes an injected `fetchImpl` and **requires** it: the
constructor throws when it is absent, so a caller that forgets fails at
construction rather than in a user's traffic. There is no fallback to a global
fetch, which is what lets `ar://` be one of the few schemes deliberately *not*
blocked while anonymization is on. The composition layer supplies
`net.fetch(url, { …, bypassCustomProtocolHandlers: true })`, which rides the
Chromium network stack and therefore the active proxy.

An implementation that offers proxying **MUST NOT** default `fetchImpl` to a
global fetch.

---

## 7. Path manifests

An Arweave **path manifest** is a transaction whose data is a JSON document
with `"manifest": "arweave/paths"`, `"version": "0.1.0"`, an optional `index`
naming a default path, and a `paths` object whose keys are subpaths and whose
values carry the transaction `id` to resolve to. It is served with
Content-Type `application/x.arweave-manifest+json`. A gateway seeing that
content type serves `GET /<manifest-txid>/<subpath>` by looking the subpath up
in the manifest and returning the transaction it names.

**This implementation does not parse manifests. At all.** There is no manifest
reader anywhere in the tree. `ar://<txid>/<path>` is turned into
`<gateway>/<txid>/<path>` (§4.3) and the gateway does the entire lookup.

That is a legitimate architecture, and it is stated here rather than hidden
because of what it costs:

- The **path→id mapping is gateway-trusted**, on top of the bytes being
  gateway-trusted (§9). Even a client that verified bytes against an id would
  still be taking the gateway's word for *which* id a path names, unless it
  fetched and parsed the manifest itself.
- **Failover across gateways (§6.1) does not carry the mapping.** Two gateways
  that disagree about a subpath cannot be caught by comparing bytes, because
  the client never learns which id each one resolved to.
- A **version-`0.2.0` manifest**, and its `fallback` behaviour, are handled or
  not handled entirely by whichever gateway answers. The canonical Arweave
  repository documents `0.1.0`; `0.2.0` (index by `id`, and `fallback`) is an
  ar.io-side extension whose clauses we have not verified against a retrievable
  specification, because the implementation reads neither —
  `../../DEVIATIONS.md` AR-U2.

An implementation that wants a stronger claim than "the gateway said so"
**SHOULD** fetch the manifest transaction itself, verify it (§9), parse it, and
then fetch the named id — turning one gateway-trusted hop into two verifiable
ones. That is not what this one does.

---

## 8. ArNS and ar.io names

**ArNS is not resolved by this implementation.** There is no ArNS client, no
ANT read, no `_ar-io` lookup, and no entry for it in the namespace table
(`../../src/router.js` `SCHEME_TABLE` has `ar` and nothing else Arweave-side).

What that means concretely, for the case this stack actually produces —
`<label>_persist.ar.io`, an ArNS undername under the `persist` name whose
records are written by our own out-of-tree service:

1. `ar.io` ends in the ICANN top-level domain `io`.
2. `classifyHost` (`../../src/router.js`) therefore returns the `icann`
   namespace (`../../SPEC.md` §3, rule 2).
3. The name is resolved through **ordinary DNS**, fetched over **ordinary
   HTTPS**, and authenticated by an **ordinary CA-issued certificate** —
   exactly like any other website. The padlock model says
   *trusted-but-not-trustless* (`../../SPEC.md` §4), which is the truth.

The undername separator is `_`, so an ArNS hostname is
`<undername>_<name>.<gateway-host>` and every ar.io gateway serves it on a
wildcard. Nothing in this implementation reads or writes that convention; it is
recorded here so that a reader does not mistake "we hold an ArNS name" for
"the browser resolves ArNS".

An implementation adding ArNS resolution **MUST NOT** route an ArNS lookup
through this chapter: an ArNS name is **mutable**, its current value is held in
an ANT contract on another chain, and none of §3's immutability reasoning
survives that. In particular, the failover rule of §6.2 — which is safe only
because an identifier is immutable — would become a way for two gateways to
disagree about the current value of a name with no way to tell which is right.
`../../DEVIATIONS.md` AR-U3.

---

## 9. What is verified, and what is not

This is the section to read.

### 9.1 What is checked

| Check | Effect |
|---|---|
| The identifier is 43 canonical base64url characters (§3.2) | 400 before any request; confines every constructed URL to `<gateway>/<id>…`, and gives one transaction one URL |
| No path segment is, or decodes to, a separator or a dot-segment (§4.3) | 400; the path cannot escape the identifier |
| The method is GET or HEAD (§6.5) | 405; nothing but a read reaches a gateway |
| Only a fixed header safelist crosses in either direction (§6.4) | nothing caller-chosen beyond a known set reaches the gateway |
| A gateway may redirect only within itself (its host or a sandbox subdomain of it) and within the same transaction (§6.3) | 502 with no `Location`; the fetch cannot be bounced to an arbitrary host |
| TLS to an `https:` gateway (§6.1) | the gateway is authenticated as a host, by a CA |
| The transaction **header** hashes to the identifier, fetched from a gateway *other* than the one that served the bytes (§9.1.1) | 502 on a mismatch, and the response says which of the two happened |

### 9.1.1 The header check

An Arweave transaction id **is** `SHA-256` of the transaction's signature — that
is the protocol's definition of the id, and ANS-104 states the same derivation
verbatim for a bundled data item. So a transaction *header* can be proved to be
the transaction an identifier names with one hash and no trust in anybody:

```js
export function headerMatchesId (header, txid) {
  // base64url-decode the signature, SHA-256 it, base64url-encode the digest,
  // and require it to equal the identifier.
}
```

`src/ar.js` `headerMatchesId`. The check is performed **after** a successful
fetch, and the rules around it are the whole of its value:

1. **The header MUST come from a gateway other than the one that served the
   bytes.** `GET <other gateway>/tx/<txid>` (`src/ar.js`, the block after the
   failover loop). A gateway that is lying about the bytes would supply a
   matching header too, so a header from the same host proves nothing at all.
2. **A mismatch is a refusal.** `502`, naming the gateway and saying that the
   signature does not hash to the id. It is never a warning, never a retry, and
   never a fall-through to the next gateway.
3. **It applies to the transaction's own data.** With a manifest path there is
   no single transaction whose header could answer for the bytes (§7 hands path
   resolution to the gateway), so the check is skipped rather than faked.
4. **It needs two gateways.** With exactly one configured (§6.1's pinned
   `{ gateway }`) there is nobody independent to ask, so it is skipped.
5. **A second gateway that will not answer is a skip, not a failure.** The
   check cannot be completed, so nothing was checked, and that is what the
   response says.
6. **The outcome is reported, machine-readably.** Every response carries
   `X-Arweave-Verified: header` when the header was proved to be this
   identifier's, and `none` in every other case — skipped, unreachable, or the
   check switched off. An implementation **MUST NOT** ever write `bytes` there:
   it is a claim §9.2 does not support.

The check is **on** in the reference browser and **off** by default in the
library (`verifyHeader`, `browser src/protocols/index.js`). That asymmetry is
deliberate — a library embedder may be pointing at one gateway it operates, and
a second request per fetch is not free — and it is the one setting an
implementation **SHOULD** enable, because it is the whole cheap half of the
verification (`../../DEVIATIONS.md` AR-D1).

**What it proves, exactly.** That the transaction the identifier names exists,
and that the header describing it — its `data_root`, its owner, its tags, its
size — is authentic, because the signature it carries hashes to the id asked
for. Two lies are removed by it: a gateway answering an identifier with a
different transaction's metadata, and an identifier that names nothing at all
being reported as content. What it does **not** prove is the bytes (§9.2), and
an implementation **MUST NOT** let the header check be read as though it did.

*(`tests/arweave-header.test.js` — the derivation, the mismatch refusal, and the
three cases where the check is honestly skipped.)*

### 9.2 What is NOT checked

**The bytes are never checked against the identifier.** No chunk proof is
verified and `data_root` — which the header check delivers, authenticated —
is never compared with anything. The transaction is proved to be the one the
identifier names; the *content* is still whatever the answering gateway chose to
send, trusted exactly the way a browser trusts any HTTPS host.

The implementation says so in its own header, in its namespace table — which
records the scheme as **`partial`**, not `live`:

```js
{ scheme: 'ar', namespace: NAMESPACES.ARWEAVE, status: 'partial',
  verify: 'immutable txid (shape only — bytes gateway-trusted until BR-6)' }
```

— and, the part that faces the user, in the trust panel.

Normatively:

> An implementation that fetches Arweave content from a gateway without
> verifying **the bytes** against the transaction id **MUST NOT** describe the
> result to a user as content-addressed, verified, or checked against its
> address — and a header check (§9.1.1) does not earn any of those three words,
> because it says nothing about the content. It **SHOULD** state that the
> gateway is trusted for the bytes, and it **SHOULD** run the result at reduced
> privilege (§10).

**What ours says.** Arweave is deliberately **not** in the set of pointer kinds
whose bytes authenticate themselves (`../../src/trust-path.js`
`CONTENT_ADDRESSED`, which holds `ipfs`, `ipns`, `bittorrent` and `hyper`). It
has its own branch, for both an `ar=` name and a bare `ar://` URL, and the step
it emits is `unverified`:

> **Content** — *Arweave tx `<id>`, fetched from a gateway over HTTPS.* The
> transaction id names immutable content, but the bytes came from an Arweave
> gateway and were not checked against the transaction, so the gateway is
> trusted the way any HTTPS site is.

An `unverified` step can never aggregate to a `verified` verdict, so the
page-level state is **`partial`**, never green — for both routes, and whether
or not the pointer itself was chain-proven.

**The padlock closes** for an `ar=` name on the chain proof alone, without a
DANE pin, the way it does for a content-addressed pointer — but for a different
reason, stated in the code: the bytes arrive from a gateway over ordinary
HTTPS, which is the same transport an `https://` page has, so the lock is the
neutral *trusted* one and the verdict beside it is `partial`. `../../SPEC.md`
§4 defines those states. Whether that is the right verdict is the one part of
this we still argue about — `../../DEVIATIONS.md` AR-U5.

**And the header check does not move any of that**, which is the point of
stating it here rather than only in §9.1.1: the trust panel's sentence, the
`unverified` step, the `partial` verdict and the neutral lock are the same
whether `X-Arweave-Verified` says `header` or `none`. The step that would change
is the one that is still missing. An implementation **MUST NOT** upgrade a trust
step, a lock or a verdict on the strength of the header check; it **MAY** report
the header check as a separate fact, and the reference implementation reports it
only in the response header.

The gap itself — no byte verification — is `../../DEVIATIONS.md` AR-1.

### 9.3 Why the shape check still buys something

An identifier names immutable content. So even without byte verification:

- A gateway can serve wrong bytes, but it cannot serve bytes that *change* —
  there is no version, no mutable pointer, nothing to move. Compare `ipns=` or
  an ArNS name, where the answer is a *current* value.
- Two gateways can be compared, because both are answering for the same
  immutable id. This is the property that makes §6.1's failover safe at all, and
  it is the property the header check spends (§9.1.1): the second gateway is
  asked for the one part of the transaction that is checkable with a hash.

The second is partly automatic and the more valuable half of it is not. The
header is compared across operators on every plain transaction fetch; the
**bytes** are still never compared, against the second gateway or against the
`data_root` the header authenticates. `../../DEVIATIONS.md` AR-D1 carries what
remains: hash a single-chunk body against `data_root`, and for a multi-chunk
transaction compare the body with the same path from the second gateway. A user
still has no affordance to force either.

### 9.4 What the chain proof does establish

When the identifier arrived from an `ar=` record on a Handshake name resolved
through the SPV path, the **binding** — this name points at this identifier —
is chain-proven and DNSSEC-validated to the on-chain DS (`../../SPEC.md` §6).
That is a real and unusual guarantee, and it is orthogonal to §9.2: the
implementation proves *which* immutable object a name names, and then does not
check that the bytes it received are that object.

When the identifier arrived over DoH, or from `_op`, or from ENS, even the
binding is taken on someone's word (`../../SPEC.md` §7, D-9, D-10). The trust
panel adds a separate `Pointer` step saying so, rather than quietly weakening
the content step.

---

## 10. Origin and privilege

`ar://` is registered at **low privilege** and as a **non-standard** scheme
(`src/main.cjs` in the browser tree):

```js
{ scheme: 'ar', privileges: { ...LOW_PRIVILEGES, stream: true } }
// standard: false, secure: false, allowServiceWorkers: false,
// supportFetchAPI: false, bypassCSP: false, corsEnabled: true
```

Two independent reasons, both of which an implementation **SHOULD** adopt:

1. **The bytes are not verified** (§9.2). A scheme whose content is
   gateway-trusted should not be a secure context, should not get service
   workers, and should not get secure-context storage. Privilege follows
   verification.
2. **Non-standard keeps the identifier intact.** A standard scheme's host is
   case-folded, and §3.4 makes that destructive. The cost is an opaque origin —
   no persistent storage, and web applications that touch `localStorage` will
   fail — which is the correct trade while (1) holds.

`stream: true` is granted so that large content (video, archives) is not
buffered whole; §6.4's `Range` safelist is what makes that streaming seekable.

---

## 11. Security considerations

**11.1 A hostile gateway is a full compromise of the content.** It can serve
any bytes at all for any identifier, and nothing in this implementation will
notice. The mitigations that exist are: TLS (so it must be *the* gateway, not a
network attacker), immutability (so it cannot roll a name forward), multiple
operators (so it must be the *specific* one that answered), and the header check
(so it cannot substitute a different transaction, only different bytes for the
right one — §9.1.1). The mitigation that does not exist is verification of the
bytes. §9.2.

**11.2 A gateway learns what you read.** Every `ar://` fetch discloses the
identifier and the path to whichever gateway answers, and the failover order is
fixed, so the first gateway in the list sees nearly everything. The fixed
header safelist (§6.4) limits what *else* it learns, and proxying (§6.6) hides
the client address — neither hides the request. An implementation **SHOULD NOT**
claim `ar://` is private.

**11.3 The identifier check is a confinement boundary, not a validation.** §3.2
is what stops an `ar://` URL addressing a gateway's own API. It is checked
before the gateway is chosen, and a test asserts that ordering explicitly. An
implementation that adds a gateway, a rewrite, or a fallback path **MUST**
preserve it. The same applies to §4.3: once segments are forwarded as received,
the decoded-separator check is the only thing keeping a path under the
identifier.

**11.4 A redirect is a steering primitive, and is treated as one.** §6.3 gives
a gateway exactly one move — send the client somewhere else under the same
transaction on the same host — and refuses everything else without handing the
attempted target to the renderer. An implementation that added `location` to
the response safelist, or raised the hop cap, would be giving an answering
gateway a general redirector inside a scheme the user believes is
content-addressed.

**11.5 The failover rule is a fingerprint.** A gateway that returns a 5xx moves
the client to the next gateway in a fixed order. A gateway that wishes to learn
whether a client is this implementation can do so in one request.

**11.6 The privacy of `ar://` rests on an injected fetch.** §6.6: the scheme is
left reachable while anonymization is on because the composition layer supplies
a proxied fetch. The constructor's refusal to run without one is what turns
that from a convention into a guarantee, and an implementation that restores a
default **MUST** gate the scheme instead.

**11.7 What an implementation may conclude from a successful `ar://` fetch.**
With `X-Arweave-Verified: none`, only this: *a host we authenticated by TLS,
chosen from a list we shipped, returned these bytes for this identifier.* With
`X-Arweave-Verified: header`, one thing more: *and a second, independent host
showed us the transaction this identifier names, so the identifier is real and
its header is authentic.* Neither says the bytes are the transaction's. Every
stronger claim requires the byte verification of §9.2, which this implementation
does not perform.

**11.8 A second gateway per fetch is a second gateway that learns what you
read.** The header check (§9.1.1) discloses the identifier to a host that was
not going to see it otherwise, which is a real widening of §11.2: with the check
on, two operators learn every plain `ar://` transaction a user opens rather than
one. It is the price of the only verification the scheme has, and an
implementation **SHOULD** say so rather than presenting the check as free. It
also makes the fingerprint of §11.5 louder: a `/tx/<id>` request arriving at one
gateway immediately after a data request for the same id at another is this
implementation's signature.
