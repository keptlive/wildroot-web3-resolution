# Chapter 4 — Arweave

> **Review pending:** [REVIEW.md](../../REVIEW.md) records unresolved questions
> about header authentication and the limits of body checks. The rewrite does not change runtime behaviour.

The [routing specification](../../SPEC.md) defines how a URL or name reaches
this namespace.

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

See [deviations and open questions](DEVIATIONS.md) (`AR-` entries) and
[references](REFERENCES.md) for limits and supporting sources.

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

This chapter defines Arweave identifiers and their use in `ar://` URLs,
Handshake pointers and EIP-1577 contenthash values. In the shared pointer
precedence table, `ar=` follows `ipfs=`, `ipns=`, `bt=` and `hyper=`
(`../../src/pointers.js`, `POINTER_PRECEDENCE`).

**In scope.** Three questions:

1. **What is a valid Arweave identifier**, and what URL form carries one (§3,
   §4).
2. **How an identifier is arrived at** — typed as `ar://`, read from an `ar=`
   TXT record on a Handshake name, or decoded from an `arweave-ns` EIP-1577
   contenthash on the HIP-5 `_op` or ENS routes (§5).
3. **What an implementation may claim about the bytes** it gets back, and what
   it must not claim (§9). See §9.2 and AR-1 for the verification limits.

**Out of scope:**

| Out of scope | Where it lives instead |
|---|---|
| **Handshake resolution itself** — how `ar=` was proven to belong to the name | `../../SPEC.md` §6 (the chain proof and the authoritative walk), §7 (`_op`), §10 (the pointer grammar) |
| **The pointer record grammar** — the `ar=<txid>` TXT syntax, precedence, and `txtStringsFrom` | `../../SPEC.md` §10, implemented in `../../src/pointers.js`. Referenced here (§5.2), not duplicated. |
| **HTTP transfer mechanics beyond what verification requires** — connection reuse, caching policy, TLS to the gateway | ordinary HTTPS; the gateway is an ordinary HTTPS host, which is precisely the problem §9 describes |
| **Writing to Arweave** — bundling, signing, posting, paying | not in this repository at all. The browser has no Arweave publish target; every `ar=` record this stack reads was written by external tooling. |
| **ArNS name resolution** | **not implemented** — §8 says what happens instead, which is nothing special |
| **Rendering** — how HTML, video or a PDF fetched from Arweave is displayed | the browser's content layer |

The handler validates identifiers and fetches from HTTPS gateways. Section 9
describes which checks support its trust claims.

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
- **`data_root`** — the Merkle root over a format-2 transaction's data chunks.
  The signed transaction header contains this root. The handler can compare
  a small response body with the supplied root, but it does not verify the
  signature over the header fields (§9).

Terms specific to this chapter:

- **Arweave identifier** (or **txid**) — the 43-character base64url string
  that names a transaction or a data item. §3.
- **Content pointer** — as in `../../SPEC.md` §2: a record naming content by a
  self-authenticating address. `ar=<txid>` is one.
- **Gateway-trusted** — content whose binding to the requested identifier has
  not been cryptographically established by this client. TLS authenticates the
  gateway host. The conditional body check in §9.2 does not remove reliance
  on the gateway-supplied header fields.

---

## 3. The Arweave identifier

### 3.1 How the identifier is derived

An Arweave transaction id is the **SHA-256 digest of the transaction's
signature**, encoded base64url. ANS-104 states the same rule for a bundled
data item verbatim: *"The id of the DataItem, is the SHA256 digest of this
signature."* Thirty-two bytes, base64url-encoded without padding (RFC 4648
§5), is **43 characters**.

The intended verification chain is id → signature → signed transaction
header → `data_root` → data. This handler checks the first relationship and,
for some responses, the last. It does not verify the signature over the
header fields, so it does not establish the full chain (§9).

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

Validation confines constructed URLs to `<gateway>/<43-char-id>…` and
prevents an `ar://` identifier from addressing gateway API paths such as
`/tx`, `/chunk`, `/price` or `/graphql`. The test "failover does not weaken
the txid rule" in `tests/arweave-gateways.test.js` checks that a rejected id
reaches no gateway.

An implementation **MUST NOT** keep a private copy of the identifier rule.
The handler and pointer parser must accept the same identifiers; the browser
tests prohibit separate txid regex declarations.

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

The accepted encoding gives each identifier one spelling. The same check
applies to `ar=` records (§5.2). Origin privileges are described in §10.

**A transaction is not distinguished from a data item.** ANS-104 data-item ids
have the same derivation, the same length and the same alphabet. This is
correct behaviour rather than a gap — a gateway resolves both at `GET /<id>` —
but an implementation **MUST NOT** report to a user that an `ar://` URL names
"a transaction" when it may name a bundled item.

### 3.4 Case

An identifier is **case-sensitive**. Changing case changes the identifier.
An implementation **MUST NOT** apply host-style case folding (§4.2).

---

## 4. The `ar://` URL form

### 4.1 Grammar

```
ar-URL = "ar://" txid [ "/" path ] [ "?" query ] [ "#" fragment ]
txid   = 43( ALPHA / DIGIT / "-" / "_" )       ; canonical — §3.2
path   = segment *( "/" segment )
```

`ar://` is a de-facto scheme used by the ar.io gateway network and Wander
(formerly ArConnect). This implementation follows that form. It has no RFC or
IANA registration; see AR-2.

### 4.2 Parsing MUST be from the raw string

```js
const raw = String(request.url).replace(/^ar:\/\//, '').split('#')[0]
```

An implementation **MUST NOT** obtain the identifier through host handling
that changes its case. This handler reads the raw URL text. Chromium's
standard-scheme host canonicalization would change a case-sensitive id; Node's
handling of a non-special scheme is different.

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

  A WHATWG `Request` may normalize literal or encoded dot segments before the
  handler sees them. The explicit guard also protects raw-string callers.
  The path-confinement test checks the requested gateway URL on both paths.

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

An implementation **SHOULD** configure gateways operated by more than one
organization. The reference list contains `arweave.net` and two ar.io nodes,
`permagate.io` and `ar-io.dev`.

An implementation **SHOULD** document its gateway-selection criterion and
review date. The reference module requires an independent operator answering
`/ar-io/info` and reachable on that date. Every configured gateway **MUST**
use `https:`.

A caller **MAY** pin one gateway (`{ gateway }`). When it does, there
**MUST** be no failover. The cross-gateway header request and dependent body
check are also skipped. An implementation **SHOULD** disclose those effects
where this option is offered.

### 6.2 When to move on — the normative rule

```
for each gateway in order:
    attempt the request (following at most one in-scope redirect, §6.3)
    if the host could not be REACHED and another gateway remains: continue
    if the response status is >= 500 and another gateway remains: continue
    otherwise: return this response as it came
if no gateway was ever reached: raise the last transport error
```

Only transport failures and 5xx responses trigger another gateway attempt.
An implementation **MUST NOT** retry a 4xx across gateways.

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

Requests use `redirect: 'manual'`. A gateway **MUST NOT** redirect an
`ar://` fetch to an arbitrary host.

A redirect is followed **only** when all of the following hold, and at most
**one** hop is taken:

1. the `Location` resolves to an `https:` URL,
2. on the **same gateway** as the one that answered — its own host, or a
   **subdomain** of it (`hostname.endsWith('.' + gateway)`, so a host that
   merely ends in the gateway's name is not one), and
3. whose first path segment is the **same identifier**.

Rule 2 permits the gateway's sandbox redirect to
`https://<label>.<gateway>/<txid>[/path]`. `sandboxLabel()` derives the label
as lowercase, unpadded base32: 52 characters for the 32-byte id. The redirect
check requires the original id in the first path segment; it does not validate
the label. When enabled, the header request follows the data fetch and uses
another configured gateway.

Anything else — another host, a subdomain of another host, another
transaction, a downgrade to `http:`, or a second redirect — is refused with
**502** and a body naming the gateway that tried it. The 502 **MUST NOT** carry a `Location`: handing the redirect back to
the renderer would restore the open redirect that `redirect: 'manual'` exists
to close. `location` is accordingly absent from the response safelist of §6.4.

This permits same-transaction redirects used for manifest index normalization.

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

The safelists carry conditional and range requests while excluding cookies
and other caller headers. `Range`, `Content-Range` and `Accept-Ranges` support
media seeking; `If-None-Match` and `ETag` support revalidation.

The handler adds `X-Arweave-Verified` to gateway responses: `bytes`,
`header` or `none` (§9). It is absent from locally generated refusals. The
gateway cannot supply this header because it is excluded from the safelist.

An implementation **MAY** choose a different safelist, but **MUST NOT** forward
caller-chosen headers wholesale, **MUST NOT** return `location` (§6.3), and
**MUST NOT** let a gateway supply the verification header itself.

### 6.5 Method

Only **GET** and **HEAD** are accepted. Other methods return **405** with
`Allow: GET, HEAD` before contacting a gateway.

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

The handler does not parse manifests. It forwards `ar://<txid>/<path>` to
`<gateway>/<txid>/<path>` and delegates the lookup to the gateway.

This delegation has three consequences:

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

For example, `<label>_persist.ar.io` is handled as follows:

1. `ar.io` ends in the ICANN top-level domain `io`.
2. `classifyHost` (`../../src/router.js`) therefore returns the `icann`
   namespace (`../../SPEC.md` §3, rule 2).
3. The name is resolved through **ordinary DNS**, fetched over **ordinary
   HTTPS**, and authenticated by an **ordinary CA-issued certificate** —
   exactly like any other website. The padlock model says
   *trusted-but-not-trustless* (`../../SPEC.md` §4), which is the truth.

ArNS uses `<undername>_<name>.<gateway-host>` for undernames. This handler
does not read ANT records or interpret that convention.

An implementation adding ArNS resolution **MUST NOT** treat an ArNS name as
the immutable identifier defined in this chapter. Its ANT record is mutable;
resolution requires rules for authenticating the mapping and selecting its
current value (AR-U3).

---

## 9. What is verified, and what is not

Identifier checks, header checks and content verification are separate steps.

### 9.1 What is checked

| Check | Result on failure |
|---|---|
| Canonical 43-character base64url id (§3.2) | 400 before contacting a gateway |
| Path segments contain no decoded separator or dot-segment (§4.3) | 400 |
| GET or HEAD method (§6.5) | 405 |
| Redirect stays within the gateway and original id (§6.3) | 502 without `Location` |
| Header signature bytes hash to the requested id (§9.1.1) | 502 when a returned header does not match |
| An eligible body matches the supplied `data_root` (§9.2) | 502 when a same-length body has a different root |

Header safelists constrain requests and responses (§6.4). HTTPS authenticates
the gateway host. Neither mechanism authenticates Arweave transaction data.

### 9.1.1 The header check

`headerMatchesId()` in `src/ar.js` computes:

```text
base64url(SHA-256(base64url-decode(header.signature))) == txid
```

This binds the supplied **signature bytes** to the requested identifier. It
does not verify that the signature signs the supplied `owner`, `tags`,
`data_size` or `data_root`. Those fields remain dependent on the gateway's
answer. [REVIEW.md](../../REVIEW.md) records this missing authentication step.

With `verifyHeader` enabled, the handler performs the check when the data
response is 200, the request has no manifest path, and at least two gateways
are configured:

1. Fetch `GET <other gateway>/tx/<txid>` from a gateway other than the one
   that served the data. The header **MUST** come from another gateway under
   this implementation's policy.
2. If a header is returned and its signature does not hash to the id, return
   **502**. Do not retry another gateway or fall through to another namespace.
3. If the other gateway is unreachable or does not return a header, skip the
   check and report `none`.
4. If the signature hash matches, continue to the conditional body check in
   §9.2. Report `header` unless that check also succeeds.

The library defaults `verifyHeader` to false; the browser enables it. An
implementation **SHOULD** enable the check, while reporting its limits. A
second gateway gives an independent response but does not replace signature
verification.

An implementation **MUST NOT** describe this check as authentication of the
header fields or the content.

### 9.2 What is NOT checked

**Current body check.** Since 2026-09-06, `src/ar.js` imports
`bytesMatchRoot()` from `src/ar-merkle.js`. After the signature-hash check
succeeds, it checks a response body when all of these hold:

- the header supplies `data_root`;
- the data response is 200 and the request has no `Range` header;
- `Number(header.data_size)` is finite, nonnegative and at most
  `MAX_VERIFY_BYTES` (**8 MiB**);
- the buffered body's length equals that declared `data_size`.

The Merkle calculation uses 256 KiB chunks, rebalancing the final two when
needed. A same-length body with a different root is refused with **502**. A
matching body is returned with `X-Arweave-Verified: bytes`.

**Skipped cases.** A different body length returns `header`, not a refusal.
This permits gateway-rendered bundle or manifest index pages whose size differs
from the transaction data. Paths, range requests, large declared transactions,
missing headers, and bundled items without a top-level `/tx/<id>` header do
not receive the body check. The handler buffers the response before comparing
its length; the declared-size threshold is not a streamed response-size limit.

**Meaning of the response header:**

| Value | What the handler established |
|---|---|
| `none` | No transaction-header check completed |
| `header` | The supplied signature bytes hash to the id |
| `bytes` | The signature hash matches and the body matches the supplied `data_root` |

The `bytes` value does **not** establish that `data_root` was signed by the
transaction owner. Full transaction authentication and chunk proofs are not
implemented. An implementation **MUST NOT** report a gateway response as
cryptographically verified against its requested Arweave id without that
binding. It **SHOULD** state the remaining gateway trust and **SHOULD** use
reduced privileges (§10).

The trust panel is constructed at resolution time, before these fetch checks.
It therefore keeps an `unverified` content step, a `partial` verdict and a
neutral TRUSTED lock. The response header reports the per-fetch result. An
implementation **MUST NOT** upgrade the panel, lock or verdict based solely
on the signature-hash check; it **MAY** report that check separately.

Arweave is excluded from `CONTENT_ADDRESSED` in `../../src/trust-path.js`.
For a Handshake `ar=` pointer, the neutral lock closes on the name's chain
proof without requiring a DANE pin because retrieval uses gateway HTTPS. The
choice of lock state remains open in AR-U5.

### 9.3 Why the shape check still buys something

Canonical identifier validation confines gateway requests to the id's URL
space and gives the id one accepted spelling. The intended object is immutable,
so independent responses concern the same object. A gateway can still return
different or changing bytes where the client does not detect them; identifier
immutability alone does not constrain an unverified response.

AR-1 documents the conditional body check. AR-D1 covers the remaining work:
authenticate the transaction header, verify larger data, and resolve bundled
items and manifests without trusting gateway mappings.

### 9.4 What the chain proof does establish

For a Handshake `ar=` record resolved through SPV, the name-to-identifier
binding is chain-proven and, on a signed zone, DNSSEC-validated to the on-chain
DS (`../../SPEC.md` §6). That binding is separate from the content checks
in §9.2.

DoH, `_op` and ENS have additional trusted steps (`../../SPEC.md` §7,
D-9 and D-10). The trust panel reports these in a separate `Pointer` step.

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

1. **The full id-to-content binding is not verified** (§9.2). A scheme whose content is
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

**11.1 A hostile gateway can substitute content.** The body check catches a
same-length mismatch against the supplied root, but other cases are skipped.
The root itself is not authenticated by a signature check. TLS and a second
gateway do not establish the full id-to-content binding (§9).

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

**11.4 Redirect confinement.** Section 6.3 permits one redirect within the
same gateway and transaction. Adding `location` to returned headers or raising
the hop limit would weaken that boundary.

**11.5 The failover rule is a fingerprint.** A gateway that returns a 5xx moves
the client to the next gateway in a fixed order. A gateway that wishes to learn
whether a client is this implementation can do so in one request.

**11.6 The privacy of `ar://` rests on an injected fetch.** §6.6: the scheme is
left reachable while anonymization is on because the composition layer supplies
a proxied fetch. The constructor's refusal to run without one is what turns
that from a convention into a guarantee, and an implementation that restores a
default **MUST** gate the scheme instead.

**11.7 A successful fetch has limited meaning.** A TLS-authenticated gateway
returned data for the requested id. `header` adds a signature-hash match;
`bytes` also adds a match against that header's supplied data root. Neither
authenticates the header's fields. Section 9 defines the exact checks.

**11.8 Header checks disclose the id to a second gateway.** With the check
enabled, two operators see each eligible transaction id. An implementation
**SHOULD** disclose that cost. The paired data and `/tx/<id>` requests can
also identify this client's request pattern.
