# Chapter 9 — Key-addressed namespaces (hyper, SSB, Gemini, BitTorrent)

> **Review pending:** [REVIEW.md](../../REVIEW.md) records unresolved questions
> about Private-mode origin handling and delegated verification. The rewrite does not change runtime behaviour.

**Version:** 0.1 (draft for public comment)
**Status:** Describes the behaviour of the Wildroot browser's `hyper://`,
`ssb://`, `gemini://`, `bittorrent://` / `bt://` and `magnet:` resolution, and
the code extracted into `src/` beside this file. Not endorsed by any standards
body. Normative statements describe what an implementation must do *to
interoperate with this one*; where a rule is inherited from an existing
standard, that standard is cited and its rule governs.
**Licence:** CC-BY-4.0 (`../../LICENSE-SPEC`). The reference implementation is
licensed separately.

The [routing specification](../../SPEC.md) defines namespace selection and
trust-state terms. This chapter covers Hypercore, SSB, Gemini and BitTorrent.
See [deviations](DEVIATIONS.md) (`KY-` entries) and
[references](REFERENCES.md) for limits and supporting sources.

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## Contents

1. [What this specifies](#k1-what-this-specifies)
2. [Terminology](#k2-terminology)
3. [Rules common to every key-addressed namespace](#k3-rules-common-to-every-key-addressed-namespace)
4. [`hyper://`](#k4-hyper)
5. [`ssb://`](#k5-ssb)
6. [`gemini://`](#k6-gemini)
7. [`bittorrent://`, `bt://` and `magnet:`](#k7-bittorrent-bt-and-magnet)
8. [Reaching these namespaces from a Handshake name](#k8-reaching-these-namespaces-from-a-handshake-name)
9. [Trust states](#k9-trust-states)
10. [`web+…` and other registered schemes](#k10-web-and-other-registered-schemes)
11. [Security considerations](#k11-security-considerations)

---

## K.1 What this specifies

The schemes in this chapter use public keys, content hashes or DNS names.
Gemini is the DNS-based exception (§K.6). Each section identifies the accepted
address forms and the checks performed by the handler or its dependencies.

This chapter specifies, for each such namespace the browser speaks:

- the **identifier syntax** it accepts, and what it rejects;
- the **validation** performed before anything is dialled;
- how the identifier is **turned into a reachable thing** — what is asked of
  what, and in which order;
- what is **verified by construction** (the key or the hash) and what is
  **trusted** (a DHT, a tracker, a DNS resolver, a certificate nobody checked);
- the **trust state** the namespace is entitled to expose.

Transport and retrieval are outside this chapter: piece selection, ranges,
streaming, rendering, caching and seeding policy. Browser documents
`docs/TORRENT-DESIGN.md`, `docs/BLOB-LAYER.md` and
`docs/STREAMING-TRANSCODE.md` cover those subjects. Retrieval checks that
affect a trust claim are identified here.

Hypercore uses `hyper-sdk` and `hypercore-fetch`; SSB uses `ssb-fetch`;
mutable BitTorrent uses `bt-fetch`. Their network and verification behaviour
is delegated to those engines. The extracted wrappers provide dispatch and
lifecycle handling. Inherited limits are recorded in [DEVIATIONS.md](DEVIATIONS.md).

The package contains additional address and handler logic for BitTorrent
(§K.7) and Gemini (§K.6), including origin-preserving redirect handling.

---

## K.2 Terminology

The spine's terminology applies. Additional terms:

- **Key-addressed** — the identifier is a public key. Content it names is
  authenticated by a signature under that key; the *content* may change while
  the address does not.
- **Content-addressed** — the identifier is a hash of the content. The content
  cannot change without the address changing.
- **Self-authenticating** — either of the above: the address alone is enough to
  decide whether received bytes are the right bytes. No third party is
  consulted.
- **Discovery** — finding a peer that has the object. Discovery is *not*
  resolution and is never authenticated: a DHT, a tracker or a swarm can
  refuse, stall or lie about who has what. It cannot make wrong bytes verify.
- **TOFU** (trust on first use) — pinning a peer's public key at the first
  connection and refusing a different one afterwards. TOFU has two halves:
  *accept the first* and *remember it*. A client that does only the first half
  is not doing TOFU (§K.6).
- **Engine** — the third-party library that owns a namespace's network layer.
- **Namespace** and the laws **L1** (an explicit scheme selects the protocol,
  always) and **L2** (a failure never crosses a namespace boundary) are as
  defined in the spine's namespace-selection chapter (`../../SPEC.md`) and in
  `docs/RESOLUTION-ROUTER.md` in the browser tree.

---

## K.3 Rules common to every key-addressed namespace

### K.3.1 The scheme table is the authority

`../../src/router.js` (byte-identical to the browser's
`src/protocols/router.js`) holds one row per scheme giving its namespace, its
maturity, and — the field that matters here — `verify`: the layer that
authenticates the canonical object. The router does not perform verification;
it names it, so that no scheme can be wired in without a verification story.
`ProtocolRouter.register()` **MUST** refuse a scheme with no row.

| Scheme | Namespace | `verify` as the table states it | What that means here |
|---|---|---|---|
| `gemini` | `gemini` | `none — TLS with no certificate verification (not TOFU: nothing is pinned)` | the row leads with `none` and names TOFU only to deny it (§K.6, D **KY-1**) |
| `hyper` | `hyper` | `hypercore key (a DNSLink name→key binding is resolver-trusted)` | the key verifies the log; the row carries the one hop inside it that a resolver is trusted for (§K.4, D **KY-4**) |
| `ssb` | `ssb` | `feed signature` | the feed id is the signing key |
| `bittorrent`, `bt` | `bittorrent` | `infohash` | exact for the 40-hex form; the 64-hex form is a *key*, and the trust panel distinguishes them (§K.7, §K.9) |
| `magnet` | `magnet` | `infohash` | `magnet:` verifies nothing itself — it redirects (§K.7.4) |

An implementation **MUST NOT** report a verification it does not perform. A
scheme that authenticates nothing says `none`; a scheme that authenticates the
object but reaches it through a hop somebody is trusted for names that hop in
the same string. The same strings are what the browser's trust UI is checked
against (§K.9), so a row that overclaims is a claim made to a user.

*(`tests/scheme-table.test.js`, "the verify strings are exactly what SPEC
quotes" and "no verify string CLAIMS a verification the code does not
perform".)*

### K.3.2 An explicit scheme is authoritative (L1)

A key-addressed namespace is reached **only** by an explicit scheme, a `magnet:`
link, or a Handshake pointer (§K.8). The bare-input classifier has no rule for
any key shape: a typed `c0ffee…` (40 hex), `dddd…` (64 hex) or a 52-character
z-base-32 string is a single label with a non-ICANN final label, so it
classifies as a **Handshake name**, exactly as `pinner` does.

An implementation **MAY** suggest a protocol for a bare key-shaped string
in the omnibox, but **MUST NOT** silently reclassify it.

*(`tests/scheme-table.test.js`, "a bare key is NOT classified into any
key-addressed namespace".)*

### K.3.3 A failure stays in its namespace (L2)

Dispatch is by scheme and nothing else. An unregistered scheme is a **501**
tagged `X-Resolution-Namespace: <namespace>`; a handler that throws is a **502**
with the same tag. Neither is re-dispatched anywhere. The tag exists so the
trust UI can show that the failure stayed inside the protocol that was named —
proof there was no fallback.

The one place this bites hardest is BitTorrent, which has two engines behind
one scheme (§K.7.2): an infohash the streaming engine cannot serve **MUST NOT**
be retried through the mutable-torrent engine. That would be a same-namespace
fallback, which is permitted by L2 but forbidden here for a different reason —
it would hide the selected engine's failure.

### K.3.4 Scheme privileges, and what canonicalisation does to a key

`hyper`, `ssb`, `gemini`, `bittorrent` and `bt` are registered with Chromium as
**standard** and **secure** schemes (`src/main.cjs`, `P2P_PRIVILEGES`): a real
tuple origin `<scheme>://<host>`, service workers, `fetch`, CORS, streaming.
`magnet` is registered **non-standard and non-secure**, which is correct — a
`magnet:` URI has no host and no authority, and it is never an origin because
it always redirects (§K.7.4).

Chromium standard-scheme registration lowercases hosts. The address forms
have these consequences:

| Namespace | The host is | Case-safe? |
|---|---|---|
| `hyper` | 64 hex, or 52 chars of z-base-32 | yes — hex is matched case-insensitively and lowercased; the z-base-32 alphabet has no upper case |
| `bittorrent`/`bt` | 40 or 64 hex (or a petname, §K.7.3) | yes — hex as above; a petname is matched case-sensitively by the engine, so lowercasing changes which local key it derives — a defect of petnames, not of the scheme |
| `ssb` | the URI *type* (`feed`, `message`, `blob`) | yes — already lower case; the base64url key is in the **path**, which keeps its case |
| `gemini` | a DNS host name | yes — DNS is case-insensitive (RFC 4343) |

Compare `ar://`, which is registered low-privilege precisely because Arweave
transaction ids are case-sensitive base64url and would collapse into one
origin. An implementation adding a case-sensitive key namespace **MUST** check
this before making its scheme standard.

The one form that does **not** survive canonicalisation is the legacy SSB sigil
(§K.5.3). It is not supported, and this is why.

### K.3.5 Engines start lazily, once, and fail as themselves

Each namespace's handler is a closure that constructs its engine on the first
request and caches it (`src/fetch-to-handler.js`, extracted byte-identical).
Concurrent first requests share one construction. An engine that will not start
produces a **500 carrying the engine's own message**, in that scheme's
namespace, and is retried on the next request rather than latched as dead.

For example, a missing `libatomic.so.1` dependency of `rocksdb-native` can
surface as `Cannot find addon '.'`. The browser's
`src/protocols/native-addon-check.js` reports the underlying library error.
An implementation **SHOULD** expose the dynamic-loader error rather than only
the wrapper's generic message.

*(`tests/engine-lifecycle.test.js`.)*

### K.3.6 Private mode: route it or refuse it

Every namespace in this chapter opens its own transport: BitTorrent and
hyperswarm dial peers directly, SSB dials its own multiserver addresses, and a
Gemini request is a raw TLS socket opened from the main process. None of them
rides Electron's `session.setProxy`, so the browser's one privacy control —
**Settings › Content delivery › Mode: Fast / Private** — reaches them only
through the rule below. The control's policy table is `policyFor()` in
`../../src/delivery-mode.js`; the row for this chapter is `p2pDiscovery`,
`allowed` in Fast and `refused` in Private, and it is row 19 of the
repository's `../../DIVERGENCE.md`.

> **The rule.** An implementation that offers a private mode **MUST** either
> route a namespace through it or refuse the namespace. Leaking is not a third
> option.

The three peer-to-peer namespaces are **refused**. In Private mode, `hyper://`,
`ssb://` and `bittorrent://` / `bt://` answer **503** `text/plain` and
**nothing underneath runs** — the gate answers before the engine is even
considered (`createNonProxiedGate` in `src/gate.js`, extracted byte-identical).
The page is built by `privateRefusal('p2p', { label })` from
`../../src/delivery-mode.js`, so it says what every Private-mode refusal in
this repository says — the mode, the reason, what was not done, and where the
switch is:

> **BitTorrent is refused in Private mode**
>
> BitTorrent serves its content over a peer-to-peer network, whose peers learn
> the address of whoever asks; that path cannot be routed through the private
> connection, so nothing was asked. Switch to Fast in Settings › Content
> delivery to load it directly.

The current swarm transports are not routed through SOCKS. The gate reads
the mode on each request, so switching to Fast takes effect without restart.

**A named site is not refused.** The refusal is for *discovery* — asking
strangers where content is. A Handshake name whose zone also states an
**origin** for its content loads from that origin in Private mode over the
proxied fetch (Chapter 3 §8; row 9 of the inventory), and the refusal page the
Handshake handler builds for a named peer-to-peer site says so in its own
words — *"A name that also publishes a stated origin for its content loads from
that origin in Private mode"*, the `host` form of the same `privateRefusal`.
For a named site the private answer is a stated origin, not a mode; §K.8 is
where a name reaches these namespaces, and this is the second half of what it
inherits.

`gemini://` uses Tor in Private mode. Its single TCP connection can be
carried by SOCKS5; if no local Tor port is available, the handler refuses the
request (§K.6.2).

503 specifically in both cases, never an invented status: a protocol handler's
status goes straight into Chromium's `net::GetHttpReasonPhrase()`, which
`NOTREACHED`s on a code it does not know.

The mode is a policy about the route and decides nothing about trust: a
`hyper://` page that is `verified` in Fast mode is `verified` in Private mode
or is not served at all, and the trust table of §K.9 does not read the mode.

*(`tests/engine-lifecycle.test.js`, "Private mode refuses the whole namespace
with a 503 — nothing underneath runs"; `tests/gemini-protocol.test.js`, "with
IP Protection on, the capsule is reached through the Tor SOCKS port by name —
or refused when there is none".)*

---

## K.4 `hyper://`

The Hypercore append-only log, and Hyperdrive on top of it. Engine:
`hyper-sdk` 6 and `hypercore-fetch` 10. Wildroot's module
(`src/protocols/hyper-protocol.js`) is thirty lines: construct the SDK, build a
writable fetch, translate an addon failure into a sentence.

### K.4.1 Identifier syntax

```
hyper://<key>/<path>            key form
hyper://<dns-name>/<path>       DNSLink form
hyper://localhost/<path>        the device's own default drive (reserved)
```

`<key>` is a 32-byte Ed25519 public key written either as

- **52 characters of z-base-32** — the form `hyper-sdk` builds `drive.url`
  from, alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`; or
- **64 hexadecimal characters** — the same 32 bytes.

Validation is by length first: 52 → z-base-32 decode, 64 → hex decode, and a
decode failure means "not a key". A `hyper://` host that is neither a key nor a
name containing a dot is **rejected** — `URLs must have either an encoded key
or a valid DNSlink domain`. There is no petname form (contrast §K.7.3).

### K.4.2 The DNSLink form, and what it costs

A host containing a `.` is treated as a DNS name and resolved:

1. query `TXT _dnslink.<host>`
2. over **DoH-JSON**, at `https://mozilla.cloudflare-dns.com/dns-query`
3. take the first answer whose value begins `dnslink=/hyper/`
4. the remainder is the key; decode it as in §K.4.1

The answer is cached in memory and in a RocksDB store; when the DoH request
fails, the cache answers.

The DNSLink route has three relevant properties:

- **The resolver is the engine's default and is not ours.** `hyperOptions` in
  `src/config.js` sets only `storage`, so `hyper-sdk`'s default resolver
  applies. Every `hyper://<name>/` navigation therefore tells one public
  resolver which hypercore name is being visited, over a path that is neither
  the browser's DoH policy nor its Oblivious DoH (D **KY-4**).
- **There is no DNSSEC.** The name→key binding is the resolver's word. This is
  exactly the shape of gap the `ens://` row of the trust panel spells out in
  two steps, and a dotted `hyper://` host is given the same two steps (§K.9).
- **A failure falls back to a cache**, so a stale key can outlive a rotation.

An implementation **SHOULD** route this lookup through whatever DNS privacy
path the rest of the browser uses, and **MUST NOT** report a DNSLink-resolved
address with the same trust state as a key address.

### K.4.3 `hyper://localhost/`

`localhost` is reserved by `hypercore-fetch` for the device's own drive, the
one named `default`. `GET hyper://localhost/` answers with that drive's
`hyper://<key>/` URL; `GET hyper://localhost/<path>` serves its files. Because
the browser constructs the fetch with `writable: true`, the write routes
(`POST`/`PUT`/`DELETE`) are live as well.

This is a *local* name in a namespace that otherwise has none, and it names a
stable per-device identifier. See D **KY-9**.

### K.4.4 What is verified, and what is trusted

| | |
|---|---|
| **Verified by construction** | The key is the public key the log is signed under. Hypercore authenticates every block against a signed Merkle tree root, so bytes served under a key address cannot be forged by a peer. Wildroot does **not** perform this check itself — `hypercore` does, and we rely on it (D **KY-7**). |
| **Trusted** | Peer discovery through hyperswarm's DHT: it can withhold a peer, delay, or partition. It cannot forge a block. |
| **Trusted** | On the DNSLink form only: the name→key binding, on one public DoH resolver's word, with no DNSSEC. The trust panel states it as its own step (§K.9). |
| **Not established** | Freshness. A hypercore is append-only and versioned; being served version *n* does not prove *n* is the latest. Nothing in this browser attempts a proof of latest-ness. |

---

## K.5 `ssb://`

Secure Scuttlebutt. Engine: `ssb-fetch` 1.5, over `ssb-uri2` and `ssb-ref`.
Wildroot's module (`src/protocols/ssb-protocol.js`) is **ten lines** and
performs no parsing or validation of its own; `ssbOptions` is `{}`, so the
engine starts an sbot from `ssb-config` defaults.

### K.5.1 Identifier syntax

The SSB URI specification's canonical form:

```
ssb:<type>/<format>/<base64url-data>[/<base64url-extra>]
```

Wildroot uses `ssb://…`; `ssb-fetch` converts it to `ssb:` before parsing.
The URI type occupies the host and the case-sensitive key stays in the path
(§K.3.4).

`ssb-uri2` validates the type/format pair and rejects anything else:

| type | accepted formats |
|---|---|
| `feed` | `ed25519`, `bendybutt-v1`, `gabbygrove-v1`, `buttwoo-v1` |
| `message` | `sha256`, `bendybutt-v1`, `gabbygrove-v1`, `buttwoo-v1` |
| `blob` | `sha256` |
| `address` | `multiserver` |
| `encryption-key` | `box2-dm-dh` |
| `identity` | `po-box`, `fusion` |

`ssb-fetch` **serves** only `feed`, `message` and `blob`. Every other valid
type parses and then answers **418** — a recognised address that is not
implemented, which is the correct in-namespace fail-closed shape (L2), though
418 is a poor way to say it (`../../DEVIATIONS.md` §3, **KY-D5**).

The data is base64url and is converted back to standard base64 (`-`→`+`,
`_`→`/`) before being handed to the sbot as a sigil.

### K.5.2 What is verified, and what is trusted

| | |
|---|---|
| **Verified by construction** | A `feed` id is an Ed25519 public key: every message in the feed is signed by it and hash-chained to its predecessor, so a feed's history cannot be forged or reordered. A `message` id is the hash of the message; a `blob` id is the SHA-256 of the blob — content-addressed outright. |
| **Trusted** | The local sbot's replication: which peers it has talked to and how far it has replicated each feed. |
| **Not established** | **Completeness and freshness.** Being shown message *n* of a feed does not prove there is no *n+1*. An eclipse — a peer that simply stops relaying a feed's later messages — is invisible, and this is a known, structural property of SSB, not a defect in this client. |

### K.5.3 What is not supported

The **legacy sigil form** — `@<base64>.ed25519`, `%<base64>.sha256`,
`&<base64>.sha256` — is not accepted. `ssb-fetch` exports a converter
(`convertLegacySSB`, `looksLikeLegacySSB`) and Wildroot never calls it. It also
could not work as a URL host: `@` is the userinfo delimiter, and Chromium would
lowercase what remains, destroying a case-sensitive base64 key (§K.3.4).

An implementation that wants to accept pasted sigils **MUST** convert them to
the URI form *before* they reach a URL parser.

---

## K.6 `gemini://`

Gemini uses DNS names and TLS. It is included here because its TOFU model
can bind a host to a previously observed certificate key. This implementation
does not yet store or compare that key (§K.6.2).

`src/gemini-protocol.js` is extracted from the browser's
`src/protocols/gemini-protocol.js` and uses `@derhuerst/gemini`.
The wrapper controls redirects so that cross-host responses do not retain the
original host's origin (§K.6.3).

### K.6.1 Identifier syntax and lookup

An ordinary RFC 3986 hierarchical URI: `gemini://host[:port]/path[?query]`,
default port **1965**. There is no identifier validation of our own.

The host is a DNS name, and **who resolves it depends on the mode**:

| Mode | Who resolves the host | Consequence |
|---|---|---|
| Fast | Node's `tls.connect()`, i.e. the operating system's resolver | the lookup uses operating-system settings, outside the browser's DoH, ODoH and Handshake policies (KY-8) |
| Private | the device-local Tor, from the name itself | no local lookup happens at all: the socket is dialled through SOCKS5 with the host as `ATYP` domain (§K.6.2), so the operating system's resolver is never asked |

A Gemini host that is a Handshake name does not resolve on either route: nothing
here consults the Handshake resolver, and Tor will not either.

### K.6.2 The connection, and the trust that is not there

```
minVersion   TLSv1.2                       (the Gemini specification's floor)
ALPN         "gemini"                      — offered; the check is overridden to pass
SNI          the requested hostname
tlsOpt       { rejectUnauthorized: false }
             + { socket, servername }      in Private mode
```

**The socket, in Private mode.** The handler takes `isAnonymized` and
`torSocks` — the anonymizer's `isOn()` and `torSocks()`, the second of which is
the device-local Tor's `socks5://` URL while traffic is routed through it and
`null` otherwise. In Private mode it opens the TCP connection itself, through
that SOCKS5 port (RFC 1928, `socksDialer`, `../../src/socks-dial.js`), and
hands the connected socket to the TLS client as `tlsOpt.socket` with
`tlsOpt.servername` set to the hostname. Three properties follow, and an
implementation that routes this scheme through a proxy **MUST** hold all three:

1. **The dial is by NAME** — the host goes to the proxy as RFC 1928 `ATYP`
   `0x03` (`DOMAINNAME`) and is resolved inside Tor — so the operating system's
   resolver is never asked in Private mode (§K.6.1). This is the same
   mechanism RFC 7686 requires for `.onion` (Chapter 8 §6.4), applied here for
   privacy rather than for correctness.
2. **`servername` is set explicitly.** TLS runs over a socket the client did not
   open, so SNI cannot be inferred from a hostname the client resolved; it
   **MUST** be passed, or the capsule is asked for the wrong virtual host and any
   future certificate pin (KY-D1) would be keyed to nothing.
3. **No Tor port is a refusal, not a fallback.** In Private mode with no SOCKS
   port available — the anonymizer has blocked because no Tor client can be
   had — the request answers **503** and no socket is opened. The sentence it
   carries is the shared `privateRefusal('site', { host })` wording every other
   Private-mode refusal uses: the capsule's name, "is not loaded in Private
   mode", nothing was sent, and the pointer at Settings › Content delivery.
   Falling back to a direct dial would leak the address the mode exists to
   hide, which is the rule of §K.3.6.

Private mode changes the connection's route and visible client address.
It does not authenticate the Gemini server.

The Gemini specification's whole security model is TOFU: a client remembers the
certificate (or its public key) it saw for a host and refuses a different one
later, because Gemini servers are expected to use self-signed certificates and
there is no CA to consult.

The handler accepts every certificate on every connection. It has no
certificate store, saved fingerprint or comparison with a previous visit.
The connection is encrypted but unauthenticated.

The handler, scheme table and trust panel report this lack of certificate
verification. KY-1 records the gap; KY-D1 proposes a persistent store.

There is consequently no Gemini identity: no client certificates, and no
transient-certificate sessions. The underlying library carries a
client-certificate store and the hooks for one; they are not enabled.

An implementation **MUST NOT** describe this connection as TOFU in metadata,
documentation or the interface. TOFU requires storing the first certificate
or key and checking subsequent connections against it.

### K.6.3 Redirects, which are decided here

A Gemini `30` (temporary) or `31` (permanent) response carries its target in
the `<META>` line. What happens next is decided by this handler, not by the
client library:

| Target | What happens |
|---|---|
| the **same** host, port and scheme | followed inside the request, at most `MAX_REDIRECTS` = **5** times |
| another **`gemini:`** host or port | **not** followed: returned to the browser as a real 30x navigation (`31` → 301, `30` → 302) with a `gemini:` `Location` |
| anything that is not `gemini:` | refused, **502**, naming the target that was not followed |

`sameHostGeminiRedirect(from, meta)` is the predicate, exported so it can be
tested on its own. It resolves the target against the request URL (so a
relative target stays on the host), compares the scheme, compares hosts
case-insensitively (DNS is case-insensitive, §K.3.4) and compares ports with
1965 as the default on both sides. Past the fifth hop the predicate stops
returning true, so the redirect is **returned** rather than followed — a loop
ends as a 302 the browser can show, not as a spinning client.

Three rules an implementation **MUST** keep:

1. **A redirect that moves the origin MUST move the address bar.** `gemini:`
   is a standard, secure scheme, so `gemini://A` is a real tuple origin with
   `localStorage` and service-worker capability. Serving host *B*'s bytes under
   it — which is what following a cross-host redirect transparently does —
   gives *B* write access to *A*'s storage. A browser that cannot change the
   address to match the content it is showing **MUST NOT** follow the redirect.
2. **A bound, and the bound is the client's.** Following is capped at five;
   the cap is the Gemini specification's own guidance.
3. **A redirect out of the namespace is refused, not followed** (L2, §K.3.3).
   A capsule cannot use a redirect to make the browser's main process issue an
   `https://` request.

*(`tests/gemini-protocol.test.js`, with the client injected via
`createHandler({ requestImpl })` so nothing opens a socket.)*

### K.6.4 Input, status and body

A `10`/`11` status is an **input request**: the handler renders a small HTML
form, escaping the server-supplied prompt, and `11` (sensitive input) renders a
password field. Submitting the form `POST`s back to the same URL, and the
handler answers **302** to that URL with the answer as its **query string**,
which is how Gemini carries input. Any method other than `GET`, `HEAD` and that
`POST` is **405**.

A Gemini status is two digits and becomes an HTTP status by multiplying by ten
— `20` → 200, `51` → 510 — passed through `safeStatus()`
(`../../src/safe-status.js`), which answers **502** for any product Chromium
does not define (`62` → 620 → 502). A handler's status goes straight into
`net::GetHttpReasonPhrase()`, which `NOTREACHED`s on a code Chromium does not
know, so an unmapped status **MUST NOT** be passed on. A `2x` body is streamed
with the `<META>` line as its `Content-Type`; any other status is served as
`text/plain` with the `<META>` line as the body — a failure explains itself in
the words the capsule chose.

### K.6.5 What is verified, and what is trusted

| | |
|---|---|
| **Verified by construction** | Nothing. |
| **Trusted** | The name→address answer — the operating system's resolver in Fast mode, the device-local Tor in Private mode (§K.6.1) — and the TLS peer (any certificate, remembered nowhere). |
| **Bounded rather than trusted** | Redirects: same-host only, five at most, and any other target is handed back to the browser as a navigation or refused (§K.6.3). |
| **Trust state** | `partial` / TRUSTED — encrypted, unauthenticated (§K.9). |

---

## K.7 `bittorrent://`, `bt://` and `magnet:`

`bittorrent` and `bt` share a namespace with two engines selected by key shape.

### K.7.1 Identifier syntax

```
bittorrent://<key>/<path>          bt:// is an exact synonym
magnet:?xt=urn:btih:<40 hex>[&dn=<name>][&…]
magnet:?xs=urn:btpk:<64 hex>[&…]
```

Two key shapes, defined **once**, in `src/magnet-protocol.js`, and imported by
everything that needs them — the magnet handler, the `bittorrent://`
dispatcher, and the torrents page's input parser. There is exactly one
definition of "infohash" for the whole scheme, and a test asserts that the
dispatcher does not fork its own:

```js
export const INFO_HASH_MATCH = /^urn:btih:([a-f0-9]{40})$/i
export const PUBLIC_KEY_MATCH = /^urn:btpk:([a-f0-9]{64})$/i
```

The regexes omit `g` because validators must not retain `lastIndex` between
calls. A regular expression used as a validator **MUST NOT** be global.

- **40 hex** — a BEP-3 v1 infohash: the SHA-1 of the bencoded `info`
  dictionary. Immutable: the address is the content.
- **64 hex** — a BEP-46 `btpk`: an Ed25519 public key whose DHT mutable item
  points at a changing infohash. The address is a key; the content may change
  under it.

Only the **hex** infohash form is accepted. BEP-9 also permits a 32-character
base32 infohash in a magnet; it is refused (D **KY-2**). BitTorrent v2
(`urn:btmh:`, BEP-52) is not served (D **KY-3**).

Unsupported v2 and base32 magnets receive errors naming the unsupported
form. "Magnet has no bittorrent infohash" is reserved for other invalid
values. An implementation **SHOULD** name a recognized form it cannot use.

### K.7.2 Dispatch, and the boundary inside the namespace

`bittorrent://<key>/…` is split on the key's **shape**, not on any lookup:

```
40 hex  →  the streaming engine (a supervised rqbit sidecar)
anything else  →  the mutable/petname engine (bt-fetch)
```

Dispatch is selected before retrieval. A streaming-engine failure returns
502 with `X-Resolution-Namespace: bittorrent` and is never retried through
the mutable engine.

`src/torrent-address.js` carries this decision (`infohashOf`) with the engine
removed.

**The ambiguity to know about.** A BitTorrent v2 infohash is SHA-256 — 32
bytes, 64 hex characters — which is byte-for-byte the shape of a BEP-46 public
key. In the URL form there is no URN to tell them apart, so a v2 address would
be read as a mutable key and handed to the wrong engine. Nothing downstream
speaks v2, so this is a failure rather than a mis-resolution, but the URL form
has no room to fix it in: D **KY-3**.

### K.7.3 The petname form, which is not ours

`bt-fetch` treats a `bittorrent://` host that matches `/^[-A-Za-z0-9_]+$/` and
is not a key as a **petname**: it derives a keypair from it locally and resolves
that. `bittorrent://mysite/` is therefore a *device-local* address with no
meaning on any other machine, reachable from any page, in a namespace whose
whole promise is that the address is the object. `bittorrent://localhost/` is
separately reserved by the same library as a meta endpoint.

Wildroot neither uses nor documents petnames; they are reachable because the
dispatcher passes everything that is not a 40-hex infohash through
(§K.7.2). See D **KY-9**, and `../../DEVIATIONS.md` §3 **KY-D4** for the
refusal that would close it.

### K.7.4 `magnet:` — a redirect, not a resolution

The `magnet:` handler resolves nothing and fetches nothing. It reads the URI's
parameters and answers a **308** into `bittorrent://`:

```
xs=urn:btpk:<64 hex>     →  308  bittorrent://<pubkey>        (checked FIRST)
xt=urn:btih:<40 hex>     →  308  bittorrent://<infohash>/
an xt this browser
  recognises and cannot
  use (urn:btmh, base32) →  400, naming that form (§K.7.1)
any other xt             →  400, "Magnet has no bittorrent infohash"
no xt and no xs          →  400, naming the missing parameter
```

Every refusal is in-namespace and carries no `Location`.

`xs` is tested before `xt`, wherever in the query string each sits. For a
BEP-46 magnet that is right — the mutable key is the address, and the infohash
it currently points at is incidental.

Two rules make that precedence stable, and both are pinned by tests:

- **Every parameter of a kind is read, not the first.** A **hybrid v1+v2
  magnet** carries two `xt` parameters — `urn:btih:` and `urn:btmh:` — in
  whichever order its publisher wrote them, so `searchParams.getAll('xt')` is
  scanned for the first that is a v1 infohash. One magnet has one meaning; a
  publisher's parameter order is not part of the address. The same applies to
  `xs`.
- **The two readers of a magnet agree.** The handler above and the navigation
  rewrite below apply the same precedence: when any `xs` carries a BEP-46 key,
  the rewrite declines the magnet (returns `null`) rather than offering its
  incidental infohash as a torrent to add. An implementation with more than one
  reader of an identifier **MUST** give them one precedence; otherwise the same
  string means different things depending on how the user arrived at it.

### K.7.5 Consent: a clicked magnet adds nothing

Following the redirect directly would start peer traffic because the torrent
handler adds the infohash before streaming.

`magnetToTorrentsPage()` rewrites an infohash magnet to
`wildroot://torrents?add=<hash>[&dn=<name>]`. That page asks the user to add
the torrent before starting it. The optional name is truncated to 200
characters and percent-encoded, so the prompt can identify the link without
fetching metadata.

An implementation **MUST NOT** begin peer traffic for a magnet the user merely
followed a link to. The rewrite **MUST** be applied at every navigation entry
point; one gap is a bypass.

Only the infohash form is rewritten: a `urn:btpk:` magnet is an address to be
browsed, not a torrent to be managed — and that holds whether or not the same
magnet also carries an `xt`, because the handler gives the mutable key
precedence and the two readers must agree (§K.7.4).

### K.7.6 Human input

`src/torrent-input.js` is the one place a typed or pasted string becomes an
address. It accepts a magnet, a bare 40-hex infohash, or a `bittorrent://` /
`bt://` URL, and normalises all of them to a single canonical magnet. Ambiguity
is refused **by name**, never guessed: a 64-hex mutable key is told to be opened
as an address rather than silently handed to an engine that cannot serve it.

A dropped `.torrent` file is checked for shape only — non-empty, under 10 MiB,
and starting with `0x64` (`d`, a bencode dictionary). Nothing verifies that its
`info` dictionary hashes to any particular infohash; the engine does that when
it adds the torrent (D **KY-6**).

### K.7.7 Path → file

A torrent is a *set* of files, so the URL path has to name one.
`resolveFileIndex()` behaves like a web server, in this order:

1. a single-file torrent streams its one file whatever the path;
2. a **directory** (the root, or any path ending `/`) resolves to `index.html`
   / `index.htm` inside it — so a torrent-hosted site renders instead of
   listing its own source;
3. an exact torrent-relative path;
4. a directory named without its trailing slash → that directory's index;
5. an unambiguous basename;
6. otherwise **null** — and the caller **MUST** say so rather than guess. Two
   files with the same basename is not a match.

A torrent whose payload is wrapped in a single top-level folder — the normal
shape — is answered with a **308 into that folder** rather than by serving the
nested index at the root, where every relative link in it would break.

### K.7.8 What is verified, and what is trusted

| | |
|---|---|
| **Verified by construction (40 hex)** | The infohash is the SHA-1 of the `info` dictionary, and every piece is checked against the piece hashes in it as it arrives. Content-addressed outright: no peer can serve wrong bytes under a right infohash. The check is the engine's, not ours. |
| **Verified by construction (64 hex)** | The BEP-46 DHT mutable item is signed under that public key, so which infohash the address currently points at is authenticated. What it points *at* is then content-addressed as above. |
| **Trusted** | **Discovery**: the DHT (BEP-5), trackers, and PEX. All of them can withhold, stall or return nothing. None can make wrong bytes verify. |
| **Not established** | **Freshness of a mutable address.** BEP-46 items carry a sequence number, and a DHT node can answer with an older one it still holds. Nothing here pins a highest-seen sequence number. |
| **Not established** | That a peer set is not adversarial in the privacy sense: joining a swarm publishes your address to everyone in it. Local Service Discovery (BEP-14) is disabled for exactly this reason — it multicasts every infohash being fetched to the whole LAN. |

---

## K.8 Reaching these namespaces from a Handshake name

A Handshake name can point at a torrent or a hypercore drive exactly as it
points at a CID. The pointer grammar is `../../src/pointers.js` in this
package (specified in the spine's Handshake chapter):

```
bt=<40 hex | 64 hex>      infohash (immutable) or BEP-46 public key
hyper=<52 z32 | 64 hex>   hypercore drive key
```

Precedence is `ipfs` → `ipns` → `bt` → `hyper` → `ar`, from the shared
pointer table.

Three properties an implementation **MUST** preserve:

1. **The pointer is served through the same handler a typed address is.** A
   name-hosted torrent inherits every rule in §K.7 — the same dispatch, the
   same Private-mode gate (§K.3.6) and the same way past it, a stated origin
   for the content, the same in-namespace failure.
2. **A malformed pointer is not a pointer.** A `bt=` whose value is neither 40
   nor 64 hex parses to `null` rather than to a half-trusted address.
3. **The trust states compose, weakest link wins.** The Handshake side proves
   *which* address the name names; the key or hash proves the bytes. A name
   resolved over the DoH fallback rather than the chain does not become trusted
   because the content it points at is content-addressed — it names a different
   address than the chain would have.

`../../src/pointers.js` defines the two BitTorrent key shapes a **second** time
(`BT_INFOHASH_RE`, `BT_PUBKEY_RE`, as bare hex rather than the URN forms)
rather than deriving them from the canonical pair in `magnet-protocol.js`. They
agree. See `../../DEVIATIONS.md` §3, **KY-D6**.

---

## K.9 Trust states

`schemeSteps()` in `../../src/trust-path.js` supplies the following trust
steps. The routing specification defines their aggregation into a verdict and
lock state.

| Address | Steps | Verdict, and the lock |
|---|---|---|
| `hyper://<key>/` | **Content, verified** — "Key-addressed: every block is checked against the signature of the key in the address. That proves who wrote it, not that you were shown the newest version." | `verified` — TRUSTLESS |
| `hyper://<dotted host>/` | **Name records, unverified** — "read from a public DNS resolver and taken on its word — no DNSSEC, no chain proof"; then **Content, verified** — "Whatever key the record named, every block is checked against that key's signatures." | `partial` — TRUSTED |
| `ssb://feed/…` | **Content, verified** — "every message is checked against the feed key's signature. That proves who wrote it, not that the feed is complete." | `verified` — TRUSTLESS |
| `bt://<40 hex>/`, `bittorrent://<40 hex>/` | **Content, verified** — "Content-addressed: every piece is checked against the infohash, so the bytes cannot have been altered." | `verified` — TRUSTLESS |
| `bittorrent://<64 hex>/` | **Content, verified** — "Key-addressed (BEP 46): the pointer is signed by the key in the address and the pieces are hash-checked. The key proves who published it, not that this is the newest version." | `verified` — TRUSTLESS |
| `gemini://host/` | **Connection, unverified** — "Gemini over TLS, certificate not verified … neither checked against an authority nor remembered from a previous visit, so nothing establishes who answered." | `partial` — TRUSTED |
| `magnet:…` | **Address, none** — "A magnet link is only a pointer to a torrent; nothing loads until it is added." | `partial` — TRUSTED |

The reference model reserves OPEN for a `Connection` step of `none`.
Gemini's encrypted but unauthenticated connection is `unverified`, producing
`partial` / TRUSTED. The browser's `tests/hns/lock-semantics.test.js` checks
the panel against the scheme table.

Five properties of that table are normative for this chapter.

- **A verdict is about the property the address carries, and no more.** A key
  or hash address is reported verified for *integrity of the bytes*, and each
  step says in its own words what it does **not** establish: freshness for a
  key, completeness for a feed. An implementation **MUST NOT** let "verified"
  imply either.
- **A key reached through a name is not a key that was typed.** A dotted
  `hyper://` host is two steps — the mapping **unverified**, the content
  **verified** — the same shape the `ens://` and HIP-5 `_op` rows use for the
  same gap. The lock still closes, because the bytes really are key-verified,
  but the verdict **MUST** be `partial` and never `verified`. An implementation
  **MUST NOT** report a resolved address as though its key had been typed.
- **The verdict is not changed by the route the socket took.** `gemini://`
  reaches its capsule through the device-local Tor in Private mode (§K.6.2) and
  directly in Fast mode, and both produce exactly the steps in the table
  above. Tor changes who sees the address, not who authenticated the
  answer, and an implementation **MUST NOT** score a step differently because
  the connection was anonymized.
- **The two BitTorrent spellings are one namespace and say one thing**, and the
  two key *shapes* inside it do not: a 40-hex infohash fixes the bytes forever;
  a 64-hex BEP-46 key authenticates a pointer that changes.
- **A scheme with no verification path says so in its own words.** `gemini://`
  has its own case saying the connection is encrypted and unauthenticated,
  rather than borrowing the default. Reaching the right verdict by having no
  case is indistinguishable from a bug, and it makes the default mean two
  things at once.

*(`tests/trust-state.test.js` pins every row above, and asserts that no address
in this chapter reaches the default sentence while a scheme with no case still
does.)*

---

## K.10 `web+…` and other registered schemes

The scheme table contains no `web+…` handlers.

`namespaceForScheme('web+…')` returns `null`, and
`ProtocolRouter.register()` rejects schemes without table rows. A `web+…`
URL therefore returns 501 tagged with its own scheme and is not reclassified.

The browser also does not call `navigator.registerProtocolHandler`, so no page
can add one.

`web+…` is a custom-handler mechanism, not a namespace defined by this
specification.

*(`tests/scheme-table.test.js`, "no `web+…` scheme is registered".)*

---

## K.11 Security considerations

Integrity checks for key- and content-addressed forms do not establish
availability, freshness or privacy. Gemini has no server authentication
(§K.6.2). The remaining risks are:

1. **Withholding.** A DHT, a swarm, a tracker or a set of SSB peers can simply
   not answer. Every namespace here fails open in the availability sense and
   closed in the integrity sense, which is the right way round, but "not found"
   is never proof of absence.
2. **Staleness.** Three of these namespaces are *key*-addressed, meaning the
   content under the address changes: a hypercore version, a BEP-46 sequence
   number, an SSB feed's tip. None of them is pinned here. An attacker who can
   control which peers you reach can serve you a real, signed, **old** answer
   indefinitely, and nothing in this browser would notice.
3. **The name hop.** Two of these namespaces reach a key through a *name* —
   `hyper://` via DNSLink, `gemini://` via ordinary DNS — and in both cases the
   answer carries no signature, so that hop is the whole security of the address
   for those forms. It is also resolved outside every DNS protection the rest of
   the browser applies: always for `hyper://` (D **KY-4**), and for `gemini://`
   in Fast mode, which is when the operating system's resolver answers (D
   **KY-8**). In Private mode the Gemini name is resolved inside Tor instead —
   which removes the disclosure and adds no signature.
4. **Metadata.** Joining a swarm publishes your address to it. This is why
   Private mode (§K.3.6) refuses the three peer-to-peer namespaces outright
   rather than pretending to proxy them, why Local Service Discovery is
   off, and why BitTorrent is deliberately never wired to the bundled Tor: UDP
   DHT and uTP cannot ride a SOCKS circuit, and the handshakes leak the real
   address anyway. `gemini://` is the exception because its transport is one TCP
   connection to one host, which a SOCKS circuit carries exactly — so it is
   routed through Tor rather than refused. Routing it buys the address and the
   lookup, and nothing else: every Gemini connection in the session shares the
   same circuits, because no SOCKS credential is sent (Chapter 8, TO-3).

Scheme privileges also affect isolation. Standard, secure schemes receive
persistent origins, storage and service-worker support. A key-addressed
origin follows its key; Gemini's origin follows a DNS host whose certificate
is not authenticated. The Gemini redirect rules keep cross-host responses
from being served under the original origin (§K.6.3).
