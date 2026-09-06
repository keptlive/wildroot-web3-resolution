# Chapter 9 — Key-addressed namespaces (hyper, SSB, Gemini, BitTorrent): deviations and open questions

Every place this chapter's implementation departs from a standard it cites,
from common practice in the namespace, or from its own stated design — plus
every place we are not sure we have made the right call.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

A note that colours all of it: **three of the five namespaces here are ten to
thirty lines of Wildroot code in front of a third-party engine.** Part of what
follows is therefore a deviation *inherited* rather than chosen. That is not an
excuse — we ship it, so we own it — but it changes what "fix" means, and each
entry says whether the fix is ours to make or requires a fork.

---

## 1. Deviations

### KY-1. `gemini://` verifies no certificate and pins none

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

**Why.** The store is not written. The rest of the client was adopted whole,
and the missing half is invisible from the outside: a Gemini connection with no
pinning looks exactly like one with pinning, until the day it matters.

**Consequence.** An active network attacker between the user and a Gemini
server can substitute a certificate, on the first connection or the thousandth,
and nothing notices. Because a Gemini server's certificate *is* its identity,
this removes the protocol's whole authentication story. Everything that
describes the scheme says so plainly rather than papering over it — the scheme
table's `verify` string leads with `none`, the trust panel's step says the
certificate is "neither checked against an authority nor remembered from a
previous visit", the handler's header comment says the same, and
`docs/Fetch-Gemini.md` in the browser tree agrees — so the user is not told
something false. They are told the truth about a control that is absent.

**Status: OPEN.** Implement the store: pin the peer's SPKI SHA-256 on first
sight, keyed by `host:port`, persist it, and on a mismatch fail closed with the
wording the DANE path already uses for a pin mismatch — the browser has that
sentence and that UI. `@derhuerst/gemini` takes an injected client-certificate
store with a `get`/`delete` shape, and a server-certificate store is the same
shape and the same injection point, so this needs no fork. Until the store
exists, no document, scheme table or padlock may describe this connection as
TOFU. The engineering item is §3, **KY-D1**.

---

### KY-2. Only the hex infohash form; BEP-9's base32 magnet is refused

**What.** `INFO_HASH_MATCH` is `/^urn:btih:([a-f0-9]{40})$/i`
(`src/magnet-protocol.js`). A magnet whose `xt` carries a 32-character base32
info-hash is refused with an in-namespace 400 that names the form:
*"This magnet writes its infohash in the base32 form, which this browser does
not read."*

**The standard says.** BEP 9 permits a magnet's info-hash to be written either
as 40 hexadecimal characters or as 32 base32 characters.

**Why.** Hex is what every current client emits; base32 magnets are a decade
old. Accepting one form keeps a single canonical key string for the whole
scheme, which is what lets the magnet handler, the `bittorrent://` dispatcher
and the torrents page share one definition (SPEC §K.7.1).

**Consequence.** An old magnet link does not resolve. There is no security
consequence: a base32 info-hash decodes to the same 20 bytes, so accepting it
would be a normalisation rather than a weakening. Since the refusal names the
form, the user is not sent looking for a fault in the magnet.

**Status: OPEN**, low priority. The right fix is to decode base32 to the same
20 bytes at the edge and carry on with the canonical hex string, so that
nothing downstream learns a second spelling: one shared decoder in
`magnet-protocol.js`, applied before `INFO_HASH_MATCH`, and the single
canonical-form argument survives intact. Until then the named refusal is
honest, so this is a completeness gap rather than a correctness one.

---

### KY-3. BitTorrent v2 is not served, and the URL form cannot express it

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

### KY-4. The DNSLink name→key binding is one public resolver's unsigned word

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
   it supplied. This is said out loud: a dotted `hyper://` host gets two trust
   steps, the mapping **unverified** and the content **verified**, the lock
   stays open, and the scheme table's `verify` string carries the same
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

### KY-5. `magnet:` is its own namespace although it only ever redirects

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

### KY-6. A dropped `.torrent` file is shape-checked, not verified

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

**Status: DELIBERATE.** Pinned by a test that says so out loud
(`tests/torrent-input.test.js`, "the .torrent check is a SHAPE check and claims
nothing more"), so nobody later reads it as verification.

---

### KY-7. Every "verified by construction" claim in this chapter is made by a dependency

**What.** The four integrity guarantees this chapter rests on — a hypercore
block against its signed Merkle root, an SSB message against its feed's
signature chain, a torrent piece against the `info` dictionary's piece hashes,
a BEP-46 item against its public key — are performed by `hypercore`,
`ssb-fetch`, the rqbit sidecar and `bt-fetch` respectively. **No verification
code is in this package**, and none of it is tested here.

**The standard says.** The Hypercore protocol, the Scuttlebutt protocol guide,
BEP 3 and BEP 46 each define a check this chapter's trust states depend on.

**Why.** Reimplementing four peer-to-peer stacks to own their integrity checks
is not a proportionate response, and a second implementation of a verifier is a
second place to get it wrong.

**Consequence.** The trust states this chapter specifies are only as true as
those libraries are. A silent regression in any of them — a check made
conditional, a verification path skipped on a fast path — is caught by nothing
here, and the padlock keeps saying verified. That is a materially weaker
position than the Handshake chapter, where every signature an answer rests on
is validated by code in this repository and tested against flipped bytes.

**Status: DELIBERATE** as to the architecture. Whether the gap should be closed
by a conformance test rather than a reimplementation is genuinely unsettled —
see §2.3.

---

### KY-8. A `gemini://` host is resolved outside every DNS protection the browser applies

**What.** The Gemini client passes the hostname to Node's `tls.connect()`,
which resolves it with the operating system's resolver. It does not use the
browser's DoH policy, its Oblivious DoH bridge, Chromium's secure-DNS setting,
or the Handshake resolver.

**The standard says.** RFC 8484 (DoH) and RFC 9230 (Oblivious DoH) are the
transports the rest of this browser uses for exactly this lookup; the Gemini
specification says only that the host is a DNS name.

**Why.** Not a decision — a consequence of a client that opens its own socket.

**Consequence.** In a browser that goes to considerable trouble to make name
lookups oblivious, one scheme looks its hosts up in the clear: the router, the
ISP and anyone on the path sees which capsule is being visited. A Gemini host
that is a Handshake name does not resolve at all, which is a missing feature
rather than a leak. The same is true of SSB's multiserver addresses and of
hyperswarm's bootstrap, but those are peer addresses rather than user-chosen
names, so the disclosure is less pointed.

**Status: OPEN.** Resolve the host with the browser's own resolver and pass the
resulting address to the client with `servername` still set to the name, so SNI
and any future certificate pin stay keyed to the name rather than the address.
That also opens the door to Gemini over Handshake names, which do not resolve
today. It is the same piece of work as KY-4's privacy half; the engineering
item is §3, **KY-D2**.

---

### KY-9. Engine-reserved host names are reachable: `bt-fetch` petnames and `localhost` drives

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

### KY-10. Every magnet parameter except `xt`, `xs` and `dn` is ignored

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

### KY-11. No freshness is pinned for any mutable address

**What.** Three of these namespaces are key-addressed, meaning the content
under a fixed address changes: a BEP-46 item has a sequence number, a hypercore
has a version, an SSB feed has a tip. Nothing records the highest value seen
for any of them.

**The standard says.** BEP 44 defines `seq` and the rule that a node should not
accept an item with a lower sequence number than one it holds; Hypercore
versions and SSB feed tips are the equivalent counters in their protocols.

**Why.** It is not done. Each needs a small persistent store keyed by address
and a policy for what to do on a regression.

**Consequence.** An attacker who can influence which peers are reached can
serve a real, correctly signed, **old** answer indefinitely, and nothing
notices. This is a rollback attack, and it is the largest gap in this chapter's
trust story — larger than any parsing deviation above, because it is invisible:
every signature checks out. The trust steps say what they can, naming freshness
as the thing a key does not establish (SPEC §K.9), but naming a gap is not
closing it.

**Status: OPEN**, and not planned. The smallest honest version is one store
keyed by address holding the highest sequence number, version or tip seen, a
refusal to render a lower one without saying so, and a trust step that reports
"newest seen" rather than staying silent. Written down because "the address is
the key, so it is verified" is a claim that quietly excludes freshness, and a
reader is entitled to know that.

---

## 2. Things we are not sure about

### 2.1. Whether key **shape** is a sound basis for dispatch at all

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

### 2.2. We cannot test the canonicalisation this chapter reasons about

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

### 2.3. Whether a dependency's verification should be tested here

KY-7 says plainly that every integrity guarantee in this chapter is a
dependency's. Whether that is acceptable as it stands is the question we cannot
settle.

The argument for leaving it: reimplementing the checks is worse, and a
conformance test against a live swarm is not deterministic.

The argument against: the Handshake chapter verifies every signature its
answers rest on with code in this repository and tests each one against flipped
bytes. Holding a different standard for these namespaces because they were
easier to adopt is a reason of convenience, not of security. A deterministic
offline vector for each — a hypercore block with a broken signature, a torrent
piece that does not match its hash, an SSB message with a tampered chain, each
asserted to be *rejected* — is buildable, and would turn "the library does it"
into a fact we check. We think the second argument is right and have not acted
on it.

### 2.4. Dropping a magnet's trackers

KY-10 discards `tr=`. For public, well-seeded torrents the DHT (BEP 5) finds
peers and nothing is lost. For a private or thinly-seeded one the trackers may
be the only way to find anybody, and the browser simply appears not to work,
with no message saying why.

Carrying trackers through means putting them in the `bittorrent://` URL, which
we do not want to do (the address should be the key), or holding them in a side
table keyed by info-hash, which is state the resolution layer does not have. We
are not sure the second is wrong.

### 2.5. Whether `hyper://localhost/` is exposed to web content

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

### 2.6. Whether Gemini belongs in this chapter at all

Gemini is not key-addressed. It is a DNS name reached over TLS, and it is here
because its *trust* model — TOFU — is the one place a name namespace behaves
like a key namespace: the certificate's key becomes the identity after the
first sight of it.

That is a real similarity and we think it earns the placement. But a reader
looking for "the key-addressed chapter" finds one namespace in it that is
neither key- nor content-addressed and that verifies nothing at all, and may
reasonably think it belongs with the ICANN/DNS material. Nothing else in this
chapter depends on it, so moving it costs nothing but the cross-references.

---

## 3. Open design items

### KY-D1. A Gemini certificate store

The half of trust-on-first-use that carries the security is remembering the
key, and no certificate is stored or compared (KY-1). Everything that describes
the scheme already says so, so this is a missing control rather than a false
claim — but it is the control the whole protocol's identity story rests on.

**Recommendation.** Pin the peer's SPKI SHA-256 on first sight, keyed by
`host:port`, in a persistent store; on a mismatch fail closed with the wording
the DANE pin-mismatch path already uses, and offer the same accept-once
affordance only where that path does. `@derhuerst/gemini` takes an injected
client-certificate store with a `get`/`delete` shape; a server-certificate
store is the same shape at the same injection point, so no fork is needed. When
it lands, the trust step becomes "certificate matches the one first seen" and
the scheme table's `verify` string changes with it — the two must move
together.

### KY-D2. Give both engines the browser's resolver

`hyper-sdk` resolves DNSLink names from its own default DoH JSON endpoint
because `hyperOptions` sets only `storage` (KY-4), and the Gemini client passes
its host to Node's `tls.connect()` (KY-8). Two schemes therefore look names up
outside every DNS protection the rest of the browser applies.

**Recommendation.** For `hyper://`, set `hyperOptions.dnsResolver` from the
browser's own DoH configuration — a config change that removes the third-party
disclosure without touching the engine. It does not add DNSSEC: the engine
speaks the DoH JSON API, not RFC 8484 wire format, so a validating lookup would
have to be performed by the browser's resolver before the SDK is constructed,
which is a larger change worth costing separately. For Gemini, resolve the host
with the browser's resolver and pass the address to `connect()` with
`servername` still set to the name; that also makes Gemini over a Handshake
name possible for the first time.

### KY-D3. Find out whether web content can reach `hyper://localhost/`

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

### KY-D4. Refuse a non-key `bittorrent://` host before the engine sees it

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

### KY-D5. A recognised-but-unserved SSB type answers 418

`ssb-uri2` validates six URI types and `ssb-fetch` serves three; `address`,
`encryption-key` and `identity` parse and then get **418 I'm a teapot**.
Failing closed inside the namespace is right (routing law L2), but 418 signals
nothing to anything, and this browser is otherwise careful that a protocol
handler never returns a status Chromium does not expect.

**Recommendation.** 501 is the code that means "recognised, not implemented",
and it is what the router already returns for a scheme with no handler. Fix it
upstream if the maintainer will take it; otherwise wrap the ssb handler and
rewrite 418 → 501 with a sentence naming the type and saying it is not served.

### KY-D6. The two BitTorrent key shapes are defined twice

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

## 4. What this chapter leaves out

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
