# Chapter 3 — IPFS, IPNS and DNSLink: deviations and open questions

Every place this chapter departs from a specification cited in
`REFERENCES.md`, every place we are not confident we have made the right call,
and every design item still open. **Section 2 is the one to read.** A deviation
that is not written down is just a bug nobody has found yet.

Paths beginning `src/` or `tests/` are in this chapter's directory; `../../src/`
is a shared module of this package; anything named *the Wildroot tree* is the
browser this is extracted from. Line numbers are as of extraction.

---

## 1. Deviations

### IP-1. Two multibases, not the table

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

**Why.** Those are the two forms anything in this ecosystem prints: `ipfs add`
produces the second, everything before CIDv1 produced the first, and a shape
test a hostile string cannot walk through is worth more here than generality.
It is a *shape* test, deliberately — it does not decode, so it cannot be tricked
into allocating on a malformed multihash.

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

### IP-2. The CID shape exists three times

**What.** `CID_RE` is shared, and two private copies live in the Wildroot tree:
`src/hns/ipfs.js:38-39` and `src/pastebin-url.js:20-21`, each a
`CIDV0_RE`/`CIDV1_RE` pair.

**The standard says.** Nothing — this is an internal consistency requirement,
and it is the mechanism behind SPEC §12.1: one address shape, in one place.

**Why.** History. A guard test exists — `../../tests/publish-pointers.test.js`,
"nobody keeps a private CID regex" — but it looks for the *specific* shape the
copies it was written against had (`[a-z0-9]{46,`), so these two, which are
written differently and are currently equivalent, pass it.

**Consequence.** Nothing today: the three agree. The cost is that they can stop
agreeing silently, which is the failure mode this codebase has already had once,
when a copy accepted two hundred characters of junk and gated a storage restore
on it.

**Status.** `OPEN`. Have `src/hns/ipfs.js` and `src/pastebin-url.js` import
`CID_RE`, then widen the guard from the one string the last drift happened to
use to the shape of *any* CID matcher — assert that no file outside
`pointers.js` contains a regular-expression literal matching `/Qm\[|\[a-z2-7\]\{/`.
See IP-D3.

### IP-3. IPNS records are not validated here

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

**Status.** `DELIBERATE`. Reimplementing a record validator beside a node that
already has one adds a second place for it to be wrong, and the honest sentence
costs nothing. The limit is stated where a reader meets it (SPEC §4.2 and §9)
rather than glossed. What we owe and cannot yet give is §2.3.

### IP-5. A URL host is canonicalised; two of our address forms are case-sensitive

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

### IP-6. No HAMT-sharded directories

**What.** `directoryCid` (`src/cid.js`) refuses a folder whose basic directory
node would exceed kubo's 256 KiB HAMT threshold, with `NOT_SUPPORTED`.

**The standard says.** [UnixFS](https://github.com/ipfs/specs/blob/main/UNIXFS.md)
defines `HAMTDirectory`, and kubo shards a directory past that threshold.

**Why.** The entire contract of that function is *"the CID kubo would compute"*.
Answering with a non-HAMT CID for a folder kubo would shard is not an
approximation, it is a wrong address — and a wrong address is worse than no
answer, because it is published.

**Consequence.** A very large folder cannot have its CID computed locally before
it is published.

**Status.** `DELIBERATE`. Refusing beats disagreeing.

### IP-7. The CAR header is decoded by a minimal reader

**What.** The Wildroot tree decodes a CARv1 header with `@ipld/dag-cbor`. That
package is not a dependency of this one, so `src/car-roots.js` carries a
~90-line CBOR reader for the header's fixed shape: unsigned integers, byte
strings, text strings, arrays, maps and tag 42, and a refusal for everything
else including the indefinite-length forms dag-cbor forbids.

**The standard says.** [DAG-CBOR](https://ipld.io/specs/codecs/dag-cbor/spec/)
defines the encoding and requires canonical map ordering on encode.

**Why.** Extraction. Adding a dependency to the package root is not this
chapter's to do, and shipping a header parser that cannot be tested here is
worse than shipping one that can.

**Consequence.** One file is not byte-identical to its Wildroot counterpart,
which is the property this package holds every other source file to. The reader
also does not check dag-cbor's canonical map ordering — neither does
`@ipld/dag-cbor` on decode, so nothing is lost against the original.

**Status.** `DELIBERATE`, and bounded: cross-checked against the real
`@ipld/dag-cbor` encoder over nine header shapes — zero, one, two and three
roots, CIDv0 and CIDv1 roots, `version: 1` and `version: 2`, and a 300-root
header that exercises the two-byte length form — and pinned in
`tests/car-roots.test.js` against the bytes that encoder produced.

### IP-8. The archive-root check is a claim check

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

**Status.** `DELIBERATE`, with the caveat that a check routinely mistaken for a
proof has a cost of its own — §2.5.

### Experimental: `car=` and origin warming

The three items below are deviations inside SPEC §8, which is marked
EXPERIMENTAL: it ships in the reference browser, it is a local convention with
no standing outside it, and its behaviour may change.

### IP-9. `car=` accepts more than it writes, and more than the decision allows

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

### IP-10. A vendor gateway is named in a resolution path

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

### IP-11. The windowing policy is ours

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

## 2. Things we are not sure about

### 2.1. Whether a stated origin is the right primitive at all (IP-9)

`car=` solves a real problem: a publisher whose bytes sit with an ordinary
storage provider has no way to say *"the archive is here"* without running a node
or handing a third party their whole read list. We are confident about the
*safety* of the answer — the origin is untrusted by construction, SPEC §12.2. We
are not confident about the *shape*:

- Should the record be a full URL, or a provider identifier plus a well-known
  path?
- A gateway-form URL contains the CID, so **the record is rewritten on every
  publish** — exactly the cost DNSLink-over-IPNS exists to avoid. A form naming
  only the gateway (`car=https://host/ipfs/`) would be stable, and a prefix that
  is not a complete URL is a new thing to specify.
- A share capability with an expiry, which is what some providers issue, needs
  renewal, and nothing in the record says when it expires.
- Is `car` the right tag, given the value is a gateway URL and not a `.car` file?

We would rather adopt somebody else's convention than defend ours, and we could
not find one: IPIP-402 and the trustless-gateway specification give the shape of
the URL, and nothing we found says how a **name** announces one.

### 2.2. Whether host canonicalisation actually breaks the case-sensitive forms (IP-5)

The reasoning is in IP-5 and it is only reasoning. What would settle it is one
navigation each to `ipfs://Qm…`, `ipns://12D3Koo…` and `pubsub://MixedTopic` in
the shipping browser, and a look at the URL the handler receives. Until that is
run, IP-5's consequence paragraph is a prediction.

### 2.3. What delegating IPNS to the node actually gives us (IP-3)

We say *"an IPNS name is a signed pointer"* and mean it, but we have not
established what the node's answer is worth in the cases that matter: how stale
an answer may be, whether a resolution that finds nothing is distinguishable
from one that finds an expired record, and what happens when the DHT is
unreachable but a cached record exists. A specification that delegates a
signature check should be able to say what the delegate promises. This one
cannot yet.

### 2.4. Whether `ipns://<domain>` (DNSLink through the node) works at all

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

### 2.5. Whether the archive-root check should exist (IP-8)

It catches a real class of operator error cheaply. It also reads exactly like a
security check, and has been described as one in a code comment. A check that is
worth having and is routinely misunderstood is not obviously worth having. The
alternative — drop it and rely entirely on asking the node for the CID
afterwards — is simpler to reason about and loses a useful diagnostic.

### 2.6. Whether a pointer's precedence should be fixed at all

`ipfs` beats `ipns` beats the swarms beats Arweave, always, everywhere. That is
right for cold-start latency and it is the spine's rule. But a name whose `ipfs=`
is stale and whose `ipns=` is current resolves to the stale one, forever, with no
way for the publisher to say "prefer the mutable pointer". We do not know whether
that is a problem in practice or a misconfiguration nobody will make.

---

## 3. Open design items

### IP-D2. Tighten the `car=` grammar to the decision it implements

`parseOrigin` accepts any absolute `https:` URL under 480 bytes while decision
D-P2 and the writer both say gateway-form only, and `src/origin-warm.js` carries
a whole-archive branch for the difference (IP-9). A published grammar broader
than its decision cannot be implemented from this chapter.

**Recommendation.** Tighten `parseOrigin` to require `…/ipfs/<something>`,
delete the whole-archive branch that then becomes unreachable, and promote the
rule in SPEC §8.1 from a description to a normative **MUST**. If the loose form
is wanted instead, amend D-P2 and say in SPEC §8.1 that a non-gateway origin is
fetch-whole-or-nothing. Either resolves it; leaving the two apart does not.

### IP-D3. One CID shape, and a guard that catches any copy

`src/hns/ipfs.js` and `src/pastebin-url.js` each keep a private `CIDV0_RE`/
`CIDV1_RE` pair, and the guard test that exists looks for the specific literal
the last drift used, so both pass it while being copies (IP-2).

**Recommendation.** Import `CID_RE` in both files, then widen the guard to the
shape of any CID matcher — no regular-expression literal matching
`/Qm\[|\[a-z2-7\]\{/` outside `pointers.js` — rather than the one string that
happened to appear last time.

### IP-D4. Decode CIDs instead of shape-matching two multibases

`CID_RE` accepts base58btc CIDv0 and base32 CIDv1 and refuses every other
multibase, while `IPNS_RE` in the same file accepts base36, so the two address
spaces of one namespace disagree about which bases exist (IP-1).

**Recommendation.** Parse with `CID.parse` inside a `try` and return the CID's
canonical string form, so a pointer round-trips to one spelling however it was
written. `multiformats` is already a dependency and `../../src/contenthash.js`
already calls `CID.decode`. Keep a cheap length bound in front of the parse, and
re-run the negative tests in `tests/ipfs-url.test.js`: this is a widening, and
the three drift shapes must still fail.

### IP-D5. Correct the comment that calls the archive-root check a verification

The Wildroot tree's `src/hns/ipfs.js:1031` says the roots come from the archive's
own header *"so the caller can verify it got the DAG it asked for"*. The header
is written by whoever wrote the archive, so the check catches a confused origin
and not a hostile one; the real protection is stated correctly three lines above
it and in SPEC §12.2 (IP-8).

**Recommendation.** Rewrite it to say what it does: the caller can tell whether
the archive **claims** the DAG it asked for — a check against a confused origin,
not a hostile one — and the hash check on every block is what makes a hostile one
harmless.

### IP-D6. Correct the error page that tells a user IPFS names work while anonymised

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

### IP-D7. Delete the hard-coded `.pinthis` gateway table

`src/origin-warm.js:42-44` maps one TLD to one company's gateway (IP-10). `car=`
generalises it, and the code already prefers a stated origin when both exist.

**Recommendation.** Re-publish the names that predate `car=` so they state their
own origin, then delete `ORIGINS` and the `originFor` branch that reads it.
Until those names are re-published, leave it: deleting it first breaks names
that have no other way to say where their bytes are.

### IP-D8. Two measurements this chapter cannot make

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

### IP-D9. Let a stated-origin name load while anonymised, by stopping the node routing

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
stated origin does in that mode (refuse, as now, is the honest answer), and
whether a node that has been offline-routing must re-announce afterwards, which
would leak on a delay instead of immediately. A gate removed on the strength of
"the fetch is proxied" alone would be a regression, and the divergence inventory
row that proposes this (`../../DIVERGENCE.md`, row 9) should not be read as
authorising that.

---

## 4. What this chapter leaves out

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
