# Deviations, uncertainties and open decisions

Every departure from a cited standard, every place we are not sure we are
right, and every design decision left open — per chapter, present tense, with
a recommendation for each open item. A deviation is numbered with its chapter's
prefix (`HS-1`, `IC-3`, …); an uncertainty is `§2.n` within its chapter;
an open design item is `<prefix>-Dn`. **This document is generated from the
chapter files by `scripts/build-docs.mjs`; edit those.**

Two rules hold throughout. A deviation is recorded whether or not we think it
is right — `DELIBERATE` says we would make the same choice again and why,
`OPEN` says we would not and what we recommend. And nothing here is history:
a departure that no longer exists is not described.

## Contents

- [Part II — Namespace selection](#part-ii-namespace-selection) — [chapter file](namespaces/router/DEVIATIONS.md)
  - RT-1 The reserved-name list is broader than the RFCs reserve
  - RT-2 .eth and .onion are carved out by hard-coded suffix
  - RT-3 A single bare label is a Handshake name
  - RT-4 <known-scheme>:<digits> is always read as a scheme
  - RT-5 The icann namespace has no scheme, so a classification and a dispatch disagree
  - RT-6 None of the schemes we invented is registered, and none uses web+
  - RT-7 The PAC script carries a second, ASCII-only copy of the host rule
  - RT-8 classify() returns javascript:, data: and file: untouched
  - RT-9 ERC-4804's w3:// short form is deliberately not offered
  - RT-10 agregore:// and browser:// are permanent silent aliases
  - RT-11 The IDNA pass fails open
  - RT-12 The dispatcher's 400 branch is unreachable through a WHATWG Request
  - RT-13 hns: is a standard scheme, and pays the URL Standard's host rule for it
  - 2.1 Is "everything non-ICANN is Handshake" a defensible default at all?
  - 2.2 Whether a bare word should navigate (RT-3)
  - 2.3 Where the carve-out list should stop (RT-2)
  - 2.4 Should a namespace be identified by classification or by scheme? (RT-5)
  - 2.5 Whether the three-state lock is comprehensible
  - 2.6 Whether partial is doing two jobs in the lock
  - 2.7 Citations we have not verified against the source text
  - 2.8 Whether search:// should be a scheme at all
  - RT-D1 Derive the privileged-scheme declaration from the scheme table
  - RT-D2 Give icann a place in one namespace vocabulary
  - RT-D4 Register hns: with IANA
  - RT-D5 Make the IDNA pass fail closed
- [Chapter 1 — Handshake](#chapter-1-handshake) — [chapter file](namespaces/handshake/DEVIATIONS.md)
  - HS-1 TTLs are ignored; a flat 60-second positive cache
  - HS-2 IPv6: a dual-stack name is reached over IPv4 (resolved 2026-09-06)
  - HS-3 SVCB / HTTPS records are parsed but never queried, and ECH is not usable
  - HS-5 One DANE profile; an unusable TLSA RRset is refused rather than ignored
  - HS-6 The TLSA owner is always _443._tcp; a port in the URL is ignored
  - HS-8 A DoH-resolved TLSA is used as a pin, on the resolver's word
  - HS-9 A CNAME target's own RRset is not validated under the target's owner
  - HS-10 No RRSIG clock-skew tolerance
  - HS-11 Standards not implemented at all
  - HS-12 A DANE mismatch re-resolves once, then fails closed; there is no "pinned before" memory
  - HS-13 Product decisions that deviate from what the naming systems themselves say
  - HS-14 Internationalized names go through the URL parser, not through our own IDNA
  - HS-15 Nameserver failover at query time (resolved 2026-09-06)
  - HS-16 Changing the anonymization mode restarts the SPV node, which re-syncs
  - 2.1 SVCB/HTTPS and ECH (HS-3)
  - 2.2 Registry TLDs that refer, and NS targets that are themselves Handshake names
  - 2.3 What the DoH fallback actually promises
  - 2.4 DANE pin rotation windows (HS-12)
  - 2.5 What an SPV proof actually proves
  - 2.6 Whether a proven absence should raise the lock as far as it does
  - 2.7 What DNSLink interoperation is worth while the gateways it was for retire
  - HS-D1 No per-resolution query budget on NS hops
  - HS-D2 hns: has no IANA URI scheme registration
- [Chapter 2 — ICANN names](#chapter-2-icann-names) — [chapter file](namespaces/icann/DEVIATIONS.md)
  - IC-1 The ICANN boundary is a build-time snapshot, not a live lookup
  - IC-2 ICANN wins a label that is also a Handshake TLD, and every other alt-root is Handshake's
  - IC-3 No DANE for ICANN names
  - IC-4 No DNSSEC validation for ICANN names
  - IC-5 The special-use carve-out is longer than the RFCs
  - IC-6 automatic falls back to unencrypted system DNS
  - IC-7 The oblivious bridge replaces the resolver pool rather than leading it
  - IC-8 ODoHConfigs come from a conventional well-known URI, fetched directly from the target
  - IC-9 The lookups that make the private path possible are not themselves private
  - IC-11 DoT, DDR, SVCB/HTTPS and ECH are not used
  - IC-12 Internationalized names cross the boundary through UTS-46, not IDNA2008
  - IC-13 The SSRF guard is not applied to ICANN addresses
  - IC-14 An http:// link to a numeric-TLD Handshake name is not rewritten
  - IC-15 The obliviousness switch and the resolver pool are configuration-file-only
  - IC-16 The resolver's default lookup is the OS resolver, in the clear
  - 2.1 Whether "ICANN first" should have a visible escape hatch
  - 2.2 Whether /.well-known/odohconfigs is standardised
  - 2.3 Whether replacing the resolver pool is the right failure ordering
  - 2.4 What the engine does on each kind of DoH failure
  - 2.5 The ten-minute window and the subdomain rule
  - 2.6 Whether the snapshot cadence is adequate
  - 2.7 Whether the IDNA divergence can actually move a name
  - 2.8 Whether refusing DANE for ICANN names is right
  - 2.9 Whether a browser should be configuring the resolver at all
  - 2.10 Whether the engine really cannot issue a numeric-TLD http request
  - IC-D1 Lead the resolver pool with the bridge instead of replacing it
  - IC-D3 Put the obliviousness switch and the resolver pool in the settings page
  - IC-D4 Give the browser's drift alarm an offline half
- [Chapter 3 — IPFS, IPNS and DNSLink](#chapter-3-ipfs-ipns-and-dnslink) — [chapter file](namespaces/ipfs/DEVIATIONS.md)
  - IP-1 Two multibases, not the table
  - IP-2 The CID shape exists three times
  - IP-3 IPNS records are not validated here
  - IP-5 A URL host is canonicalised; two of our address forms are case-sensitive
  - IP-6 No HAMT-sharded directories
  - IP-7 The CAR header is decoded by a minimal reader
  - IP-8 The archive-root check is a claim check
  - IP-9 car= accepts more than it writes, and more than the decision allows
  - IP-10 A vendor gateway is named in a resolution path
  - IP-11 The windowing policy is ours
  - 2.1 Whether a stated origin is the right primitive at all (IP-9)
  - 2.2 Whether host canonicalisation actually breaks the case-sensitive forms (IP-5)
  - 2.3 What delegating IPNS to the node actually gives us (IP-3)
  - 2.4 Whether ipns://<domain> (DNSLink through the node) works at all
  - 2.5 Whether the archive-root check should exist (IP-8)
  - 2.6 Whether a pointer's precedence should be fixed at all
  - IP-D2 Tighten the car= grammar to the decision it implements
  - IP-D3 One CID shape, and a guard that catches any copy
  - IP-D4 Decode CIDs instead of shape-matching two multibases
  - IP-D5 Correct the comment that calls the archive-root check a verification
  - IP-D6 Correct the error page that tells a user IPFS names work while anonymised
  - IP-D7 Delete the hard-coded .pinthis gateway table
  - IP-D8 Two measurements this chapter cannot make
  - IP-D9 Let a stated-origin name load while anonymised, by stopping the node routing
- [Chapter 4 — Arweave](#chapter-4-arweave) — [chapter file](namespaces/arweave/DEVIATIONS.md)
  - AR-1 The BYTES are verified against the transaction for a top-level transaction under 8 MiB (resolved 2026-09-06, with a stated limit)
  - AR-2 ar:// is a de-facto scheme with no registration
  - AR-3 An arweave resolution is cached for a flat 60 seconds
  - AR-U1 Is delegating manifest resolution to the gateway defensible at all?
  - AR-U2 We have not verified the manifest version 0.2.0 clauses
  - AR-U3 What should an ar://-adjacent ArNS implementation look like?
  - AR-U4 Is one hardcoded gateway list the right shape?
  - AR-U5 Should an ar= pointer close the padlock at all?
  - AR-D1 The data_root half of the cheap check
  - AR-D2 Config.arOptions has no schema, default or validation
- [Chapter 5 — ENS and `web3://`](#chapter-5-ens-and-web3) — [chapter file](namespaces/ens/DEVIATIONS.md)
  - EN-1 Only contenthash is read; addr, text and the rest are not
  - EN-2 A CCIP resolver's rigour is deliberately not graded
  - EN-3 Reverse resolution (EIP-181) is not implemented
  - EN-4 Two normalisations for one hash function
  - EN-5 A gateway **hostname** is never resolved before it is fetched
  - EN-6 Nothing is cached; every navigation re-resolves
  - EN-7 Whole areas of ENS are not implemented at all
  - 2.1 Is ens:// TRUSTED, or OPEN?
  - 2.2 Would grading CCIP rigour become right, with a light client?
  - 2.3 Revert data is found by the error's shape
  - 2.4 Should .eth be the only alt-root we carve out?
  - 2.5 Pinning the Universal Resolver address
  - 2.6 web3://'s privilege posture
  - EN-D1 web3:// has no deadline of its own and no policy over its RPC list
  - EN-D2 web3:// keeps a stronger privilege posture than ens://
- [Chapter 6 — Nostr](#chapter-6-nostr) — [chapter file](namespaces/nostr/DEVIATIONS.md)
  - NO-1 A NIP-05 address is classified nowhere
  - NO-2 The nip05 claim on a protocol page is displayed, but never looked up
  - NO-3 Relay selection is a bundled set plus the link author's hints; NIP-65 is never read
  - NO-4 BIP-173's 90-character limit is not enforced, and bech32 is implemented locally
  - NO-5 nostr:// is accepted although NIP-21 defines only nostr:
  - NO-6 An nsec is refused by name, quoting it back to nobody
  - NO-7 No NIP-42 AUTH: a relay that wants sign-in is a relay that answered nothing
  - NO-8 Fixed result limits, no pagination, no time window
  - NO-9 Three independent NIP-01 implementations, and a trust header nobody reads
  - NO-10 The canonical serialisation is delegated to the host's JSON.stringify
  - NO-11 The _nostr DNS record is designed and documented but not published
  - NO-12 On a .hns.one NIP-05 address the Handshake guarantees do not apply to the lookup
  - NO-14 The nsec arm is claimed on its prefix, not on its checksum
  - NO-15 Private mode hides who is asking, not what is asked
  - NO-16 Two WebSocket implementations on two routes
  - 2.1 Whether a lock can ever close for Nostr — and whether a padlock is the right instrument
  - 2.2 What "the right event" means, once the answer is bound to the query
  - 2.3 Whether NIP-05 belongs in a resolution specification at all
  - 2.4 The default relay list is a decision we made for the user
  - 2.5 Whether nostr: should be a standard scheme
  - 2.6 Whether a bare npub should navigate
  - 2.7 What we should be doing about relay disclosure
  - 2.8 Whether a refused relay hint should be silent
  - NO-D1 Resolve the nip05 claim, or say the domain was unreachable
  - NO-D3 Publish the _nostr record, or stop documenting it
  - NO-D4 Read NIP-65 relay lists
  - NO-D5 Read X-Nostr-Trust, or delete it
  - NO-D6 Collapse the three NIP-01 implementations
- [Chapter 7 — DID, AT Protocol and ActivityPub](#chapter-7-did-at-protocol-and-activitypub) — [chapter file](namespaces/did/DEVIATIONS.md)
  - DI-1 A resolved DID document is served with Access-Control-Allow-Origin: *
  - DI-2 did:plc is directory-trusted; the operation log is never fetched
  - DI-3 The result is a bare DID document, as application/json
  - DI-4 did:// is accepted as an alias for did:
  - DI-5 AT Protocol handle resolution is not implemented; the AppView is asked instead
  - DI-10 Nothing enforces that an identity anchor's epoch moves forward
  - DI-11 _nostr.<name> is designed and not published
  - 2.1 Whether "recognised, fail-closed" is a resting state
  - 2.2 Whether a DID document should be a *page* at all
  - 2.3 Whether a bare atproto handle should be classified as an atproto address
  - 2.4 Whether a client-side epoch memory actually fixes DI-10
  - 2.5 did:web:<name>.hns.one versus did:plc
  - 2.6 What the AppView path should be *called*
  - 2.7 Whether this chapter should exist yet
  - 2.8 Whether a labelled default PDS should exist at all
  - DI-D1 Resolve AT Protocol handles locally, not through the AppView
  - DI-D5 Verify the did:plc operation log
  - DI-D6 Return a DID resolution result, not a bare document
- [Chapter 8 — Tor](#chapter-8-tor) — [chapter file](namespaces/tor/DEVIATIONS.md)
  - TO-1 With Tor off, and off Tor, we answer with a page rather than an error
  - TO-2 An explicit non-onion scheme on an onion host is not protected
  - TO-3 No SOCKS stream isolation: everything shares circuits
  - TO-4 Whether the session cookie jar reaches the onion fetch is not established
  - TO-5 Onion services with client authorization cannot be reached
  - TO-6 IP Protection is all-or-nothing for the whole session
  - TO-7 While BLOCKED, a session request fails as a proxy error, not as a page that names the mode
  - 2.1 Whether "device-local" should have any escape hatch at all
  - 2.2 Whether an explicit scheme should be allowed to defeat R1 (TO-2)
  - 2.3 Whether routing before the circuit is ready is the right call (R11)
  - 2.4 Whether a browser that does not resist fingerprinting should offer .onion at all
  - 2.5 Whether the mode is at the right granularity (TO-6)
  - 2.6 Whether onion:// is the right URL form
  - 2.7 What a redirect chain should mean for the address bar
  - TO-D1 Per-origin SOCKS credentials for circuit isolation
  - TO-D2 Decide what https://<addr>.onion/ should do
  - TO-D3 Establish, then pin, what happens to cookies
  - TO-D4 Support onion services with client authorization
  - TO-D5 Let a user name their own Tor endpoint, loudly
- [Chapter 9 — Key-addressed namespaces](#chapter-9-key-addressed-namespaces) — [chapter file](namespaces/keys/DEVIATIONS.md)
  - KY-1 gemini:// verifies no certificate and pins none
  - KY-2 Only the hex infohash form; BEP-9's base32 magnet is refused
  - KY-3 BitTorrent v2 is not served, and the URL form cannot express it
  - KY-4 The DNSLink name→key binding is one public resolver's unsigned word
  - KY-5 magnet: is its own namespace although it only ever redirects
  - KY-6 A dropped .torrent file is shape-checked, not verified
  - KY-7 Every "verified by construction" claim in this chapter is made by a dependency
  - KY-8 In Fast mode, a gemini:// host is resolved by the operating system
  - KY-9 Engine-reserved host names are reachable: bt-fetch petnames and localhost drives
  - KY-10 Every magnet parameter except xt, xs and dn is ignored
  - KY-11 No freshness is pinned for any mutable address
  - 2.1 Whether key **shape** is a sound basis for dispatch at all
  - 2.2 We cannot test the canonicalisation this chapter reasons about
  - 2.3 Whether a dependency's verification should be tested here
  - 2.4 Dropping a magnet's trackers
  - 2.5 Whether hyper://localhost/ is exposed to web content
  - 2.6 Whether Gemini belongs in this chapter at all
  - 2.7 What Tor's exit does with a Gemini host name, and whether it has been proven
  - KY-D1 A Gemini certificate store
  - KY-D2 Give hyper:// the browser's resolver
  - KY-D3 Find out whether web content can reach hyper://localhost/
  - KY-D4 Refuse a non-key bittorrent:// host before the engine sees it
  - KY-D5 A recognised-but-unserved SSB type answers 418
  - KY-D6 The two BitTorrent key shapes are defined twice
- [Chapter 10 — Experimental: HIP-5 `_op` and numeric Handshake TLDs](#chapter-10-experimental-hip-5-op-and-numeric-handshake-tlds) — [chapter file](namespaces/experimental/DEVIATIONS.md)
  - OP-1 Two fall-throughs to the seller's nameservers
  - NT-1 Numeric Handshake top-level names: DECIDED 2026-09-06 — off by default, behind a switch
  - NT-2 A numeric TLD is written with a leading underscore in a URL
  - NT-3 The http:// spelling of a numeric name cannot be rewritten
  - OP-2.1 _op is chain-pointed and RPC-answered
  - OP-2.2 One deployment is not a specification
  - OP-2.3 What the registry read does under an anonymizing proxy
  - NT-2.1 The marker is a local invention, and its value depends on being shared
  - OP-D1 The library default fetch is unproxied
  - OP-D2 No light-client verification of the registry's answer
  - NT-D1 Numeric top-level names have no test of the whole path
- [Chapter 11 — Native applications on a Handshake name](#chapter-11-native-applications-on-a-handshake-name) — [chapter file](namespaces/apps/DEVIATIONS.md)
  - AP-2 The tunnel cannot require proxy authentication, and ships with none
  - AP-3 No service workers at a Handshake name
  - AP-4 WebSocket routing is decided by the target host, not by the initiating origin
  - AP-5 A native page's sign-in token is bound to a URL the request is not sent to
  - AP-6 Manifests are unsigned, so an installed application's identity is only its origin
  - AP-7 A Handshake WebSocket is reachable on port 443 and nowhere else
  - 2.1 Whether the 101 is checked for Sec-WebSocket-Accept in our stack
  - 2.2 What Chromium actually sends to the tunnel for a plaintext ws://
  - 2.3 Whether the PAC leaves loopback traffic reachable in Private mode
  - 2.4 Cookie behaviour on an hns:// origin
  - 2.5 Storage partitioning inside a native document
  - 2.6 Whether the PAC is applied to every session that can open a WebSocket
  - 2.7 Internationalised hosts in the PAC
  - 2.8 The numeric-TLD path has never been proven end to end
  - 2.9 verified: true is a live observation, not a regression test
  - AP-D1 Give the PAC a loopback and private-literal branch
  - AP-D4 Decide the service-worker question for hns://
  - AP-D5 Sign manifests, and make verified mean something
  - AP-D6 A revoke / manage-applications interface
  - AP-D7 Native discovery for a dotted Handshake name
  - AP-D8 Surface the tunnel's refusal reason
  - AP-D9 Bound the tunnel's concurrency
- [Cross-cutting — Divergence inventory: where privacy and speed pull apart](#cross-cutting-divergence-inventory-where-privacy-and-speed-pull-apart) — [source file](DIVERGENCE.md)

---

## Part II — Namespace selection

_Source: [`namespaces/router/DEVIATIONS.md`](namespaces/router/DEVIATIONS.md)._

Every place the router and classifier depart from a standard they cite, from
common browser practice, or from their own stated design — plus every place we
are not sure we have made the right call, and every design item we have decided
against or not yet done.

The rule this file serves, as everywhere in this specification: **a deviation
that is not written down is just a bug nobody has found yet.**

Entries are prefixed `RT` so they do not collide with the other chapters'.
Where a deviation is really another chapter's, it is cross-referenced and not
restated. Line references are to the reference implementation at the repository
root.

---

### 1. Deviations

#### RT-1. The reserved-name list is broader than the RFCs reserve

**What.** Thirteen labels are refused as Handshake names
(`src/reserved-names.cjs:19-33`). Seven have IETF standing: `localhost`,
`invalid`, `test`, `example` (RFC 6761), `local` (RFC 6762), `onion` (RFC
7686), `arpa` (RFC 3172, carrying RFC 8375's `home.arpa`). The other six do
not.

**The standard says.** RFC 6761 §5 sets out what a special-use name obliges a
resolver to do, and RFC 6761/6762/7686/8375 between them reserve exactly the
seven labels above. Nothing in the IETF reserves `internal`, `home`, `lan`,
`corp`, `intranet` or `private`:

| Label | Standing |
|---|---|
| `internal` | Reserved by **ICANN**, 2024, for private use. Not an IETF reservation; the code comment calling it "RFC 8375 (home.arpa's informal twin)" is not accurate |
| `home`, `corp` | Deferred indefinitely from ICANN's new-gTLD programme on name-collision grounds. Not reserved, but not delegable either |
| `lan`, `intranet`, `private` | Pure convention. No standing anywhere |

**Why.** These are the labels home routers and corporate networks *actually*
use. A carve-out that covers only what the IETF reserved leaves `printer.lan`
disclosed to whoever registers the Handshake top-level name `lan`, which is the
case the carve-out exists for.

**Consequence.** Six labels can never be reached as Handshake names in this
implementation, even though the Handshake chain will happily sell them, and
somebody may have bought one. A Handshake registrant of `lan` has a name this
client refuses to resolve.

**Status: DELIBERATE.** The disclosure the list prevents is unrecoverable and
the names it forfeits are ones no sensible registrant would build a public site
on. It is stated here so an implementer copying the list knows it is copying a
judgement and not a citation.

---

#### RT-2. `.eth` and `.onion` are carved out by hard-coded suffix

**What.** Two suffixes are removed from the Handshake namespace by a literal
regular expression before any list is consulted: `/\.onion$/i` and `/\.eth$/i`
(`src/classify-host.cjs:33, 37`).

**The standard says.** RFC 7686 §2 rule 1: applications SHOULD NOT resolve
`.onion` names via DNS, and by the same argument must not resolve them on a
chain either. `.eth` has no standard behind it at all: it is not reserved, not
in the ICANN root, and is an ordinary Handshake top-level name somebody has in
fact registered.

**Why.** For `.onion` the requirement is absolute and the harm is
deanonymisation. For `.eth` the alternative is that traffic a user intends for
ENS is delivered to whoever holds the Handshake name — a hijack the user cannot
see and would not expect.

**Consequence.** The Handshake registrant of `eth` cannot serve this client's
users. The list is also unbounded in principle: `.crypto`, `.sol`, `.bnb`,
`.zil` and every future alt-root have the same claim and are **not** carved out
(they resolve as Handshake names — the spine's `D-16`). The line between the two
is "does routing it elsewhere prevent a disclosure or a hijack we consider
serious", which is a judgement, not a rule.

**Status: DELIBERATE**, unreservedly for `.onion` and with the boundary
question open for the rest — see §2.3.

---

#### RT-3. A single bare label is a Handshake name

**What.** `pinner`, `hnshosting`, `bananas`, `14898` and `🤝` navigate as
Handshake names (`src/router.js:383-409`). `com`, `org`, `app`, `blog` and
`link` — labels that are themselves ICANN top-level domains — are searches.
Anything containing whitespace is a search.

**The standard says.** Nothing. No standard governs what a browser does with a
bare word, and every mainstream browser searches. This is a departure from
common practice rather than from a specification.

**Why.** Most Handshake sites *are* bare top-level names, and a browser whose
subject is names should not answer `pinner` by asking a search engine.

**Consequence, stated because it is a privacy cost and not only a UX trade.**
Every mistyped word becomes a name lookup. Where that lookup goes over DoH
rather than the local chain node, the resolver observes it. A browser that
searched by default would disclose the same string to a search engine instead,
so this is a change of *who* learns it rather than a new disclosure — but an
implementer should choose deliberately. The mitigation is that the suggestion
list always offers the search as a visible second row, so nothing is
unreachable.

**Status: DELIBERATE** as a product decision for this client, and **uncertain**
as a default for somebody else's — see §2.2.

---

#### RT-4. `<known-scheme>:<digits>` is always read as a scheme

**What.** The explicit-scheme test refuses to treat `example.com:8080` as a
scheme, because a real scheme is never followed by a bare port number. The
exception is a token the registry already knows (`src/router.js:205-217`):

```
hasExplicitScheme('example.com:8080') -> false   (host:port)
hasExplicitScheme('hns:8080')         -> true    (scheme hns, path 8080)
```

**The standard says.** RFC 3986 §3.1 defines a scheme as
`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` and §3.2.2/§3.2.3 define the
`host:port` authority. The two grammars overlap on this input and the RFC does
not adjudicate; a receiver has to choose.

**Why.** The alternative — treating a known scheme followed by digits as a host
— breaks `magnet:?…`-shaped inputs and every `did:`-style path.

**Consequence.** A Handshake top-level name spelled the same as one of the 32
registered schemes cannot be typed with a port. `hns:8080`, `ar:8080`,
`search:8080`, `media:8080` and so on are read as scheme-plus-path. The
Handshake name `hns` exists; the others are mostly hypothetical. The failure is
a wrong navigation, not a disclosure — the input stays in a namespace we own.

**Status: DELIBERATE.** Listed because a reader will otherwise find it and
think it is a bug nobody noticed.

---

#### RT-5. The `icann` namespace has no scheme, so a classification and a dispatch disagree

**What.** `NAMESPACES.ICANN` is declared and used by the classifier, but no row
in `SCHEME_TABLE` carries it — an ICANN name is navigated as `https://`, whose
row is in namespace `web` (`src/router.js:62-84, 368-370`). So:

```
classify('example.com').namespace  === 'icann'
namespaceForScheme('https')        === 'web'
```

and a failure routed for that name is tagged `X-Resolution-Namespace: web`.

**The standard says.** Nothing directly; the marker is ours. But SPEC §10.1
claims that every namespace reports into *one* vocabulary, and this is the one
place the claim is not true of the namespace identifier itself.

**Why.** The classifier answers "what did the user mean" and the dispatcher
answers "what is being fetched". Both questions are real and the model has
never chosen which one `namespace` names.

**Consequence.** The namespace vocabulary has two dialects. SPEC §4.3
states which one the marker speaks — the scheme table's — so nothing is
ambiguous in practice, and nothing is unsafe: the marker is truthful about the
scheme. But an interface that compares `classify().namespace` with the header
finds they differ for every ordinary web page, and a documented wrinkle is
still a wrinkle.

**Status: OPEN.** We lean to dropping `NAMESPACES.ICANN` entirely and having
`classifyHost` return `web` for an ICANN name, keeping `reason: 'icann-tld'` as
the finer signal — one vocabulary, one loss (the classifier could not then say
"this is a DNS name" without reading the reason). The alternative, splitting
`web` into `icann` (named hosts) and `web` (IP literals and explicit URLs) and
making `namespaceForScheme` host-aware, is more faithful to what a user meant
and considerably more machinery. See RT-D2.

---

#### RT-6. None of the schemes we invented is registered, and none uses `web+`

**What.** Checked against the IANA URI Schemes registry rather than assumed. Of
the 32 rows in `SCHEME_TABLE`:

| Status | Count | Schemes |
|---|---|---|
| **Permanent** | 2 | `http`, `https` |
| **Provisional** | 11 | `ipfs`, `ipns`, `ar`, `ens`, `web3`, `nostr`, `at`, `did`, `hyper`, `ssb`, `magnet` |
| **Unregistered** | 19 | `hns`, `ipld`, `pubsub`, `activitypub`, `onion`, `https+raw`, `gemini`, `bittorrent`, `bt`, `wildroot`, `agregore`, `browser`, `search`, `paste`, `editor`, `bluesky`, `mastodon`, `media`, `docview` |

**The standard says.** RFC 7595 sets out the registration procedure and the low
bar for a Provisional entry: a specification of any stability, and an email to
the reviewer. The HTML Standard's `registerProtocolHandler` defines the `web+`
prefix for schemes a *web page* registers a handler for.

**Why.** The application-private schemes (`wildroot`, `search`, `paste`,
`editor`, `media`, `docview`, `bluesky`, `mastodon`) exist to get isolation
from each other; they have no interoperability story and registering them would
claim one. `web+`-prefixing is inapplicable — that convention is for a web
page's handler, not for a scheme a browser implements natively. `hns` is the
different case: it *is* meant to interoperate and other Handshake clients
already spell it the same way.

**Consequence.** `hns:` has no registry entry, so there is nothing to point a
second implementer at and nothing to stop the name being claimed for something
else. `https+raw` is a syntactically legal scheme name (RFC 3986 permits `+`)
that no other software will recognise.

**Status: OPEN for `hns`, DELIBERATE for the application-private schemes.** A
Provisional registration is a low bar and this repository contains the
specification RFC 7595 asks for; nothing in the code changes. See RT-D4.

---

#### RT-7. The PAC script carries a second, ASCII-only copy of the host rule

**What.** The host rule is one dependency-free module,
`../../src/classify-host.cjs`: the router imports it and re-exports its
predicates, and the address bar requires the same file and carries no host rule
of its own. The WebSocket PAC script cannot load it. A PAC script is a string
evaluated inside the browser's network stack, with no module loader and — the
part that decides this — **no URL parser**, which `asciiTld` needs to punycode
a Unicode label before comparing it. So the PAC embeds the two lists
(`src/reserved-names.cjs`, `src/icann-tlds.cjs`, the same files) and an
ASCII-only form of the rule: a bare label or a non-ICANN / numeric final label
is Handshake, and IP literals, `localhost`, reserved labels, `.eth` and
`.onion` are not.

**The standard says.** Nothing. This is a departure from our own stated design:
SPEC §11.5 says one classifier, consumed everywhere.

**Why.** The PAC sandbox has neither an import nor a `URL`. The rule it needs is
also narrower than the classifier's — it answers one question, "does this
ws/wss host go through the Handshake tunnel or around it" — and the hosts it
sees have already been through Chromium's own host parser, so they arrive as
A-labels.

**Consequence.** One copy remains, and what it is held to is *behaviour* rather
than source text: the test generates the PAC, evaluates it the way the network
stack does, and compares `FindProxyForURL`'s routing decision with
`classifyHost()`'s answer across a corpus that includes a Unicode host, a
numeric TLD, a malformed onion, IP literals and reserved names. A divergence
fails the test rather than a rename. The residual risk is a host shape the
corpus does not contain, and the direction of a divergence matters: a host the
PAC wrongly calls Handshake goes to a proxy that refuses it, while a host it
wrongly calls ordinary is a WebSocket leaving around the tunnel.

**Status: OPEN**, and narrowly. The remaining copy cannot be removed while the
rule must run inside a PAC sandbox; it can only be made smaller. Emitting a
generated, ASCII-only projection *of the shared module* — rather than a
hand-written mirror of it — would leave one source and one generator, and is
the shape any fix should take.

---

#### RT-8. `classify()` returns `javascript:`, `data:` and `file:` untouched

**What.** L1 says an explicit scheme is authoritative and the classifier does
not get a vote. It applies to every scheme (`src/router.js:288-300`):

```
classify('javascript:alert(1)') -> { scheme: 'javascript', namespace: null, known: false }
classify('data:text/html,x')    -> { scheme: 'data',       namespace: null, known: false }
classify('file:///etc/passwd')  -> { scheme: 'file',       namespace: null, known: false }
```

**The standard says.** Nothing requires a classifier to filter. The HTML
Standard's navigation model puts the safety decision in the navigating context,
which is where we put it too.

**Why.** A classifier that silently rewrote some schemes and not others would
not be a classifier, and the L1 guarantee would have exceptions the caller could
not enumerate.

**Consequence.** `classify()` is **not** a navigation-safety filter. The
decision carries `known`, which is `false` for exactly these schemes, so a
caller can require `known === true` instead of inheriting a rule from a comment
— but `known` says the registry has a row, not that the scheme is a link target
(`navigable: false` is a separate marker). A caller that navigates still needs
its own policy.

**Status: DELIBERATE.** The behaviour is right under L1 and the contract is
carried in the decision object rather than in prose.

---

#### RT-9. ERC-4804's `w3://` short form is deliberately not offered

**What.** `web3://` is registered; `w3://` is not, and
`namespaceForScheme('w3')` is `null` — pinned by a test.

**The standard says.** ERC-4804 defines `web3://` and offers `w3://` as a
short form.

**Why.** `.w3` is a Handshake top-level name in active use. A `w3:` scheme
would make `w3://proof` ambiguous with the name `proof.w3` in a way no user
could be expected to hold in their head, and one of the two would silently
shadow the other.

**Consequence.** A `w3://` URL from an ERC-4804 client is an unknown scheme
here and fails closed with a 501 rather than resolving. That is a deliberate
interoperability gap with a standard we otherwise implement.

**Status: DELIBERATE.**

---

#### RT-10. `agregore://` and `browser://` are permanent silent aliases

**What.** Two schemes are served identically to `wildroot://` and rewritten to
it on navigation. They are never advertised (`src/router.js:152-154`).

**The standard says.** Nothing. Listed because the WHATWG URL Standard's origin
model is what makes it consequential: three schemes are three tuple origins.

**Why.** Old sessions and links in the wild carry them.

**Consequence.** Three standard origins for one set of pages, so a chrome
page's storage is keyed by whichever spelling the user arrived through. The
navigation-time rewrite is what keeps that from mattering, which makes the
rewrite load-bearing rather than cosmetic.

**Status: DELIBERATE.**

---

#### RT-11. The IDNA pass fails open

**What.** A host is converted to A-labels by handing it to the URL constructor
and reading back `hostname`. When the constructor throws, the raw final label is
used for the ICANN comparison instead (`src/classify-host.cjs:68-76`):

```js
try {
  const ascii = new URL('http://' + host).hostname
  tld = ascii.split('.').filter(Boolean).pop()
} catch { /* keep the raw tld */ }
```

**The standard says.** RFC 5891 (IDNA2008) specifies that a label failing
validation is not a valid IDN and is to be rejected, not used. UTS #46, which is
what the URL Standard actually requires, likewise defines failure as failure.
Neither offers "use the unconverted form".

**Why.** No deliberate reason; the fallback is a defensive `catch` that turned
into a policy.

**Consequence.** A host the URL parser rejects is still classified, on a label
that was never normalised. Since a non-ICANN label means "Handshake", the
failure direction is "send it to the namespace we own", so this is not a
cross-namespace leak. It is still a classification made on unnormalised input,
and it hides parser rejections an implementer would want to see.

Separately, and recorded in the spine as `D-17`: what this delivers is UTS #46
as the URL Standard specifies it, not IDNA2008 as RFC 5891 specifies it. The
two differ on the deviation characters and on transitional processing, and we
have not audited which Handshake labels that can affect.

**Status: OPEN.** `asciiTld` should return `null` on a parse failure and
`classifyHost` should return `null` in turn, so the input falls through to
search rather than to a name lookup. If that is judged too strict, the minimum
is to surface the failure in the decision's `reason` (`idna-failed`) so it is
visible to the interface and to a test. See RT-D5.

---

#### RT-12. The dispatcher's 400 branch is unreachable through a WHATWG `Request`

**What.** `dispatch` answers `400` with no namespace marker when the URL will
not parse *and* names no scheme (`src/router.js:504-518`). A WHATWG `Request`
cannot be constructed with an unparseable URL, so through the documented
interface the branch is dead; it is reachable only from a caller that passes a
plain object with a `url` property, which is what the Electron runtime and our
own tests do.

**The standard says.** WHATWG Fetch defines `Request` to throw on a URL that
does not parse, which is exactly why the branch cannot be reached through it.

**Why.** The dispatcher is written against a slightly wider interface than
`Request` so it can serve the runtime's own request objects.

**Consequence.** None operationally. It is listed because it is the one
dispatch outcome that carries **no** `X-Resolution-Namespace` header —
correctly, since no scheme was established — and an implementer counting the
outcomes from the specification should know why there are four and not three.

**Status: DELIBERATE.**

---

#### RT-13. `hns:` is a standard scheme, and pays the URL Standard's host rule for it

**What.** `hns` is declared to the URL parser as a *standard* (WHATWG
"special") scheme, so `hns://pinner/` has a real tuple origin — and so its host
is parsed by the WHATWG host parser, with every rule that parser applies.

**The standard says.** The WHATWG URL Standard's
[host parsing](https://url.spec.whatwg.org/#host-parsing) and
[origin](https://url.spec.whatwg.org/#concept-url-origin) sections: a
non-special scheme's origin is opaque, and only a special scheme's host goes
through the host parser (and therefore through the
["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker)
and the IPv4 parser).

**Why.** Without a tuple origin there is no `localStorage`, no IndexedDB, no
`crypto.subtle` and no same-origin policy, so no real web application runs
under a Handshake name at all. That is not a trade we are willing to make.

**Consequence.** A Handshake label the host parser mangles cannot be spelled
in an `hns://` URL as typed. The two are one decision and cannot be separated
(SPEC §4.4). Where the consequence lands in *this* part is a single ordering
constraint on the classifier (SPEC §8.2).

**Status: DELIBERATE.** The standard-scheme decision itself is the spine's
`D-4`. The URL convention that works around the host parser's numeric rule is
experimental and carries its own deviations under the `NT` prefix in Chapter 10
(Part B); neither is restated here.

---

### 2. Things we are not sure about

These are the ones we most want argued with.

#### 2.1. Is "everything non-ICANN is Handshake" a defensible default at all?

The rule is stated confidently in SPEC §6.2 and it decides every input. But it
is a *default to a specific commercial namespace* for every label the IANA root
does not contain — which is to say, for the entire future. When ICANN delegates
a new top-level domain, this client resolves it as Handshake until the bundled
snapshot is refreshed and shipped; when a Handshake registrant buys a label
ICANN later delegates, the two swap silently under a user who did nothing.

The alternative — default to search, and require a scheme or a suffix for
Handshake — is what an ordinary browser does, and it makes Handshake names
second-class in a browser whose subject is Handshake names.

We think the rule is right for this client and we are not sure it is right in
general.

#### 2.2. Whether a bare word should navigate (RT-3)

The rule is deliberate and we can defend it inside this browser. What we cannot
say is whether the privacy cost is acceptable in a client whose Handshake
lookups go over DoH rather than a local chain node, because there the resolver
observes every mistyped word. An implementer whose users have no local node
should probably not copy it.

#### 2.3. Where the carve-out list should stop (RT-2)

`.onion` is required by RFC 7686. `.eth` is a judgement. `.crypto`, `.sol`,
`.bnb`, `.zil` and the rest of the alt-roots have precisely the same claim as
`.eth` and get nothing. The honest description of our rule is "we carve out the
namespaces whose misrouting would embarrass us most", which is not a rule.

Two coherent positions exist and we hold neither cleanly: carve out *nothing*
that has no RFC (and accept that ENS traffic goes to a Handshake registrant),
or carve out *every* alt-root we can name (and accept an unbounded,
unmaintainable list that hard-codes a view of which naming systems are real).

#### 2.4. Should a namespace be identified by classification or by scheme? (RT-5)

The `icann`/`web` split is a symptom. The deeper question is whether "namespace"
is a property of the *input* (what the user meant) or of the *scheme* (what will
be dispatched). We use both, and SPEC §4.3 resolves the ambiguity for the marker
by naming one — it does not resolve it for the model.

#### 2.5. Whether the three-state lock is comprehensible

SPEC §10.4 requires TRUSTLESS, TRUSTED and OPEN to be distinguishable. We
believe the distinction is the honest one and we have no evidence that users
read it. It is possible that a third state produces less understanding rather
than more, and that the right answer is two states plus an explanation. We have
not tested this on anyone.

#### 2.6. Whether `partial` is doing two jobs in the lock

Everything that is not fully verified and not outright broken aggregates to
`partial`, so an ordinary `https://` page, an Arweave gateway fetch, an ENS
name, a Gemini connection with no certificate check and a Nostr page whose
completeness cannot be proven all land in the same state. The step list
distinguishes them and the summary names the weak steps, but the single
indicator does not. We do not know whether that flattening is a simplification
or a loss.

#### 2.7. Citations we have not verified against the source text

Two claims in [`REFERENCES.md`](REFERENCES.md) rest on our recollection rather
than on the document: that ICANN's board reserved `internal` for private use in
2024, and that `corp` and `home` were deferred indefinitely from the new-gTLD
programme on name-collision grounds. Both are load-bearing for RT-1. We cite the
standing ICANN pages that describe the programmes rather than the board
resolutions themselves, and we would rather be corrected than have this read as
settled.

#### 2.8. Whether `search://` should be a scheme at all

Making the metasearch a scheme buys it a real origin and puts it in the same
registry as everything else, which is tidy. It also means a search results page
is a *navigable origin* that history, bookmarks and session restore all carry —
so a query string ends up in more places than a query typed into a search
engine's own page would. We think the tidiness is worth it. We are not certain
the storage footprint is.

---

### 3. Open design items

Changes to the reference implementation we think are right and have not made.
Nothing here is normative.

#### RT-D1. Derive the privileged-scheme declaration from the scheme table

Two hand-maintained lists of the same 32 schemes: `SCHEME_TABLE` and the
Electron privilege declaration in the browser's `src/main.cjs`. The consequence
of their diverging is not a lint failure — a scheme that is dispatched but never
declared is unknown to Chromium, and loading one as a main-frame document has
hard-crashed this application on Windows.

**Recommendation.** Put the privilege object in the table row and have the
declaration site map over the table. The declaration site is CommonJS and the
router is an ES module, so the mechanical version is to move `SCHEME_TABLE` into
a `.cjs` both can read — the same move `icann-tlds.cjs` and `reserved-names.cjs`
already make for exactly this reason. If that is judged too invasive, the cheap
version is a test that reads the declaration file as text and asserts a
`scheme: '<name>'` literal exists for every table row and nothing else; the
browser's `tests/hns/nav-scheme-coverage.test.js` already does precisely this
for the navigation allowlist, so the pattern is established.

#### RT-D2. Give `icann` a place in one namespace vocabulary

`NAMESPACES.ICANN` is used by the classifier and appears in no table row, so a
classification and a dispatch marker answer with two dialects for the same page
(RT-5). SPEC §4.3 says which dialect the marker speaks, which removes the
ambiguity without removing the split.

**Recommendation.** Drop `NAMESPACES.ICANN` and have `classifyHost` return `web`
for an ICANN name, keeping `reason: 'icann-tld'` as the finer signal — one
vocabulary, and the classifier can still say "this is a DNS name" by reading the
reason. The alternative (splitting `web` into `icann` and `web`, and making
`namespaceForScheme` host-aware) is more faithful to what a user meant and
considerably more machinery; either is better than two dialects, and the choice
should be written down wherever it is made.

#### RT-D4. Register `hns:` with IANA

Of the 19 unregistered schemes, 18 are application-private and should stay that
way. `hns:` is not: it is meant to interoperate, other Handshake clients already
spell it the same way, and a Provisional registration under RFC 7595 needs a
specification of any stability and an email to the reviewer (RT-6).

**Recommendation.** File it. This repository contains the specification RFC
7595 asks for, and nothing in the code changes. It removes the situation where
the scheme this whole stack is named for has no entry anywhere a second
implementer could find.

#### RT-D5. Make the IDNA pass fail closed

`asciiTld` swallows a URL-parser rejection and falls back to the raw final
label, so a host the parser refuses is still classified — on a label that was
never normalised (RT-11). The failure direction happens to be safe; it is
silent, which is the objection.

**Recommendation.** Return `null` from `asciiTld` on a parse failure and have
`classifyHost` return `null` in turn, so the input falls through to search
rather than to a name lookup. If that is judged too strict, at minimum surface
the failure in the decision's `reason` (`idna-failed`) so it is visible to the
interface and pinnable by a test.

---

### 4. What this chapter leaves out

1. **The Electron wiring.** The file that declares scheme privileges before
   application startup, and the file that binds every scheme to the dispatcher,
   are entirely Electron-bound and are not extracted here. Their *contract* is
   specified normatively in SPEC §4.4 and §5. If you are implementing from the
   specification, that layer is yours to write — and RT-D1 says what we think is
   wrong with ours.

2. **The address bar and the PAC script.** Both live in the browser tree. The
   address bar requires the shared `src/classify-host.cjs` and so has no rule
   of its own to extract; the PAC generator's ASCII-only copy (RT-7) does, and
   the test that evaluates the generated script beside `classifyHost()` runs
   there. The corpus it uses is reproduced in
   `tests/classification-order.test.js` as a table the router is held to on its
   own.

3. **The per-namespace resolvers.** What happens *after* a namespace is chosen
   belongs to the spine (for Handshake) and to the sibling chapters (for
   everything else). This part stops at the decision.

4. **The ICANN transport policy itself.** SPEC §10.3 specifies what the trust
   step must *say* about an ICANN lookup. Which resolver is chosen, how the
   oblivious bridge is started and what `dns.mode` means are the ICANN
   chapter's.

5. **The search backend.** The `search://` URL grammar is specified (SPEC §9.1).
   The metasearch behind it — which engines, how results are merged, the bang
   prefixes — is a product, not a resolution mechanism, and is not specified.

6. **The numeric-TLD URL form.** SPEC §8.2 states only the ordering constraint
   it places on the classifier. The form itself is experimental and is specified,
   with its own deviations under the `NT` prefix, in Chapter 10, Part B.


---

## Chapter 1 — Handshake

_Source: [`namespaces/handshake/DEVIATIONS.md`](namespaces/handshake/DEVIATIONS.md)._

Every place this chapter's implementation departs from a standard it cites,
from common resolver practice, or from its own stated design — plus every place
we are not sure we have made the right call, and every design item that is open.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

Identifiers are prefixed `HS-` so they cannot collide with another chapter's.
Everything below is measured against `../../src/`, the reference implementation
of this chapter, and its tests in `../../tests/`.

---

### 1. Deviations

#### HS-1. TTLs are ignored; a flat 60-second positive cache

**What.** A successful resolution is cached for 60 seconds regardless of the
records' TTLs. Only positive results are cached — every failure kind
(`unreachable`, `dnssec-fail`, `unregistered`) is re-asked. `../../src/resolver.js`.

**The standard says.** RFC 2181 §5.2: the TTL is the operator's statement of
how long an RRset may be reused, and every record in an RRset carries the same
one.

**Why.** The cache exists to stop a page's own subresources re-resolving the
name a dozen times, not to be a recursive resolver. A publish flow that moves a
pointer invalidates its own name explicitly (`forget()`), which is the case a
short TTL is usually protecting.

**Consequence.** A record with a TTL below 60 s is honoured late. A record with
a very long TTL is re-fetched more often than the operator asked. Neither is a
security property; both are impolite to the authoritative server.

**Status.** OPEN. Honour the minimum TTL of the RRsets a resolution rests on,
clamped to a floor and a ceiling, and keep the rule that failures are never
cached (SPEC §6.8). It is a small change and there is no argument against it.

---

#### HS-2. IPv6: a dual-stack name is reached over IPv4 (resolved 2026-09-06)

**What.** Until 2026-09-06 only `A`, `GLUE4` and `SYNTH4` were read and an
IPv6-only Handshake site did not resolve at all. `AAAA` is now asked beside
`A` at the zone, `GLUE6`/`SYNTH6` are read beside `GLUE4`/`SYNTH4`, and the
SPV reader decodes the `_<base32hex>._synth.` referral hsd's root server
renders a SYNTH record as (before this, no SYNTH apex resolved from an SPV
node: the `_synth` name was kept as a nameserver and asked, on port 53, for
its own address). §6.5f, §6.4, §6.2; `../../src/resolver.js`,
`../../src/spv.js`; `../../tests/ipv6.test.js`.

**What remains a deviation.** The family rule is *IPv4 when the name has one*,
not RFC 6724 / RFC 8305 (Happy Eyeballs) address selection. A dual-stack site
is always dialled over IPv4, even from a network that has only IPv6; a
nameserver with only a `GLUE6` is chosen in NS order, not skipped for a
sibling with both when the client has no IPv6 route.

**The standard says.** RFC 6724 orders candidate addresses by policy and
RFC 8305 races the families; both prefer IPv6 where it is reachable.

**Why.** One address, chosen once, is what the whole path is built on — the
SSRF guard, the DANE dial, the SOCKS tunnel and the trust panel all name one
address. IPv4 reaches a site from every network today; a race would add a
second connection attempt to the most-measured path for a case with no known
Handshake site in it.

**Consequence.** An IPv6-only *client* network cannot reach a dual-stack
Handshake site (it can reach an IPv6-only one). Rare, and reported honestly
as a connection failure rather than as a broken name.

**Status.** DELIBERATE for now. Revisit when an IPv6-only client network is a
case anyone has hit: the change is contained in `preferV4` and the one
nameserver-selection loop.

---

#### HS-3. SVCB / HTTPS records are parsed but never queried, and ECH is not usable

**What.** A complete RFC 9460 parser exists and is tested against real
Cloudflare RDATA, including a live 71-byte ECHConfigList. Nothing in the
resolution algorithm ever issues a query for type 65. `../../src/dns-query.js`.

**The standard says.** RFC 9460 defines the SVCB/HTTPS RR and expects a client
to query it before connecting; RFC 9848 requires the client to take its
ECHConfigList from that record.

**Why.** Two independent reasons.

1. Querying type 65 costs a round trip on every A-record navigation, and no
   Handshake zone publishes one today — including ours. Our own authoritative
   server cannot serve the record.
2. Even holding a valid ECHConfigList the transport could not use it. The
   `hns://` transport is a raw Node TLS socket, and **Node exposes no ECH
   option at all**. There is nothing to hand the config to. (Chromium does ECH
   for ordinary `https://` on its own, outside this code path.)

**Consequence.** `hns://` connections send the server name in the clear in the
TLS ClientHello. An observer learns which Handshake site is being visited even
though the DNS lookup may have been oblivious — so the ODoH work is partly
undone by the transport. Any SvcParam an operator publishes (`alpn`, `port`,
`ipv4hint`) is ignored.

**Status.** OPEN, and blocked on something that is not ours: Node's TLS
bindings. Until they expose ECH, the honest position is this entry rather than
listing ECH as "planned". The cheap half — reading the `port` SvcParam — is
worth doing together with HS-6, not before it.

---

#### HS-5. One DANE profile; an unusable TLSA RRset is refused rather than ignored

**What.** Only usage 3 / selector 1 / matching type 1 (DANE-EE, SPKI, SHA-256)
is accepted. Any other parameter combination is treated as a **mismatch** — the
connection fails — not as an unusable record. `../../src/dane.js`.

**The standard says.** RFC 7671 §4.1: when *every* record in a TLSA RRset is
unusable, the client should treat the RRset as absent and fall back to PKIX.

**Why.** `3 1 1` is what the Handshake ecosystem standardised on. Supporting
usages 0/1/2 would require implementing PKIX chain validation, which
reintroduces exactly the CA trust this design exists to remove — and there is
no PKIX to fall back to for a Handshake name in the first place, because no CA
can issue for one. Falling back on confusion is how a pinning scheme quietly
stops pinning.

**Consequence.** A zone that publishes, say, `2 0 1` gets a hard connection
failure here where a §4.1-conforming client would connect over PKIX. For a
Handshake name that "PKIX connection" would be to a certificate no CA will
sign, so in practice this costs nothing — but it is a real deviation from the
RFC's text.

**Status.** DELIBERATE. The RFC's fallback assumes a PKIX world that does not
exist for these names; refusing is the only behaviour that keeps the pin
meaning what it says.

---

#### HS-6. The TLSA owner is always `_443._tcp`; a port in the URL is ignored

**What.** The pin is looked up at `_443._tcp.<host>` whatever port the URL
names, and the connection is made to 443 (or 80) regardless.
`../../src/resolver.js`.

**The standard says.** RFC 6698 §3: the TLSA owner name is
`_<port>._tcp.<host>` for the port the connection is actually made to.

**Why.** Not a decision so much as an unfinished one. It is coupled to HS-3:
the right fix reads the HTTPS record's `port` SvcParam, connects there, and
moves the TLSA owner to `_<port>._tcp.<host>`. Doing the port without the
record, or the record without the port, gets the pin wrong.

**Consequence.** A Handshake site on a non-standard port is unreachable over
`hns://`.

**Status.** OPEN, deliberately paired with HS-3. Read the port from the URL and
from the HTTPS record in the same change, and derive the TLSA owner from the
port actually dialled.

---

#### HS-8. A DoH-resolved TLSA is used as a pin, on the resolver's word

**What.** On the DoH fallback path a `_443._tcp.<host>` TLSA lookup is made and
the returned record **is used to pin the TLS handshake**, marked as the
resolver's word. A DoH NODATA for that owner allows a plaintext connection; a
DoH lookup that *fails* refuses to connect. `../../src/doh.js`.

**The standard says.** RFC 6698 assumes the TLSA record arrives through a
DNSSEC-validating path; RFC 8484 provides a channel to a resolver, not a proof.
A pin taken on a resolver's word is not the guarantee DANE describes.

**Why.** A DoH path that reads no TLSA means an attacker who merely breaks the
chain path — drop TCP/53 to the authoritative server, the resolver throws, the
browser falls back — downgrades **every** DANE-pinned Handshake site to
plaintext. Pinning to the resolver's word is strictly stronger than the
plaintext it replaces.

**Consequence.** A malicious DoH resolver can substitute a pin, and can assert
"no pin exists" and get a plaintext connection. The trust panel says so — the
lock reads TRUSTED, not trustless, and names the resolver — but a user who does
not read the panel gets a weaker guarantee than the closed lock suggests.

**Status.** DELIBERATE as against the alternative (reading no TLSA at all,
which is a strictly worse outcome). The residual gap is that nothing remembers
a host was ever pinned; that is HS-12, and it is open.

---

#### HS-9. A CNAME target's own RRset is not validated under the target's owner

**What.** The `CNAME` RRset itself **is** validated: on the address path a
`CNAME` in a signed zone is not followed until the RRset validates to the
on-chain DS anchor, with the RFC 4035 §5.3.4 wildcard proof where the answer was
wildcard-expanded (SPEC §6.5f). What is not done is the rest of RFC 4035
§5.3.1's chain: the **target's** RRset is not validated under the target's own
owner name. In practice the target of a Handshake `CNAME` is an ICANN host,
whose address comes back through the ICANN-host lookup seam (SPEC §6.11) and is
therefore ICANN's word, not the Handshake zone's. `../../src/resolver.js`.

**The standard says.** RFC 4035 §5.3.1 describes validating each RRset in a
CNAME chain under its own owner name.

**Consequence.** Two things, of different sizes. A `CNAME` to an ICANN host
works and the resolution is reported as unvalidated from that point on
(`dnssecValidated` stays false and the trust panel names the source of the
address) — which is the truth and cannot be anything else, because the target's
zone is not anchored to the Handshake chain at all. A `CNAME` *within* a signed
Handshake zone, pointing at another name in the same zone or a delegated one, is
not chased and validated the way §5.3.1 describes; its RRset is validated, its
target's is not.

It also decides which half of RFC 7671 §7.2 the DANE base-domain rule rests on
(SPEC §8): because the expansion is not *secure* in the RFC's sense, the pin is
correctly looked up at the original name.

**Status.** OPEN, and narrow: what remains is chasing the target
inside the zone and validating each RRset under its own owner. Keep the
ICANN-target case reported as unvalidated.

---

#### HS-10. No RRSIG clock-skew tolerance

**What.** The RRSIG inception/expiration window is checked against the real
system clock with zero tolerance. `../../src/dnssec.js`.

**The standard says.** RFC 4034 §3.1.5 defines the window; it does not require
a tolerance, and it does not forbid one.

**Why.** unbound and BIND allow none by default either, so this is
conventional. There is also an explicit guard preventing any module in the
resolution stack from reading a clock other than the one guarded call site,
pinned by `../../tests/dnssec-clock-guard.test.js`.

**Consequence.** A machine with a badly wrong clock fails every signed zone
closed. That is the correct direction, but it is a total outage rather than a
degraded one, and a user has no way to tell it apart from an attack.

**Status.** DELIBERATE, and recorded because the failure mode is confusing
rather than because the rule is doubtful. What could improve is the *message*,
not the tolerance: a validator that notices every zone failing at once can say
"this machine's clock is wrong" instead of "this zone is bogus".

---

#### HS-11. Standards not implemented at all

**What and why.** Listed so their absence is a decision on the record rather
than an oversight.

| Standard | Why not |
|---|---|
| **RFC 9462 DDR** (Discovery of Designated Resolvers) | Nobody's browser does it and the records are live. An opportunity not taken, not a gap we are unaware of. |
| **draft-ietf-dnsop-deleg** | In WG Last Call; the RR types are not allocated at IANA, so nothing can interoperate. Revisit on allocation. |
| **RFC 5011 trust-anchor rollover** | Structurally inapplicable: the anchor is a DS record on the Handshake chain, which rolls by a chain transaction, not by a hold-down timer. We use §2.1 (the REVOKE bit) and nothing else. |
| **RFC 6891 extended RCODEs, RFC 8914 EDE** | The OPT record is written to carry the DO bit and dropped on parse. Extended DNS Errors would make several failure messages much better; they are not read. |
| **PKIX chain validation on the `hns://` path** | Deliberate — see HS-5. |

**Consequence.** Per row: no designated-resolver discovery, no DELEG, no
automated anchor rollover (and none needed), failure messages coarser than the
protocol allows, and no CA path on `hns://` by design.

**Status.** DELIBERATE for RFC 5011 and PKIX; OPEN for RFC 8914 EDE, which is
the cheapest real improvement in the table — read the OPT record back and carry
the extended error into the failure kind and the panel text.

---

#### HS-12. A DANE mismatch re-resolves once, then fails closed; there is no "pinned before" memory

**What.** When the certificate does not match the pin, the cache entry is
dropped and the name is resolved once more; a second mismatch fails closed.
Nothing records that a host was ever pinned. `../../src/resolver.js`.

**The standard says.** RFC 7671 §8.1 expects operators to pre-publish the new
TLSA before rotating the key, which would make any retry unnecessary.

**Why.** Real operators sometimes do not pre-publish, and a browser that fails
permanently on a few seconds of skew is unusable. One retry recovers the
"published the TLSA seconds late" case without weakening the pin — the second
answer must still match.

**Consequence.** The retry itself is sound. The gap is the missing memory: break
the chain path entirely, answer over DoH with a proven "no TLSA", and a host
that has always been pinned is served in the clear, because nothing knows it
used to be pinned.

**Status.** OPEN. An HSTS-shaped rule — *a host that ever resolved chain-proven
with a pin refuses plaintext until a proven absence says otherwise* — closes the
last availability-driven downgrade. It also introduces a persistent, per-host,
attacker-influenceable state store, whose own failure mode is pinning a host
into unreachability; the shape needs deciding before the code (§2.4).

---

#### HS-13. Product decisions that deviate from what the naming systems themselves say

These are not standards deviations so much as places where we resolve a conflict
between systems in a way the systems' own advocates would dispute.

**What, and why.**

- **ICANN wins for ICANN TLDs, even though the Handshake root is the root.** A
  dotted name whose final label is a delegated ICANN top-level domain is an
  ICANN domain; every other name is a Handshake name. In Handshake's own model,
  ICANN TLDs are reserved and claimable with a DNSSEC proof, and a claimed one
  would make the chain authoritative — we route to ICANN anyway. That is what
  makes the browser safe to use as somebody's only browser.
- **Every other alt-root is Handshake.** `.crypto`, `.sol`, `.bnb`, `.nft` and
  anything else non-ICANN, non-`.eth`, non-`.onion` goes to whoever holds the
  Handshake TLD of that name. So `brad.crypto` resolves to the Handshake
  `crypto` owner's records, not to Unstoppable's registry. Consistent
  application of the rule above; other implementers may reasonably differ.
- **A `_<chain>` pseudo-TLD other than `_op` is not read.** HIP-5's own shipped
  example is `_eth` (ENS on Ethereum mainnet). A top-level name that delegates
  through one — the Handshake name `hns` does — is resolved here through its
  remaining ordinary `NS` records. The `_op` route itself is Chapter 10.
- **ODoH is implemented and is not called a privacy feature.** Two ODoH relays
  exist worldwide and one is run by a target operator, so RFC 9230's
  non-collusion assumption does not hold at that scale. The code stays; the
  interface must not claim privacy from it.
- **A single authoritative "hop" is really a bounded walk.** A registry TLD
  holds none of the names it sells, so it *refers* rather than answers, and its
  NS targets are frequently themselves Handshake names (§2.2).

**Consequence.** A user of this implementation reaches ICANN names the way
every other browser does, reaches alt-root names as their Handshake owner
publishes them (which is not what the alt-root's own client would show), and is
told the truth about what ODoH buys at today's scale.

**Status.** DELIBERATE, each of them. The ODoH line is unusual and worth
stating: most implementations claim the property the RFC describes rather than
the one the deployment provides.

---

#### HS-14. Internationalized names go through the URL parser, not through our own IDNA

**What.** A Unicode host is punycoded by handing it to `new URL()` and reading
back `hostname`, before it reaches the resolver or the ICANN comparison.
`../../src/router.js`.

**The standard says.** RFC 5890/5891 define IDNA2008; UTS #46 defines the
compatibility processing the WHATWG URL Standard actually requires. The two
differ on a small set of characters (the deviation characters, and transitional
processing).

**Consequence.** What is implemented is UTS-46 as the URL Standard specifies
it, not IDNA2008 as RFC 5891 specifies it. Which Handshake labels this can
affect has not been audited.

**Status.** OPEN, and under-examined. The work is an audit first — enumerate the
deviation characters against the registered Handshake label set — and a decision
second; there is no point implementing IDNA2008 by hand before knowing whether
any real name differs.

---

#### HS-15. Nameserver failover at query time (resolved 2026-09-06)

**What.** Until 2026-09-06, once a nameserver had been chosen the first query
failure against it was final. Now `_withFailover` in `../../src/resolver.js`
walks the zone's nameservers lazily, in the zone's order, each with its glue
addresses IPv4 first, and puts the whole question to the next one when a
server cannot be ASKED — unreachable, timed out, or answered a different
question. An answer that fails validation is returned as it is: a second
server cannot make a forged answer honest, and asking it would be shopping.
`../../tests/nameserver-failover.test.js`.

**The standard says.** RFC 1034 §4.3.2 and ordinary resolver practice: a zone's
NS set is a set, and a resolver is expected to try another server when one does
not answer.

**Consequence.** A zone with two nameservers, one of which is dark, does not
resolve — even though the other one would have answered.

**Status.** RESOLVED as recommended. What remains a limitation: a server that
answers slowly rather than not at all costs its full timeout before the next
is tried; there is no parallel race.

---

#### HS-16. Changing the anonymization mode restarts the SPV node, which re-syncs

**What.** The chain path survives anonymization by pointing the SPV node's own
peer traffic at the device-local SOCKS proxy and dialling this
implementation's authoritative queries through the same port (SPEC §6.11). hsd
reads its `--proxy` setting **once, at start**, so a change of mode is a
respawn of the node: the process is stopped and started with the new setting,
and its headers sync again — from the persisted chain in the ordinary case, or
from scratch for a node running entirely in memory (the fallback when no native
LevelDB backend is available). Until it reaches the tip its proofs are null,
so resolution rides DoH over the proxied fetch in the meantime, exactly as it
does at launch. An adopted or externally-configured node is not restarted at
all: the wish is recorded and the caller can see that the running node does not
honour it. `../../src/spv.js` (`setProxy`, `_nodeIsProxied`).

**The standard says.** Nothing. This is a property of hsd's command line, and
through it of every client that spawns hsd rather than linking it.

**Consequence.** Switching between Fast and Private (the one control,
`SPEC.md` §4.2) costs a window — seconds from a persisted chain, minutes
from scratch — in which every Handshake name resolves `unverified` over DoH
rather than chain-proven, and the trust panel says so while it lasts. In
Private the interim is narrower still: the DoH answer is oblivious or the name
is `unreachable` (SPEC §9.3), so the window costs availability where in Fast it
costs a disclosure. The guarantee a page load receives therefore depends on the
clock (§2.5) at one more moment than it used to: not only at launch, but at
every mode change. It is a degradation to the weaker-but-honest path, never to
a false answer, and the alternative — keeping a node whose peers see the real
address while protection is on — is worse.

**Status.** OPEN, and the fix is not in this tree. The clean answer is a node
that can be told to change its proxy at runtime (an hsd RPC, or a peer manager
that re-dials) so a mode change costs a reconnection instead of a re-sync; the
cheap mitigation is to keep the chain directory persisted on every platform, so
the re-sync is always the short one. A composition that spawns the node
**MUST** report the interim honestly rather than presenting a DoH answer as
chain-proven.

---



### 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each is
a real decision that is currently shipping, and each could be wrong.

#### 2.1. SVCB/HTTPS and ECH (HS-3)

We are not sure the right answer is "query type 65 on every navigation". The
cost is a round trip per A-record site for a record essentially no Handshake
zone publishes. A DNSSEC-signed zone could advertise its presence more cheaply
— that is roughly what the type bitmap in an NSEC record already does, and
those are already fetched for other reasons. We have not worked this out.

#### 2.2. Registry TLDs that refer, and NS targets that are themselves Handshake names

A registry TLD (`persist`, `hns`) holds none of the names it sells. Asked about
`maya.persist`, its nameserver returns a **referral** — NS records with no SOA —
not an answer. An implementation that treats the authoritative hop as literally
one query resolves every such name as unregistered.

So the hop is a **bounded walk**: `_fromZone` re-enters itself per delegation up
to `MAX_DELEGATIONS`, a referral is told from a NODATA by the presence of an SOA
(RFC 1034 §4.3.2), and `_descend` validates the parent's DS for the child —
under keys the on-chain DS anchors — before anything the child says is believed.

Two things about this we are not certain of:

1. **An NS target that is itself a Handshake name.** `pinner.hns` delegates to
   `ns1.lumeweb`, which is not resolvable in ICANN's DNS at all. It is resolved
   from the `lumeweb` chain resource (`_chainAddress`). That is right, and it is
   also a second chain lookup inside a resolution, with its own failure modes
   and its own cache. Whether the depth of that recursion should be bounded
   separately from `MAX_DELEGATIONS`, and what a cycle looks like, is not fully
   worked out. The related budget question is HS-D1.
2. **Bailiwick.** Sideways and upward referrals are refused. We believe the
   check is right and it is tested, but "which referrals are in bailiwick" is
   the classic place a resolver gets subtly wrong, and we would like another
   pair of eyes on it.

#### 2.3. What the DoH fallback actually promises

When the chain path fails, resolution falls back to DoH (`query.hns.one`, then
`hnsdoh.com`, then `dns.easyhns.com`). Everything resolved that way is marked
as the resolver's word and the trust panel names the resolver. Three things we
are not settled on:

- **In Fast mode the fallback is unconditional on infrastructure failure.**
  Any thrown error on the chain path leads to a DoH attempt, oblivious first and
  plain beneath it. That is availability-first. An attacker who can reliably
  break the chain path can therefore *choose* which resolver answers, and gets
  HS-8's weaker pin semantics as a bonus. In Private mode (SPEC §9.3) the plain
  transport is never taken, so the same attacker gets the oblivious resolver's
  answer or nothing — narrower, and still the resolver's word. We think the
  answer in both modes is the "pinned before" memory (§2.4) rather than
  removing the fallback, but we are not sure.
- **Where the fallback is *not* allowed is settled**, and it is the part that
  matters: a synced chain's authoritative `unregistered` is final, and a DoH
  answer never overrides it (SPEC §9.1). DoH answers only the three states in
  which the chain said nothing — no node, a node short of the tip, and a thrown
  chain-path failure — and even on the third a DoH `unregistered` is not adopted
  in place of the failure. What is left unsettled is the paragraph above, which
  is about availability, not about precedence.
- **What "trusted" should mean in an interface.** The lock has three visible
  states, not two (SPEC §4.1). Whether that is comprehensible to anybody who has
  not read this specification is an open product question, not just an
  engineering one.

#### 2.4. DANE pin rotation windows (HS-12)

Exactly one re-resolve is allowed on a mismatch. A too-generous retry policy is
a downgrade oracle; a too-strict one breaks sites during a legitimate rotation.
We have no data on what real Handshake operators' rotation windows look like,
so "one retry" is a guess, not a measurement.

The related and larger gap is that there is no memory of having pinned a host
before. An HSTS-shaped rule would close the last availability-driven downgrade,
and would introduce a persistent, per-host, attacker-influenceable state store,
which is its own class of problem (pinning a host into unreachability). It is
not built and we are not sure of the right shape.

#### 2.5. What an SPV proof actually proves

The chain path's guarantee is: *hsd, running on this machine, verified an Urkel
tree proof for this name against a tree root committed in a block header on the
most-work header chain it has seen.* That is a strong property and it is the
reason this project exists. It is not the same as running a full node:

- SPV follows the most-work header chain. It does not validate blocks, so it
  inherits the standard SPV assumption that the most-work chain is the valid
  chain.
- The browser process reads the verified result from the local hsd over
  loopback RPC or the node's own root nameserver. It trusts that local process.
- A node that is still syncing returns null proofs. That is reported
  `unreachable` and the client rides DoH until it reaches the tip, then flips to
  chain proof mid-session. That is correct, but it means the guarantee a given
  page load got depends on the clock, which the trust panel has to explain and
  which nobody expects. Turning anonymization on or off restarts the node and
  re-opens that window deliberately (HS-16), so the clock dependence is not
  only a launch-time artefact.

#### 2.6. Whether a proven absence should raise the lock as far as it does

A signed zone's proven "no TLSA", beside a validated `A` RRset, is treated as a
fully validated resolution over plaintext (SPEC §8). Every record the answer
rests on is chained to the on-chain DS, so the claim is true. It still means a
closed-book plaintext connection is reported as validated, and we are not
certain users read the distinction the way the model intends.

#### 2.7. What DNSLink interoperation is worth while the gateways it was for retire

Reading DNSLink (SPEC §10.1) is justified as the migration path, and the
ecosystem that path leads to is contracting on a published timetable: the public
gateways `ipfs.io` and `dweb.link` retire on **2026-09-21**, and the Shipyard
bootstrap nodes that every default kubo configuration dials on **2026-09-30**.

What that changes and what it does not:

- **The record convention does not retire.** `_dnslink.<name> TXT dnslink=/…`
  is read by kubo, IPFS Companion and Brave in the client, not by a gateway.
  A site published for those clients keeps working, which is exactly the
  interoperation the read buys, and it becomes *more* valuable rather than less
  when the hosted middlemen go away.
- **A gateway URL in documentation does retire.** This chapter names no public
  gateway, and where an example needs one it is a gateway whose operator is
  known to whoever publishes the example (`https://pinthis.cloud/ipfs/<cid>`).
  Quoting `ipfs.io` would put a dead host in a specification.
- **Retrieval is somebody else's chapter, and it has the harder problem.**
  Losing the default bootstrap peers is a Chapter 3 concern (an implementation
  that ships a node needs peers of its own); it does not touch what a name
  *means*.

The uncertainty is one of emphasis rather than mechanism: we are confident the
read is right, and not confident how long "the ecosystem reads DNSLink" stays
true if the ecosystem's own defaults keep shrinking. If it stops being true the
read costs one query per resolution and should be re-argued, not quietly kept.

---

### 3. Open design items

Items considered and not applied. Each states the problem and what we would do.

#### HS-D1. No per-resolution query budget on NS hops

A resolution's cost is bounded only by a delegation depth of 3 and a per-query
timeout. Nothing counts the *total* queries one navigation can cause: each zone
in the walk fetches DNSKEYs, TXT, `_dnslink` TXT, A and TLSA, each nameserver
name may need its own chain lookup and its own queries, and a hostile registry
TLD can compose those into far more work than any legitimate zone needs. The
DNSLink query (SPEC §6.5d) is one more per zone on every name, including a plain
address-record name that carries no pointer at all, which is the price of being
able to detect a disagreement rather than only a missing record; on the DoH
route it is asked in parallel and costs no round trip, on the
authoritative-DNS route it costs one.

**Recommendation.** Thread a counter through the resolution context — one
object, incremented at the single place a query is issued — cap it at roughly
32 queries per resolution, and refuse with `unreachable` (never `unregistered`,
which would state something false about the name) when it is exhausted. A cap
in the resolution context also bounds the nameserver-address recursion of §2.2
without a second mechanism.

#### HS-D2. `hns:` has no IANA URI scheme registration

`hns:` is used as a standard, secure, web-origin-bearing scheme, and it appears
in no IANA registry. Anyone else may use the same token for something else, and
a browser vendor asked to support it has nothing to point at.

**Recommendation.** File a **provisional** registration under RFC 7595 §3.8:
scheme name, syntax (SPEC §5), the operations it supports, security
considerations by reference to SPEC §11, and this document as the
specification. A provisional registration costs an email, does not require a
standards-track document, and is the only thing that makes the scheme name
citable.

---

### 4. What this chapter leaves out

Four things this chapter deliberately does not contain, each of which affects
how the code reads:

1. **The composition layer.** In Wildroot, `src/hns/index.js` is the Electron
   `hns://` protocol handler: it chooses per request between the chain resolver
   and DoH, applies the DoH fallback policy, injects the two egress seams of
   SPEC §6.11 (the SOCKS dialler for the authoritative hop and the DoH/ODoH
   client for ICANN hosts) and the proxied fetch, keeps the SPV node's proxy
   setting following the delivery mode, opens the TLS connection through
   `connectDane` with the route the mode decides (SPEC §8.1), applies the
   Private-mode decisions at the pointer (SPEC §10.2) and turns a private
   lookup failure into the page and trust state of SPEC §9.3, and records the
   trust steps. It is Electron-bound and is not extracted into `../../src/`;
   the pieces that are — `dane-connect.js`, `socks-dial.js`, `doh.js`,
   `delivery-mode.js` — are the ones its policy rests on. Its *policy* is
   specified normatively here (SPEC §6.11, §8, §9, §10.2); the deviations that
   live in it is HS-8, and the restart cost of the proxy switch is
   HS-16 — but the code for them is not in this tree. An implementation of this chapter writes
   that layer itself, and the rule that makes it auditable is that the seams are
   injected rather than defaulted: a composition that omits one gets a working
   resolver that leaks, silently, because it works.

2. **Content fetching.** What happens to an `ipfs=`, `ar=`, `hyper=` or torrent
   pointer once resolved — the IPFS node, the Arweave gateway, the torrent
   client — belongs to Chapters 3, 4 and 9. This chapter ends at the pointer,
   and states only what a pointer's *kind* implies about verification (SPEC
   §10), because that changes the trust state.

3. **The `_op` route.** A top-level name that delegates through an
   `<registry>._op.` NS record is resolved by Chapter 10, which is marked
   experimental. This chapter states where that route is entered and what its
   trust step is, and nothing else about it.

4. **The browser chrome.** How the address bar, the padlock and the security
   panel render the model of SPEC §4 is not specified here; SPEC §11.4 says only
   what such an interface must not claim.


---

## Chapter 2 — ICANN names

_Source: [`namespaces/icann/DEVIATIONS.md`](namespaces/icann/DEVIATIONS.md)._

Every place this chapter's implementation departs from a standard it cites,
from common browser practice, or from its own stated design — plus every place
we are not sure we have made the right call, and every change we intend to make
and have not.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

Entries are numbered `IC-n`, and the open design items `IC-Dn`, to keep them
distinct from the spine's `D-n` and from the other chapters'. Every reference in
[`SPEC.md`](SPEC.md) uses those numbers.

Three path conventions are used. `../../src/…` is a module in this
repository's shared `src/`. A bare `src/dns-policy.js` or
`src/icann-tld-snapshot.js` is this chapter's own `namespaces/icann/src/`.
Every other `src/…` is in the Wildroot browser tree; those are given with line
numbers so a claim can be checked against the code that makes it.

---

### 1. Deviations

#### IC-1. The ICANN boundary is a build-time snapshot, not a live lookup
*IANA root zone database · `../../src/icann-tlds.cjs`, `src/icann-tld-snapshot.js`*

**What.** The set of delegated ICANN top-level domains is fetched from IANA at
build time, rendered into a committed source file, and shipped. Nothing fetches
it at runtime. The snapshot is IANA version 2026090500 (5 September 2026),
1,438 labels.

**The standard says.** IANA publishes the root zone database and its
machine-readable form (`https://data.iana.org/TLD/tlds-alpha-by-domain.txt`) as
the authoritative list of delegated top-level domains. It is a live registry;
nothing about it is versioned for offline use.

**Why.** A privacy browser does not phone home at startup, and the classifier
has to answer a keystroke without waiting for the network. The same reasoning
governs the ad-filter lists.

**Consequence.** The boundary is only as fresh as the last release, and drift
misroutes names in both directions (SPEC §2.4). The direction that grows is
*missing* delegations: ICANN's 2026 round drew roughly 1,600 applications, and
each delegation turns a string that resolves as a Handshake name today into an
ICANN TLD — so a browser running an old snapshot keeps handing that domain to a
Handshake resolver, where whoever registered the corresponding chain name can
answer for it. A live drift alarm compares the snapshot against IANA on every
networked test run and reports both directions
(`tests/hns/icann-tlds-live.test.js`); it is deliberately an alarm and never a
build gate, because a red build caused by IANA being unreachable teaches
everyone to ignore the alarm. `tests/icann-tld-snapshot.test.js` here adds the
offline half: the committed file is byte-for-byte what the generator produces,
so a hand-edited boundary fails a test that needs no network.

**Status: OPEN.** The bundling itself we would defend and do not intend to
change. What is open is the cadence: nothing forces a refresh before a release
and nothing measures how stale a shipped snapshot was. We recommend a
release-blocking check on the snapshot's age — the `Version` line is a
`YYYYMMDDNN` integer, so "older than N days" is a one-line offline assertion —
together with the offline half of the alarm living in the browser tree (IC-D4).
What N should be is §2.4.

---

#### IC-2. ICANN wins a label that is also a Handshake TLD, and every other alt-root is Handshake's
*`../../src/classify-host.cjs:87-116`*

**What.** Two rules, one decision procedure. A dotted name whose final label is
in the IANA snapshot is an ICANN domain, even if the same string is a
registered Handshake top-level name with published records. Any other
non-`.eth`, non-`.onion`, non-reserved label is a Handshake name — including
`.crypto`, `.sol`, `.bnb` and `.nft`, which go to whoever holds the Handshake
name of that string rather than to that alt-root's own registry.

**The standard says.** Handshake's own model reserves the ICANN labels and lets
their ICANN holder claim them with a DNSSEC proof; a claimed name makes the
chain authoritative for it. Following that model would mean consulting the
chain first for a colliding label.

**Why.** This rule is what makes the browser safe to use as somebody's *only*
browser. A user who cannot reach their bank because a chain name shadowed it
has been harmed by our alt-root, and no amount of correctness in the alt-root
repairs that.

**Consequence.** A Handshake registrant of an ICANN string cannot serve that
name to this browser without the user typing `hns://` explicitly, which is the
only escape hatch and is never offered automatically. Conversely, `brad.crypto`
here is not the name Unstoppable's users mean. The second half is a consistent
application of the first, and other implementers may reasonably differ on it.

**Status: DELIBERATE.** The spine's D-16 states the same decision from the
Handshake side. What is *not* settled is whether the escape hatch should be
visible; see §2.1.

---

#### IC-3. No DANE for ICANN names
*RFC 6698 · `src/index.js:1330-1331`*

**What.** The session-wide certificate verification hook defers to the
platform's WebPKI (`cb(-3)`) for every host that is not a Handshake host. No
TLSA record is queried for an ICANN name and no pin is applied, although
`../../src/dane.js` is present and is used for Handshake names.

**The standard says.** RFC 6698 defines TLSA records for binding a certificate
or key to a name, and RFC 7671 §4 recommends applying them wherever they are
published. Several ICANN zones (`.se`, `.nl`) publish TLSA records today.

**Why.** DANE-for-HTTPS is only as good as the DNSSEC validation under it, and
there is none on this path (IC-4). A pin taken on a resolver's word, applied to
a name a CA already vouches for, adds an availability failure mode and no
security.

**Consequence.** An ICANN HTTPS page is exactly as authenticated as it is in
any other browser: a CA vouched, and so did every other CA the platform trusts.
The interface says so in those words.

**Status: DELIBERATE**, but see §2.8 — we are not certain a validating ICANN
resolver would change the answer.

---

#### IC-4. No DNSSEC validation for ICANN names
*RFC 4033 / 4035 · nothing on this path*

**What.** No signature is validated for an ICANN answer. The ICANN root's
trust anchor is not configured anywhere in this browser; the only anchor it
knows is the on-chain DS of a Handshake name.

**The standard says.** RFC 4033 §3.1 and RFC 4035 describe a validating
security-aware resolver, which a security-aware stub is expected to be able to
rely on or to be.

**Why.** The address comes from the engine's own resolver, which does not
validate either, and the browser never sees the wire response. Adding a
validating resolver of our own for ICANN names would be a second DNS stack for
a namespace we deliberately do not own.

**Consequence.** An ICANN address is the resolver's word. The Domain name step
says exactly that, and never reads `verified`.

**Status: DELIBERATE.** It is a real gap and it is the ordinary web's gap; we do
not think a browser should quietly close it in a way no other browser does.

---

#### IC-5. The special-use carve-out is longer than the RFCs
*RFC 6761 / 6762 / 7686 / 8375 · `../../src/reserved-names.cjs`*

**What.** Alongside the reserved labels (`localhost`, `invalid`, `test`,
`example`, `local`, `onion`, `arpa`) the list also refuses `internal`, `home`,
`lan`, `corp`, `intranet` and `private`, none of which is reserved by any RFC.
`localhost` is treated as a subtree, per RFC 6761 §6.3, so `app.localhost` is
covered too — and so is every other entry, because the test compares both the
whole host and its final label.

**The standard says.** RFC 6761 §4 defines the process by which a name becomes
special-use and lists the ones that are; the six extra labels are not on it.
RFC 8375 reserves `home.arpa` precisely *instead of* `.home`, which the IETF
declined to reserve.

**Why.** Those six are what home routers and corporate networks actually use.
None is in the IANA snapshot, so without the carve-out the "otherwise,
Handshake" rule catches every one of them.

**Consequence.** If any of those strings is ever delegated by ICANN, or
registered on Handshake by somebody who intends to serve it, this browser will
not resolve it as a name — it will hand it to the platform resolver, which is
what the user's own network expects. We consider that the right failure: the
alternative is sending the names of machines on a user's own LAN to a stranger
who can answer for them.

**Status: DELIBERATE.**

---

#### IC-6. `automatic` falls back to unencrypted system DNS
*`../../src/dns-policy.js`, `src/config.js:348-357`*

**What.** In Fast mode — the configured plan — the default `dns.mode` is
`automatic`: encrypted DNS to the configured resolvers, falling back to
unencrypted system DNS when none answer. The plan reports this as
`plaintextFallback: true` and the interface says it in words. In Private mode
the block is replaced by `privateDns()` before it is read (SPEC §5.7), so the
fallback does not exist there: `secure`, the bridge alone, or nothing.

**The standard says.** RFC 8484 defines the DoH transport but not a fallback
policy; RFC 8310 §8.2, on the analogous DoT case, distinguishes an opportunistic
profile from a strict one and is explicit that the opportunistic profile gives
no protection against an active attacker. `automatic` is the opportunistic
profile.

**Why.** Captive portals and hotel Wi-Fi intercept DNS and would otherwise make
the network unusable. This is a genuine availability-versus-privacy trade and it
is resolved in favour of availability by default.

**Consequence.** In Fast mode an attacker who can make the configured resolvers
unreachable can force every ICANN lookup into the clear — and, because the
bridge replaces the pool (IC-7), needs only to reach the two relays to do it.
`secure` mode exists, refuses plaintext even when that means resolving nothing
at all, is documented in the settings page in the user's own words, and is what
Private mode forces.

**Status: DELIBERATE** as a default, and stated as a limitation everywhere it
applies (SPEC §5.5, §9.2).

---

#### IC-7. The oblivious bridge replaces the resolver pool rather than leading it
*`../../src/dns-policy.js` `planDnsTransport`*

**What.** When the loopback ODoH bridge starts, its template becomes the whole
of `secureDnsServers`. The configured DoH pool is discarded for the life of the
process, so the engine has exactly one secure resolver and, below it, whatever
the mode permits. This is a Fast-mode question: in Private the pool is dropped
by policy before the bridge is consulted (`privateDns()`, SPEC §5.7), so there
the bridge is the only server whether or not it replaces anything.

**The standard says.** Nothing requires either arrangement; RFC 8484 clients
customarily hold a list. This is a deviation from what a reader of the
configuration would expect — `dns.servers` names four resolvers and, with the
default `odoh.icann`, none of them is used.

**Why.** A mixed list is simpler to get wrong than to get right: the engine
would fall from an oblivious template to a plain one silently, and the
interface's per-name claim (SPEC §6.2) would become the only thing that could
tell the two apart.

**Consequence.** Turning obliviousness on changes the floor beneath a failed
lookup from *encrypted* to *plaintext* in Fast mode's `automatic`, and to a
total ICANN outage in `secure` mode — configured, or forced by Private. The
second is the honest trade; the first is a downgrade the user did not ask for
by asking for more privacy.

**Status: OPEN.** We think leading the pool with the bridge is strictly better
on privacy and would take it — but only with a measurement first. What is
missing is not the code (`servers = [bridge.template, ...servers]`) but the
evidence: we have not measured what the engine does with a mixed template list,
how it chooses between entries, or how long it remembers a failing one. Until
that is measured, prepending would make the per-name claim carry weight we have
not tested it for. IC-D1.

---

#### IC-8. ODoHConfigs come from a conventional well-known URI, fetched directly from the target
*RFC 9230 · `../../src/odoh.js`*

**What.** The target's `ODoHConfigs` are fetched over ordinary HTTPS from
`https://<target>/.well-known/odohconfigs` and cached for one hour. The fetch
goes straight to the target, not through a relay.

**The standard says.** RFC 9230 defines the `ODoHConfigs` structure and, as we
read it, deliberately defines **no** discovery mechanism.
`/.well-known/odohconfigs` is the convention the deployed implementations use,
and — as far as we can establish — it is not an IANA-registered well-known URI
under RFC 8615.

**Why (the direct fetch).** The configuration is public and authenticated by
the target's own TLS. Fetching it through a relay would add nothing: a relay
that tampered with it could not read anything — decryption would simply fail
for every subsequent query.

**Consequence.** The target learns the client's IP address about once an hour,
unlinked to any query. That is a weaker disclosure than a DoH resolver's, and
it is a disclosure. And every ODoH client depends on a path that is nobody's to
change.

**Status: DELIBERATE** for the direct fetch, which we would defend. The URI's
standing is an uncertainty rather than a decision: §2.2.

---

#### IC-9. The lookups that make the private path possible are not themselves private
*`../../src/odoh-bridge.js`, `../../src/odoh.js`*

**What.** Two classes of ICANN lookup escape the whole of SPEC §5:

1. **Bootstrap.** The bridge must resolve the relay and target hostnames
   (`odoh-relay.numa.rs`, `odoh.hns.one`) to open HTTPS connections to them.
   Those go through the runtime's own resolver — `getaddrinfo` — not through
   the engine's configured secure DNS and not through the bridge. The same is
   true of the DoH pool's hostnames in the non-bridged case.
2. **Configuration refresh**, hourly, for the same reason.

A Handshake resolution's own ICANN lookups — a nameserver's name, a glue-less
`NS` target, a `CNAME` target — are **not** in this list: they go through the
resolver's injected `lookup`, which the browser sets to its own DoH/ODoH client
in every mode (SPEC §8). The one thing about that injection which belongs
beside the two entries above is its *library default*, and that is IC-16.

**The standard says.** RFC 9230's privacy analysis assumes the client reaches
the relay without disclosing the query; it says nothing about how the relay's
own name is resolved. RFC 8484 §8.2 warns that a DoH client's bootstrap can
itself be a disclosure.

**Why.** The bridge cannot resolve its own upstream through itself. There is no
chicken-and-egg-free answer at the moment it is needed.

**Consequence.** These disclose *which privacy infrastructure this browser
uses* to the local network in the clear. What bounds it is that they are two
fixed hostnames, asked once a session and once an hour: no name a user typed
is in them, and there is nothing per navigation.

Private mode does not change the lookups themselves (SPEC §5.7): the mode
replaces what the engine is told. The connections that follow them — the
bridge's relay leg and its config fetch — ride the session's proxied fetch
(`OdohTransport({ fetchImpl })`), so in Private they leave through Tor and
while BLOCKED they stop with everything else.

**Status: OPEN**, and not hard: the relay and target addresses can be pinned in
the configuration, or resolved through the engine once it is configured, which
removes the per-session and per-hour disclosure entirely.

---

#### IC-11. DoT, DDR, SVCB/HTTPS and ECH are not used
*RFC 7858 / 8310, RFC 9462, RFC 9460, RFC 9848*

**What.**

- **DoT (RFC 7858 / 8310)** and DNS-over-QUIC: not used, and not usable — the
  engine accepts only RFC 8484 HTTPS templates, whatever the configuration
  says.
- **DDR (RFC 9462)**: not implemented. The resolver list is configuration,
  never discovered.
- **SVCB / HTTPS RR (RFC 9460)** is parsed by `../../src/dns-query.js` and
  never queried, on this path or any other; **ECH (RFC 9848)** is therefore
  unreachable, and is also blocked on the runtime exposing no ECH option.

**The standard says.** RFC 9462 §4 specifies how a client discovers a
designated encrypted resolver from the one it already has, which is the
standard answer to "the user's network operator runs a good resolver and we
overrode it". RFC 9460 defines the record that carries it.

**Why.** DoT is the engine's constraint, not our choice, and is recorded so its
absence is not read as an oversight. DDR and SVCB are work nobody has done.

**Consequence.** The resolver list can only be what the configuration file
says, so a network that offers a designated encrypted resolver is ignored — see
§2.9 for the argument that this is the wrong side of a real question. Without
ECH the server name is in the ClientHello regardless, so an oblivious DNS
lookup does not by itself hide which site was visited from an on-path observer.

**Status: OPEN** for DDR, which is the only one of the four that is ours to
take. We recommend implementing the RFC 9462 §4 discovery path — query the
`_dns.resolver.arpa` SVCB record through the configured resolver at startup and
offer any designated encrypted resolver it names as an additional template —
behind a configuration key that is off by default, so that the discovery cannot
silently widen the set of resolvers a user chose. DoT and ECH stay recorded
constraints until the engine offers them.

---

#### IC-12. Internationalized names cross the boundary through UTS-46, not IDNA2008
*RFC 5890 / 5891, UTS #46 · `../../src/classify-host.cjs:68-76`*

**What.** A Unicode host is converted to A-labels by handing it to `new URL()`
and reading `hostname` back, which is UTS-46 as the WHATWG URL Standard
specifies it, not IDNA2008 as RFC 5891 specifies it.

**The standard says.** RFC 5891 §4 defines the registration and lookup
protocols for IDNA2008; UTS #46 defines a compatibility processing that differs
from it on a small set of characters (the four deviation characters, and
transitional versus non-transitional processing).

**Why.** The conversion is the URL parser's, and the URL parser is the thing
that will actually carry the name afterwards. Implementing IDNA2008 separately
would mean a host that classified one way and navigated another.

**Consequence.** On the Handshake path the divergence produces a name the chain
has not heard of. **Here it can move a name across the ICANN boundary** — a
host that IDNA2008 would map to an A-label outside the snapshot, and UTS-46
maps to one inside it, is routed to a different root. We have not audited which
labels this can affect.

**Status: OPEN**, and under-examined. The bounded piece of work is to enumerate
the delegated TLDs reachable by a UTS-46/IDNA2008 divergence — the deviation
characters are four, the snapshot is 1,438 labels, and the cross product is
small enough to check exhaustively offline. Until that is done we state the
possibility rather than a consequence (§2.7). The spine's D-17 is the same
deviation with a weaker consequence.

---

#### IC-13. The SSRF guard is not applied to ICANN addresses
*RFC 6890 / 1918 / 4193 · `../../src/safe-address.js`*

**What.** `assertPublicAddress()` refuses loopback, private, link-local
(including `169.254.169.254`), CGNAT, benchmarking, multicast and reserved
addresses. It is applied on the Handshake path, on the HIP-5 `_op` path and in
the WebSocket proxy. It is not applied to ICANN names.

**The standard says.** RFC 6890 enumerates the special-purpose ranges; nothing
requires a browser to refuse them, and browsers do not.

**Why.** It cannot be applied: the address never passes through our code. The
engine resolves and connects.

**Consequence.** `http://internal.example/` resolving to `10.0.0.1` behaves
exactly as it does in any other browser, subject to the engine's own
private-network protections and nothing of ours. This is not a regression
against browser norms; it is a place where the Handshake path is *stronger*
than the ICANN path, and a reader should not assume the guard is universal.

**Status: DELIBERATE.**

---

#### IC-14. An `http://` link to a numeric-TLD Handshake name is not rewritten
*WHATWG URL Standard · `src/hns/hns-host.js:85-98`*

**What.** `rewriteToHns()` parses its input with `new URL()`. For a host whose
last label is all digits the WHATWG "ends in a number" rule sends the host to
the IPv4 parser, which fails, and the constructor throws — so the function
returns `null` and the URL is left alone. Typed input takes a different path
and does handle the case, via the `_` marker convention
(`hns://hello._14898/`).

**The standard says.** The URL Standard's "ends in a number" checker and IPv4
parser make `http://hello.14898/` an invalid URL. Both the classifier and the
engine are bound by that rule.

**Why.** There is nothing to rewrite. The engine cannot construct that URL
either, so it never becomes a navigation and the rewrite hook is never reached
with it. A rescue path in `rewriteToHns` would be code that no input can
execute.

**Consequence.** `http://hello.14898/` written as a literal link in a page is a
dead end — but it is a dead end in every browser, ours included, before our
code is consulted. The two classification paths disagree on paper about a name
only one of them can be handed. The spine's D-4 is the same URL-parsing rule
seen from the Handshake side, where the `_` convention answers it.

**Status: DELIBERATE.** Recorded because the disagreement is real and a reader
comparing the two paths will find it; the reason it is not repaired is that the
input cannot arrive. See §2.10 for what we have not verified about that.

---

#### IC-15. The obliviousness switch and the resolver pool are configuration-file-only
*`src/pages/settings.html:464-472`, `src/config.js:348-357`, `:376-408`*

**What.** `dns.mode` is exposed in the settings page as a free-text field with
all three values explained. `odoh.icann` — the switch that decides whether
ordinary web lookups go through the relay at all, and which costs about 200 ms
per cache miss — is only editable in the configuration file, even though the
code comment beside it calls it "a setting". `dns.servers` is likewise
config-file-only.

**The standard says.** Nothing; this is a deviation from our own stated design,
which is that the user should be able to make this trade.

**Why.** `dns.mode` was the setting with a user-facing question attached
("should ordinary DNS be encrypted?"), and it got a field. `odoh.icann` and
`dns.servers` are the settings with a cost attached, and a cost is harder to
word than a switch — so they stayed where they were written.

**Consequence.** The trade this design most wants the user to make consciously
is the one they are least able to reach. And a free-text field for a
three-valued enumeration is a typo waiting to happen — harmless now that the
value is normalised and a bad one is reported (SPEC §5.2), but still a field
that can be wrong.

The Fast / Private switch (SPEC §5.7) is in the settings page and the Privacy
menu, and it does not expose these two keys either. With `odoh.icann: false`
Private mode resolves **no** ICANN name at all — the plan fails closed with no
bridge — and nothing on the switch says so; only the Domain name step does,
after the fact.

**Status: OPEN.** Add a checkbox for `odoh.icann` in the same DNS privacy
block, with the cost stated in the hint text — including that Private mode
depends on it — and a textarea for `dns.servers`; make `dns.mode` a `<select>`
so the class of error disappears rather than being reported. The plumbing
exists — `dns.mode` is already written through the settings preload. IC-D3.

---

#### IC-16. The resolver's default `lookup` is the OS resolver, in the clear
*`../../src/resolver.js:226` · SPEC §8*

**What.** The three places a chain walk needs an ICANN host's address all go
through one injected function, `HNSResolver`'s `lookup`. The browser passes its
DoH/ODoH client, so nothing goes out in the clear. **The constructor's default
does not**: with no `lookup` supplied it is
`(host) => dns.lookup(host, { family: 4 })` — `getaddrinfo`, outside the whole
of SPEC §5.

**The standard says.** Nothing about a library's defaults. RFC 8484 §8.2 is the
nearest: a client that can resolve privately and does not has disclosed the
query.

**Why.** The module has to run as a library under plain `node` — that is how
its own test suite drives it — and a library cannot assume a DoH client. The
default is the one that always works.

**Consequence.** The protection is a property of the **composition**, not of
the module. An integrator who takes `resolver.js` and omits one constructor
argument discloses one ICANN name in the clear for every Handshake resolution
that walks to an ICANN nameserver or follows a `CNAME` out of the zone.
Nothing warns them, and the resolution's own trust reporting cannot tell the
two apart — an address is the resolver's word either way, so the panel's step
reads the same whether the lookup was encrypted or not.

**Status: OPEN.** Two candidate fixes, and we prefer the first: make `lookup`
**required** and let construction fail without it, so the decision is taken
once and visibly; or keep the default and record on each resolution which
transport the lookup used, so the trust step can say "in the clear" when it
was. Either is better than a default whose safety depends on a caller reading
a comment.

---


### 2. Things we are not sure about

These are the ones we most want challenged.

#### 2.1. Whether "ICANN first" should have a visible escape hatch

The collision rule (IC-2) is settled as a *default*. What is not settled is
that the only way to reach the Handshake answer for a colliding name is to know
that `hns://` exists and type it. A registrant who buys the Handshake name of
an ICANN string cannot serve it to our users at all, and our users are never
told there is another answer. Every design we have sketched for telling them —
a second suggestion row, a one-line notice, a per-name preference — either
teaches users to click through a security-shaped prompt or creates persistent
per-name state an attacker can influence. We do not know the right shape.

#### 2.2. Whether `/.well-known/odohconfigs` is standardised

RFC 9230 defines the `ODoHConfigs` structure and, as we read it, deliberately
does not define discovery. The deployed convention is a well-known URI that we
believe is not registered under RFC 8615. If it is registered, we are citing it
wrongly and would like to know. If it is not, then every ODoH client depends on
an unregistered path, which is a thing the working group might want to hear.

#### 2.3. Whether replacing the resolver pool is the right failure ordering

In Fast mode, IC-7 means the fallback below a failed oblivious lookup is
plaintext rather than DoH. Prepending the bridge to the pool instead would make the fallback
encrypted-but-not-oblivious, which is strictly better on privacy — but it also
means a *silent* downgrade from oblivious to non-oblivious that the engine
performs without telling us, and the interface's per-name claim (SPEC §6.2)
would then be doing more work than we have tested it for. We think prepending
wins. We have not measured what the engine actually does across a mixed list.

#### 2.4. What the engine does on each kind of DoH failure

`automatic` "falls back to system DNS when the secure resolver cannot be
reached" is the documented behaviour, and we repeat it. We have **not**
measured whether a SERVFAIL response — which is what our bridge returns on
failure, and which is a *successful* HTTP exchange — triggers the same fallback
as a transport failure, nor how long the engine remembers a failing resolver.
The bridge's failure policy was chosen on the assumption that it does. If it
does not, a relay outage in Fast mode's `automatic` is a hard failure rather
than a silent downgrade — which would be *better* for privacy and worse for
availability, and either way we should know which one we shipped. In Private
mode the question does not arise: `secure` refuses every fallback, so a SERVFAIL
from the bridge is a failed lookup whichever way the engine reads it. The same
measurement answers what threshold IC-1's staleness check should use only by
analogy; that one is a separate guess.

#### 2.5. The ten-minute window and the subdomain rule

`servedRecently()` vouches for a name the bridge answered within ten minutes,
and for any subdomain of such a name. Both are guesses. Ten minutes can outlive
the answer's own TTL, so a page can be reported as obliviously resolved when
this navigation's address came from somewhere else. The subdomain rule is the
right *direction* — the reverse would let one attacker-chosen lookup vouch for
its parent, and even for `com` — but "we resolved `example.com`, therefore
`a.b.example.com` was oblivious too" is not strictly true either. The
alternative, threading the actual resolution event through to the interface, is
not available to us: the engine does the resolving.

#### 2.6. Whether the snapshot cadence is adequate

IC-1's alarm fires on a networked test run. Nothing forces a refresh before a
release, and nothing measures how stale a shipped snapshot was. Against a round
that may delegate hundreds of TLDs over the next two years, "we have an alarm"
may not be enough. We have not decided what the staleness threshold should be,
and the honest reason is that we do not know how quickly a delegation becomes a
name somebody visits.

#### 2.7. Whether the IDNA divergence can actually move a name

IC-12 is stated as a possibility because that is exactly what it is: we know
UTS-46 and IDNA2008 differ, we know the difference is applied at the point
where the boundary is decided, and we have not enumerated the labels for which
it changes the answer. It may be that no delegated TLD is reachable by such a
divergence. It may be that several are.

#### 2.8. Whether refusing DANE for ICANN names is right

IC-3's argument is that a pin is only as good as the DNSSEC under it, and there
is none. The counter-argument is that this is the only shipping browser that
validates DANE for HTTPS at all, that a validating resolver for ICANN names is
a solved problem, and that a browser willing to build the whole Handshake
apparatus could reasonably offer DANE for the `.se`/`.nl`-style zones that
publish TLSA records today. We did not do it because it is a second DNS stack
for a namespace we deliberately do not own, and because the availability
failure modes of DANE on the open web are notorious. We are not certain that is
more than an excuse.

#### 2.9. Whether a browser should be configuring the resolver at all

Every decision in SPEC §5 is made on the user's behalf, at startup, from a
configuration file most people will never open. There is a coherent opposite
position: the operating system owns DNS, a browser that overrides it fragments
the user's threat model across applications, and a corporate or household
resolver that exists for a reason is silently bypassed. We think the plaintext
default is bad enough to justify overriding it, and we say which resolver
answered. We would not call the question settled — and IC-11's missing DDR is
the standard's own answer to it, which we have not taken.

#### 2.10. Whether the engine really cannot issue a numeric-TLD http request

IC-14 rests on a claim about the platform: that `http://hello.14898/` never
becomes a navigation, so the rewrite hook is never reached with it. That
follows from the URL Standard, and it matches what the URL constructor does in
our own tests. We have not instrumented the engine's navigation path to confirm
that no code path anywhere constructs such a request by another route — through
a redirect target, say, or a subresource URL assembled relative to a base. If
one does, IC-14 becomes a real gap rather than an unreachable one.

---

### 3. Open design items

Changes we intend or recommend, that are not made. Each names the deviation it
would resolve.

#### IC-D1. Lead the resolver pool with the bridge instead of replacing it

The bridge's template becomes the whole of `secureDnsServers`, so in Fast
mode's `automatic` the floor beneath a failed oblivious lookup is plaintext
rather than the configured DoH pool (IC-7); Private mode has no floor by policy
(SPEC §5.7). Prepending would keep an encrypted floor, at the cost of a silent
oblivious-to-non-oblivious downgrade that only the interface's per-name claim
could detect.

**Recommendation.** Do it, but not first. Measure the engine's behaviour on a
mixed template list — how it chooses between entries, whether it falls from the
first to the second on a SERVFAIL as well as on a transport failure, how long
it remembers a failing one — and only then change `planDnsTransport` to
`servers = [bridge.template, ...servers]`. The measurement is also what §2.4
needs, so it pays for itself twice.

#### IC-D3. Put the obliviousness switch and the resolver pool in the settings page

`odoh.icann` and `dns.servers` are editable only in the configuration file,
although `odoh.icann` is the setting this design most wants the user to choose
consciously (IC-15). `dns.mode` has a field, but a free-text one.

**Recommendation.** A checkbox for `odoh.icann` with its latency cost in the
hint text ("about 200 ms on the first lookup for each site; Handshake names
stay oblivious either way"), a textarea for `dns.servers`, and a `<select>` for
`dns.mode`. The settings preload already writes `dns.mode`, so the plumbing
exists.

#### IC-D4. Give the browser's drift alarm an offline half

`tests/hns/icann-tlds-live.test.js` skips entirely without network, so an
offline run — a release build on a locked-down machine, a contributor on a
plane — checks the ICANN boundary not at all, including the parts that need no
network: that the file is well-formed, that it is what the generator produces,
and that it carries a version line.

**Recommendation.** Lift `tests/icann-tld-snapshot.test.js` from this chapter
into the browser tree, with its imports pointed at `src/ui/icann-tlds.cjs` and
`scripts/fetch-icann-tlds.mjs`; the live comparison stays as it is. Add a
staleness assertion at the same time — `Version` is a `YYYYMMDDNN` integer, so
"this snapshot is more than N days old" is a one-line offline check, and §2.6
is the open question of what N should be.

---

### 4. What this chapter leaves out

1. **Any ICANN resolver.** There is none in this package, and none in the
   browser: the engine resolves ICANN names. `src/dns-policy.js` here is the
   *policy* the browser's Electron composition layer calls at both of its
   gates, not an implementation of resolution. If you are implementing from
   this specification, the resolver is your platform's and §5 is a description
   of what to tell it. The re-application of the plan on a mode switch
   (`applyDnsPlan`, driven by the `DeliveryMode` controller's `change` event)
   is part of that composition layer; its policy is SPEC §5.7.

2. **The modules this chapter is about that live in the spine's `src/`.**
   `router.js`, `hns-host.js`, `icann-tlds.cjs`, `reserved-names.cjs`,
   `safe-address.js`, `self-cert.js`, `odoh.js`, `odoh-bridge.js`, `doh.js`,
   `dns-query.js` and `trust-path.js` are all in `../../src/`, byte-identical
   to their Wildroot counterparts, and are not duplicated here. Only
   `dns-policy.js` and the snapshot generator's parse-and-render half are in
   this chapter's `src/`.

3. **`src/hns/privacy.js`.** It is named in this chapter's brief and it is
   about something else entirely: Electron permission defaults (camera,
   microphone, clipboard, fullscreen) and tracking-parameter stripping. It has
   no DNS content. The DNS privacy policy lives in `src/hns/dns-policy.js`,
   `src/index.js`, `src/config.js` and `src/hns/odoh-bridge.js`, which is what
   SPEC §5 documents. Recorded so the next reader does not go looking.

4. **The engine's own behaviour.** Cache lifetimes, DoH probing, the downgrade
   heuristics behind `automatic`, and private-network access protections are
   the engine's, not ours. Where a claim we make depends on one of them, §2.4
   says we have not measured it rather than asserting it.


---

## Chapter 3 — IPFS, IPNS and DNSLink

_Source: [`namespaces/ipfs/DEVIATIONS.md`](namespaces/ipfs/DEVIATIONS.md)._

Every place this chapter departs from a specification cited in
`REFERENCES.md`, every place we are not confident we have made the right call,
and every design item still open. **Section 2 is the one to read.** A deviation
that is not written down is just a bug nobody has found yet.

Paths beginning `src/` or `tests/` are in this chapter's directory; `../../src/`
is a shared module of this package; anything named *the Wildroot tree* is the
browser this is extracted from. Line numbers are as of extraction.

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

**Consequence.** Nothing today: the three agree. The cost is that they can stop
agreeing silently, which is the failure mode this codebase has already had once,
when a copy accepted two hundred characters of junk and gated a storage restore
on it.

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

**Status.** `DELIBERATE`. Reimplementing a record validator beside a node that
already has one adds a second place for it to be wrong, and the honest sentence
costs nothing. The limit is stated where a reader meets it (SPEC §4.2 and §9)
rather than glossed. What we owe and cannot yet give is §2.3.

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

**Why.** The entire contract of that function is *"the CID kubo would compute"*.
Answering with a non-HAMT CID for a folder kubo would shard is not an
approximation, it is a wrong address — and a wrong address is worse than no
answer, because it is published.

**Consequence.** A very large folder cannot have its CID computed locally before
it is published.

**Status.** `DELIBERATE`. Refusing beats disagreeing.

#### IP-7. The CAR header is decoded by a minimal reader

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

**Status.** `DELIBERATE`, with the caveat that a check routinely mistaken for a
proof has a cost of its own — §2.5.

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

#### 2.2. Whether host canonicalisation actually breaks the case-sensitive forms (IP-5)

The reasoning is in IP-5 and it is only reasoning. What would settle it is one
navigation each to `ipfs://Qm…`, `ipns://12D3Koo…` and `pubsub://MixedTopic` in
the shipping browser, and a look at the URL the handler receives. Until that is
run, IP-5's consequence paragraph is a prediction.

#### 2.3. What delegating IPNS to the node actually gives us (IP-3)

We say *"an IPNS name is a signed pointer"* and mean it, but we have not
established what the node's answer is worth in the cases that matter: how stale
an answer may be, whether a resolution that finds nothing is distinguishable
from one that finds an expired record, and what happens when the DHT is
unreachable but a cached record exists. A specification that delegates a
signature check should be able to say what the delegate promises. This one
cannot yet.

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

It catches a real class of operator error cheaply. It also reads exactly like a
security check, and has been described as one in a code comment. A check that is
worth having and is routinely misunderstood is not obviously worth having. The
alternative — drop it and rely entirely on asking the node for the CID
afterwards — is simpler to reason about and loses a useful diagnostic.

#### 2.6. Whether a pointer's precedence should be fixed at all

`ipfs` beats `ipns` beats the swarms beats Arweave, always, everywhere. That is
right for cold-start latency and it is the spine's rule. But a name whose `ipfs=`
is stale and whose `ipns=` is current resolves to the stale one, forever, with no
way for the publisher to say "prefer the mutable pointer". We do not know whether
that is a problem in practice or a misconfiguration nobody will make.

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
stated origin does in that mode (refuse, as now, is the honest answer), and
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

## Chapter 4 — Arweave

_Source: [`namespaces/arweave/DEVIATIONS.md`](namespaces/arweave/DEVIATIONS.md)._

Every place this chapter's implementation departs from a specification it
cites, from common practice, or from its own stated design — plus every place
we are not sure we have made the right call, and every design item still open.

The rule this file serves, inherited from the spine: **a deviation that is not
written down is just a bug nobody has found yet.**

Everything measured below was measured against
`namespaces/arweave/src/ar.js`, which is byte-identical to `src/hns/ar.js` in
the Wildroot tree, and against `../../src/pointers.js` and
`../../src/trust-path.js`, which this chapter shares with its siblings.

---

### 1. Deviations

#### AR-1. The BYTES are verified against the transaction for a top-level transaction under 8 MiB (resolved 2026-09-06, with a stated limit)

*SPEC §9.2 · `src/ar.js` (whole module)*

**What.** No chunk proof is checked and `data_root` is never compared with
anything. The transaction *header* is checked — fetched from a second gateway
and required to hash to the identifier (SPEC §9.1.1), which is where the
`data_root` arrives, authenticated — and then the bytes that were served are
not measured against it. For the content itself the answering gateway is
trusted like any HTTPS host.

**The standard says.** An Arweave transaction id is the SHA-256 digest of the
transaction's signature, and a format-2 transaction's data is committed by the
`data_root` Merkle root inside that signed header (the Arweave reference
implementation's documentation; ANS-104 states the same derivation verbatim for
a bundled data item: *"The id of the DataItem, is the SHA256 digest of this
signature."*). The identifier is therefore checkable, and a client that does
not check it is trusting whoever answered.

**Why.** Full chunk verification is a real amount of work — the chunk endpoint,
the Merkle proof format, and a bounded buffer to hash against — where the header
check was one hash and one request. The cheap half was therefore done first
(AR-D1), and the expensive half is what is left. The scheme's namespace-table
row still records `status: 'partial'` rather than `live` for exactly this
reason, which is the model this file wants: the deviation lives in the code's
own metadata, not only in prose.

**Consequence.** SPEC §11.7: a successful `ar://` fetch establishes that a
TLS-authenticated host from a list we shipped returned these bytes for this
identifier, and — with the header check — that a second, independent host agrees
the identifier names a real transaction. Neither is a statement about the bytes.
A hostile or compromised gateway still serves arbitrary content for the right
transaction and nothing notices. Contrast `ipfs://`, where the local node checks
every block hash, and `bittorrent://`, where the infohash does it — Arweave is
the one content scheme in this browser whose bytes are not checked. What limits
the damage is that the claim is not overstated anywhere: the trust panel calls
the content step `unverified`, the aggregate verdict is `partial`, the scheme
table says `partial`, and the response header says `header`, never `bytes`
(SPEC §9.2, §9.1.1).

**Status: RESOLVED for the common case, with the limit stated.** Since
2026-09-06 `../../src/ar-merkle.js` computes the chunk Merkle root (256 KiB
chunks, the last two rebalanced; leaf `H(H(H(chunk))‖H(note))`, branch
`H(H(l)‖H(r)‖H(note))`; validated live against top-level transactions) and
`../../src/ar.js` holds a whole body of a proven header's transaction up to
`MAX_VERIFY_BYTES` (8 MiB), refuses one that does not hash to `data_root`,
and answers `X-Arweave-Verified: bytes`. Above the limit, on a Range request,
and for a bundled data item (no top-level header: `/tx/<id>` is 404 on every
gateway), the header check stands alone and the header says `header` or
`none` — the label never claims what was not checked. The trust panel's
content step remains `unverified` because it is written at resolution time,
before the fetch; the response header is the per-fetch truth. What remains:
chunk proofs for bodies above the limit, and bundled items via their bundle.

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

**Why.** Adopting the ecosystem's form unchanged is better than inventing a
second one. This is the same reasoning the spine applies elsewhere, and the
opposite of the case where no convention existed at all and one had to be
invented.

**Consequence.** Interoperability rests on convention. If ar.io changed the
form, or if a registration standardised a different one, we would follow rather
than argue. Nothing in this implementation depends on the scheme being
registered, and the parsing rule that matters — read the identifier from the
raw string, never from a URL host accessor (SPEC §4.2) — is ours to keep
either way.

**Status: DELIBERATE.** Registering `ar` is not ours to do: the scheme belongs
to the Arweave ecosystem, and a registration filed by a browser vendor that did
not define it would be presumptuous. We would support and follow one.

---

#### AR-3. An `arweave` resolution is cached for a flat 60 seconds

*Spine `DEVIATIONS.md` D-1 · `../../src/resolver.js` `CACHEABLE`*

**What.** `CACHEABLE` includes `'arweave'`, so a name that resolves to an
Arweave pointer is remembered for 60 seconds and the record's TTL is ignored,
exactly as for every other positive resolution.

**The standard says.** RFC 2181 §5.2 and RFC 1035 §3.2.1: the TTL is the
authoritative server's statement of how long an RRset may be cached, and a
resolver honours it.

**Why.** Inherited from the spine's D-1; no Arweave-specific decision was made.

**Consequence.** Worth naming separately only because Arweave is the one kind
where a *longer* cache would be safe by construction: the identifier is
immutable, so the answer cannot go stale in a way that matters until the name's
owner republishes, and a republish already calls `forget()`. The deviation here
is that we are more conservative than we need to be, which costs lookups and
nothing else.

**Status: DELIBERATE** as an Arweave decision — there is nothing to change in
this chapter. The underlying flat-60-second cache is the spine's D-1 and is
open on its own terms; when it starts honouring TTLs, an `ar=` pointer is the
safest kind to give a generous ceiling.

---

### 2. Things we are not sure about

These are not settled positions. They are the places where we think the
implementation may be wrong and would like to be told so.

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

We do not know whether the right answer is "parse manifests client-side" (real
work, real drift risk) or "keep delegating and be loud about it" (what we do).

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

There is a second, sharper question underneath. We hold `<label>_persist.ar.io`
and it resolves through ordinary DNS and an ordinary CA-issued certificate —
which is *precisely* the trust model this whole project exists to improve on.
Presenting an ar.io URL as a durability story while it is CA-authenticated
deserves a clearer statement than it currently gets anywhere.

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
*trusted-but-not-trustless* with a closed lock (SPEC §9.2, `SPEC.md` §4).

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

This item had two steps and the first is built. The header is fetched from a
gateway other than the one that served the bytes and required to hash to the
identifier (SPEC §9.1.1, `headerMatchesId`, `tests/arweave-header.test.js`); a
mismatch is a 502 in the Arweave namespace, and `X-Arweave-Verified` reports
which of `header` and `none` happened.

**What is left.** The header carries a `data_root`, authenticated, and nothing
compares the bytes with it. Recommendation, in order: buffer the body when it is
small enough (a threshold — 4 MB covers a manifest and most pages) and hash it
against `data_root` for a single-chunk transaction; above the threshold, or for a
multi-chunk transaction, compare the body with the same path fetched from the
second gateway; then, and only if it is worth it, the chunk endpoint and the
Merkle proof format for the general case. Prove it with a mock gateway returning
tampered bytes for a valid header, which must fail closed as an Arweave-namespace
failure and never as a fall-through — the mirror of the case
`tests/arweave-header.test.js` already pins. The response header gains a `bytes`
value at that point and not before, and only then may the trust step change
(AR-1, AR-U5).

**One thing to preserve.** The header request must keep coming from a gateway
other than the one that served the bytes, for the same reason it does now: a
lying gateway would supply a matching `data_root` too. When the body comparison
is added, the *bytes* must come from the two hosts in the other order, or one
operator answers for both halves of its own proof.

#### AR-D2. `Config.arOptions` has no schema, default or validation

The composition layer spreads `...(Config.arOptions || {})` straight into
`createArHandler`, so an rc file can replace the gateway list — but there is no
schema, no documented default, no validation and no settings UI. In practice
the list is compiled in, and a typo in an rc key fails silently. Nothing checks
that a configured gateway is `https:`, so a user or a bad rc file can put the
whole fetch in plaintext, which SPEC §6.1 requires against.

**Recommendation.** Declare `arOptions` in the configuration schema with
`AR_GATEWAYS` as its documented default; validate that every entry parses as an
`https:` URL and reject the configuration loudly when one does not; report an
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

## Chapter 5 — ENS and `web3://`

_Source: [`namespaces/ens/DEVIATIONS.md`](namespaces/ens/DEVIATIONS.md)._

Every place this chapter's implementation departs from a standard it cites,
from common ENS-client practice, or from its own stated design — plus every
place we are not sure we have made the right call, and every design item that
is open.

The rule this file serves is the spine's: **a deviation that is not written
down is just a bug nobody has found yet.**

---

### 1. Deviations

#### EN-1. Only `contenthash` is read; `addr`, `text` and the rest are not

**What.** One record, one call. No address record, no text records, no avatar,
no multichain address records, no ENS metadata.

**The standard says.** ENS resolvers expose a profile of records — EIP-137
`addr(bytes32)`, ENSIP-5 `text(bytes32,string)` and ENSIP-9 multichain
addresses among them — and a general ENS client reads whichever it needs.

**Why.** The scheme's job is to open a name as a **website**. Every other
record belongs to a wallet or a profile viewer, and reading them would put a
per-navigation cost on every ENS name for data nothing renders.

**Consequence.** A name that publishes only an address is reported as having no
website — and the error page says so in those words, rather than implying the
name does not exist. A user who wants the profile does not get one here.

**Status: DELIBERATE.** This chapter specifies browsing, not ENS. Reading a
record nothing displays would add a lookup, a failure mode and a disclosure to
the RPC endpoint for no user-visible result. A "name info" panel would be the
place for the rest, and there is no such panel.

---

#### EN-2. A CCIP resolver's rigour is deliberately not graded

**What.** Every ENS resolution carries the same trust state, whether the
offchain resolver behind it checked an operator's signature or verified a
Merkle storage proof or a DNSSEC chain on chain.

**The standard says.** ERC-3668 is explicit that it is a transport and that
what the callback does with the gateway's answer is the contract's business;
it defines no way to signal, and no obligation to distinguish, the strength of
that check.

**Why.** Without an Ethereum light client, the registry read, the resolver
address, the revert and the callback result all arrive on the word of an RPC
endpoint. **A "verified storage proof" we learned about from an endpoint that
could equally have invented it is not evidence of anything.** Grading would
show the user a difference the client cannot observe. Payload size and revert
shape make the two partly distinguishable, which is exactly the temptation.

**Consequence.** A genuinely rigorous offchain resolver gets no credit for it
here.

**Status: DELIBERATE**, and conditional on the light client — see §2.2. A lock
that reports a distinction the client cannot check is worse than one that
reports the weakest hop honestly.

---

#### EN-3. Reverse resolution (EIP-181) is not implemented

**What.** `addr.reverse` is never queried; no primary name is ever displayed.

**The standard says.** EIP-181 defines the `.addr.reverse` namespace and the
`name(bytes32)` record so that an address can be shown as the name it claims.

**Why.** Nothing on a browsing path has an Ethereum address to reverse. Reverse
resolution answers "what does this address call itself", which is a wallet's
question.

**Consequence.** None for resolution. Named because an ENS chapter that omitted
it silently would look like it had forgotten it, and because reverse records are
where a name-display feature would have to start.

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

**Status: DELIBERATE**, and worth stating rather than leaving as an
inconsistency a reader has to discover.

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

**Why.** No reason beyond that nothing builds it. The Handshake path next door
has a flat 60-second positive cache and is the model.

**Consequence.** Latency, and — more importantly — **disclosure volume**: the
RPC endpoint and any CCIP gateway see one request per navigation rather than
one per cache lifetime. For a scheme whose stated privacy problem is "the
endpoint learns which names you open", re-asking is the wrong default.

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
| **ENS text records** (`text(bytes32,string)`) — `url`, `description`, `com.twitter`, the avatar | Nothing renders them. They would be the natural content of a "name info" panel, which does not exist. |
| **Multichain address records** (ENSIP-9) | A wallet's job, not a browser's. |
| **`Registry.ttl(bytes32)`** | Nothing caches (EN-6), so there is nothing for a TTL to govern. |
| **ENS on an L2, read natively** | Reached through CCIP-Read (SPEC §6) like every other client without an L2 light client. Reading the L2 directly would swap one trusted RPC for another. |
| **An Ethereum light client** | The single change that would move this namespace out of `unverified`. It is a large piece of work and is not started. Everything in SPEC §7 is conditional on it. |

**The standard says.** Each row's own specification defines behaviour this
implementation does not provide.

**Consequence.** This is an ENS *browsing* client, not an ENS client. Anything
that needs a record other than `contenthash` needs a different tool.

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

We ship TRUSTED and we are not certain. What we are certain of is that the
verdict must be one thing everywhere — shipping one verdict while the comments
describe another is worse than either answer — and it is.

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

One address is hardcoded and the one in the bundled chain registry is ignored.
Ours is verified and is the DAO-owned proxy; theirs is an older deployment. But
"hardcode a contract address in a browser and ignore the registry that ships
with your dependency" is a maintenance trap with a long fuse, and the failure
mode when ENS moves is that every `.eth` name stops resolving at once. A
verified-at-build-time list, or reading the registry and *checking* it against
a known-good, would both be better. We have not decided which.

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

## Chapter 6 — Nostr

_Source: [`namespaces/nostr/DEVIATIONS.md`](namespaces/nostr/DEVIATIONS.md)._

Every place this chapter's implementation departs from a standard it cites,
from common Nostr client practice, or from its own stated design — plus every
place we are not sure we have made the right call.

The rule this file serves, inherited from the repository's consolidated
`DEVIATIONS.md`: **a deviation that is not written down is just a bug
nobody has found yet.** Some of these are deliberate and settled; some are
unfinished work. Each entry says which.

Section 1 is the deviations, numbered `NO-…`. Section 2 is the
honest-uncertainty list, called out separately because those are the ones we
most want challenged. Section 3 is the open design items — changes we think
are right and have not made. Section 4 is what this chapter deliberately
leaves out.

---

### 1. Deviations

#### NO-1. A NIP-05 address is classified nowhere
*SPEC §3 · `../../src/router.js` `classify`, `../../src/classify-host.cjs`*

**What.** A bare NIP-19 identifier has a classifier row and is routed to this
namespace (SPEC §3). A pasted **NIP-05 address** does not: `alice@example.com`
carries a single `@`, and a scheme-less input with an `@` in it that is not the
canonical `@user@host` Fediverse form is a search. So the one Nostr address
form that looks like an email address is neither Nostr nor anything else.

**The standard says.** Nothing directly: neither NIP-05 nor NIP-21 specifies
how an address bar should behave. What makes this a deviation rather than a
missing feature is that the form is genuinely ambiguous — `alice@example.com`
is the NIP-05 shape *and* the Mastodon shape *and* an email address — and the
browser resolves it as both elsewhere while the address bar resolves it as
neither.

**Why.** The `@` rule exists for a real hazard: the URL constructor reads
everything before the last `@` as userinfo and silently drops it, so
`alice@example` typed as a host navigates to `example` with a stray credential.
Making every `@` a search is the safe direction. The cost is that the one
address form that would benefit from a lookup gets a search.

**Consequence.** Wildroot's `social-model.js` classifies the ambiguous form as
`fediverse-or-nip05` and resolves *both*, presenting whichever answers — so the
capability exists in the product and is unreachable from the address bar. It is
not a security problem: a search discloses the string to the search backend,
which is what a search always does, and no namespace is entered on a guess.
Pinned by `tests/classification.test.js` ("DOCUMENTED GAP (NO-1)").

**Status: OPEN.** The honest fix is not a classifier row — one input cannot
belong to two namespaces — but an omnibox that *offers* both resolutions as
suggestions and lets the user choose, which is where "I meant to look that up"
is answered for a bare word already. NO-D1 is the related work on the `nip05`
claim itself.

---

#### NO-2. The `nip05` claim on a protocol page is displayed, but never looked up
*NIP-05 · `src/nostr-protocol.js` (`renderProfile`), `src/nip05.js`*

**What.** A profile page renders a kind:0's `nip05` field as *"claims
`<handle>` (not verified — the handle was not looked up)"*. The handle is
marked, honestly, as an unverified claim. It is not resolved: no
`.well-known/nostr.json` request is made from this page.

**The standard says.** NIP-05, "Showing just the domain as an identifier": a
client that displays a `nip05` field is expected to verify it against the
domain, and NIP-05 exists precisely to close the impersonation gap that an
unchecked handle leaves open.

**Why.** The lookup exists in the tree — it is what `src/nip05.js` factors out,
and the social page uses it correctly — but resolving a handle costs an HTTPS
request to a domain a *stranger* named, which is the SSRF surface SPEC §10.5 is
about. Shipping the marking first and the lookup second was the order that kept
the page honest at every step.

**Consequence.** Any key can display any handle. `satoshi@bitcoin.org` renders
the same whether or not bitcoin.org has ever heard of that key. The marking
means a careful reader is not misled, and it does not tell a reader what the
domain would have said.

**Status: OPEN.** Resolve the claim with `lookupNip05` (which already derives
the host from the identifier and refuses redirects) and render three states
rather than two: verified against the domain, contradicted by the domain, and
not reachable. The host validation the lookup needs is already in place, so
this is wiring rather than design. The concrete shape is NO-D1.

---

#### NO-3. Relay selection is a bundled set plus the link author's hints; NIP-65 is never read
*NIP-65 · SPEC §8.2 · `src/relay.js` (`DEFAULT_RELAYS`)*

**What.** With no hints in the identifier, the resolver queries
`wss://social.hns.one`, `wss://relay.damus.io`, `wss://nos.lol` and
`wss://relay.nostr.band`. It never asks for the author's own kind:10002 relay
list.

**The standard says.** NIP-65 defines kind:10002 as the mechanism by which an
author announces where their events can be found, and says clients SHOULD
consult it when looking for a user's data.

**Why.** The bundled set works for the common case, because the large public
relays hold most of the network's events. Reading NIP-65 requires a *first*
query to find out where to send the *real* one, on relays chosen the same
arbitrary way, so it does not eliminate the bootstrap problem — it moves it.

**Consequence.** A key that publishes only to relays outside this set resolves
as empty. A key whose author has deliberately moved to their own relay is
invisible unless the link carries a hint. It also means **we** chose four
servers on the user's behalf, and every query discloses the user's interest to
all four (SPEC §10.3). A set of unreachable relays returns 502 rather than 404,
so "we asked and nobody had it" is at least distinguishable from "we could not
ask" — but "the four we chose did not have it" still reads as an empty key.

**Status: OPEN.** For a target that carries a pubkey, issue
`{kinds:[10002], authors:[pubkey]}` first, read the `r` tags, honour the
`read`/`write` markers, and query the union of that list with the current set,
each entry passing the same `isSafeRelayUrl` check a hint passes. Cache the
list for the navigation. The concrete shape is NO-D4.

---

#### NO-4. BIP-173's 90-character limit is not enforced, and bech32 is implemented locally
*BIP-173 · `src/nip19.js`*

**What.** The decoder implements BIP-173 exactly — charset, HRP expansion,
polymod checksum, mixed-case prohibition, non-zero-padding rejection — with
the single exception of the 90-character length cap, which is not applied. The
implementation is local rather than a dependency.

**The standard says.** BIP-173, "Bech32": *"the string is at most 90
characters"*, and its error-detection proof is stated for strings within that
bound.

**Why.** NIP-19 identifiers routinely exceed 90 characters: an `nevent` with an
author and two relay hints does, an `naddr` with a long `d` tag comfortably
does. A limit-enforcing decoder rejects perfectly valid Nostr identifiers. The
two bech32 implementations already present in the browser's tree are both
transitive dependencies (they arrive under `hsd`) and both enforce the limit,
so neither can be used, and taking an undeclared transitive dependency breaks
the day that tree reshuffles.

**Consequence.** A pathological identifier can be arbitrarily long. BIP-173's
guarantee — at most 4 errors detected *within* 90 characters — does not hold
beyond it, so a longer identifier has a weaker (though still ~2⁻³⁰ against
random corruption) guarantee. The decoder is total and the payload is
length-checked per type, so a long string wastes work and does not do damage.

**Status: DELIBERATE.** Every Nostr implementation does this; enforcing the
limit would reject valid identifiers and interoperate with nobody. Pinned by a
test that builds an over-90-character `nevent` with an independent encoder.

---

#### NO-5. `nostr://` is accepted although NIP-21 defines only `nostr:`
*NIP-21 · RFC 3986 · `src/nip19.js` (`parseNostrURI`)*

**What.** `nostr://npub1…` parses identically to `nostr:npub1…`, and a trailing
`/`, `?…` or `#…` is stripped.

**The standard says.** NIP-21: the URI is the scheme token followed *directly*
by a NIP-19 entity, with no authority component. In RFC 3986 terms `nostr:` is
a path and `nostr://` introduces an authority — two different productions.

**Why.** Chromium normalises a registered scheme's URL into the authority form
before the protocol handler sees it, and appends a path to a bare authority.
Refusing the shape would mean refusing requests our own browser generates.

**Consequence.** We accept a form NIP-21 does not define, which is lenient in
the direction that costs nothing: no valid identifier is rejected and no
invalid one is accepted, since the bech32 checksum still governs. A link
*written* as `nostr://` does not work in a client that reads NIP-21 strictly,
so this affects what we accept and must never affect what we emit.

**Status: DELIBERATE**, with the standing rule that anything this
implementation *generates* uses the bare `nostr:` form.

---

#### NO-6. An `nsec` is refused by name, quoting it back to nobody
*NIP-21 · `src/nip19.js` (`decodeNip19`)*

**What.** An `nsec` is not treated as an unsupported prefix. It is matched
explicitly and refused with: *"that is a PRIVATE KEY (nsec). It was not sent
anywhere. Never paste it into a browser or share it."*

**The standard says.** NIP-21 excludes `nsec` from the URI scheme; a strict
reading is satisfied by "unknown prefix", and NIP-19 says nothing about error
text.

**Why.** The person who has just pasted their secret key into an address bar
needs to be told it is a secret, not that the browser lacks a handler. The
message is also a factual claim we are able to make: parsing happens before any
network access, and a test asserts nothing is dialled before the address
parses, so "it was not sent anywhere" is true.

**Consequence.** The error text names the string's *type*. It never echoes the
key. Anyone reading over the user's shoulder learns that a secret was pasted,
which is a disclosure we accept as strictly better than the alternative. The
claim holds on both paths a secret can arrive on: a bare `nsec` typed into the
address bar is classified into this namespace on its prefix, before any name
rule sees it (SPEC §3), so it reaches this refusal rather than a resolver.

**Status: DELIBERATE.** The wording is the feature and a test pins both halves
of it.

---

#### NO-7. No NIP-42 AUTH: a relay that wants sign-in is a relay that answered nothing
*NIP-42 · `src/relay.js`*

**What.** `AUTH` frames are ignored — they fall into the "not our subscription
id" branch. A relay that requires authentication before serving reads
contributes zero events, and the relay report shows it as having answered with
nothing rather than as having demanded something.

**The standard says.** NIP-42 defines the `AUTH` challenge/response by which a
relay may require a client to prove control of a key before serving it.

**Why.** Not implementing the handshake is deliberate: the resolver holds no
key. `nostr:` resolution is anonymous by construction, and authenticating would
mean either using the user's identity — turning a page load into an identified
request — or minting a throwaway key, which most auth-gated relays exist to
prevent. What is *not* deliberate is the silence: the condition is
distinguishable on the wire and is not reported.

**Consequence.** Paid and members-only relays are unusable from `nostr:`, and
the user cannot tell *why*. Wildroot's social client, which does hold a key,
distinguishes this case ("wants sign-in") in `relayHealth`; the resolver does
not.

**Status: OPEN** on the reporting half. Recognise an `AUTH` frame for our
subscription and finish the query with an error string naming the condition —
"relay requires sign-in" — so the relay report says why the relay contributed
nothing. The anonymity property is unaffected: nothing is signed and no key is
held. Answering the challenge stays out of scope.

---

#### NO-8. Fixed result limits, no pagination, no time window
*NIP-01 · `src/nostr-protocol.js` (`renderProfile`, `renderNote`, `renderAddressable`)*

**What.** A profile fetches at most 5 kind:0 events and 20 kind:1 events; a
note or addressable lookup fetches 1. `since`, `until` and any form of paging
are unimplemented, and a caller-supplied `limit` inside a filter is overwritten
by the option.

**The standard says.** NIP-01 defines `limit`, `since` and `until` as filter
fields a client may use, and describes `limit` as applying to the initial
query.

**Why.** A resolver returns *an answer*, not a feed. Paging belongs to a
client, and this chapter specifies a resolver (SPEC §1.1).

**Consequence.** "20 verified notes" is 20 notes out of an unknown number, and
the heading says "verified", which is true, rather than "all", which would not
be. There is no way to see the 21st. For a prolific author the page is a
window, not an archive.

**Status: DELIBERATE** for a resolver. A client built on this chapter needs its
own paging, and inherits `matchesFilter` for free when it adds `since`/`until`
to a query.

---

#### NO-9. Three independent NIP-01 implementations, and a trust header nobody reads
*`src/event.js`; in the browser, `src/nostr/nostr-event.js`, `src/identity/nostr-event.js`, `src/hns/trust-path.js`*

**What.** The Wildroot tree contains three separate implementations of the
NIP-01 serialisation and signature check: this one (verifies, on
`node:crypto`), the identity keystore's (signs, on `node:crypto`), and a
vendored copy of a standalone package (both, on `@noble/hashes`). They are held
in agreement by a cross-verification test and a hash manifest.

Separately, every response carries `X-Nostr-Trust: signature-verified;
completeness-unverified` and `X-Nostr-Pubkey`, described in a comment as
"machine-readable for the lock UI". **Nothing reads either header.** The trust
panel's Nostr arm exists and is correct, and it derives its two steps from the
URL's *scheme*, not from the header the page emitted.

**The standard says.** Nothing — no NIP governs either half. The rule broken is
the ordinary one about a single source of truth, and about a comment that
describes a thing that does not happen.

**Why.** The three copies have real causes: `electron-builder` packages one
directory, so a cross-repo import resolves in a dev checkout and is absent from
the installed app; and the keystore's copy signs while this one only verifies.
The header is a wiring step that stopped one file short of its reader.

**Consequence.** A fix to the serialisation must be made three times, and the
drift test tells you when you forgot rather than preventing it. The header is
harmless and inert: because the panel's arm is keyed on the scheme, a page that
somehow reached the panel *without* verifying anything would still be described
as verified — the panel is stating the handler's contract, not observing its
output.

**Status: OPEN** on both halves. For the header: have the trust panel read
`X-Nostr-Trust` where the response is available to it, so the claim is the
page's own rather than the scheme's, or delete the header and the comment that
oversells it. For the implementations: one module that both signs and verifies,
vendored once, with the drift test kept as a guard rather than as the
mechanism. The concrete shapes are NO-D5 and NO-D6.

---

#### NO-10. The canonical serialisation is delegated to the host's `JSON.stringify`
*NIP-01 · RFC 8259 · `src/event.js` (`eventId`)*

**What.** NIP-01 specifies the event-id serialisation exactly, including which
characters are escaped. The implementation builds the array and calls
`JSON.stringify` on it, relying on the host to produce that byte string.

**The standard says.** NIP-01: the id is the SHA-256 of the UTF-8 serialisation
of `[0, pubkey, created_at, kind, tags, content]` with no whitespace, escaping
`"`, `\`, `\n`, `\r`, `\t`, `\b`, `\f` and nothing else.

**Why.** NIP-01's own text says the serialisation *is* the JSON of that array,
and every implementation in the ecosystem does this. Hand-rolling it would be
three copies of an escaping table (NO-9) rather than one.

**Consequence.** It is an assumption about the runtime, not a check. It holds
in V8 for the cases that matter, including well-formed-`JSON.stringify`
behaviour for lone surrogates and literal U+2028/U+2029 in strings, and it is
pinned by a cross-implementation test whose fixture deliberately contains
quotes, a backslash, a newline, non-ASCII, an astral character and U+2028. It
has never been tested against a *non-V8* JSON implementation, and a runtime
that escaped differently would compute different ids and reject valid events —
failing closed, which is the right direction, and confusingly.

**Status: DELIBERATE**, with the assumption stated rather than hidden.

---

#### NO-11. The `_nostr` DNS record is designed and documented but not published
*In the browser, `docs/RESOLUTION-ROUTER.md`, `docs/Protocols.md`, `src/identity/record.js` — not in this chapter*

**What.** The Wildroot design has a Handshake name's zone bind the name to a
Nostr key with a `_nostr.<name>` TXT record, attested by the name's control
key. Three design documents describe it and the record parser exists. The live
zone contains `_hns` records and **no** `_nostr` records.

**The standard says.** Nothing — no NIP and no RFC governs this. It is our own
design, and the deviation is from our own documents, which describe the binding
in the present tense.

**Why.** Unfinished work, not a decision.

**Consequence.** The Handshake→Nostr binding that would make a name→key mapping
*chain-proven* rather than WebPKI-asserted does not exist in practice. The only
name→key mapping that works today is NIP-05, with the trust properties of SPEC
§7.3. Any document that describes the `_nostr` binding in the present tense is
describing a design, not a deployment.

**Status: OPEN.** Publish the record for the names that already have a Nostr
key, and read it on the Handshake path so a name resolves to a key through the
chain proof and the DNSSEC chain anchored to the on-chain DS. This is the
single most valuable thing this namespace could gain: it is the one available
route to a Nostr identity mapping that is not somebody's word. Until it exists,
every document describes it in the future tense — this one does. The concrete
shape is NO-D3.

---

#### NO-12. On a `.hns.one` NIP-05 address the Handshake guarantees do not apply to the lookup
*SPEC §7.3 · `src/nip05.js`*

**What.** `_@alice.w3.hns.one` is verified by fetching
`https://alice.w3.hns.one/.well-known/nostr.json?name=_` with the platform
`fetch`. That request goes through the host's own resolver and WebPKI. It does
**not** go through the chain-proof, DNSSEC-to-on-chain-DS, DANE-pinned path
that the Handshake chapter of this specification defines for `hns://`.

**The standard says.** NIP-05 requires an HTTPS GET and forbids following
redirects; it says nothing about which resolver or which trust anchor. The
deviation is from *our own* stronger path, not from NIP-05.

**Why.** It is deliberate that the address be *ordinarily* resolvable — the
point of `_@<name>.hns.one` is that a client with no Handshake support can
verify it. What is not deliberate is that our own browser, which has the
stronger path available, does not use it.

**Consequence.** A NIP-05 verification performed inside Wildroot is exactly as
strong as one performed inside any other client, and no stronger. A reader who
knows the Handshake chapter may reasonably assume otherwise, which is the only
reason this is a deviation and not a footnote.

**Status: OPEN.** Route the well-known fetch for a `.hns.one` name through the
`hns://` path, so the hop is DANE-pinned and chain-anchored, while keeping the
address ordinarily resolvable for every other client — the cost is that our own
client no longer exercises the same code path everyone else does, which is a
real loss of "we test what they test" and is why this is worth arguing about
rather than simply doing.

---

#### NO-14. The `nsec` arm is claimed on its prefix, not on its checksum
*SPEC §3, §5.3 · `../../src/router.js` `classify`*

**What.** The five public prefixes are claimed only when `decodeNip19`
succeeds. `nsec` is claimed whenever the input matches `nsec1` followed by six
or more bech32 characters, decode or no decode — because its decode is
*designed* to fail (§5.3). So `nsec1qqqqqq`, which is not a valid identifier,
is routed to this namespace and met with the PRIVATE KEY refusal, and a
Handshake name of that shape can never be reached.

**The standard says.** Nothing. NIP-21 excludes `nsec` from the URI scheme,
which is consistent with refusing it rather than resolving it.

**Why.** The alternative is worse in the only direction that matters. A
checksum-gated `nsec` arm would release a mistyped or truncated secret key to
the bare-label rule, which transmits it to a chain node or a DoH resolver *as a
name*. A mistyped secret is exactly the case where the refusal is most needed.

**Consequence.** A narrow range of the Handshake namespace — names beginning
`nsec1` with a bech32 tail — is unreachable from the address bar. We know of no
such registration, and it can still be reached with an explicit `hns://`, which
is what L1 is for. The trade is a deliberate one: an unreachable name is
recoverable, a disclosed secret is not.

**Status: DELIBERATE.** An implementation **MAY** narrow the arm to
prefix + valid bech32 *charset* (which is what is implemented) and **MUST NOT**
narrow it to a valid checksum.

---

#### NO-15. Private mode hides who is asking, not what is asked
*SPEC §8.5, §10.3 · `../../DIVERGENCE.md` row 15 · `src/tor-websocket.js`, `src/nostr-protocol.js` (`relayClass`)*

**What.** In Private mode every relay is dialled through the device-local Tor
by name, so a relay sees a Tor exit's address and the local network never sees
a relay's name. The relay still receives the filter — the key, the event id,
the `d` tag — because that is the question, and NIP-01 has no way to ask it
without saying it.

**The standard says.** Nothing: NIP-01 defines no oblivious query, and no NIP
does. The deviation is from this repository's own design rule (the browser's
`docs/MODES.md`): make privacy and speed stop pulling apart before adding a
mode. For Nostr the attempt fails by protocol, which is why row 15 survives as
one of the five places a mode is for.

**Why.** A relay is a store that answers the question it is asked. The
both-sides options are all partial: our own relay sees the question but is
ours (§2.4); caching an answer removes repeats, not the first ask; NIP-65
(NO-3) changes which relays are asked, not what they learn.

**Consequence.** The Private-mode disclosure to a relay is "someone, from a Tor
exit, asked about this key at this moment". Across the four default relays and
the hints, the same exit can ask all of them, because no SOCKS credential is
sent and the circuits are the session's (Chapter 8, TO-3) — so the relays are
linkable to one another through the exit as well as through the identical
filter. The refusal page and the settings disclosure say the mode hides this
device's address; neither says the question is hidden, and nothing in this
chapter may.

**Status: DELIBERATE**, and bounded. The recommendation is the pair that
narrows the disclosure without a new protocol: cache an answer for the
navigation, so following a link on a profile page does not re-ask every relay
for the same profile; and read NIP-65 (NO-D4), so the relays asked are the
author's rather than ours. Per-relay stream isolation is Chapter 8's item
(TO-3), not this chapter's.

---

#### NO-16. Two WebSocket implementations on two routes
*SPEC §8.1, §8.5 · `src/relay.js`, `src/tor-websocket.js`*

**What.** On the direct route the relay client uses the injected
`WebSocketImpl` or the runtime's global `WebSocket`. On the Private route it
uses the `ws` package, because the runtime's `WebSocket` accepts no transport
and cannot be given a socket that came out of a SOCKS tunnel. Two clients, one
relay protocol, one event surface (`onopen` / `onmessage` / `onerror` /
`onclose`, `send`, `close`).

**The standard says.** RFC 6455 is the wire protocol both implement; the
WHATWG WebSockets Standard is the API the direct route uses. `ws` implements
RFC 6455 and presents a compatible subset of the WHATWG surface; it is not the
WHATWG interface.

**Why.** There is no seam in the built-in client. The alternative — `ws` on
both routes — would make the direct route depend on a package for something
the platform provides, and would change the direct route to fix the private
one.

**Consequence.** A behaviour that differs between the two clients shows only
in Private mode. The one known difference is handled — `ws` delivers a text
frame to `onmessage` as a string, which is what `src/relay.js` reads — and the
Tor route is driven end to end by the real relay client against a real
`wss://` server (`tests/tor-websocket.test.js`), so the relay protocol is
proven on both. Timeouts, close codes and error shapes are not compared between
the two.

**Status: DELIBERATE.** The recommendation is a conformance run: drive the
scripted-relay suite of `tests/nostr-protocol.test.js` through the `ws` class
as well as through the scripted `WebSocketImpl`, so a difference between the
two clients is found by the suite rather than by a user in Private mode.

---

### 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each
is a real decision that is currently shipping, and each could be wrong.

#### 2.1. Whether a lock can ever close for Nostr — and whether a padlock is the right instrument

Our position (SPEC §4.1) is that completeness is permanently `unverified`,
therefore the aggregate is permanently `partial`, therefore a Nostr page never
gets a closed green lock however much verification happened. We think that is
right and we are aware it produces a strange result: the namespace with the
*strongest* per-object guarantee in the browser — every byte displayed is
signature-checked in-process, which is more than `https://` can say — presents
with an indicator weaker than the one an ordinary web page gets.

The alternative would be a fourth aggregate state meaning "the object is
proven, the answer set is not", which is honest and is one more thing a user
has to learn.

What we are unsure of: whether the right conclusion is instead that a padlock
is simply the wrong instrument for a namespace like this, and that the relay
report should be the primary surface with no lock at all.

#### 2.2. What "the right event" means, once the answer is bound to the query

Binding the answer to the filter closes substitution. It does not close
**currency**, and we do not think anything can.

For a replaceable event — kind:0 profile metadata, kind:3, kind:10002 — the
"right" answer is the newest one its author signed, and a relay can serve an
older one that matches the filter and verifies perfectly. There is no signed
sequence number, no chain, no proof that a newer one does not exist. Ordering
by `created_at` is ordering by a number the author chose, so an author who
backdates — or a relay that only holds a backdated copy — wins. A profile shown
here may be a year stale and correct-looking.

We do not know what to do about this beyond saying it. "You are seeing the
newest of N relays' answers, here are the N" is what we have. If there is prior
art on freshness in a system with no root, we have not found it.

#### 2.3. Whether NIP-05 belongs in a resolution specification at all

NIP-05 is the only name→key mapping most Nostr users ever use, so leaving it
out would make this chapter useless. But it is not cryptographic, it is WebPKI
with extra steps, and putting it in a document that also specifies BIP-340
signature verification risks the reader averaging the two.

We try to solve this by stating SPEC §7.3 as bluntly as we can. We are not sure
that is enough, and we are not sure a specification is even the right place for
the warning — the place a user meets the claim is the interface, not the spec.
A related worry: NIP-05's own text says the mapping is not an identity proof,
and essentially every client in the ecosystem renders it as a blue tick anyway.

#### 2.4. The default relay list is a decision we made for the user

Four relays, chosen by us, one of them ours. Every `nostr:` navigation
discloses the target key to all four, from the user's address, and the answer
the user sees is bounded by what those four hold.

We think a default is unavoidable — an empty relay set resolves nothing, and
asking a user to configure relays before their first link works is not a
product. We are much less comfortable that the list is a constant in a source
file rather than something the user can see and change, and least comfortable
that ours is first in it. A relay operated by the party shipping the browser,
queried on every navigation, is a log of what the user looked at. We do not
keep such a log; the correct answer is not "trust us" but "you can see this and
change it", and that surface does not exist.

Reading NIP-65 (NO-3) reduces but does not remove this: the bootstrap query
still goes somewhere chosen by us.

#### 2.5. Whether `nostr:` should be a standard scheme

`nostr:` is registered with **low** privileges in Electron: no origin, no
`fetch`, no service workers, no secure context. `hns:` is registered as
standard, which is what makes a Handshake site a real web origin and is also
what drags in the URL Standard's IPv4 host rule.

Low privileges are right for what the handler does: it renders a static
document with no script. If a Nostr *client* ever lived at `nostr:` it would
need an origin, and then a key becomes an origin — a genuinely interesting
question, since 32 bytes of x-only pubkey is a far better origin than a
hostname in that it cannot be transferred or seized, and one we have not
thought through. Storage keyed by an npub would be a real thing to have. It
would also mean a page's origin changes when it is the same author under a
different identifier form (`npub` vs `nprofile`), which is exactly the kind of
detail that turns into a security bug.

#### 2.6. Whether a bare `npub` should navigate

It does, and the rule that decides it is explicit and tested (SPEC §3). What we
are still not certain of is the collision itself: Handshake's bare-label rule
claims the same input space (most Handshake sites are bare TLDs), and we
settled it with the bech32 checksum — a 30-bit checksum over a fixed
human-readable part, which we think is not thin evidence for a namespace claim.

The residue is the `nsec` arm, which does *not* have that evidence: it is
claimed on the prefix alone, so it takes a small range of the Handshake
namespace with it (NO-14). We are confident that is the right trade for a
secret key and we would rather it were argued with than assumed.

#### 2.7. What we should be doing about relay disclosure

The Handshake chapter has an answer for the equivalent problem: Oblivious DoH,
where the resolver learns the query and not who asked. Nostr has no analogue. A
relay learns the key you asked about and your address, and the fan-out that
makes answers better makes the disclosure wider.

Private mode does the half that is possible: every relay is dialled through
the device-local Tor by name (SPEC §8.5), so the relay sees an exit's address
and the local network sees no relay name — and the relay still sees the
question, because there is no way to ask it otherwise (NO-15). Asking every
relay for a superset and filtering locally is the classic answer to the other
half and is prohibitively expensive here. What we are not sure of is whether
hiding the asker without hiding the question is worth what it costs the user —
Tor's latency on every relay, and relays that refuse Tor exits — or whether the
honest line for this namespace is that Private mode buys less here than
anywhere else in the browser, and the page should say so.

#### 2.8. Whether a refused relay hint should be silent

A hint that fails `isSafeRelayUrl` is listed in the relay report with its URL
and the reason. That is the honest choice and it also prints an
attacker-supplied string — escaped, on a page with no script source — onto the
user's screen, which is a small phishing surface: a link author can put text of
their choosing in the report by encoding it as a relay hint. We think naming
the refusal beats hiding it, and we are not certain the trade is right.

---

### 3. Open design items

Changes we think are correct and have not made. Each names the deviation it
closes.

#### NO-D1. Resolve the `nip05` claim, or say the domain was unreachable

**Problem.** The profile page marks a `nip05` field as an unverified claim
(NO-2) and never asks the domain. `lookupNip05` in `src/nip05.js` already does
the request correctly — the host is derived from the identifier, redirects are
refused, the local part is checked against NIP-05's grammar — and the profile
renderer does not call it.

**Recommendation.** Call it, with the injected `fetchImpl` so the request rides
the same proxied session fetch the rest of the browser uses, and render three
outcomes instead of one: the domain names this key (a fact about the domain,
still `unverified` in the trust model and still labelled with the domain's
name); the domain names a *different* key or none (a contradiction, which is
worth saying loudly); the domain could not be asked. Bound it with the same
deadline the relay query uses, and never let a slow domain hold the page.

#### NO-D3. Publish the `_nostr` record, or stop documenting it

**Problem.** Three design documents and a record parser describe a
`_nostr.<name>` TXT record binding a Handshake name to a Nostr key. The live
zone has none (NO-11).

**Recommendation.** Publish it for the names that already carry a Nostr key,
and read it on the Handshake path. This is worth doing rather than deleting
because it is the only available route to a Nostr name→key mapping that is not
somebody's word: NIP-05 is WebPKI, while a `_nostr` TXT record in a
DNSSEC-signed zone anchored to the on-chain DS is chain-proven, using the entire
apparatus the Handshake chapter already specifies and tests. It would make this
the only client that can say "this key is this name" and mean it
cryptographically.

#### NO-D4. Read NIP-65 relay lists

**Problem.** Relay selection is four relays we chose plus whatever the link
author chose, so an author who has moved to their own relay is unreachable
(NO-3).

**Recommendation.** For a target that carries a pubkey (`npub`, `nprofile`,
`naddr`, and `nevent` with an author), issue `{kinds:[10002], authors:[pubkey]}`
first, read the `r` tags, honour the `read`/`write` markers, and query the union
of that with the current set — each URL through `isSafeRelayUrl` and
`normalizeRelayUrl`, and under the same bound hints get, because a kind:10002
is also a stranger's choice of who this browser talks to. Cache the list for
the navigation. It does not remove the bootstrap problem — the kind:10002 query
goes to relays chosen the same arbitrary way — and it is still worth it.

#### NO-D5. Read `X-Nostr-Trust`, or delete it

**Problem.** The response header is emitted with a comment calling it
"machine-readable for the lock UI", and nothing reads it. The trust panel's
Nostr arm derives its steps from the scheme instead (NO-9).

**Recommendation.** Either give the panel the response's headers where the
navigation makes them available, so the two steps it shows are the ones the
handler actually performed rather than the ones the scheme promises — which
also makes the arm degrade correctly if the handler ever changes — or delete
both headers and the comment. The current state is a comment describing a wire
that was never connected, which is the kind of thing a reader believes.

#### NO-D6. Collapse the three NIP-01 implementations

**Problem.** Three implementations of one serialisation and one signature
check, held in agreement by a cross-verification test and a hash manifest
(NO-9). A fix must be made three times.

**Recommendation.** One module in the tree that both signs and verifies,
vendored once, with the drift test kept as a guard rather than as the
mechanism. The causes are real — `electron-builder` packages one directory, and
the keystore's copy signs while the protocol's only verifies — so this is a
design task rather than an edit, and the design constraint to solve is
packaging, not cryptography.

Two changes that look like improvements and are not, recorded so they are not
re-proposed: **enforcing BIP-173's 90-character limit**, which would reject
valid NIP-19 identifiers (NO-4 is deliberate and every implementation agrees);
and **closing the lock when a signature verifies**, which would be the precise
misrepresentation SPEC §4.1 and §10.2 exist to prevent — authorship is proven
per event, completeness never is, and with the answer bound to the query as
well the temptation is stronger and the answer is still no.

---

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

## Chapter 7 — DID, AT Protocol and ActivityPub

_Source: [`namespaces/did/DEVIATIONS.md`](namespaces/did/DEVIATIONS.md)._

Every place this chapter's implementation departs from a standard it cites,
from common practice, or from its own stated design — plus every place we are
not sure we have made the right call.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

Each entry gives **what** we do, **what the standard says**, **why**, the
**consequence** (including the attack it does and does not enable), and a
**status** — `DELIBERATE` (we would defend it) or `OPEN` (we intend to change
it, with the change we would make).

A cross-cutting note before the list. This namespace is *thinner* than the
Handshake chapter of this specification. The Handshake path fails closed on
every unproven step; this path resolves two things itself, refuses two more,
and takes a third party's word for a fourth. Most of what follows is therefore
not "we chose a different rule from the RFC" but "we have not implemented the
check yet, and here is exactly which check". That is a worse position to be
in, and writing it down is the point.

---

### 1. Deviations

#### DI-1. A resolved DID document is served with `Access-Control-Allow-Origin: *`

**What.** A successful document is answered with `Access-Control-Allow-Origin: *`,
`Allow-CSP-From: *`, and wildcard allowed headers and methods
(`src/did-protocol.js`).

**The standard says.** The WHATWG Fetch Standard makes
`Access-Control-Allow-Origin: *` a grant of cross-origin read access to every
origin. A response fetched on behalf of a navigation, from a host a stranger
named, is not a response that wants that grant.

**Why.** Inherited from the browser's protocol-handler conventions, where a
handler serves content pages are meant to read.

**Consequence.** Read literally, the header makes the handler a cross-origin
reader for a DID document on any host the caller names. In this build it is
inert: `did:` is registered non-standard with `supportFetchAPI: false`, so a
page cannot `fetch('did:…')` at all, and a non-standard scheme's response is an
opaque origin. The exposure it would otherwise pair with is closed
independently — the host guard refuses private and reserved hosts before
connecting (SPEC §5.3), so there is no address space to read out of. What
remains is that the headers describe an intent the scheme's privileges
contradict, and a future decision to make `did:` a standard scheme — a
reasonable thing to want — turns an inert header into a live one with no other
edit.

**Status: OPEN.** The headers should say what is intended. A document no page
can read does not need `*`; the change belongs with DI-3, which rewrites the
response anyway. Pinned by `tests/did-protocol.test.js` so it cannot change
silently.

---

#### DI-2. `did:plc` is directory-trusted; the operation log is never fetched

**What.** `did:plc` is resolved by `GET https://plc.directory/<did>` and the
returned document is used once its `id` matches. The method's audit log
(`GET /<did>/log/audit`) is never requested and never checked
(`src/did-protocol.js`, and `resolvePds` in `src/bsky.js`).

**The standard says.** The did:plc method specification derives the identifier
from the genesis operation — base32 of a truncated hash of the signed operation
— so the DID commits to its own creation, and the directory publishes the full
signed operation log. Verifying that log against the DID is what makes the
method self-certifying rather than a database lookup.

**Why.** Not attempted. The document endpoint is one request and answers the
question the callers ask.

**Consequence.** `did:plc` is reduced from a *verifiable* method to *one
operator's database lookup*. It is the same shape of gap as the `ens://`
handler's — the binding is RPC-trusted, not chain-proven — and this chapter
reports it the same way: SPEC §4 marks the step unverified, the lock is
TRUSTED and never green, and the trust panel says in words that this is the
server's word.

**Status: OPEN**, and it is the highest-value thing that could be *added*
rather than fixed. Fetch the audit log, verify the operation chain — each
operation signed by a rotation key valid at that point, each carrying the
previous operation's CID, the DID equal to the hash of the genesis operation —
and check the served document against the head of that chain. It is
self-contained, needs no infrastructure and no chain, and would make `did:plc`
the strongest link in this chapter instead of the weakest. See DI-D5.

---

#### DI-3. The result is a bare DID document, as `application/json`

**What.** A successful resolution answers with the DID document alone, as
`Content-Type: application/json; charset=utf-8` (`src/did-protocol.js`).

**The standard says.** W3C DID Core §7.1 defines resolution as returning a
**result**: `didDocument` alongside `didResolutionMetadata` (content type,
error) and `didDocumentMetadata` (created, updated, deactivated, versionId).
The registered media type for a DID document is `application/did+json`.

**Why.** The consumers are a page renderer and a PDS lookup; neither reads the
metadata.

**Consequence.** Mostly cosmetic, and one thing that is not: the metadata
envelope is the natural place to say *"resolved, and here is what was and was
not checked"* — that the `id` was compared (it is) and that the `did:plc`
operation log was not (DI-2). Returning a bare document means those facts live
only in the trust panel, which is a UI surface rather than data a caller can
act on.

**Status: OPEN.** Wrap the document as DID Core §7.1 specifies and serve it as
`application/did+json`, with the verification facts in
`didResolutionMetadata`. Do it after DI-2, so there is something interesting
to put there. See DI-D6.

---

#### DI-4. `did://` is accepted as an alias for `did:`

**What.** `did://plc:abc` is normalised to `did:plc:abc` before parsing
(`src/did-protocol.js`).

**The standard says.** W3C DID Core §3.1 gives the syntax as
`did:<method-name>:<method-specific-id>`. A DID has no authority component, so
`did://…` is not valid DID syntax.

**Why.** Stated in the code: a rendering engine handed a registered scheme
sometimes returns it in authority form, and Electron's protocol layer does.

**Consequence.** A tolerated input form that is not a DID. It is only a
*receiving* leniency — nothing in this tree emits `did://`, and the normalised
identifier is what every downstream comparison uses — so no invalid DID escapes
into a document or a link. Worth stating because a reader implementing from
this chapter will otherwise see the branch and wonder whether it is a form they
must produce. It is not.

**Status: DELIBERATE.** It is a compatibility shim for one engine, it accepts
strictly more than the syntax rather than resolving something different, and
SPEC §3.1 states it so nobody mistakes it for a URL form. An implementation
SHOULD NOT emit it.

---

#### DI-5. AT Protocol handle resolution is not implemented; the AppView is asked instead

**What.** `resolveHandle` (`src/bsky.js`) calls
`com.atproto.identity.resolveHandle` on Bluesky's public AppView
(`https://public.api.bsky.app`) and takes the answer.

**The standard says.** The AT Protocol handle resolution specification gives
two authoritative methods, either of which a client may use, DNS preferred: a
`_atproto.<handle>` DNS `TXT` record carrying `did=…`, or
`GET https://<handle>/.well-known/atproto-did`. It further requires
**bidirectional verification** — the DID document reached from the handle must
list `at://<handle>` in its `alsoKnownAs`, or the handle is not that account's.
None of that is done here.

**Why.** The adapter was written for the *social client*, where the AppView is
already the read path for everything else and one more endpoint is free. It was
not written as a resolver.

**Consequence.** Handle → DID is a third party's word. That is an ordinary
posture for an ordinary client and an odd one here, for a specific reason: the
DNS method resolves a `TXT` record under a domain, and this browser already
resolves Handshake names from a chain proof, validates DNSSEC against an
on-chain DS, and has an oblivious DNS transport. It is the one client on the
network that could make `_atproto.<handshake-name>` mean something no stock
client can check, and it asks an AppView instead. The privacy cost is separate
and also real: every handle looked at is disclosed to one operator (SPEC
§10.4).

**Status: OPEN**, and it is the largest single gap in this chapter. Implement
the DNS `TXT` method against the browser's own validating resolver, fall back
to the well-known method, verify bidirectionally against `alsoKnownAs`, and
keep the AppView only as a last resort reported as unverified. See DI-D1.

---

#### Experimental: identity anchors

The two deviations below are in the **experimental** part of this chapter
(SPEC §9): record formats that are shipped and signed by the browser's
keystore but are not a proposed standard and may change. They are separated
here so a reader does not weigh them against the stable resolution path.

#### DI-10. Nothing enforces that an identity anchor's `epoch` moves forward

**What.** A claim receipt binds `(name, pubkey, epoch, created_at)` and
verifies for ever. A receipt for epoch 1 is still valid after the name has
moved to epoch 2. No component in this chapter, and nothing in the browser's
consumer of it, remembers the highest epoch it has seen for a name
(`src/record.js`, `src/receipt.js`).

**The standard says.** No cited standard governs this — the `_hns` record is
our own format (SPEC §9.1). The relevant expectation is the design's own: an
`epoch` field exists to make a key rotation legible, and a monotonic counter
that nothing enforces is not a counter.

**Why.** The defence was placed entirely on publication: the registry serves
one current record, DNSSEC-signed, under a Handshake name.

**Consequence.** A previous holder of a name keeps a permanently valid receipt
for their own epoch. Using it requires getting that record served, which needs
control of the zone — the thing they no longer have — so this is a
defence-in-depth gap rather than a live attack. But "the only thing stopping
rollback is that the zone is honest" is a weaker statement than the rest of
this design makes, and rollback is exactly what a DNS cache, a stale ODoH
answer or a compromised-then-recovered registry produces. Pinned by
`tests/identity-anchor.test.js` ("DI-10").

**Status: OPEN**, with a recommendation we hold loosely. The obvious fix — a
per-name highest-epoch memory that refuses anything lower — has three problems
set out in §2.4, and we are not confident it is right. What we are confident
of is that the resolver MUST report the epoch it accepted alongside the key, so
a caller that *does* have durable memory can apply a floor. Do that first; it
is unambiguous and it unblocks the rest.

---

#### DI-11. `_nostr.<name>` is designed and not published

**What.** `record.js` and `keys.js` describe a sibling anchor,
`_nostr.<name>`, sharing the `_hns` schema and answering a different question —
who the name *is* on Nostr, as opposed to which key *controls* it. Nothing in
this chapter builds, publishes, parses or verifies it. `_hns` is the only
anchor the code implements end to end.

**The standard says.** NIP-05 specifies how a Nostr identifier is verified
against a domain (`/.well-known/nostr.json`), and this is not that. The
`_nostr` record is a second, DNS-side binding of our own design, intended to be
attested *by* the control key rather than by a well-known endpoint.

**Why.** Keeping the two records apart is what lets an owner hand a delegate
the control key for one domain without handing over their social identity. The
social half was deferred until the control half had shipped.

**Consequence.** A reader of `src/record.js` meets a record format that does
not exist yet, described in the present tense beside one that does. The
practical gap is that a Handshake name's Nostr identity currently has no
attested anchor at all: NIP-05 verification against `<name>.hns.one` is the
operator's word, exactly the thing `_hns` was built to stop being.

**Status: OPEN.** Either specify and publish `_nostr.<name>` with a receipt of
its own — the `hns:nostr:` `d`-tag prefix, by the same argument that makes
`hns:atproto:` non-interchangeable with `hns:` (SPEC §9.3) — or remove it from
the code's documentation until it is real. Half a format is worse than either.

---

### 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each is
a real decision that is currently shipping, and each could be wrong.

#### 2.1. Whether "recognised, fail-closed" is a resting state

`at://` and `activitypub:` are *recognised and refused*. The refusal is
defensible: it is honest, it leaks nothing, and it is strictly better than the
cross-namespace hijack that created the category. But a refusal is not a
resolution, and there is a version of this argument where "we recognise it and
will not resolve it" is a way of never having to state a trust model.

We think the fail-closed contract (SPEC §8) is right, and we think the bar in
SPEC §10.5 is the right bar, and we are **not** sure those two things together
are not a well-documented way of not shipping. The counter-argument is the
`ens://` and `nostr:` precedent in this same browser: both moved from refused
to *resolved with the lock open*, on the principle that an unverified answer
clearly marked unverified beats no answer. We have not applied that principle
here and we cannot fully articulate why not, beyond that `at://`'s verification
path is genuinely reachable (SPEC §10.5) in a way that ENS's is not, so
shipping the unverified version first may make it permanent.

If you have shipped an `at://` resolver, we would like to know whether the
unverified stage was a stepping stone or a resting place.

#### 2.2. Whether a DID document should be a *page* at all

`did:` is registered as a non-standard, non-secure scheme, so a resolved
document renders in an opaque origin with no storage, no service workers and no
`fetch`. That is a deliberately minimal posture for a document from a host a
stranger named, and we would defend it.

What we are not sure about is whether "navigate to a DID and look at the JSON"
is a feature, versus an artefact of the protocol-handler architecture making it
nearly free. The useful consumers of DID resolution in this product are
internal — find a PDS, check a binding — and they call the adapter directly
rather than going through the scheme. If the scheme exists mainly so that a DID
is a clickable link, it should render a *rendered* document — subject, keys,
services, and what was and was not checked — rather than raw JSON with wildcard
CORS headers (DI-1, DI-3).

#### 2.3. Whether a bare atproto handle should be classified as an atproto address

A bare `@user@host` classifies to `activitypub`, and we think that is clearly
right: it is not a host, and the URL parser reads it as a credential. The same
question for AT Protocol is much less clear, because an atproto handle **is** a
domain name. `alice.bsky.social` is a real host serving a real website; so is
`alice.hns.one`. A classifier routing every domain-shaped input to `atproto`
would break the web; one routing none of them means a handle is never
addressable as a handle.

The honest answer is probably that a bare domain is a website and an atproto
handle needs a scheme — which is what happens today, by inheritance rather than
by decision. We would like it to be a decision, and we are not sure it is the
right one, because a user who types their friend's Bluesky handle gets a
website they did not want.

#### 2.4. Whether a client-side epoch memory actually fixes DI-10

The obvious fix for identity-anchor rollback is: remember the highest epoch seen
per name, refuse anything lower. We are not confident that is right.

- It turns a **legitimate key rotation that resets or renumbers** into a
  permanent lockout, with no recovery path that is not "trust the registry
  again" — the thing the memory was protecting against.
- It is per-device, so the same user is protected on one machine and not
  another, and a fresh install has no memory at all, which is precisely the
  state an attacker would want to induce.
- It does not distinguish a rollback from a **transfer**, and a transfer *is* a
  legitimate change of both key and epoch. The `d`-tag replaceability semantics
  (newest claim per name wins) were chosen for transfers; an epoch floor argues
  with them.

What a monotonic counter wants is somewhere durable and shared to live, and the
only such place in this design is the chain — which knows the TLD and not the
SLD, which is the whole reason `_hns` is a mutual attestation in the first
place. This is the interesting problem in SPEC §9.

#### 2.5. `did:web:<name>.hns.one` versus `did:plc`

SPEC §9.4 records the decision: a Handshake name's AT Protocol identity is a
`did:web` on the operator's ICANN subdomain, because that resolves for every
stock client and not only inside this browser. Both methods resolve here, and
the binding receipt is method-agnostic; the choice is only which is the
default, and the code commits to neither — the method is chosen by the
provisioning worker, outside this chapter.

We are not sure the decision is right, and it is **irreversible per account**:

- `did:web` is not portable off the domain. If the operator's infrastructure
  goes away, so does every identity anchored to it — a strange default for this
  project.
- `did:web` has no in-document key rotation. `did:plc`'s operation log does,
  and is what makes DI-2's verification possible at all; choosing `did:web`
  forecloses the strongest verification story available in this chapter.
- Against that: `did:plc` depends on `plc.directory`, which is *also* one
  operator, and one we do not run. Both are dependencies; only one is a
  dependency we can fix when it breaks.
- And it is not established that Bluesky's relay and AppView handle `did:web`
  accounts as well as `did:plc` at network scale.

The decision is recorded as made; the reasoning above is why we would not
object to it being remade.

#### 2.6. What the AppView path should be *called*

DI-5 says handle resolution should not go through the AppView. Suppose it is
implemented properly and the AppView is kept as a fallback for when DNS and the
well-known both fail. What is that step's trust state?

"Unverified" (SPEC §4) is the mechanically correct answer and it is
unsatisfying, because it puts a query to a well-run public service in the same
bucket as a document from a host an attacker named. The Handshake chapter had
the same problem with its DoH fallback and answered it by naming *who* was
trusted rather than only *that* someone was. We have not done the equivalent
here, and we suspect a single "unverified" loses information a user would want.

#### 2.7. Whether this chapter should exist yet

Stated plainly, because it is the honest uncertainty behind all the others: of
the four things this chapter names, one resolves with a real check but no proof
(`did:`), one resolves by proxy (atproto identity), and two are refused. A
chapter for a namespace that mostly refuses is a strange document.

We publish it anyway for two reasons. The fail-closed contract (SPEC §8) is a
real, reusable design rule that we think other clients get wrong, and it is
worth writing down independently of what is behind it. And the list above is
the actual state of the code, which is more useful to a reviewer than a
document that waits until the state is flattering.

#### 2.8. Whether a labelled default PDS should exist at all

A PDS lookup that cannot resolve returns `{ pds: 'https://bsky.social',
assumed: true, reason }` (SPEC §6.2 rule 4). The AT Protocol DID specification
says an unresolvable DID is a resolution failure, full stop, and we keep a
default because the sign-in path is right for almost everyone and fails loudly
when it is wrong.

The label carries the weight: nothing can present the substitution as a
resolution without ignoring a field that says otherwise. What we cannot settle
is whether the default should exist at all. Against it: a value
labelled "assumed" is still a value, and the failure mode of a caller that
forgets to read one field is the failure mode we just fixed. For it: refusing
outright turns a momentarily unreachable directory into "you cannot log in",
for a network where one directory serves nearly every account.

We think the labelled default is right for a client and wrong for a resolver,
and this chapter is trying to be both.

---

### 3. Open design items

Work we think should be done, ranked by (security or correctness impact) ×
(how cheap the fix is), with the tie broken toward things that unblock other
things. This is opinion; §1 is description.

#### DI-D1. Resolve AT Protocol handles locally, not through the AppView

`resolveHandle` asks Bluesky's public AppView for handle → DID, so the mapping
this browser is uniquely equipped to check itself is a third party's word
(DI-5). The DNS `TXT` method resolves a record under a domain, and this browser
already validates DNSSEC against an on-chain DS and has an oblivious transport
for the query.

**Recommendation.** Implement the DNS `TXT` method against the browser's own
validating resolver, fall back to `GET https://<handle>/.well-known/atproto-did`,
verify bidirectionally against the DID document's `alsoKnownAs`, and keep the
AppView only as a last resort, reported as unverified and distinguishable in
the returned value. Highest impact in this chapter.

#### DI-D5. Verify the `did:plc` operation log

`GET https://plc.directory/<did>` and believe it (DI-2).

**Recommendation.** Fetch `GET /<did>/log/audit`, verify the operation chain to
the genesis operation — each operation signed by a rotation key valid at that
point, each carrying the previous operation's CID, the DID equal to the base32
of the truncated hash of the signed genesis operation — and check the served
document against the head. It is the only change in this list that would move a
step in SPEC §4 from **unverified** to **verified**, and it needs no
infrastructure, no operator and no chain. It is ranked here rather than first
only because it is genuinely a piece of work: signature verification over the
operation's DAG-CBOR encoding, rotation and recovery-window semantics, and a
cache so it is not re-fetched per navigation.

#### DI-D6. Return a DID resolution result, not a bare document

The response is the document alone, as `application/json` (DI-3).

**Recommendation.** Wrap it as DID Core §7.1 specifies — `didDocument`,
`didResolutionMetadata`, `didDocumentMetadata` — and serve
`application/did+json`, putting the verification facts in the metadata. Do it
after DI-D5, because the value is not conformance for its own sake: the
envelope is where "resolved, and here is what was and was not checked" belongs.
Reconsider DI-1's wildcard CORS headers in the same change.

---

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

**Dependencies.** This chapter adds exactly one runtime dependency beyond the
Node standard library and the shared modules of `../../src/`:
**`@noble/curves`**, for BIP-340 over secp256k1, reached through `src/keys.js`
and `src/nostr-event.js`. `src/did-protocol.js`, `src/unimplemented-protocol.js`,
`src/bsky.js` and `src/xrpc.js` need nothing beyond `fetch`, `Response`, `URL`
and `AbortSignal` from the platform; `src/gate.js` adds only the shared
`../../src/delivery-mode.js`, for the words its refusal carries.


---

## Chapter 8 — Tor

_Source: [`namespaces/tor/DEVIATIONS.md`](namespaces/tor/DEVIATIONS.md)._

Every place this chapter's implementation departs from a standard it cites,
from common practice, or from its own stated design — plus every place we are
not sure we have made the right call, and the design work we know is still to
do.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

A note on proportion before the list. **The property this namespace exists to
provide — that an onion address never reaches a name resolver — holds, and is
tested at all four entry points** (`namespaces/tor/tests/onion-leak-guard.test.js`).
Everything below is about the *other* things: what is disclosed to the service
once the tunnel is up, the granularity of the mode, an unmeasured cookie jar,
and one exception to the leak rule that lives in the router's first law rather
than in this namespace.

Paths written `../../src/…` are shared modules of the top-level package; paths
written `src/…` and `tests/…` are this chapter's, under `namespaces/tor/`.

---

### 1. Deviations

#### TO-1. With Tor off, and off Tor, we answer with a page rather than an error

**What.** Two of this handler's answers are `200` documents where a caller might
expect a failure status. In Fast mode — IP Protection off — an `onion://`
navigation gets a `200` interstitial explaining what to turn on, where, and what
the limitation is (`src/onion-protocol.js:125-128`, `:228-238`). When an onion
service redirects to a target outside Tor, the answer is a `200` page naming the
destination and offering it as a link (`:167-172`).

**The standard says.** RFC 7686 §2 tells application software that does not
implement the Tor protocol to *generate an error* and not perform a DNS lookup.
This browser does implement it, so it is on the other branch of that
requirement — but with protection off it neither errors nor looks up.

**Why.** The no-lookup half of RFC 7686 is the half that matters, and it is
satisfied absolutely: zero network activity of any kind. The error half exists
so that a user is not silently given the wrong thing. A page that says *"this
browser reaches .onion only through the Tor client on your own device; that path
is off right now; here is how to turn it on"* serves that intent better than an
error code the user cannot act on. The same reasoning covers the off-Tor
redirect: refusing it silently would leave the user believing the onion service
simply failed, when what actually happened is that it tried to send them
somewhere else.

**Consequence.** A script that fetches an `onion://` URL with protection off, or
one whose target redirects to the clearnet, sees a `200` and an HTML body rather
than a failure. That is a real interoperability wart for programmatic callers.
The trade is that the human case — by far the common one — is answered usefully.
There is a second-order effect the design depends on: because the interstitial
is a successful load, `did-fail-load` never fires, which is why the "reload when
the circuit is up" rule keys on the **scheme** and not on the load status
(`src/tor-reload.js`, SPEC §7.4).

**Status: DELIBERATE.** The requirement RFC 7686 is protecting — that the name
is never resolved — is met in full and tested. The status code is the part we
trade, and we trade it for a page a person can act on. An implementation aimed
at programmatic callers rather than at a human navigating should invert this
choice.

---

#### TO-2. An explicit non-onion scheme on an onion host is not protected

**What.** `https://<addr>.onion/` typed by a user, or followed as a top-level
link, keeps its explicit scheme. It is not reclassified into the `tor`
namespace, because the router's first law is that an explicit scheme selects the
protocol and is never sniffed (`../../src/router.js:362-376`).

**The standard says.** RFC 7686 §2: software that does not implement the Tor
protocol "should generate an error" for a `.onion` name and "should not perform
a DNS lookup" for it. The requirement is on the *name*, not on the scheme the
name was written under.

**Why.** Sniffing an explicit scheme is how `https://` silently becomes
something else, which is a worse and more general property than one unprotected
input. The law is held hard everywhere else in the router.

**Consequence.** That load goes to Chromium as an ordinary HTTPS request, and
Chromium hands `<addr>.onion` to the system resolver. **This is a real leak
path**, narrower than a classifier miss but real: it needs the user, or a link,
to name a scheme explicitly, which a hostile page can do. Partially mitigated:
the **subresource guard acts on the host regardless of scheme**, so
`<img src="https://<addr>.onion/x">` is cancelled
(`tests/onion-leak-guard.test.js`). The hole is top-level navigation only.

**Status: OPEN.** We recommend refusing it rather than routing it: a `.onion`
host under any scheme other than `onion:` is an unroutable address, and the
answer should be a fail-closed page from the `tor` namespace that names the
address as an onion service and offers the `onion://` form as a link. That is an
error rather than a lookup, which is what RFC 7686 §2 asks of software that will
not use Tor for the name, and it does not require sniffing — the scheme still
selects the protocol, it simply does not select *deanonymisation*. The cost is a
genuine, stated exception to the router's first law in a codebase that otherwise
holds it absolutely, which is why this is a decision to take deliberately rather
than a patch to apply; see §2.2 and TO-D2.

---

#### TO-3. No SOCKS stream isolation: everything shares circuits

**What.** One SOCKS proxy URL with no credentials is applied to the whole
session (`src/anonymize.js:243-258`), and the five main-process paths that dial
the same port for themselves — the Handshake resolver's authoritative hop, an
A-record `hns://` site's DANE-pinned socket, the `wss://` tunnel's upstream, a
`gemini://` TLS socket and a Nostr relay's WebSocket, all through
`../../src/socks-dial.js` (SPEC §7.5) — send none either.

**The standard says.** RFC 1929 defines username/password authentication for
SOCKS 5. Tor's `SocksPort` overloads it for *stream isolation* and has
`IsolateSOCKSAuth` on by default (Tor manual, `SocksPort` options), so a client
that supplied distinct SOCKS username/password pairs per first-party origin
would get a separate circuit per origin at no cost. We supply none.

**Why.** For the session the proxy is configured once, as an Electron
session-level `proxyRules` string, and that API has no hook for per-request
SOCKS credentials. For the five direct dialers the reason is different and
weaker: the shared SOCKS client simply does not take a credential, because it
was written for the session's own no-auth port and nothing asked it for one.

**Consequence.** Every onion service, and all clearnet traffic in the same
session, can share exit-side and circuit-level correlation. Tor Browser isolates
by first-party domain precisely to prevent that. It is a genuine anonymity gap,
and it is part of what "hides your IP, is not full anonymity" is paying for. The
direct dialers widen it in a specific and slightly worse way: a Handshake
nameserver query, the site connection that follows it, the WebSocket to that
name's origin, an unrelated Gemini capsule and a Nostr relay query can all
traverse one circuit, so a relay that sees the lookup may see the socket that
follows it.

**Status: OPEN**, with a real obstacle for the session half: we do not currently
know how to do this through Electron's session proxy API, and the fix is a piece
of design work rather than a line of code. TO-D1 states the three routes we can
see and why none of them is a one-liner. The five direct dialers are the
exception — they build their own SOCKS connection and could pass a credential
today — which makes them the place to measure whether Tor isolates on one at
all. Until per-site isolation exists anywhere, the product claim must keep
saying it is absent.

---

#### TO-4. Whether the session cookie jar reaches the onion fetch is not established

**What.** The handler forwards no `Cookie` header and passes no `Set-Cookie`
back (`src/onion-protocol.js:182-190`, `:209-219`). Whether the injected
session-bound fetch attaches session cookies of its own accord is **not
determined** by this code, and no test in this package or the browser's asserts
either way.

**The standard says.** RFC 6265 §5.4 has a user agent attach cookies for a
request URI from its cookie store; whether one store is shared across origins is
the user agent's decision, and the specification does not make it for us. The
deviation is therefore from our own stated design rather than from the RFC: a
namespace whose whole purpose is non-disclosure should know whether it shares
state with clearnet browsing.

**Why.** It was never measured.

**Consequence.** Unknown, which is the problem. If the session jar is attached,
an onion service shares a cookie space with the rest of the session, which is a
linkability surface exactly the size of the jar. If it is not, some onion sites
will not keep a login. Either answer is defensible; not knowing which one is
true is not.

**Status: OPEN.** This is a measurement we owe, not a design question, and it
has to be an Electron integration test because the behaviour lives in
`net.fetch` rather than in this handler: set a cookie on the session, issue a
request through the handler against a local server, and assert what arrives.
Then pick — we lean towards isolating, because a namespace built for
non-disclosure should not share state with clearnet browsing by default — and
pin the choice. See TO-D3.

---

#### TO-5. Onion services with client authorization cannot be reached

**What.** The generated `torrc` configures no `ClientOnionAuthDir`
(`src/tor.js:197-208`), and there is no interface for entering a
client-authorization key.

**The standard says.** rend-spec-v3 specifies client authorization for v3 onion
services — a descriptor encrypted to a set of authorized client keys — and the
Tor manual's `ClientOnionAuthDir` is where a client's keys live.

**Why.** Not implemented.

**Consequence.** A v3 onion service that requires client authorization is
unreachable, and fails with the generic `502` rather than a message naming the
reason. It fails closed and leaks nothing.

**Status: OPEN**, low priority. The `torrc` line and a `0700` directory are
trivial; the real work is the key-entry surface, because a client-authorization
key is a credential and belongs wherever the browser already keeps those, not in
a text box on an error page. Worth doing together with a `502` branch that
recognises the "descriptor requires client authorization" case and says so. See
TO-D4.

---

#### TO-6. IP Protection is all-or-nothing for the whole session

**What.** There is one proxy state for the whole browser session
(`src/anonymize.js:243-258`), and it is driven by Settings › Content delivery ›
Mode (SPEC §2). Reaching a single onion service means putting the whole browser
in Private: every tab, every protocol handler and the search fan-out through
Tor, and the Handshake, ICANN, Nostr and peer-to-peer policies that move with
the switch (`SPEC.md` §4.2), for as long as it is on.

**The standard says.** Nothing directly; this is a deviation from the Tor
Browser design document, whose first-party isolation model is the reference
point every claim about anonymity in this chapter is measured against.

**Why.** It is the honest version of the simple thing. A per-request or
per-origin proxy would be better, but Electron allows one proxy configuration
per session, and a design in which *some* traffic is proxied is a design in
which it is easy to be wrong about which.

**Consequence.** A user who wants one onion page pays Tor latency on everything
else, and the Private-mode refusals besides — peer-to-peer content, a Handshake
name whose oblivious lookup fails — which is a strong incentive to stay in Fast;
and Fast is the condition under which onion addresses are unreachable at all. The design
that is safest is also the one that discourages use. It is also, per TO-3, the
configuration in which everything shares circuits.

**Status: OPEN**, and it is the largest open design question in this chapter. We
do not recommend changing it until one of the routes in TO-D1 is proven, because
every alternative we can see either does not work (a PAC file gives a distinct
proxy string but no distinct SOCKS credentials, so Tor does not isolate on it),
or introduces a new listening socket in a privacy feature (a local SOCKS shim),
or multiplies Electron sessions. A whole-session proxy with no "was this request
proxied?" question in it is worth a great deal, and we would rather keep it than
trade it for a partial answer. See §2.5.

---

#### TO-7. While BLOCKED, a session request fails as a proxy error, not as a page that names the mode

**What.** In BLOCKED (SPEC §7.6) every session is pointed at
`socks5://127.0.0.1:9`. A page load, a subresource or a protocol handler's
session fetch then fails with the engine's `ERR_PROXY_CONNECTION_FAILED`, and
what the user sees is the engine's own error page — or, for `onion://`, the
handler's `502` echoing the proxy error (SPEC §6.7). The controller's note names
the mode and the switch, but it is shown in the status surface, not on the
failed page. Only the five raw-socket paths of SPEC §7.5 refuse in words
(`privateRefusal`).

**The specification says.** `SPEC.md` §4.2: every refusal or failure a
mode causes MUST name the mode, say what was not done, not blame the site, and
point at the control.

**Why.** The blackhole is what makes fail-closed hold for *everything* the
session sends, with no list of consumers to keep complete; a page that names the
mode needs a hook at the point where each load fails, which the proxy has no
part in.

**Consequence.** A person in Private mode whose Tor is down sees a generic
connection error on every site, and learns why only from the status note or the
menu. The behaviour is correct — nothing leaks — and the explanation is in the
wrong place.

**Status: OPEN. Recommendation:** in the composition, on a main-frame
`did-fail-load` with a proxy-connection error while the controller is BLOCKED,
replace the engine's error page with one built from the controller's note — the
same words: the mode, nothing loads, the switch — using the same hook the
Tor-ready reload of SPEC §7.4 already has on those tabs. Keep the blackhole; add
the page.

---


### 2. Things we are not sure about

These are the ones we would most like other implementers to argue with. Each is
a real decision that is currently shipping, and each could be wrong.

#### 2.1. Whether "device-local" should have any escape hatch at all

The rule in SPEC §1 is absolute: `127.0.0.1` or nothing. It rules out a hosted
relay, which is the case it was written for and which we would defend without
hesitation — an operator-run SOCKS endpoint learns every hidden service its users
ask for, and offering that while describing it as privacy is the specific
dishonesty this project exists not to commit.

But the same rule also rules out cases that are not that:

- a Tor daemon on another machine **on the user's own LAN** (a home server, a
  router), which many privacy-conscious people actually run;
- a Tor daemon in a container or VM alongside the browser;
- an organisation's own internal Tor instance.

In each of those the user *is* the operator. The rule as written cannot express
"a Tor I control", only "a Tor on this host", and `127.0.0.1:9050` is hard-coded
in two places. We think a configurable endpoint with a loud, non-default,
explicitly-consented-to setting would be strictly better than the current
position — and we are not sure, because the moment such a setting exists it is
the thing a bad tutorial tells people to point at somebody else's server. **We
would like to hear how other clients have drawn this line.** See TO-D5.

#### 2.2. Whether an explicit scheme should be allowed to defeat R1 (TO-2)

Two principles collide and only one can win:

- *An explicit scheme selects the protocol, always.* Sniffing is how `https://`
  quietly becomes something else, and we hold this law hard everywhere else.
- *A `.onion` host never reaches a resolver.* Disclosure cannot be undone, and
  this namespace exists for that rule alone.

Currently the first wins for top-level navigation and the second wins for
subresources, which is at least defensible — a subresource is not a user's
expressed intent — but is also two answers to one question. We lean towards
refusing `https://<addr>.onion/` outright, because "the scheme wins" cannot
sensibly mean "the scheme wins the right to deanonymise you". We have not
convinced ourselves that the special case is not the thin end of a wedge, and
the wedge is the thing we are unsure about rather than this instance of it.

#### 2.3. Whether routing before the circuit is ready is the right call (R11)

We argue in SPEC §7.2 that opening the gate on the *mode* rather than on
*readiness* is the leak-safe order, because the alternative leaves a window in
which the session is direct and some code path might take the request. We
believe that.

What we are less sure of is the user consequence: with the gate open and the
circuit still building, a first onion navigation can sit for up to a minute with
nothing to show but a progress percentage. The temptation to add a "try
directly" affordance to that screen is exactly the temptation this namespace must
never yield to, and a design that creates the temptation is a design with a
weakness in it. We do not have a better one.

#### 2.4. Whether a browser that does not resist fingerprinting should offer `.onion` at all

The strongest argument against everything in this chapter: reaching an onion
service in a browser without Tor Browser's fingerprinting defences may give
users a *feeling* of anonymity that the software does not provide, and a false
sense of protection can be worse than none. Someone who would have used Tor
Browser and instead uses this is worse off.

Our position is that the two things being conflated are separable and that
saying so plainly is the whole job: **hiding your IP** is what this delivers, and
it delivers it properly; **anonymity** is what Tor Browser delivers, and this
does not. Every string on this path pairs them — the interstitial, the mode note,
the trust panel — and `tests/onion-protocol.test.js` asserts the caveat is
present in the interstitial so it cannot be quietly dropped in a copy edit.

We are aware that is a claim about whether users read, and that we have no
evidence for it. **If somebody has run this experiment, we would like to know.**

#### 2.5. Whether the mode is at the right granularity (TO-6)

A whole-session proxy is simple, auditable, and has no "was this request
proxied?" question in it — properties we value highly — and it is also the
granularity of the whole Fast / Private switch, which drives it. It also makes the safe
path expensive enough that users will not stay on it, and per-origin circuit
isolation (TO-3) impossible.

The alternatives we can see are a per-request proxy (Electron does not offer
one), a PAC file that routes `.onion` differently from everything else (possible,
and composes badly with the WebSocket PAC the same controller already installs),
or a small local SOCKS shim of our own that fans out to Tor with per-origin
credentials (most capable, most code, most new attack surface). We have not
worked this out.

#### 2.6. Whether `onion://` is the right URL form

Tor Browser uses `http://<addr>.onion/`, and so does every link in the wild. We
carry a distinct internal scheme because in a general browser the namespace has
to be visible in the URL — the address bar has to be able to say *which* system
this address belongs to, and the rewrite from a clicked `http://` link is how
those in-the-wild links keep working.

The cost is that a URL copied out of Wildroot's address bar is not a URL anybody
else can use, and a shared `onion://` link is dead outside this browser. That is
the same complaint as the numeric-TLD convention in the Handshake chapter and it
has the same shape: a local convention forced by a real constraint. We would
rather converge with other alt-namespace browsers than defend ours.

#### 2.7. What a redirect chain should mean for the address bar

A same-service redirect is followed inside the handler, so the URL the user sees
stays the one they asked for while the bytes come from the path the service
redirected to. That is what an ordinary browser does for a redirect it follows
inside the network stack, and it is what makes a `302` to `/welcome` behave
normally — but here the handler is doing it on the browser's behalf, one layer
further out, and we have not thought through whether the address bar should
learn about the hop. It has no security consequence we can see (the origin is
identical by construction), and we are noting it because "the browser cannot see
the redirect" is the sort of thing that turns out to matter later.

---

### 3. Open design items

Work we believe should happen and have not done. Each states the problem and a
recommendation; none of it is implemented.

#### TO-D1. Per-origin SOCKS credentials for circuit isolation

One credential-free `socks5://127.0.0.1:<port>` is applied to the whole session,
so every onion service and all clearnet traffic in it can share circuits, where
Tor's `IsolateSOCKSAuth` would give a separate circuit per origin for free if we
sent distinct credentials. Electron's `session.setProxy` takes a session-wide
`proxyRules` string with no hook for per-request SOCKS credentials, so there is
no small version of this change (TO-3, TO-6).

**Recommendation.** Start where it is nearly free: the five main-process
dialers of SPEC §7.5 construct their own SOCKS connection, so giving
`../../src/socks-dial.js` an optional username/password derived from the
first-party (the Handshake name — for its nameserver hop and its site socket
alike — the WebSocket origin, the capsule host, the relay) is a parameter and a
test, and it answers the question the session-wide routes below
all depend on — *does this Tor isolate on it?* — for the cost of an afternoon. A
positive answer justifies the session work; a negative one saves it. Then take
the three session routes in order of what they would prove, not of effort. **(a)** A PAC script returning a different `SOCKS5` line per host
gets a distinct proxy *string* per origin but still no credentials, so whether
Tor isolates on it is doubtful and must be measured before it is believed; it
also has to compose with the WebSocket PAC the same controller already installs
(`this.proxyConfigFor`), which is a real constraint. **(b)** A tiny local SOCKS
shim that takes the intended first-party from a per-origin listener and opens
the upstream Tor connection with credentials derived from it is the most capable
and needs a security review rather than an afternoon, because it adds a
listening socket to a privacy feature. **(c)** Multiple Electron sessions, one
per first-party, is structurally clean and changes a great deal besides this.
Measure (a) first: it is the only one whose answer is cheap, and a negative
result is what justifies the cost of (b).

#### TO-D2. Decide what `https://<addr>.onion/` should do

An explicit scheme wins, so a typed or top-level-linked `https://<addr>.onion/`
goes to Chromium as ordinary HTTPS and the host reaches the system resolver.
Subresources are covered; top-level navigation is not (TO-2, §2.2).

**Recommendation.** Refuse it rather than route it. In `classify()`, before the
explicit-scheme return, recognise a `.onion` host under a non-`onion` scheme and
return a decision marked unroutable in the `tor` namespace, whose handler serves
a fail-closed page naming the address as an onion service and offering the
`onion://` form as a link. Write the exception to the first law into the comment
at the point where it is taken, in the words of the reason: an explicit scheme
selects the protocol, and does not select deanonymisation.

#### TO-D3. Establish, then pin, what happens to cookies

Whether the session cookie jar is attached to the onion fetch is unknown, and no
test asserts either way (TO-4).

**Recommendation.** Measure before deciding. An Electron integration test — set
a cookie on the session, issue a proxied request through the handler against a
local server, assert what arrives — turns the unknown into a fact. Then choose
isolation (`credentials: 'omit'`, or a partition of its own) unless the
measurement shows something that argues otherwise, and pin the choice with the
same test. Whichever way it lands, TO-4 stops being an uncertainty.

#### TO-D4. Support onion services with client authorization

No `ClientOnionAuthDir` in the generated `torrc` and no way to enter a key, so an
authorized service is unreachable and reports the generic `502` (TO-5).

**Recommendation.** Add `ClientOnionAuthDir <dataDir>/onion-auth` to the `torrc`
and create the directory `0700`; give the `502` page a branch that recognises
tor's "descriptor requires client authorization" and says so. Then design the key
entry properly: it is a credential, and it belongs wherever the browser already
keeps credentials, not in a text box on an error page. Ranked low because the
population of such services is small, not because the failure is graceful.

#### TO-D5. Let a user name their own Tor endpoint, loudly

`127.0.0.1:9050` is hard-coded in two modules, so "device-local" is implemented
as "this host" — which correctly excludes a hosted relay and also excludes a Tor
daemon the user runs on their own LAN, in their own container, or in their own
organisation (§2.1).

**Recommendation.** If it is done at all, a single configurable SOCKS endpoint
with three non-optional properties: not discoverable by accident (no
auto-detection beyond the existing `127.0.0.1:9050` fallback); explicitly
consented to once, with text naming the actual risk — *"the operator of this Tor
instance can see which onion services you ask for; only point this at a Tor you
control"*; and visible while it is in use, in the same surface that reports the
mode, so a non-default endpoint is never a silent state. We are genuinely
uncertain this should be built: the moment the setting exists, it is the thing a
bad tutorial tells people to point at somebody else's server. Being talked out
of it is a good outcome.

---

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

## Chapter 9 — Key-addressed namespaces

_Source: [`namespaces/keys/DEVIATIONS.md`](namespaces/keys/DEVIATIONS.md)._

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

#### KY-2. Only the hex infohash form; BEP-9's base32 magnet is refused

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

**Status: DELIBERATE.** Pinned by a test that says so out loud
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

That is a real similarity and we think it earns the placement. But a reader
looking for "the key-addressed chapter" finds one namespace in it that is
neither key- nor content-addressed and that verifies nothing at all, and may
reasonably think it belongs with the ICANN/DNS material. It is also the one
namespace here that Private mode **routes** instead of refusing (§K.3.6),
which is one more way in which it is not like its neighbours. Nothing
else in this chapter depends on it, so moving it costs nothing but the
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

## Chapter 10 — Experimental: HIP-5 `_op` and numeric Handshake TLDs

_Source: [`namespaces/experimental/DEVIATIONS.md`](namespaces/experimental/DEVIATIONS.md)._

Both parts of this chapter are experimental, so the whole file should be read
with that word in front of it: these are not settled positions we are defending
but a record of what ships and what we know is unresolved about it.

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
   `unreachable`, not "ask the box the contract exists not to trust".
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
reachable by an attacker who can make every Optimism RPC endpoint fail. That is
not a trivial capability, but it is not a high bar either.

Not a fallback, deliberately: a **private or link-local address** from the
registry is `blocked`, never retried against DNS.

**Status.** OPEN. Implement ENSIP-10 wildcard resolution for case 2, which is a
strict improvement and removes the case entirely; for case 1, report
`unreachable` rather than falling back, once there is more than one registry
operator and the fallback is no longer to ourselves. The current behaviour is
pinned by a test (`../../tests/hip5-op.test.js`, "every RPC failing falls back
…") so that changing it is a deliberate act.

---

#### NT-1. Numeric Handshake top-level names: DECIDED 2026-09-06 — off by default, behind a switch

**What.** An all-numeric final label is classified as a Handshake name
(`../../src/router.js`: ICANN has no all-numeric top-level domains), and the
`_` marker of SPEC Part B gives it a written URL form. Both are implemented and
neither is committed.

**The standard says.** Nothing forbids a numeric Handshake label — Handshake
labels are `[a-z0-9-]` and the registry sells them. The WHATWG URL Standard's
host parser is what makes them unwritable as URLs (NT-2).

**Why.** They exist and have been paid for, including the free-name registry
top-level name `14898`, so refusing them strands real registrations. Supporting
them costs a written convention nobody else implements.

**Consequence.** Until this is decided, anything written against Part B may
have to be rewritten: links, documentation, and any other client's
interoperation.

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
for every special (standard) scheme and parses such a host as an
[IPv4 address](https://url.spec.whatwg.org/#concept-ipv4-parser). It provides no
per-scheme opt-out, and `_` is not a
[forbidden host code point](https://url.spec.whatwg.org/#forbidden-host-code-point),
so the marked form is a conforming host while the unmarked one is not a host at
all.

**Why.** `hns:` is registered as a standard scheme to get a real web origin
(Chapter 1 §5), which is the same decision that subjects the host to that
parser. Something has to give, and every alternative is worse (SPEC B.4).

**Consequence.** Every name under a numeric Handshake top-level name has two
written forms, and any third party writing a link to one must know the
convention or the link is dead on arrival. It is a local convention with no
standing anywhere else, so a link written by this client may be dead in another
Handshake client and vice versa.

**Status.** OPEN. If a different convention gains traction anywhere else we
would rather adopt it than defend this one — the value of a convention here is
entirely in it being *one* convention (§NT-2.1).

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

**Status.** OPEN, and not fixable inside this codebase; it is a consequence of
NT-1 being undecided. If numeric top-level names are supported, the answer is
that they must be written `hns://` and the documentation has to say so.

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

`persist` on Optimism mainnet is the only live `_op` registry, and it is ours.
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

Two things about the convention we are unsure of beyond NT-1:

- Whether the marker belongs on the **numeric label** (`hello._14898`) or as a
  **whole-host** marker. A prefix on the label is minimal and local; a host-wide
  marker would be uglier but would not change meaning depending on which label
  it lands on.
- Whether other Handshake clients will do something different, at which point a
  link written by one is dead in the other. **That is the reason this is
  specified at all: if there is going to be a convention it should be one
  convention, and we would rather adopt somebody else's than defend ours.**

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

This matters more than it reads: the route runs while anonymization is on and is
not gated (SPEC §A.6), so the default is the one place where a mode the user
turned on for privacy can be defeated by an omission in an embedder rather than
by a decision anybody made.

**Recommendation.** Require it: throw from the constructor when no `fetchImpl`
is given, as the Arweave handler does. A library caller that genuinely wants
the global fetch can pass it explicitly, which makes the choice visible in the
caller rather than invisible in the default.

#### OP-D2. No light-client verification of the registry's answer

The obvious next step, and the same one `ens://` wants: verify the storage slot
against a block header, by a light client or an execution proof, at which point
this hop could honestly report `verified` and close a trustless lock.

**Recommendation.** Not now — the dependency is large and the route already
degrades honestly. Revisit when a usable Optimism light-client or storage-proof
library exists in a form a browser can load on every navigation; until then,
keep saying `unverified` in words.

#### NT-D1. Numeric top-level names have no test of the whole path

`../../tests/hns-url.test.js` covers the encode/decode/display/rewrite edge
cases, including the trailing-dot case. What is not covered anywhere is the
*path*: a typed `hello.14898`, through the classifier, through the URL
construction, through a resolution, back to a displayed address bar.

**Recommendation.** If NT-1 is decided in favour of supporting numeric
top-level names, add that end-to-end test before anything else; if it is
decided against, delete the convention rather than leaving it untested.

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

## Chapter 11 — Native applications on a Handshake name

_Source: [`namespaces/apps/DEVIATIONS.md`](namespaces/apps/DEVIATIONS.md)._

Every place this chapter's implementation departs from a standard it cites,
from common practice, or from its own stated design — plus every place we are
not sure we have made the right call, and the design work we know is still to
do.

The rule this file serves: **a deviation that is not written down is just a bug
nobody has found yet.**

A note on proportion before the list. The property this chapter exists to
provide — that a WebSocket from a Handshake page is end-to-end TLS pinned to the
same on-chain key material as the document, through a tunnel that never holds a
key — holds, and the pin is proven through a real spliced connection by
`tests/ws-proxy.test.js` ("e2e: the tunnel preserves end-to-end TLS so a DANE
pin verifies through it"). The five fences hold and each is pinned by a test,
including on the anonymized route, where the upstream is dialled through the
device-local Tor by address and the name is never given to the proxy.
Everything below is about the *other* things: the authentication that cannot
exist, the service worker we do not allow, the origin the token is bound to, the
manifest nobody signs, and a long list of what we have not measured.

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
with `Proxy-Authorization`. RFC 1928/1929 define the SOCKS5 equivalent. Both
are available on paper and neither is reachable in practice: Chromium's SOCKS5
client offers only the "no authentication" method, and Chromium does not
surface a proxy-auth challenge to its embedder for a `wss://` handshake, so the
`407` is never answered and the socket dies instead of retrying.

**Why.** Two implementations were built and neither could connect once. The
choice is between a fence that cannot be enforced and an honest statement that
the boundary is the loopback bind plus the four content fences.

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
address, which is the opposite of what this chapter is for.

**Status: OPEN.** We recommend enabling service workers at `hns://` once two
questions are answered: what a cached, self-persisting copy of a page means for
a name whose records (and therefore its DANE pin) can change under it, and
whether a worker's own fetches take the same header allowlist as the page's
(SPEC §3.4). Both are answerable; neither has been answered, and shipping a
worker that outlives a pin rotation would be worse than not shipping one.

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

**Status: DELIBERATE.** Matching the web platform is right here; diverging would
make Handshake sockets behave unlike every other socket, which is a worse trap
than the one it closes. Applications must check `Origin` as they would anywhere.

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

**Status: DELIBERATE**, with a clean fix if a port ever needs to be. Give the
resolution a port parameter, read `_<port>._tcp.<name>`, and thread the port
from the CONNECT through to the certificate check; until the engine's
verification callback carries the port, the honest set is the one port the pin
covers, and refusing is better than splicing unpinned. Both halves must move
together, or the port becomes reachable before it becomes pinned.

---

### 2. Things we are not sure about

These are the ones we would most like other implementers to argue with, and the
claims we could not verify against either the code or a measurement.

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

Work we know is worth doing and have not done. Each names the file and lines to
start from.

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
exists the consent at install is a decision the user cannot take back, which is
the strongest possible reason to keep that consent narrow.

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

## Cross-cutting — Divergence inventory: where privacy and speed pull apart

_Source: [`DIVERGENCE.md`](DIVERGENCE.md)._

A cross-cutting record, in one table, of every place in this specification
where the **fast path** (what the browser does when nothing is being hidden)
and a **private path** (what it would do to disclose nothing about the user to
anyone who is not the party they are talking to) are different operations.

The order of operations it serves is fixed. **First, try to resolve the
trade-off so both sides win** — a provider-side change, a relay that hides who
is asking, a cache that removes the question, a protocol feature nobody had
switched on. Only when that attempt has demonstrably failed does a divergence
earn a **PRIVATE mode / FAST mode** pair, and for that pair to mean anything the
private paths have to be implemented, not described. So every row carries a
*no-trade-off attempt* column before the two-mode columns; rows marked
**BOTH** are the preferred work, and the two-mode design applies only to the
rest.

Vocabulary for the "today" column. **Leak** — the fast path runs while
anonymization is on and discloses something. **Refuse** — the request is
answered 503 (or refused before any I/O) while anonymization is on. **Degrade**
— a different, weaker path runs and the trust state says so. **Proxied** — the
same path runs through the proxied session fetch, so the counterparty sees the
Tor exit, not the user. "Anonymization on" means IP Protection (`tor` mode,
Chapter 8), the only privacy setting the browser has today. Sizes are rough:
**S** an afternoon, **M** days, **L** a design and a review.

| # | Where | Fast path | Private path | Today | No-trade-off attempt | If the attempt fails: the private path |
|---|---|---|---|---|---|---|
| 1 | **Handshake resolution, the authoritative hop** (Ch. 1 §6) | chain proof from the local SPV node, then plaintext TCP/53 to the zone's nameserver — the operator and the path see the name and the user's IP | the chain proof kept, the hop carried over Tor | **Done**: the authoritative hop is dialled through the device-local Tor's SOCKS port (`src/socks-dial.js`, `query()`'s `dial`) and the SPV node runs through hsd `--proxy`; chain proof and DNSSEC validation are kept. Until the node has restarted through Tor, DoH answers and the trust state says so | **BOTH, partly.** The chain proof never leaves the machine — only the authoritative hop discloses. Carrying that one TCP query over Tor keeps the proof and hides the asker; the cost is Tor latency on one round trip per name, which the flat cache already amortises. What Tor cannot give back is the plaintext hop's integrity — DNSSEC does, and every record on the path validates or fails. Remaining trade: a Tor circuit's latency on the first visit only | built — the remaining trade is Tor's latency on a first visit |
| 2 | **The SPV node's peer traffic** (Ch. 1 §11.5) | hsd connects to Handshake peers directly; peers learn the user's IP and that a Handshake client is there, not which names | hsd's P2P over Tor | **Done**: `SPVNode` takes `proxy` → hsd `--proxy`, set from the anonymizer; a change restarts the spawned node | **BOTH.** hsd supports a SOCKS proxy; started against the Tor port the node syncs privately at the cost of a slower initial sync, which happens once. No functional loss | built — the cost is a header re-sync on each change (from the persisted chain, or from scratch in `--memory` mode), with resolution on DoH meanwhile |
| 3 | **Handshake names over DoH / ODoH** (Ch. 1 §9) | ODoH to `odoh.hns.one` through an independent relay; plain DoH to `query.hns.one` when the relay path fails (a leak of the name, and the trust state names the endpoint) | the same, and fails closed: `unreachable`, said in words | **Shipped as the Private/Fast switch**: in Private `DoHResolver({ strictOblivious })` never takes the plain fallback; the page names the mode, says nothing is known about the site, and points at the switch (`privateRefusal('lookup')`) | **No** — the fallback exists precisely because the relays are two and can both fail; the only both-sides option is more relays (a provider-side change: run one ourselves that is *not* the target operator) | done |
| 4 | **The resolver's plaintext `dns.lookup()`** for NS and CNAME targets that are ICANN hosts (Ch. 1 §6.5, §6.8) | the OS resolver, in the clear, from the chain path | the same lookup through the browser's DoH/ODoH client | **Done**: `HNSResolver` takes `lookup`, the browser hands it `DoHResolver.addressOf`; nameserver names and CNAME targets go through DoH/ODoH in every mode. The OS resolver is the library default only | **BOTH.** Resolving the ICANN host through the ODoH bridge or `DoHResolver` is neither slower in any way a user sees nor less functional; it removes the plaintext query on the fast path too | built |
| 5 | **ODoH configuration fetch** (`/.well-known/odohconfigs`, Ch. 2 IC-9) | fetched directly from the target at startup | through a relay, or pinned in the release | **Leak** of "this user runs Wildroot's oblivious path" to the target, once per start | **BOTH, in principle.** An ODoH relay forwards only the oblivious query (RFC 9230 §4.2), not a GET for `/.well-known/odohconfigs`, so "through the relay" is not available as written; the both-sides shape is a config pinned in the release and refreshed through Tor when IP Protection is on | **S–M** |
| 6 | **ICANN browsing DNS** (Ch. 2 §5) | Chromium's own secure DNS to the configured pool (encrypted, not oblivious) | the loopback ODoH bridge | **Degrade with a stated cost**: the bridge replaces the pool; in `automatic` mode the fallback below it is **plaintext system DNS** (IC-7); in `secure` mode there is none; the panel reports which happened | **BOTH, mostly.** The bridge is the both-sides answer for the lookup itself (private, and encrypted DNS was already a round trip). The remaining trade is availability: what happens when the bridge cannot answer — DoH to the pool (fast, not oblivious) or nothing. A cache of bridge answers narrows the window; more relays narrow it further | **S–M** — a PRIVATE mode is `secure` + bridge; measure the engine on a mixed template list before deciding whether the pool sits behind the bridge |
| 7 | **ICANN page fetches** (Ch. 2) | direct | through Tor (the session proxy) | **Shipped as the Private/Fast switch**: Private routes the session through the device-local Tor and **fails closed** when Tor cannot be had (`MODES.BLOCKED`, a loopback blackhole proxy — never a direct fallback); ICANN names resolve through the oblivious bridge only (`privateDns()`); the site sees a Tor exit | **No** — the site must see *some* address; only Tor or a VPN-shaped relay hides the user's, and both cost latency and Tor-blocking sites. This is the divergence the switch *is* | done |
| 8 | **IPFS: the local node's DHT and bitswap** (Ch. 3 §7) | kubo dials peers directly; peers learn the user's IP and every CID asked for | a trustless gateway over the proxied fetch with every block verified, or kubo over Tor | **Refuse** (503) for `ipfs://`, `ipns://` and an `ipfs=` name while anonymization is on — the stated-origin fetch itself is proxied (row 9), but the local node would PROVIDE the imported blocks to the DHT, which is the disclosure the gate exists for | **BOTH, for named sites.** A Handshake name can state its origin (`car=`, Ch. 3 §8) and the browser can fetch the whole CAR from it over HTTPS and verify every block on import — no DHT, no peers, first byte from one round trip. Private because the origin sees a Tor exit when proxied and one CID it already serves; fast because it is a single HTTPS fetch. Our own provider (pinthis) already announces every sub-root so that the default mode is both private and fast. What it does not cover: a bare `ipfs://` CID with no stated origin, which needs a configured trustless gateway (a third party sees the CID) | **DONE 2026-09-06** — the local node runs `kubo daemon --offline` in Private (no swarm, no DHT client, no announces; `IPFSNode.setRouting`, the policy table's `contentNode`) and as a DHT client in Fast, restarted on the switch; the stated-origin fetch serves named sites privately from the imported archive. **L** for kubo over Tor remains for a bare CID |
| 9 | **Origin warming and the `car=` stated origin** (Ch. 3 §8, experimental) | an HTTPS fetch of a CAR from the stated origin: faster first paint; the origin sees the user's IP and the CID | the same fetch over the proxied session fetch | **Proxied** — origin-warm rides the proxied session fetch; still unreachable while anonymized by inheritance from row 8's gate | **BOTH** — this row *is* the no-trade-off attempt for row 8: the fetch is verification-on-import already; injecting the proxied fetch makes it private with no loss. The warm path should stop being a warm-up and become the anonymized delivery path | the fetch is built; ungating waits on row 8's node-side change |
| 10 | **Cooperative delivery** (the coop project, not in this specification yet) | fetch from other Wildroot users' nodes: fast, and every peer learns the user's IP and CID | peers reached as onion services, or refuse | not shipped in either mode (Phase 0 blocked on provider peer identity); the switch's disclosure says so | **Unknown.** The both-sides shape would be peers that serve as onion services, so a fetcher learns nothing about a peer and a peer nothing about a fetcher; whether that is fast enough to be worth having is unmeasured. Serving-on-by-default is a disclosure by construction | **L** — a design decision before it ships |
| 11 | **Arweave gateways** (Ch. 4 §6) | `ar.io` gateway over the proxied session fetch; the gateway sees the txid and the user's IP | the same over Tor | **Proxied** — works while anonymized | **BOTH, already.** The same code path serves both; the only cost is Tor latency, which is the IP Protection switch (row 7) | done; byte verification (AR-1) is a trust item, not a privacy one |
| 12 | **ENS resolution** (Ch. 5 §5) | public Ethereum RPC over the proxied fetch; the endpoint sees the `.eth` name and the user's IP | the same over Tor; a light client removes the endpoint entirely | **Proxied** — works while anonymized; CCIP-Read gateways ride the same fetch | **BOTH, partly.** A short positive cache (EN-6) removes repeat questions on both paths. Removing the endpoint's knowledge of *which* name needs either a light client or an oblivious relay for `eth_call` — the latter is the ODoH idea applied to JSON-RPC and nobody runs one | done for privacy under Tor; **L** for a light client |
| 13 | **`web3://` (ERC-4804)** (Ch. 5 §8) | the `web3protocol` client's own RPC calls, over its own fetch (unproxied) | the same through the proxied fetch | **Refuse** (503) while anonymized | **BOTH, blocked on the library.** `web3protocol` builds its own viem chain clients and takes no fetch implementation; handing it the proxied fetch needs a fork or an upstream option | **M** — an upstream change request, else a fork |
| 14 | **HIP-5 `_op` registry reads** (Ch. 10 Part A) | Optimism RPC over the injected proxied fetch, from the chain path | already private when it runs | **Done** with row 1: when the chain path is alive under Tor the `_op` read runs anonymized over the injected proxied fetch; a name published only on chain is reachable | **BOTH** — built with row 1 | — |
| 15 | **Nostr relay queries** (Ch. 6 §8) | a WebSocket to each relay from the main process; the relay sees the user's IP and the exact filter | relays dialled through Tor | **Shipped as the Private/Fast switch**: in Private the relays are dialled through the Tor SOCKS port by name (`namespaces/nostr/src/tor-websocket.js`, the handler's `WebSocketImpl` seam); the relay sees the question, never the asker; with no Tor port the request is refused in words (`privateRefusal('relay')`) | **No, by protocol.** A relay must see the question to answer it; there is no oblivious NIP-01. Both-sides options are partial: our own relay (`social.hns.one`) sees the question but is ours; caching answers for the navigation removes repeats. The IP can be hidden (Tor); the question cannot | **M** — a SOCKS-capable WebSocket fills the handler's `WebSocketImpl` seam |
| 16 | **DID documents, AT Protocol and WebFinger** (Ch. 7) | `plc.directory` or the `did:web` host over the proxied fetch | the same over Tor | **Proxied** — `did:` works while anonymized | **BOTH, already** for the transport; the directory still learns *which* DID (an audit-log mirror would remove even that, and is the trust item DI-2) | done |
| 17 | **Tor / `onion://`** (Ch. 8) | none — the namespace exists only through the device-local Tor | the only path | works only with IP Protection on; interstitial otherwise | not a divergence: there is one path by design | per-site circuit isolation (TO-3) is the open privacy item |
| 18 | **Gemini** (Ch. 9 §K.6) | `tls.connect` from the main process: the OS resolver sees the host, the capsule sees the user's IP | dial through the Tor SOCKS port; resolve through the browser's resolver | **Done**, half: while anonymized the capsule is dialled through Tor BY NAME (no OS lookup) and refused only without a Tor port; with protection off the OS resolver still sees the host | **BOTH, half.** Resolving the host through the browser's resolver instead of the OS's is free on both paths (and opens Gemini over Handshake names). Hiding the IP from the capsule is Tor, row 7 | built for the anonymized half; the protection-off lookup through the browser's resolver remains **S** |
| 19 | **hyper / SSB / BitTorrent discovery** (Ch. 9) | DHT, swarm and gossip from the main process over UDP and TCP; peers learn the user's IP and what is sought | refuse, and say why | **Shipped as the Private/Fast switch**: refused (503) in Private with the mode, the reason, "nothing was asked" and the switch on the page (`privateRefusal('p2p')`); a Handshake name with a stated origin loads from that origin instead (row 9) | **No.** A DHT is a disclosure to strangers by design; a TCP-only proxied swarm is a different, weaker engine. The honest both-sides answer for a *named* site is row 8's: state an origin and fetch from it | **L**, and possibly "refuse, and say why" is the right private path |
| 20 | **hyper DNSLink lookups** (Ch. 9 KY-4) | `hyper-sdk` asks a DoH JSON resolver (Cloudflare by default) — a third party learns which hypercore names are opened | the same lookup at the browser's own bridge, or through Tor | **Leak** to a third-party resolver even with anonymization off; refused with the engine while on | **BOTH, not free.** `hyper-sdk` speaks the DoH JSON API and would not trust the bridge's loopback certificate, while the bridge speaks wire format for Chromium; pointing the engine at the bridge needs a JSON endpoint on the bridge and a fetch that trusts its pin | **M** |
| 21 | **WebSockets to a Handshake name** (Ch. 11 §4) | the loopback CONNECT tunnel dials the resolved address from the main process | the tunnel dials through the Tor SOCKS port | **Done**: with IP Protection on the upstream is dialled through the Tor SOCKS port (`torSocks` → `socksDialer`); refused only without one | **BOTH, at Tor's latency.** Built: chain proof, DANE pin and fences unchanged, only the socket's route differs | built |
| 22 | **Search** (`search://`) | the metasearch backend over the proxied fetch | the same over Tor | **Proxied** | **BOTH, already** — the backend is ours and blind-token-gated; it sees a Tor exit when IP Protection is on | done |
| 24 | **The A-record `hns://` document fetch** (Ch. 1 §8) — the raw-socket path outside the session proxy, which no earlier row inventoried | `tls.connect` to the resolved address with the DANE pin checked on the handshake; the site sees the user's IP | the same socket through the Tor SOCKS port, by address | **Done**: `src/dane-connect.js connectDane({ dial })` — in Private the site is dialled through the SOCKS port by address (Tor learns an IP and no name), the pin is checked on that handshake, SNI is the name; with no Tor port the page is refused (`privateRefusal('site')`), never sent directly | **BOTH, at Tor's latency** — the check is identical on both routes | built |
| 23 | **Bootstrap and configuration fetches** (kubo AutoConf, delegated routers, mDNS; the ICANN TLD snapshot; the ODoH config) | kubo's are disabled by policy (Ch. 3); the TLD list is bundled; the ODoH config is row 5 | — | no leak from kubo by construction; row 5 remains | **BOTH, by policy** — bundling and disabling are the no-trade-off answers, already taken | — |

What follows from the table, recorded rather than decided:

1. **Seventeen of twenty-four rows have a no-trade-off option** (rows 1, 2, 4,
   5, 6, 8, 9, 11, 13, 14, 16, 18, 20, 21, 22, 23, 24 marked BOTH in whole or
   in part), and **ten of them are built**: 1, 2, 4, 9 (the fetch), 11, 14,
   16, 18 (the anonymized half), 21, 22, 24 and 23 by policy. What remains on
   the both-sides side is node-side (row 8: kubo without a DHT while
   anonymized — the stated-origin path of row 9 serves a whole archive from
   disk meanwhile), library-side (13, 20), a pinned ODoH config (5), and the
   protection-off Gemini lookup (18).
2. **The divergences that survive the attempt are rows 3, 7, 10, 15 and 19**:
   the plain-DoH fallback, the site seeing an address at all, cooperative
   delivery, Nostr's question-must-be-seen, and DHT discovery. Those five are
   **shipped as the Fast / Private switch** (`SPEC.md` §4.2,
   `src/delivery-mode.js`): one control that drives the Tor session proxy —
   failing closed — and the four private paths together; for 19 the private
   path is "refuse, and say why", and 10 is not offered in either mode.
3. **The Handshake chain proof no longer costs anonymization anything in
   trust** (rows 1, 2, 14): the authoritative hop and the node's peers go
   through the device-local Tor and the proof stays. What it costs is a node
   restart and a header re-sync when IP Protection changes, with DoH answering
   meanwhile — a latency and availability cost, honestly reported by the
   trust state, not a trust cost.
4. **Two leaks exist with anonymization OFF that a user would not expect** —
   the hyper DNSLink resolver (20) and the ODoH configuration fetch (5) — and
   both turned out to be **M**, not S, once the bridge's wire-only endpoint and
   the relay's POST-only forwarding were checked. The Private/Fast design that
   follows from this table is the browser's `docs/MODES.md`; the switch it
   describes is built, and the disclosure it carries is `DISCLOSURE` in
   `src/delivery-mode.js`.

