# Part II — Namespace selection: deviations and open questions

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

## 1. Deviations

### RT-1. The reserved-name list is broader than the RFCs reserve

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

### RT-2. `.eth` and `.onion` are carved out by hard-coded suffix

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

### RT-3. A single bare label is a Handshake name

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

### RT-4. `<known-scheme>:<digits>` is always read as a scheme

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

### RT-5. The `icann` namespace has no scheme, so a classification and a dispatch disagree

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

### RT-6. None of the schemes we invented is registered, and none uses `web+`

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

### RT-7. The PAC script carries a second, ASCII-only copy of the host rule

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

### RT-8. `classify()` returns `javascript:`, `data:` and `file:` untouched

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

### RT-9. ERC-4804's `w3://` short form is deliberately not offered

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

### RT-10. `agregore://` and `browser://` are permanent silent aliases

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

### RT-11. The IDNA pass fails open

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

### RT-12. The dispatcher's 400 branch is unreachable through a WHATWG `Request`

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

### RT-13. `hns:` is a standard scheme, and pays the URL Standard's host rule for it

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

## 2. Things we are not sure about

These are the ones we most want argued with.

### 2.1. Is "everything non-ICANN is Handshake" a defensible default at all?

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

### 2.2. Whether a bare word should navigate (RT-3)

The rule is deliberate and we can defend it inside this browser. What we cannot
say is whether the privacy cost is acceptable in a client whose Handshake
lookups go over DoH rather than a local chain node, because there the resolver
observes every mistyped word. An implementer whose users have no local node
should probably not copy it.

### 2.3. Where the carve-out list should stop (RT-2)

`.onion` is required by RFC 7686. `.eth` is a judgement. `.crypto`, `.sol`,
`.bnb`, `.zil` and the rest of the alt-roots have precisely the same claim as
`.eth` and get nothing. The honest description of our rule is "we carve out the
namespaces whose misrouting would embarrass us most", which is not a rule.

Two coherent positions exist and we hold neither cleanly: carve out *nothing*
that has no RFC (and accept that ENS traffic goes to a Handshake registrant),
or carve out *every* alt-root we can name (and accept an unbounded,
unmaintainable list that hard-codes a view of which naming systems are real).

### 2.4. Should a namespace be identified by classification or by scheme? (RT-5)

The `icann`/`web` split is a symptom. The deeper question is whether "namespace"
is a property of the *input* (what the user meant) or of the *scheme* (what will
be dispatched). We use both, and SPEC §4.3 resolves the ambiguity for the marker
by naming one — it does not resolve it for the model.

### 2.5. Whether the three-state lock is comprehensible

SPEC §10.4 requires TRUSTLESS, TRUSTED and OPEN to be distinguishable. We
believe the distinction is the honest one and we have no evidence that users
read it. It is possible that a third state produces less understanding rather
than more, and that the right answer is two states plus an explanation. We have
not tested this on anyone.

### 2.6. Whether `partial` is doing two jobs in the lock

Everything that is not fully verified and not outright broken aggregates to
`partial`, so an ordinary `https://` page, an Arweave gateway fetch, an ENS
name, a Gemini connection with no certificate check and a Nostr page whose
completeness cannot be proven all land in the same state. The step list
distinguishes them and the summary names the weak steps, but the single
indicator does not. We do not know whether that flattening is a simplification
or a loss.

### 2.7. Citations we have not verified against the source text

Two claims in [`REFERENCES.md`](REFERENCES.md) rest on our recollection rather
than on the document: that ICANN's board reserved `internal` for private use in
2024, and that `corp` and `home` were deferred indefinitely from the new-gTLD
programme on name-collision grounds. Both are load-bearing for RT-1. We cite the
standing ICANN pages that describe the programmes rather than the board
resolutions themselves, and we would rather be corrected than have this read as
settled.

### 2.8. Whether `search://` should be a scheme at all

Making the metasearch a scheme buys it a real origin and puts it in the same
registry as everything else, which is tidy. It also means a search results page
is a *navigable origin* that history, bookmarks and session restore all carry —
so a query string ends up in more places than a query typed into a search
engine's own page would. We think the tidiness is worth it. We are not certain
the storage footprint is.

---

## 3. Open design items

Changes to the reference implementation we think are right and have not made.
Nothing here is normative.

### RT-D1. Derive the privileged-scheme declaration from the scheme table

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

### RT-D2. Give `icann` a place in one namespace vocabulary

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

### RT-D4. Register `hns:` with IANA

Of the 19 unregistered schemes, 18 are application-private and should stay that
way. `hns:` is not: it is meant to interoperate, other Handshake clients already
spell it the same way, and a Provisional registration under RFC 7595 needs a
specification of any stability and an email to the reviewer (RT-6).

**Recommendation.** File it. This repository contains the specification RFC
7595 asks for, and nothing in the code changes. It removes the situation where
the scheme this whole stack is named for has no entry anywhere a second
implementer could find.

### RT-D5. Make the IDNA pass fail closed

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

## 4. What this chapter leaves out

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
