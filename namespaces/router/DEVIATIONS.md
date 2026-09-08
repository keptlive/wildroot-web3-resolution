# Part II — Namespace selection: deviations and open questions

This file records routing limitations, product choices, and proposed changes.
`RT-n` identifies an existing deviation; `RT-Dn` identifies a proposal.
Paths refer to the repository root unless stated otherwise.

See [REVIEW.md](../../REVIEW.md) for contradictions found during the editorial
review. Proposals below do not change the implementation.

## 1. Deviations

### RT-1. The reserved-name list is broader than the RFCs reserve

**Behavior.** `src/reserved-names.cjs` excludes thirteen final labels from
Handshake. Seven have the IETF status listed in SPEC §7; the additional labels
are `internal`, `home`, `lan`, `corp`, `intranet`, and `private`.

`internal` was reserved by ICANN for private use in 2024; `home` and `corp`
were deferred from the new-gTLD programme. The remaining labels are local
network conventions. These claims require the source checks listed in §2.7.

**Reason and effect.** The extra exclusions prevent local device names from
being sent to a Handshake resolver. They also make those Handshake labels
unreachable through normal classification.

**Status: DELIBERATE.** This list is a client policy, not an IETF reservation list.

---

### RT-2. `.eth` and `.onion` are carved out by hard-coded suffix

**Behavior.** Literal `.onion` and `.eth` suffix checks run before the lists
(`src/classify-host.cjs`). RFC 7686 supplies the onion requirement. The ENS
exception is a product choice: a name intended for ENS must not reach the
Handshake holder of `eth`.

**Effect.** The Handshake `eth` name is excluded from normal classification.
Other alternative roots, including `.crypto`, `.sol`, `.bnb`, and `.zil`, have
no equivalent exclusion and select Handshake.

**Status: DELIBERATE.** The policy for adding further exceptions is open (§2.3).

---

### RT-3. A single bare label is a Handshake name

**Behavior.** Bare labels such as `pinner`, `hnshosting`, `bananas`, and `🤝` select Handshake. Numeric names such as `14898` require
the optional numeric-name setting; they are off by default. Labels that are ICANN TLDs (`com`, `org`, `app`,
`blog`, `link`) and inputs containing whitespace select search
(`src/router.js`). No standard specifies this address-bar behavior.

**Reason and effect.** Bare Handshake names are convenient to enter, but
mistyped words become lookups visible to the selected resolver. The suggestion
list offers search as a second choice.

**Status: DELIBERATE** for Wildroot; suitability for other clients is open (§2.2).

---

### RT-4. `<known-scheme>:<digits>` is always read as a scheme

**Behavior.** A scheme-like token followed by a bare port number is treated
as a host unless the token is registered (`src/router.js`):

```
hasExplicitScheme('example.com:8080') -> false   (host:port)
hasExplicitScheme('hns:8080')         -> true    (scheme hns, path 8080)
```

RFC 3986 supplies the scheme and authority grammars; the input classifier must
choose an interpretation for this shorthand.

**Effect.** A Handshake label sharing a registered scheme name cannot use the
bare `label:port` form. `hns:8080`, `ar:8080`, `search:8080`, and `media:8080`
are interpreted as explicit schemes.

**Status: DELIBERATE.**

---

### RT-5. The `icann` namespace has no scheme, so a classification and a dispatch disagree

**Behavior.** ICANN names have different namespace identifiers at
classification and dispatch:

```js
classify('example.com').namespace  === 'icann'
namespaceForScheme('https')        === 'web'
```

The `X-Resolution-Namespace` marker follows the scheme table and therefore uses
`web` (SPEC §4.3).

**Effect.** Consumers cannot compare the classification's namespace directly
with the response marker for an ordinary web navigation.

**Status: OPEN.** RT-D2 proposes returning `web` from classification and retaining
`reason: 'icann-tld'`. A host-aware dispatch vocabulary is another option.

---

### RT-6. None of the schemes we invented is registered, and none uses `web+`

**Behavior.** The scheme registry contains application-defined names without
IANA registration. The status inventory recorded for the 32 schemes is:

| Status | Count | Schemes |
|---|---|---|
| **Permanent** | 2 | `http`, `https` |
| **Provisional** | 11 | `ipfs`, `ipns`, `ar`, `ens`, `web3`, `nostr`, `at`, `did`, `hyper`, `ssb`, `magnet` |
| **Unregistered** | 19 | `hns`, `ipld`, `pubsub`, `activitypub`, `onion`, `https+raw`, `gemini`, `bittorrent`, `bt`, `wildroot`, `agregore`, `browser`, `search`, `paste`, `editor`, `bluesky`, `mastodon`, `media`, `docview` |

RFC 7595 defines registration. The HTML `web+` convention applies to handlers
registered by web pages, rather than native browser schemes.

**Effect.** Unregistered interoperable schemes have no IANA entry that another
implementer can use to identify their owner or specification.

**Status: OPEN** for `hns` (RT-D4); **DELIBERATE** for application-private
schemes. The inventory's registration statuses need periodic verification.

---

### RT-7. The PAC script carries a second, ASCII-only copy of the host rule

**Behavior.** The router and address bar share `src/classify-host.cjs`. A
WebSocket PAC script cannot import it or use its URL parser, so it embeds the
shared lists and an ASCII-only version of the rule. Chromium supplies the PAC
with already-parsed hosts.

**Effect.** Tests compare the generated PAC with `classifyHost()` using Unicode,
numeric-TLD, malformed-onion, IP-literal, and reserved-name inputs. An untested
divergence can still send a WebSocket outside the Handshake tunnel or cause the
proxy to refuse it.

**Status: OPEN.** Generate the ASCII rule from a shared representation if the
PAC environment continues to require a separate script.

---

### RT-8. `classify()` returns `javascript:`, `data:` and `file:` untouched

**Behavior.** L1 preserves explicit schemes, including:

```
classify('javascript:alert(1)') -> { scheme: 'javascript', namespace: null, known: false }
classify('data:text/html,x')    -> { scheme: 'data',       namespace: null, known: false }
classify('file:///etc/passwd')  -> { scheme: 'file',       namespace: null, known: false }
```

**Effect.** `classify()` is not a navigation filter. `known` indicates registry
membership; `navigable` is a separate property. The caller still needs a
navigation policy, consistent with the HTML navigation model.

**Status: DELIBERATE.**

---

### RT-9. ERC-4804's `w3://` short form is deliberately not offered

**Behavior.** `web3` is registered; ERC-4804's `w3` alias is not.
`namespaceForScheme('w3')` returns `null` and dispatch refuses the scheme with
501. A test checks this behavior.

**Reason.** The existing design cites a possible conflict with the Handshake
TLD `.w3`. Whether scheme syntax actually creates that conflict is a review
question; see [REVIEW.md](../../REVIEW.md).

**Status: DELIBERATE.** This is an ERC-4804 interoperability limitation.

---

### RT-10. `agregore://` and `browser://` are permanent silent aliases

**Behavior.** `agregore://` and `browser://` serve the same pages as
`wildroot://` and are rewritten to it during navigation. The aliases remain
available for old sessions and links (`src/router.js`).

**Effect.** Schemes have distinct origins. The navigation rewrite is required
to give these pages consistent storage and origin behavior.

**Status: DELIBERATE.**

---

### RT-11. The IDNA pass fails open

**Behavior.** `asciiTld` uses the URL parser for A-label conversion and retains
the raw final label when parsing fails (`src/classify-host.cjs`):

```js
try {
  const ascii = new URL('http://' + host).hostname
  tld = ascii.split('.').filter(Boolean).pop()
} catch { /* keep the raw tld */ }
```

**Effect.** Invalid or unnormalised input can still select a namespace. This
does not meet SPEC §8.1's fail-closed requirement. The use of WHATWG UTS #46,
rather than IDNA2008, is a separate compatibility question (HS-14).

**Status: OPEN.** RT-D5 proposes returning `null` on failure, or at minimum
reporting `reason: 'idna-failed'`. Numeric-label handling must be considered
before changing this fallback.

---

### RT-12. The dispatcher's 400 branch is unreachable through a WHATWG `Request`

**Behavior.** Dispatch returns 400 without a namespace marker only when an
input cannot be parsed and has no scheme. WHATWG `Request` rejects such URLs
during construction, so this branch is reached only through a request-like
object with a `url` property, as used by the runtime and tests.

**Effect.** The dispatch interface is wider than WHATWG `Request`. No namespace
marker is possible when no scheme has been established.

**Status: DELIBERATE.**

---

### RT-13. `hns:` is a standard scheme, and pays the URL Standard's host rule for it

**Behavior.** Electron registers `hns` with `standard: true` to provide tuple
origins and browser storage APIs. Chromium's host parsing then constrains the
labels that an `hns://` URL can carry.

**Effect.** Numeric final labels need the experimental form in Chapter 10,
Part B. SPEC §8.2 gives the classifier's ordering requirement. The relationship
between Electron's custom standard schemes and WHATWG's fixed special-scheme
set needs more precise wording; see [REVIEW.md](../../REVIEW.md).

**Status: DELIBERATE.** The numeric convention retains its own `NT` deviations.

---

## 2. Things we are not sure about

The following product and interoperability questions remain open.

### 2.1. Is "everything non-ICANN is Handshake" a defensible default at all?

Should every unreserved, non-ICANN label default to Handshake? This supports
bare Handshake navigation, but a new ICANN delegation changes a label’s meaning
when the bundled snapshot is updated. Requiring an explicit Handshake scheme
would avoid that default at the cost of more input.

### 2.2. Whether a bare word should navigate (RT-3)

Bare-label navigation discloses mistyped words to the lookup provider. Is
that acceptable when users rely on DoH rather than a local chain node?

### 2.3. Where the carve-out list should stop (RT-2)

RFC 7686 supports the `.onion` exception. `.eth` is a product choice. The
project has not defined a general criterion for adding `.crypto`, `.sol`,
`.bnb`, `.zil`, or future alternative roots.

### 2.4. Should a namespace be identified by classification or by scheme? (RT-5)

Should `namespace` identify the input’s naming system or the dispatched
scheme? The classifier uses `icann` while the scheme table uses `web` (RT-5).

### 2.5. Whether the three-state lock is comprehensible

The TRUSTLESS, TRUSTED, and OPEN indicator states have not been tested with
users. Would two states plus detailed steps communicate the guarantees better?

### 2.6. Whether `partial` is doing two jobs in the lock

The `partial` verdict includes WebPKI HTTPS, gateway-trusted Arweave,
RPC-trusted ENS, unchecked Gemini TLS, and incomplete Nostr results. The steps
distinguish them; the single indicator does not. Is that grouping useful?

### 2.7. Citations we have not verified against the source text

The original reference list did not verify the ICANN board actions for
`internal`, `corp`, and `home` against their resolutions. Those claims should
be linked to primary decisions before they are treated as settled provenance.

### 2.8. Whether `search://` should be a scheme at all

A `search://` origin gives search pages consistent routing and storage, but
also stores queries in history, bookmarks, and restored sessions. The privacy
comparison with ordinary search URLs has not been measured.

## 3. Open design items

These proposals are not normative and have not been implemented.

### RT-D1. Derive the privileged-scheme declaration from the scheme table

Store scheme privilege metadata alongside `SCHEME_TABLE` and derive the
Electron declaration from it. The current CommonJS/ES-module split can be
handled by a shared `.cjs` data module. As an interim measure, test that every
registered scheme is declared and every declaration has a registry row.

### RT-D2. Give `icann` a place in one namespace vocabulary

Choose one namespace vocabulary (RT-5). The current proposal is to return
`web` for ICANN hosts and retain `reason: 'icann-tld'`. An alternative is to
make dispatch host-aware. Neither change is adopted here.

### RT-D4. Register `hns:` with IANA

Prepare a provisional IANA registration for `hns` under RFC 7595, using
SPEC §5 for syntax and the security considerations for its risks. Review the
other unregistered names individually; RT-6’s list includes more than internal
application pages.

### RT-D5. Make the IDNA pass fail closed

Make parsing failure explicit in `asciiTld` and `classifyHost` (RT-11).
Returning `null` would allow a search result; an `idna-failed` reason would make
the current fallback visible. Check numeric-TLD input before choosing either.

## 4. What this chapter leaves out

- **Electron wiring:** scheme privilege declarations and dispatcher bindings
  remain in the browser. SPEC §4.4–§5 defines their contract.
- **Address bar and PAC integration:** these remain in the browser. The shared
  classifier and local classification corpus are included here (RT-7).
- **Resolution:** namespace chapters define what happens after classification.
- **ICANN DNS policy:** Chapter 2 defines the resolver plan and bridge. This
  chapter defines the trust-reporting contract.
- **Search backend:** engines, result merging, and bang prefixes are outside
  the `search://` grammar specified here.
- **Numeric-TLD URL form:** Chapter 10, Part B defines the experimental form;
  SPEC §8.2 supplies only its classifier constraint.
