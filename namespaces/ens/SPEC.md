# Chapter 5 — ENS and `web3://`

> **Review pending:** [REVIEW.md](../../REVIEW.md) records unresolved questions
> about resolver error wording and content trust labels. The rewrite does not change runtime behaviour.

The [routing specification](../../SPEC.md) defines how `.eth` names reach
this namespace.

**Status:** describes the behaviour of the reference implementation in
`namespaces/ens/src/`, which ships in the Wildroot browser. Not endorsed by any
standards body, and not endorsed by ENS. Normative statements below describe
what an implementation must do *to interoperate with this one*; where a rule is
inherited from an existing standard, that standard is cited and its text
governs.
**Licence:** CC-BY-4.0 (`../../LICENSE-SPEC`). The reference implementation is
licensed separately (Apache-2.0).

The routing specification defines the namespace and trust-state vocabulary.
See [deviations](DEVIATIONS.md) (`EN-` entries) and [references](REFERENCES.md)
for limits and supporting sources.

---

## Contents

1. [What this specifies](#1-what-this-specifies) — including [**scope**](#11-scope)
2. [Terminology](#2-terminology)
3. [Which names belong to this namespace](#3-which-names-belong-to-this-namespace)
4. [The `ens://` URL form](#4-the-ens-url-form)
5. [The resolution algorithm](#5-the-resolution-algorithm)
6. [CCIP-Read (ERC-3668)](#6-ccip-read-erc-3668)
7. [Trust state](#7-trust-state)
8. [`web3://` — ERC-4804](#8-web3--erc-4804)
9. [Security considerations](#9-security-considerations)

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## 1. What this specifies

This chapter resolves `.eth` names to websites by reading EIP-1577
`contenthash` records. It also documents the separate `web3://` handler (§8).

The ENS read uses `eth_call` over HTTPS to a public JSON-RPC endpoint.
There is no Ethereum light client or proof against a verified block header.
The endpoint is trusted for the name-to-contenthash mapping and learns the
lookup. Content handlers apply their own verification rules after handoff.

Two properties follow, and both are normative:

- an implementation **MUST NOT** present an ENS resolution as
  cryptographically verified, and
- an implementation **MUST NOT** fall back out of this namespace on failure — a
  `.eth` name that does not resolve here is not then looked up as a Handshake
  name, an ICANN domain, or a search query. This is the spine's namespace rule
  (RFC 9498 §9.10), applied to `.eth`.

Without the `.eth` routing exception, a non-ICANN suffix would be sent to
Handshake and could resolve through the owner of the Handshake name `eth`.

`web3://` (ERC-4804) belongs to a separate namespace. It is covered here
because both handlers read Ethereum. It is also distinct from the Handshake
top-level name `.w3`.

### 1.1 Scope

**In scope:** website content pointers, the associated trust state, and the
errors and limited text-record display used when no website is published.

- ENSIP-15 name normalisation and EIP-137 `namehash`;
- the single ENSIP-10 `resolve(bytes,bytes)` call through the ENS Universal
  Resolver, and the JSON-RPC transport it runs over;
- ERC-3668 CCIP-Read, including the ENSIP-21 batch-gateway sentinel;
- decoding the EIP-1577 / ENSIP-7 `contenthash` into a content pointer (the
  grammar itself is the Handshake chapter's and `../../src/contenthash.js` —
  referenced here, not restated);
- the `ens://` URL form and the handoff to the content handlers;
- the trust state the result carries, and the failure kinds.

**Out of scope:**

| Out of scope | Where it lives |
|---|---|
| **Fetching the content** the pointer names — IPFS, IPNS, Arweave: retrieval, CID verification, rendering | the IPFS and Arweave chapters; this chapter ends at the pointer, exactly as the Handshake chapter's content-pointer section does |
| **Wallet and reverse records** — `addr`, multichain addresses, reverse resolution (EIP-181), primary names | Not read. Selected text records are displayed only on the no-website page (§5.6a); see EN-1 and EN-3. |
| **Writing ENS records**, registration, renewal, the ENS registrar | a different problem with a different threat model |
| **Ethereum consensus, light clients, `eth_getProof`** | cited, not restated. §7 states what an RPC answer is worth, which is the only part a resolver needs |
| **The HIP-5 `_op` route**, which uses the *same* EIP-137/EIP-1577 primitives against an Optimism registry | the Handshake chapter. It is a Handshake resolution that happens to read a contract; this is an ENS resolution. They share the pointer grammar and nothing else |
| **The browser's padlock and security panel** | §7 specifies the model an interface is given; not a rendering |

This is a website-resolution specification, not a general ENS client.
Its scope excludes wallet operations and record-management workflows.

---

## 2. Terminology

Terms from the spine (`../../SPEC.md`) are used unchanged, in particular
**content pointer**, **trust state** and **resolution kind**.

Terms specific to this chapter:

- **Universal Resolver** — the ENS contract that performs the ENSIP-10 walk to
  the nearest ancestor with a resolver, and the ERC-3668 revert, **on chain**,
  so that a client makes one call instead of two-plus-a-walk. The address this
  implementation calls is `0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe` on
  Ethereum mainnet.
- **Offchain lookup** — an ERC-3668 `OffchainLookup(address,string[],bytes,bytes4,bytes)`
  revert: a contract's instruction to fetch data from a named URL and hand it
  back to a named callback.
- **Batch sentinel** — the literal URL `x-batch-gateway:true` (ENSIP-21),
  meaning "any compliant batch gateway will do, including your own".
- **Answer** — an RPC result or revert. A transport failure produces no
  answer about the name. This distinction controls error classification (§5.6);
  the RPC endpoint remains trusted for the result.

---

## 3. Which names belong to this namespace

`isEthName()` in `../../src/router.js` uses a case-insensitive `eth`
suffix test after removing a trailing dot and port. It does not query the
registry during classification.

Order matters, and this namespace sits **second** in the spine's classification
order:

1. `.onion` → Tor (unconditionally, including a malformed one);
2. **`.eth` → ENS**;
3. a name the network reserves (RFC 6761 / 6762 / 7686 / 8375 and the
   home-network labels) → the user's own device;
4. an IP literal → the web;
5. an ICANN top-level domain → ordinary DNS;
6. everything else → Handshake.

An implementation **MUST NOT** resolve a `.eth` name in any other namespace,
and **MUST NOT** consult another namespace when the ENS resolution fails, for
any failure kind in §5.7. An implementation **MUST** apply the rule to a host
whose *label* merely contains `eth` (`eth.14898`, `my-eth-wallet.com`,
`ethos.org`) by the ordinary suffix test, which excludes all three.

An **explicit scheme wins over the suffix test.** `ipfs://vitalik.eth/` is an
IPFS request whose CID-shaped component happens to look like an ENS name; it
**MUST** reach the IPFS handler and **MUST NOT** be re-sniffed into ENS. This
is the spine's law that a named scheme is authoritative.

`.eth` is not in the ICANN root, so under rule 6 it would otherwise be a
Handshake name. Rule 2 is therefore a deliberate carve-out of exactly one label
from the Handshake namespace, and the only one made for an alternative naming
system other than Tor. Other alt-roots (`.crypto`, `.sol`, `.bnb`) are **not**
carved out and resolve as Handshake names; the reasoning, which is a product
decision and not a technical one, is the router chapter's, and the question of
whether it will age well is `../../DEVIATIONS.md` §2 under this prefix.

---

## 4. The `ens://` URL form

```
ens://<name>[/<path>][?<query>][#<fragment>]
```

- `<name>` is a `.eth` name. It is **percent-decoded**, lowercased, and a
  single trailing dot is stripped. The scheme prefix is matched
  case-insensitively.
- The **fragment is removed before parsing** and is never transmitted: it
  belongs to the document, not to the resolution.
- `<path>` runs from the first `/` or `?`, whichever comes first, to the end,
  and **includes the query string**. When the URL carries a query but no path,
  the path is the query.
- When there is neither, the path is `/`.

The parsed path is appended to the resolved content pointer **only when it is
not `/`**, so that `ens://vitalik.eth/` and `ens://vitalik.eth` both fetch
`ipfs://<cid>` rather than `ipfs://<cid>/`.

The handler can receive a percent-encoded non-ASCII name such as
`ens://%F0%9F%9A%80.eth/`. An implementation **MUST** decode `<name>` before
ENSIP-15 normalization, and the decode **MUST** be guarded. If decoding fails
(for example, `ens://100%.eth/`), retain the original text and let ENSIP-15
report the invalid name.

`ens:` is registered as a **non-standard, non-secure** scheme in the browser
(`LOW_PRIVILEGES`, plus streaming). An ENS page therefore has an **opaque
origin**: no service workers, no secure-context storage, no persistent origin.
That is deliberate and matches the trust state — an unverified mapping does not
get the privileges a verified one gets. An implementation **SHOULD** make the
same choice, and **MUST NOT** grant an ENS-resolved document more privilege
than it grants the content network the pointer resolved to.

There is no `ens://` short form, no `.eth` gateway suffix, and no rewriting of
an `ens://` URL into any other scheme.

---

## 5. The resolution algorithm

Input: a name from §4. Output: exactly one resolution kind from §5.7.

### 5.1 Step 1 — normalise, hash, and DNS-encode

```
normalized = ENSIP-15 normalize(name)             (UTS-46-derived, ENS's own profile)
node       = namehash(normalized)                 EIP-137
dnsName    = RFC 1035 wire-format(normalized)     length-prefixed labels, root-terminated
```

An implementation **MUST** normalize with **ENSIP-15**. Bare UTS-46 or
lowercasing alone can produce a different namehash. The reference handler uses
`normalize()` from `viem/ens`, backed by `@adraffy/ens-normalize` via `ox`.

**EIP-137's own text specifies UTS-46 / nameprep.** ENSIP-15 supersedes it and
is what the namespace actually uses; where the two disagree, ENSIP-15 governs.
This is stated because EIP-137 is the document a reader will find first.

If normalisation throws, the resolution kind is `invalid-name` and the detail
is the normaliser's message. An implementation **MUST NOT** fall back to the
un-normalised name. Normalisation happens **before any network request**, so a
name this step refuses discloses nothing to an RPC endpoint.

`dnsName` uses no compression pointers. A label longer than 255 bytes is
replaced by its encoded labelhash (`[<hex labelhash>]`), which is what the
Universal Resolver accepts; this is viem's behaviour and we inherit it.

**On the HIP-5 `_op` route the same `namehash` is computed with no ENSIP-15
step at all**, because those labels are Handshake labels, already lowercase
A-labels. The two routes therefore normalise differently on purpose; see EN-4.

### 5.2 Step 2 — one call, through the Universal Resolver

```
inner = contenthash(bytes32 node)                        selector 0xbc1c58d1   EIP-1577 / ENSIP-7
outer = resolve(bytes dnsName, bytes inner)              ENSIP-10
result, resolverAddress = eth_call(UniversalResolver, outer, "latest")
```

An implementation **SHOULD** issue this single Universal Resolver call and
**SHOULD NOT** call `Registry.resolver(node)` directly unless it has verified
that the name is a second-level `.eth` registration. ENSIP-10 requires finding
the nearest ancestor with a resolver. The Universal Resolver performs that
walk and wildcard handling for names such as `jesse.base.eth`.

The Universal Resolver address **MUST** be verified to be a contract before it
is trusted as one. `0xb8c2C29ee19D8307cb7255e1Cd9CbDE883A267d5` circulates as
this contract's address and has **zero bytecode** — it is an externally owned
account. The address in the reference implementation answered `eth_getCode`
with 2,491 bytes when it was checked, and resolved `vitalik.eth` through it. An
implementation **SHOULD** use the DAO-owned upgradable **proxy** rather than
pinning an implementation address, so that an ENS upgrade behind an unchanged
read interface needs no client change.

The contract address is pinned in this module. Only RPC endpoints are read
from the bundled `web3protocol` chain registry; its older Universal Resolver
and `ensRegistry` entries are unused. Section 2.5 of [DEVIATIONS.md](DEVIATIONS.md)
discusses maintenance of the pinned address.

### 5.3 Step 3 — the JSON-RPC transport

For each RPC endpoint of Ethereum mainnet (`chainId` 1) in order, until one
answers:

```
POST <rpcUrl>
content-type: application/json
{"jsonrpc":"2.0","id":1,"method":"eth_call",
 "params":[{"to":<contract>,"data":<calldata>},"latest"]}
```

Rules, all normative:

- **Every attempt carries its own deadline** (8 s here). Without one, an
  endpoint that accepts the connection and then says nothing holds the
  navigation open forever and the second endpoint is never tried — so a list of
  two "independent operators" is worth exactly one.
- A non-2xx HTTP status is a failure to obtain an answer from that endpoint;
  **try the next**.
- A JSON-RPC `error` carrying **revert data** is an **answer**, not a failure.
  It **MUST** be returned to the caller immediately and the remaining endpoints
  **MUST NOT** be tried: they would return the same revert more slowly. This is
  not an optimisation — ERC-3668 delivers its entire protocol through a revert,
  so an implementation that collapses reverts into "RPC error" cannot resolve
  any offchain name.
- Endpoints disagree about where revert bytes live: `error.data`, a nested
  `error.data.data`, or only inside `error.message`. An implementation **MUST**
  accept all three. The reference implementation takes the first `0x`-prefixed
  hex run of ≥ 8 nibbles it finds among them, in that order.
- A JSON-RPC `error` **without** revert data is not an answer; try the next
  endpoint.
- A `result` of `0x` or empty is **null**, not an error.
- When no endpoint answered, the last error is thrown — and §5.6 turns it into
  `unreachable`, never into a claim about the name.

The endpoints are not ours and are not chosen by us: they come from the chain
registry bundled with the `web3protocol` package, which for mainnet is
`https://ethereum.publicnode.com` and `https://cloudflare-eth.com`. An
implementation **MUST** state which endpoints it uses in its trust output (§7),
because they are the trusted service.

The RPC request **SHOULD** be issued through the same proxy/anonymisation path
as the page load, so that turning on IP protection does not leave the name
lookup riding the user's real address. The reference implementation passes the
browser session's proxied `net.fetch` as `fetchImpl`.

### 5.4 Step 4 — read the result

```
(encoded, resolverAddress) = abi.decode(result, (bytes, address))
value                      = abi.decode(encoded, (bytes))
```

- `result` null → `no-resolver`.
- `encoded` empty or `0x` → `no-content`.
- otherwise `value` is the raw contenthash byte string.

The decode is **outside** the call's error handling and has its own. A
well-formed JSON-RPC answer whose `result` is not the declared ABI shape is a
broken or hostile endpoint, not a fact about the name: an implementation
**MUST** report it as `unreachable` (§5.6), never as `no-content`.

### 5.5 Step 5 — decode the contenthash and hand off

`value` is decoded by the EIP-1577 grammar shared with the Handshake chapter
(`../../src/contenthash.js`). The outcomes:

| decode | kind | then |
|---|---|---|
| no record at all | `no-content` | a page saying the name has no website |
| `ipfs-ns` 0xe3 → `ipfs://<cid>` | `content` | handed to the IPFS handler |
| `ipns-ns` 0xe5 → `ipns://<cid>` | `content` | handed to the IPFS handler |
| `arweave-ns` 0xb29910 → `ar://<txid>` | `content` | handed to the Arweave handler |
| `swarm-ns` 0xe4, or an unknown codec | `unsupported` | a page **naming the protocol** |

A recognised codec this client cannot fetch **MUST** be refused by name and
**MUST NOT** be silently discarded or mis-routed to another network. "This name
points at Swarm content, which this build cannot fetch" is a true and useful
sentence; falling through to a search box is not.

The request is re-issued at `pointer.url + path` (§4), retaining the method
and, except for GET/HEAD, the body. The content handler's response receives:

- `X-Resolution-Namespace: ens` — on **every** response this handler produces,
  including every error page, so that a downstream consumer can tell which
  namespace answered;
- `X-HNS-Trust: ens-rpc-unverified` — set only if the content handler did not
  already set a trust header.

An implementation **MUST** carry an equivalent signal. A resolution whose
weakest step is unverified and which is served with no marking is
indistinguishable, downstream, from a verified one.

### 5.6 Distinguishing "no" from "we could not ask"

The error classification distinguishes a resolver response from a failure to
obtain one.

**An error is treated as an answer about the name only when it carries revert
data.** The revert selector determines the handler's classification. Every
other failure — no RPC reachable, a CCIP gateway that did not answer, a lookup
that did not terminate, a result that will not decode — does not yield a usable resolver answer, and an implementation **MUST** report it as `unreachable` with
HTTP status **502, never 404**. Nothing was learned about the name, so nothing
may be claimed about it.

An endpoint outage does not establish whether a name is registered. The
answer/failure decision is based on the presence of revert data and **MUST NOT**
be inferred from error-message wording alone.

When the call throws with revert data, the Universal Resolver's own errors, by
selector:

| selector | error | kind | shown as |
|---|---|---|---|
| `0x77209fe8` | `ResolverNotFound(bytes)` | `no-resolver` | "not registered" |
| `0x7199966d` | `ResolverNotFound()` | `no-resolver` | "not registered" |
| `0x1e9535f2` | `ResolverNotContract(bytes,address)` | `no-resolver` | "not registered" |
| `0x7b1c461b` | `UnsupportedResolverProfile(bytes4)` | `no-content` | "has no website" |
| `0x95c0c752` | `ResolverError(bytes)` | `no-content` | "has no website" |
| anything else | — | `no-content` | "has no website" |

The handler labels `no-resolver` as "not registered". Resolver configuration
does not by itself establish registration status; [REVIEW.md](../../REVIEW.md)
records the wording issue. Likewise, an unknown resolver error does not prove
that `contenthash` is absent.

An unrecognized revert selector defaults to `no-content`. The handler treats
the revert as a resolver answer whose more specific meaning is unknown.

### 5.6a ENSIP-5 text records, on the no-website page only

When resolution returns `no-content`, the page also reads these ENSIP-5
text keys: `url`, `description`, `avatar` (ENSIP-12), `email`,
`com.twitter`, `com.github` and `org.telegram`. Each uses `text(node, key)`
inside the same Universal Resolver `resolve()` call, one request per key.
Values are escaped, capped at 512 characters and never fetched. `url` becomes
a link only when it uses `https:`. The page identifies the RPC trust limit.
`textRecords()` in `src/ens-protocol.js` implements this display.

### 5.7 Resolution kinds

| kind | meaning | status served |
|---|---|---|
| `content` | a supported content pointer | whatever the content handler returns |
| `unsupported` | a decoded pointer this client cannot fetch, named | 501 |
| `no-resolver` | the RPC response indicates no usable resolver | 404 |
| `no-content` | the name resolves and publishes no `contenthash` | 404 |
| `unreachable` | no answer was obtained; **nothing is claimed about the name** | 502 |
| `invalid-name` | ENSIP-15 rejected the name | 400 |

Every failure **MUST** remain an ENS failure. None **MAY** trigger a lookup
in another namespace. The reference error pages state that no Handshake lookup
was attempted.

A failure to load the resolver machinery at all (§5.1's dependencies) is 502,
not 404, for the same reason as `unreachable`. `resolve()` loads those
dependencies itself, so a caller that uses it directly gets a resolution kind
rather than a type error.

---

## 6. CCIP-Read (ERC-3668)

Offchain ENS records use ERC-3668 `OffchainLookup`, including names under
`base.eth`, `uni.eth` and `linea.eth`, and the gasless DNSSEC import path.

An implementation that follows an offchain lookup **MUST**:

1. **Check the sender.** The `address` in the revert **MUST** equal the contract
   that reverted. Without this, any contract can point the client at any other
   contract's callback and have the result attributed to it.
2. **Cap the recursion.** A callback may itself revert with `OffchainLookup`,
   so the depth is chosen by the contract. ERC-3668 makes a cap mandatory and
   asks for at least 4; this implementation allows exactly 4 and then fails.
3. **Refuse an unsafe gateway URL.** The URL arrives inside a revert — it is
   chosen by whoever deployed the contract, and the client is being asked to
   fetch it. The rules applied here: **`https:` only**; never `localhost`,
   `*.localhost`, `*.local` or `*.internal`; and an **IP literal** must be a
   public address by the shared SSRF guard (`../../src/safe-address.js`). A
   refused URL is **fatal for that lookup**, not skipped past — it is a bad
   URL, not a slow one. What this does not cover is a *hostname* that resolves
   to a private address: EN-5.
4. **Not follow redirects.** A gateway that redirects is asking the client to
   fetch a URL nothing checked.
5. **Cap the response** (1 MiB here), by declared `content-length` *and* by
   actual length, so a lying header does not buy a buffer.
6. **Deadline each attempt** (8 s here).
7. **Stop on 4xx, continue on 5xx.** ERC-3668 makes this the client's rule:
   a 4xx is the gateway answering "no" and returns an error to the caller;
   a 5xx moves to the next URL.
8. Require a JSON body with a `data` field matching `^0x[0-9a-fA-F]*$`.

The callback calldata is then `callbackFunction ‖ abi.encode(bytes response,
bytes extraData)`, and the loop repeats.

**ENSIP-21 is not optional here.** The outer URL of a modern ENS lookup is
ENS's own batch gateway (`ccip-v3.ens.xyz`), so a client that simply follows it
**discloses every name its user resolves to a third party**. The sentinel
`x-batch-gateway:true` means "substitute your own; all compliant batch gateways
are equivalent". An implementation **MUST** substitute its own, under three
rules:

- **The calldata MUST carry the `query((address,string[],bytes)[])` selector
  `0xa780bab6`.** The sentinel says "use your own batch gateway", not "decode
  whatever follows against the batch shape". Calldata with any other selector
  is refused, and the refusal is fatal for the lookup rather than a reason to
  try the next URL.
- **The number of sub-requests MUST be capped** (16 here). Every triple is a
  fetch and every triple is chosen by the same contract that chose the batch.
  A batch over the cap is **refused whole, never truncated**, so the callback
  never receives a silently short array and cannot be fed a partial answer it
  would read as complete.
- Each sub-request is performed directly against the resolver's own gateway
  under rules 3–8 above, and the result is returned as
  `(bool[] failures, bytes[] responses)`. A sub-request that fails is reported
  as a **failure in the array**, not as a failed batch — that is the
  interface's own shape.

CCIP-Read transports a gateway answer to a contract callback. The callback
may verify an operator signature, a storage proof or a DNSSEC chain; the
transport protocol alone does not establish which assurance applies.

An implementation **MUST NOT** grade the lock by the callback's apparent
verification method. Without a verified Ethereum state, the RPC endpoint can
fabricate that method and its result. EN-2 records this limit.

---

## 7. Trust state

The reference trust model uses two steps for ENS. The second is currently
generic; its accuracy for an Arweave pointer is an open issue in
[REVIEW.md](../../REVIEW.md).

| # | label | state | says |
|---|---|---|---|
| 1 | **Name records** | `unverified` | what this name points at was read from an Ethereum RPC endpoint; this client runs no light client, so that endpoint's answer is taken on its word, and a wrong or hostile one could name different content |
| 2 | **Content** | `verified` | whatever address the record named, the bytes fetched are checked against it — the content cannot have been altered in transit, even though the pointer to it is unverified |

Aggregating by the spine's weakest-link rule gives **`partial`** — the lock is
**CLOSED and marked TRUSTED**, the same state an ordinary `https://` page is
in, and never the trustless state. The verdict is one thing everywhere: the
scheme table's `verify` string, the handler's own comments, the trust panel's
step text and this chapter all say TRUSTED, never green, and
`../../tests/lock-semantics.test.js` pins it ("ens:// is TRUSTED — and stays so
until there is a light client").

An implementation **MUST NOT** show an ENS resolution in the trustless state,
and **MUST** name the unverified hop in words rather than omitting the step. A
panel that falls through to "this browser has no verification path for this
scheme" is both wrong and silent about the one hop that actually needs saying.

The reference verdict is TRUSTED. Whether it should instead be OPEN remains
an unresolved policy question in [DEVIATIONS.md](DEVIATIONS.md) §2.1.

The trust output **MUST** name the RPC endpoints. "An RPC endpoint" is not a
disclosure; `ethereum.publicnode.com` is.

---

## 8. `web3://` — ERC-4804

### 8.1 What it is

ERC-4804 defines `web3://` as an HTTP-shaped read of an EVM contract: the
authority is a contract address (and optionally a chain id), and the path is
translated into a contract call whose return value is the response body. It is
a *different thing* from ENS — no name records, no contenthash — and it is in
this chapter only because both read Ethereum.

### 8.2 The scheme is `web3`, and only `web3`

`web3://` is registered. **`w3://` is deliberately not offered**, because `.w3`
is a Handshake top-level name in active use: `web3://` executes an EVM call
while `proof.w3` is an ordinary Handshake name resolved by the Handshake
resolver. They share a fragment of a name and nothing else, and a `w3://` alias
would make one typo route a Handshake site into an EVM read.

`namespaceForScheme('web3') === 'web3'` while `classify('proof.w3').namespace
=== 'hns'`, and that separation is pinned by `../../tests/router.test.js`. No
document in the tree offers the alias, and none may: a design document that
advertises it is how it eventually gets implemented by someone reading the
document instead of the code.

### 8.3 What the implementation does

The `web3protocol` dependency handles URL parsing, auto/manual mode,
ERC-6821 cross-chain `contentcontract` resolution, ERC-5219 requests and
ERC-7617 chunking. This chapter's wrapper:

1. imports the library and the chain registry **lazily, on the first
   `web3://` request**, never at startup (the default chain registry costs
   roughly half a second to import, for a scheme most sessions never touch);
2. refuses any method other than `GET` with **405**;
3. **clamps the contract-chosen status** and **filters the contract-chosen
   headers** before either reaches the engine (below);
4. adds permissive CORS headers;
5. turns a thrown error into a 500 whose body is the error **message**, served
   as `text/plain` — never the stack, which carries this installation's
   absolute paths and would be readable by any page on a scheme with
   `supportFetchAPI` and CORS `*`.

Step 3 exists because ERC-5219 returns `(uint16, bytes, (string,string)[])`:
**the contract chooses the HTTP status code and the response headers.** An
implementation **MUST** constrain both before they reach a browser engine.

- **The status MUST be clamped to a code the engine has a reason phrase for.**
  In Chromium, a protocol handler's status goes through
  `net::GetHttpReasonPhrase()`, which `NOTREACHED`s on any code it does not
  define — every code in 520–599 included. A contract returning `523` would
  otherwise be choosing a crash. The reference implementation routes the value
  through the shared `safeStatus()` (`../../src/safe-status.js`), which carries
  a known code unchanged and answers **502** — "bad gateway", because the party
  that chose the code is upstream of the handler — for anything else. A source
  scan for *literal* statuses cannot catch this: the value is a variable, and
  it is chosen by an adversary.
- **The headers MUST be filtered to a set that only describes the body.** The
  allowlist is `content-type`, `content-length`, `content-disposition`,
  `cache-control`, `etag`, `last-modified`; a value that is not a string is
  dropped rather than coerced. Everything else — `Location`, `Set-Cookie`,
  `Content-Security-Policy`, `Service-Worker-Allowed` — is discarded. On a
  scheme registered standard, secure and service-worker-capable, an
  unconstrained pass-through hands a redirect, a cookie and a security policy
  to an arbitrary contract.

`web3://` is **gated off while IP protection is on** (503, with an explanatory
body), because the library performs its own `fetch` outside the browser
session's proxy and would reveal the real address.

### 8.4 Status

**Partial.** The scheme resolves, the status and headers are constrained, and
the library's conformance to ERC-4804 is the library's; this implementation
adds no verification of its own, applies no SSRF policy to the chain registry's
RPC list, and imposes no overall deadline. §9.5 says what that means for
privilege. The row in `../../src/router.js` reads `status: 'partial'` for
exactly these reasons.

---

## 9. Security considerations

### 9.1 The gateway URL is attacker-chosen, by design

ERC-3668's gateway URL comes out of a contract revert. Anyone can deploy a
contract, and a name in this namespace can be made to resolve through one. The
client is then asked to make an HTTPS request to a URL of the attacker's
choosing and hand the result back to the attacker's contract. That is the
complete SSRF pattern with a protocol wrapped around it, and §6's rules 3–8
exist for it.

Two residual exposures an implementer should know about:

- **Hostnames are not resolved before fetching.** The address check applies only
  to an IP literal. A gateway hostname whose DNS resolves to `127.0.0.1` or to a
  cloud metadata address is not caught, and neither is DNS rebinding between the
  check and the fetch. The fetched bytes only ever reach the contract callback,
  so the exposure is **exfiltration of an internal response into a contract**,
  not display of it — but that is a real exposure, not an absent one. EN-5.
- **The sender check does not extend into an ENSIP-21 batch.** The outer
  `sender == to` rule is enforced; inside a batch the triples belong to *other*
  resolvers by the interface's own design, so their senders and URLs are
  contract-chosen. Each sub-request URL still passes §6 rule 3, the selector is
  checked, and the count is capped at 16 per batch and 4 rounds — so the
  fetching a contract can direct is bounded, and this is an amplifier with a
  ceiling rather than a bypass.

<a id="92-the-rpc-endpoint-is-a-trusted-third-party-and-it-is-watching"></a>

### 9.2 RPC trust and disclosure

The endpoint learns every `.eth` name the user opens, in real time, tied to
their IP address unless the request rides a proxy. It can also lie: return a
different `contenthash`, fabricate a `ResolverNotFound`, or fabricate an
`OffchainLookup` pointing at a gateway of its choosing. The first two are
detectable only by asking a second endpoint; the third is bounded by §6. A
malformed answer is the one lie that gains it nothing, because §5.4 reports it
as `unreachable`.

The ENS path has no cache. Navigations and subresources repeat the RPC and
CCIP lookups, increasing latency and disclosure volume (EN-6).

An implementation **SHOULD** send the RPC request over the same
proxy/anonymisation path as the page, and **MUST** say in the trust output that
this hop exists.

### 9.3 Privacy: the batch gateway is the leak

Handling ENSIP-21 locally avoids sending lookups to the shared outer batch
gateway. The resolver's own gateway still receives each sub-request. Section 6
requires local handling for this privacy reason.

### 9.4 Unknown is `unreachable`

Transport failures, CCIP timeouts, lookup-limit failures and malformed ABI
answers return `unreachable` with HTTP 502. Resolver answers indicating no
resolver or no `contenthash` return 404.

An implementation **MUST** keep unclassified failures as `unreachable`; a
failure to obtain records must not become a statement that a name is absent.

### 9.5 Privilege follows verification

An `ens://` document is served on an opaque origin with no secure context (§4)
because its pointer is unverified. A `web3://` document is served on a
**standard, secure, service-worker-capable** origin whose body is chosen by an
arbitrary contract, with no verification of any kind — the status and headers
are constrained (§8.3), but the posture is not. Those two postures are
inconsistent, and the inconsistency runs the wrong way. An implementation
**SHOULD** grant `web3://` no more privilege than `ens://` until there is
something verifying the read: `../../DEVIATIONS.md` §3, `EN-D2`.
