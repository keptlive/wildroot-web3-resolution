# Chapter 5 — ENS and `web3://`: deviations and open questions

Known deviations, unresolved questions and proposed changes for ENS website resolution, CCIP-Read and the separate `web3://` handler.

Entries distinguish current behaviour from recommendations. Paths beginning
`src/` or `tests/` are relative to this chapter; `../../src/` names shared
modules. Browser paths refer to the Wildroot source tree. Historical line
references may have moved since extraction.

[Chapter specification](SPEC.md) · [References](REFERENCES.md)

---

## 1. Deviations

<a id="en-1-only-contenthash-is-read-addr-text-and-the-rest-are-not"></a>

### EN-1. Website resolution with a limited text-record display

**Current behaviour.** Navigation resolves `contenthash`. Since 2026-09-06,
the no-website page also reads seven ENSIP-5 text keys: `url`, `description`,
`avatar`, `email`, `com.twitter`, `com.github` and `org.telegram`.
Those values are displayed as escaped text, capped at 512 characters; only
an HTTPS `url` becomes a link. They are not fetched. See SPEC §5.6a and
`src/ens-protocol.js` (`textRecords`, `textRecordsHtml`).

**Scope.** This remains a browsing client. It does not resolve payment
addresses, multichain address records or primary names. The text display runs
only for a `no-content` result, so successful website navigations do not incur
those additional lookups.

**Status: IMPLEMENTED WITH LIMITED SCOPE.** A name with no website can expose
the selected descriptive records. Each value is read through the same trusted
RPC and Universal Resolver path as the content pointer.

---

### EN-2. A CCIP resolver's rigour is deliberately not graded

**What.** Every ENS resolution carries the same trust state, whether the
offchain resolver behind it checked an operator's signature or verified a
Merkle storage proof or a DNSSEC chain on chain.

**The standard says.** ERC-3668 is explicit that it is a transport and that
what the callback does with the gateway's answer is the contract's business;
it defines no way to signal, and no obligation to distinguish, the strength of
that check.

**Why.** The RPC endpoint supplies the resolver address, revert and callback
result without a locally verified Ethereum state. The client cannot establish
which callback verification actually ran.

**Consequence.** Stronger checks performed by a resolver do not change this
client's trust verdict.

**Status: DELIBERATE**, conditional on the absence of a light client (§2.2).

---

### EN-3. Reverse resolution (EIP-181) is not implemented

**What.** `addr.reverse` is never queried; no primary name is ever displayed.

**The standard says.** EIP-181 defines the `.addr.reverse` namespace and the
`name(bytes32)` record so that an address can be shown as the name it claims.

**Why.** Nothing on a browsing path has an Ethereum address to reverse. Reverse
resolution answers "what does this address call itself", which is a wallet's
question.

**Consequence.** Website resolution does not expose reverse names. A future
address-display feature would need this record profile.

**Status: DELIBERATE.**

---

### EN-4. Two normalisations for one hash function

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

**Status: DELIBERATE.** Each route uses its namespace's normalization rules.

---

### EN-5. A gateway **hostname** is never resolved before it is fetched

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

### EN-6. Nothing is cached; every navigation re-resolves

**What.** There is no cache on the `ens://` path. Each navigation, and each
subresource load that goes through it, performs the full §5 sequence including
any CCIP round trip. The ENS registry's own `ttl(bytes32)` is never read.

**The standard says.** EIP-137 gives every node a TTL, `ttl(bytes32)` on the
registry, for exactly this purpose.

**Why.** A cache has not been implemented.

**Consequence.** Repeated navigations increase latency and the number of
requests observed by RPC endpoints and CCIP gateways.

**Status: OPEN.** A short positive cache keyed by the normalised name,
invalidated the way the Handshake resolver's `forget()` works, is the whole
change. Negative results **must not** be cached — `unreachable` especially,
because caching "we could not ask" turns one outage into a persistent wrong
answer.

---

### EN-7. Whole areas of ENS are not implemented at all

**What and why**, in one table:

| Thing | Why not |
|---|---|
| **Full ENS text profile** (`text(bytes32,string)`) | Seven keys are read on the no-website page (EN-1). General profile browsing is not implemented. |
| **Multichain address records** (ENSIP-9) | A wallet's job, not a browser's. |
| **`Registry.ttl(bytes32)`** | Nothing caches (EN-6), so there is nothing for a TTL to govern. |
| **ENS on an L2, read natively** | Reached through CCIP-Read (SPEC §6) like every other client without an L2 light client. Reading the L2 directly would swap one trusted RPC for another. |
| **An Ethereum light client** | The single change that would move this namespace out of `unverified`. It is a large piece of work and is not started. Everything in SPEC §7 is conditional on it. |

**The standard says.** Each row's own specification defines behaviour this
implementation does not provide.

**Consequence.** This is an ENS *browsing* client, not an ENS client. Wallet records and general profile browsing remain outside its scope.

**Status: DELIBERATE** for every row except the light client, which is
**OPEN** and is the only one that would change a trust state.

---

## 2. Things we are not sure about

### 2.1. Is `ens://` TRUSTED, or OPEN?

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

The current choice is TRUSTED. Any change needs to update the handler,
metadata, trust panel, documentation and tests together.

### 2.2. Would grading CCIP rigour become right, with a light client?

EN-2 refuses to distinguish a signed-gateway answer from an on-chain proof,
because the difference is not observable. With a light client it is: the
callback's verification runs against state we proved. At that point a
CCIP-Read resolver that verifies a DNSSEC chain on chain is genuinely
**trustless**, and one that checks an operator's signature is genuinely
**trusted**, and showing them identically is the lie. So the rule in EN-2 is
correct *and* temporary, and we do not know how to write it in a way that does
not silently become wrong.

### 2.3. Revert data is found by the error's shape

The answer/failure decision is structural — is there revert data? — and so is
finding it: `error.data`, or a nested `error.data.data`, counts only when the
whole string is `0x`-prefixed hex; an error *message* is consulted only when it
says the call reverted, and an endpoint that merely echoes a hex value into a
plain error (an address in "invalid argument …") is a transport failure, not an
answer. What remains uncertain is the message path itself: JSON-RPC endpoints
differ in where they put revert data, and a client that only ever saw typed
errors would not need to read messages at all. We have not surveyed enough
endpoints to know whether the "revert" test is too narrow for some of them.

### 2.4. Should `.eth` be the only alt-root we carve out?

`.eth` and `.onion` are carved out of the Handshake namespace; `.crypto`,
`.sol`, `.bnb` are not, and resolve as Handshake names. The justification is
that ENS and Tor are live systems with real usage and the others are not. That
is a judgement about the market, made once, in a table of one label. It will
age, and there is no mechanism here for noticing when it has.

### 2.5. Pinning the Universal Resolver address

The Universal Resolver address is pinned and the bundled registry entry is
ignored. Maintaining that pin requires checking future ENS deployments. Options
include a list verified at build time or validating the registry entry against
a known deployment.

### 2.6. `web3://`'s privilege posture

`ens://` is deliberately opaque-origin and non-secure because its answer is
unverified. `web3://` is standard, secure and service-worker-capable, and its
answer is *equally* unverified. The status and headers a contract returns are
constrained, which removes the sharpest edges, but the origin posture is not. We think the right move is EN-D2 below; we do not know whether any
ERC-4804 site relies on the storage that demotion would take away.

---

## 3. Open design items

The two other open items, EN-5 (pin the resolved gateway address) and EN-6 (a
short positive cache), carry their recommendations in §1 and are not repeated
here.

### EN-D1. `web3://` has no deadline of its own and no policy over its RPC list

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

### EN-D2. `web3://` keeps a stronger privilege posture than `ens://`

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

## 4. What this chapter leaves out

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
