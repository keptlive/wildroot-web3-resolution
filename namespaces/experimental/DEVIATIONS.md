# Chapter 10 — Experimental: deviations and open questions

This file records limitations and open questions for the experimental
registry and numeric-name conventions. Remaining questions are
tracked in [the content review](../../REVIEW.md). The numeric-name default
below reflects the current classifier.

Identifiers are prefixed `OP-` (Part A, HIP-5 `_op`) and `NT-` (Part B, numeric
Handshake TLDs) so they cannot collide with another chapter's. The code is
`../../src/hip5-op.js` and the `_op` step in `../../src/resolver.js` for Part A,
`../../src/hns-url.cjs` and the classification rule in `../../src/router.js`
for Part B.

---

## 1. Deviations

### OP-1. Two fall-throughs to the seller's nameservers

**What.** When a top-level name delegates to an Optimism registry contract via
an `0x<addr>._op.` NS record, the `_op` route is preferred, and it falls back to
the top-level name's ordinary NS records in two cases the route's own rationale
argues against:

1. **Every RPC endpoint failed or timed out.** Arguably this should be
   `unreachable`, rather than querying the TLD operator's nameserver.
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
reachable by an attacker who can make every Optimism RPC endpoint fail. This depends on the attacker being able to disrupt every configured RPC endpoint.

Not a fallback, deliberately: a **private or link-local address** from the
registry is `blocked`, never retried against DNS.

**Status.** OPEN. Implement ENSIP-10 wildcard resolution for case 2, which is a
strict improvement and removes the case entirely; for case 1, report
`unreachable` rather than falling back, once there is more than one registry
operator and the fallback is no longer to ourselves. The current behaviour is
pinned by a test (`../../tests/hip5-op.test.js`, "every RPC failing falls back
…") so that changing it is a deliberate act.

---

### NT-1. Numeric Handshake top-level names: off by default, behind a switch

**What.** Numeric-name classification is optional and off by default.
`setNumericNames()` in `../../src/classify-host.cjs` enables it. SPEC Part B
defines the retained `_` marker for explicit URLs.

**The standard says.** Nothing forbids a numeric Handshake label — Handshake
labels are `[a-z0-9-]` and the registry sells them. The WHATWG URL Standard's
host parser is what makes them unwritable as URLs (NT-2).

**Why.** They exist and have been paid for, including the free-name registry
top-level name `14898`, so refusing them strands real registrations. Supporting
them costs a written convention nobody else implements.

**Consequence.** Bare numeric names are not automatically routed to Handshake
unless the option is enabled. Clients using the explicit URL form must
implement the marker convention.

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

### NT-2. A numeric TLD is written with a leading underscore in a URL

**What.** In an `hns://` URL a final label consisting entirely of ASCII digits
is written with a `_` prefix: `14898` → `hns://_14898/`, `hello.14898` →
`hns://hello._14898/`. The marker is stripped before the name reaches the
resolver and re-added before a URL is built; the address bar displays the
unmarked form. `../../src/hns-url.cjs`.

**The standard says.** The WHATWG URL Standard's
[host parser](https://url.spec.whatwg.org/#host-parsing) runs the
["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker)
for special schemes and parses such a host as an
[IPv4 address](https://url.spec.whatwg.org/#concept-ipv4-parser). It provides no
per-scheme opt-out, and `_` is not a
[forbidden host code point](https://url.spec.whatwg.org/#forbidden-host-code-point),
so the marked form is a conforming host while the unmarked one is not a host at
all.

**Why.** `hns:` is registered as a standard scheme to get a real web origin
(Chapter 1 §5), which is the same decision that subjects the host to that
parser. SPEC B.4 records the alternatives considered.

**Consequence.** Every name under a numeric Handshake top-level name has two
written forms, and any third party writing a link to one must know the
convention or the link is dead on arrival. It is a local convention with no
standing anywhere else, so a link written by this client may be dead in another
Handshake client and vice versa.

**Status.** OPEN. If a different convention gains traction anywhere else we
would rather adopt it than defend this one — a shared convention is needed for interoperable links (§NT-2.1).

---

### NT-3. The `http://` spelling of a numeric name cannot be rewritten

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

**Status.** The automatic classification policy is decided in NT-1.
This URL-parser limitation remains: links to supported numeric names need
the marked `hns://` form.

---

## 2. Things we are not sure about

### OP-2.1. `_op` is chain-pointed and RPC-answered

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

### OP-2.2. One deployment is not a specification

`persist` on Optimism mainnet is the registry deployment documented here.
Every property in SPEC A.3 is a property of that contract, verified by reading
it; none of them is enforced by the mechanism. A second registry that behaves
differently — a `resolver(node)` that reverts rather than returning zero, a
`dnsRecord` that returns records under a different owner name — would be
resolved by this client in ways we have not tested.

### OP-2.3. What the registry read does under an anonymizing proxy

The `_op` read rides the embedder's proxied fetch, so it is private in the sense
that matters — the RPC endpoint sees the proxy, not the user (SPEC §A.6). What we
have not measured is whether it still *answers*: public JSON-RPC endpoints
commonly rate-limit or refuse traffic from anonymizing-network exits, and this
route's behaviour when every endpoint fails is to fall back to the top-level
name's ordinary nameservers (OP-1, case 1). If that is what happens under a
proxy, then the mode a user turns on for privacy is also the mode that quietly
returns them to the seller's nameserver — which is the one outcome the route
exists to avoid. It is a measurement, not an argument, and it has not been made.

### NT-2.1. The marker is a local invention, and its value depends on being shared

Two interoperability questions remain after the default-off decision:

- Whether the marker belongs on the **numeric label** (`hello._14898`) or as a
  **whole-host** marker. A prefix on the label is minimal and local; a host-wide
  marker would be uglier but would not change meaning depending on which label
  it lands on.
- Whether other Handshake clients will do something different, at which point a
  link written by one is dead in the other. A shared convention would prevent incompatible links.

---

## 3. Open design items

### OP-D1. The library default fetch is unproxied

The `_op` registry read uses an injected `fetchImpl` when the embedder provides
one, and the browser provides its proxied session fetch, so the shipped
composition never makes this request outside the proxy (SPEC A.6). When no
implementation is injected, the module falls back to the platform's global
fetch — which ignores the session's proxy settings. An embedder that forgets
the injection gets a route that works and leaks the user's address to the RPC
endpoint, with nothing to notice.

This affects privacy because the route runs while anonymization is on and is
not gated (SPEC §A.6), so the default is the one place where a mode the user
turned on for privacy can be defeated by an omission in an embedder rather than
by a decision anybody made.

**Recommendation.** Require it: throw from the constructor when no `fetchImpl`
is given, as the Arweave handler does. A library caller that genuinely wants
the global fetch can pass it explicitly, which makes the choice visible in the
caller rather than invisible in the default.

### OP-D2. No light-client verification of the registry's answer

A possible next step, also applicable to `ens://`, is to verify the storage slot
against a block header, by a light client or an execution proof, which would allow the record step to report `verified` if that proof validates.

**Recommendation.** Not now — the dependency is large and the route already
degrades honestly. Revisit when a usable Optimism light-client or storage-proof
library exists in a form a browser can load on every navigation; until then,
keep saying `unverified` in words.

### NT-D1. Numeric top-level names have no test of the whole path

`../../tests/hns-url.test.js` covers the encode/decode/display/rewrite edge
cases, including the trailing-dot case. What is not covered anywhere is the
*path*: a typed `hello.14898`, through the classifier, through the URL
construction, through a resolution, back to a displayed address bar.

**Recommendation.** Add an end-to-end test for both the opt-in classifier
and explicit marked URLs, since both remain supported.

---

## 4. What this chapter leaves out

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
