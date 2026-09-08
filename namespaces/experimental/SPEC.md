# Chapter 10 — Experimental: HIP-5 `_op` on-chain resolution, and numeric Handshake TLDs

This chapter describes two experimental Handshake conventions:

- **Part A:** use a `<registry>._op.` NS record to direct a sub-name lookup
  to an Optimism registry contract.
- **Part B:** encode numeric Handshake TLDs in `hns://` URLs with an underscore
  marker.

Neither convention is a ratified standard. Numeric-name classification is off
by default; the optional marker remains supported for explicit `hns://` URLs.
The [content review](../../REVIEW.md) records unresolved behavior questions.

[Chapter 1](../handshake/SPEC.md) defines the Handshake chain path that enters
these mechanisms. The implementation is in `../../src/hip5-op.js`,
`../../src/resolver.js`, `../../src/hns-url.cjs`, and the shared host
classifier. These modules are not duplicated in this directory.

[Deviations](DEVIATIONS.md) use `OP-` for registry resolution and `NT-` for
numeric names. [References](REFERENCES.md) lists the cited standards.

Key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
used as in RFC 2119 / RFC 8174.

---

## Contents

**Part A — HIP-5 `_op` on-chain resolution**
- [A.1 The problem](#a1-the-problem)
- [A.2 The route](#a2-the-route)
- [A.3 Contract properties a client relies on](#a3-contract-properties-a-client-relies-on)
- [A.4 Fallback](#a4-fallback)
- [A.5 Trust](#a5-trust)
- [A.6 Privacy and egress](#a6-privacy-and-egress)
- [A.7 Draft normative text for a HIP](#a7-draft-normative-text-for-a-hip)

**Part B — Numeric Handshake TLDs and the `_` URL marker**
- [B.1 The numeric-TLD problem](#b1-the-numeric-tld-problem)
- [B.2 The convention](#b2-the-convention)
- [B.3 What the implementation does](#b3-what-the-implementation-does)
- [B.4 Alternatives considered](#b4-alternatives-considered)

---

# Part A — HIP-5 `_op` on-chain resolution

**Status: HIP-0005 is a permanent Draft and the HIP process is not active.**
`_op` as specified here is an extension of that draft's mechanism, shipping on
Handshake mainnet for the top-level name `persist`. It is not a ratified standard.

## A.1 The problem

A Handshake top-level name normally delegates sub-name resolution through
`NS` records. For a registry that sells sub-names, this leaves the registry
operator able to answer DNS queries for those names, even when ownership is
recorded in a smart contract. A chain proof of the TLD delegation does not
independently prove each sub-name owner's records.

HIP-5 defines an alternative: a label under a `_<chain>` pseudo-TLD is not a host at
all — it is a pointer into another naming system, and the resolver strips the
suffix and reads that system directly. The draft's shipped example is `_eth`
(ENS on Ethereum). `_op` is the same idea aimed at **Optimism mainnet, chainId
10**, where the label is the address of an ENS-shaped registry contract.

```
persist.   NS  ns1.hns.one.
persist.   NS  ns2.hns.one.
persist.   NS  0x233b4fbf4e8f0e60bff0a5f1a24ffa257987dbf2._op.
```

This is the `persist` deployment example recorded by the project. This
repository does not verify its current live configuration.

## A.2 The route

Entered from Chapter 1 §6.3, for a name below the apex, lowercased:

```
node     = namehash(name)                                    EIP-137
resolver = Registry.resolver(node)          -> address       0x0178b8bf
content  = Resolver.contenthash(node)       -> bytes         0xbc1c58d1  (EIP-1577)
exists   = Resolver.hasDNSRecords(node, nameKey) -> bool      0x4cbf6ba4
rrset    = Resolver.dnsRecord(node, nameKey, type) -> bytes   0xa8fa5682

nameKey  = keccak256(RFC 1035 wire-format, lowercased, root-terminated owner name)
```

Records read, and what they become:

| owner | type | becomes |
|---|---|---|
| `<name>` | TXT (16) | a content pointer (Chapter 1 §10) |
| `<name>` | A (1) | `{ kind: 'site', address }` |
| `_443._tcp.<name>` | TLSA (52) | the DANE pin, the same shape the DNS route yields |

Precedence inside the route matches the DNS route exactly: `contenthash` first
(it is the native form and costs one call), then a TXT content pointer, then
the address. An address MUST pass the public-address guard of Chapter 1 §11.2.
A resolution produced here has the same shape and the same kinds as one from
the DNS route (Chapter 1 §6.9).

The three record reads MUST be issued together and **one failure retires the
whole route**. An endpoint that can serve the `A` record but not the `TLSA` one
would strip the pin and look exactly like a name that has none.

Stored records MUST NOT be trusted to be free of compression pointers: a length
octet ≥ 0xC0 ends the parse. Compression pointers are unsupported in these stored records.

RPC endpoints are tried in order, each with its own deadline, so a dead
endpoint costs one timeout and not a navigation.

The **apex** is untouched: its records are the chain resource, already proven.

## A.3 Contract properties a client relies on

- `dnsRecord` returns concatenated RFC 1035 resource records, byte-compatible
  with ENS's DNSResolver. The owner name baked into each RR is the on-chain
  name.
- `resolver(node)` **may** answer with a registry default, so the zero address
  means "this registry has nothing for this name", not "no override set".
- **A revert is not a failure.** A resolver that does not implement
  `contenthash` reverts; that means "no content", and the route continues.
- Records are versioned by ownership epoch, so when a name changes hands
  everything the previous holder wrote stops being served — with no transaction
  and with no version parameter in the read path. This is a property of the registry contract, not a guarantee enforced by
  the reader.

## A.4 Fallback

1. `_op` first when the record is present and well-formed.
2. The ordinary `NS` records when the route yields **nothing**: a zero resolver;
   `hasDNSRecords` false with no contenthash (a minted name whose holder has
   published nothing); records but no address and no usable pointer; or every
   RPC endpoint failing. The reason SHOULD be logged once per name so RPC failures remain visible. **See `OP-1`:
   two of these cases arguably should not fall back at all.**
3. A **non-public address** from the registry is not a fallback case. The
   record was found and it says something we refuse to fetch; asking a second
   source for permission would be theatre.

Every `._op.` target, well-formed or not, is removed from the nameserver list
before step 2 (Chapter 1 §6.3). Nothing under that pseudo-TLD is a host.

## A.5 Trust

The chain proof covers the **pointer**: consensus says the top-level name
delegates to contract `0x…`. Nothing covers the contract's **answer**, which is
read from a public JSON-RPC endpoint over HTTPS with no light client and no
Merkle proof against a block header.

Therefore an implementation:

- **MUST** produce a `Name records` trust step in state `unverified`, naming
  the registry contract and the RPC endpoint in words (Chapter 1 §4, step 2);
- **MUST NOT** present an `_op` answer as cryptographically verified unless it
  verified the contract's storage against a block header;
- **SHOULD** apply the same lock rule the DNS route applies — a content pointer
  closes the lock on the chain proof, an address closes it only on a matched
  DANE pin. The aggregate verdict is therefore never better than `partial`
  (TRUSTED, the neutral closed lock), because one step is `unverified`.

The open question about that lock rule is recorded in
`../../DEVIATIONS.md` (Chapter 10, §OP-2.1): the existing rationale compares it with the DNS
route,
which also takes an unsigned answer on a nameserver's word and over plaintext
where this hop is HTTPS, and not with `ens://`, which has no chain anchor at
all. A reasonable implementer could hold that an RPC-trusted answer should
never close a lock, full stop.

Interoperability limitation: a name that publishes records
**only** on chain is unreachable from any client that does not implement HIP-5. A registry can publish a DNS mirror for other clients.

## A.6 Privacy and egress

The RPC endpoint learns which name was asked, and learns it from the user's own
address unless the request is proxied.

The registry read therefore **MUST** be made through a fetch implementation the
embedder injects, so that it rides whatever proxied session the embedder has
configured. In the reference implementation the resolver takes `fetchImpl` as a
constructor option and hands it to the `_op` route
(`../../src/resolver.js` → `../../src/hip5-op.js`), and the browser passes its
proxied session fetch; the invariant that this egress is never unproxied is
held by construction rather than by a policy that turns the route off. The
library default, when no `fetchImpl` is injected, is the platform's global
fetch, which is **not** proxied — an embedder that omits the injection gets a
working route and an unproxied one, silently, which is why the browser pins the
injection with a test rather than a code review.

The route can run while anonymization is enabled when the injected fetch
uses the configured proxy. Its one egress is an HTTPS request, and an HTTPS request made through
the injected fetch is covered by whatever proxied session the embedder
configured — which is what the injection is for. What decides whether the
route is *reached* under anonymization belongs to Chapter 1: the `_op` step sits
inside the chain-proof path (Chapter 1 §6.3), and a composition selects that
path while anonymized only when the SPV node's peer traffic and the
authoritative hop both go through the proxy (Chapter 1 §6.11). The condition is
"the chain path is alive under the proxy", and it is inherited rather than
re-decided here.

An implementation therefore **MUST NOT** refuse the `_op` route merely because
anonymization is on: refusing a request that is already proxied buys no privacy
and turns every name under an `_op` registry into a failure in the mode where a
user most wants a name to resolve. It **MUST NOT** answer it through an
unproxied default fetch either (`OP-D1`). The embedder is responsible for supplying the correct transport.

## A.7 Draft normative text for a HIP

> A Handshake name MAY delegate resolution of names beneath it to a smart
> contract on Optimism mainnet (chainId 10) by publishing an `NS` record whose
> target is `<address>._op.`, where `<address>` is the 20-byte contract address
> in lowercase hexadecimal with a `0x` prefix — 42 characters, exactly as it
> appears on chain — followed by the pseudo-TLD label `_op`.
>
> The contract MUST implement the ENS registry interface
> `resolver(bytes32) returns (address)` (EIP-137 `namehash` over the full
> dotted name, lowercased), and the resolver it names SHOULD implement
> `contenthash(bytes32)` (EIP-1577) and MAY implement the ENS DNSResolver
> methods `hasDNSRecords(bytes32,bytes32)` and
> `dnsRecord(bytes32,bytes32,uint16)`, where the second argument is
> `keccak256` of the lowercased, root-terminated, RFC 1035 wire-format owner
> name and stored records are wire-format RRsets containing no compression
> pointer.
>
> A resolver that understands `_op` **MUST** prefer it over any other `NS`
> record on the same name: the pointer to the contract is proven by Handshake
> consensus, whereas an ordinary `NS` delegation names a server the name's
> current holder does not control. It **MAY** fall back to the remaining `NS`
> records when the `_op` route yields no answer — no resolver set, no records
> and no contenthash, or no reachable RPC endpoint — and it **MUST NOT** treat
> a `._op.` target as a hostname to resolve.
>
> A resolver **MUST NOT** present an `_op` answer as cryptographically
> verified unless it verified the contract's storage against a block header:
> absent a light client, the RPC endpoint is a trusted third party for the
> record, and the user interface must say so.
>
> `_op` is one member of a family; `_eth` (ENS on Ethereum mainnet) is the
> existing prior art. A registry of `_<chain>` labels belongs in the HIP
> itself so two chains cannot claim one label.

---

# Part B — Numeric Handshake TLDs and the `_` URL marker

**Status:** Optional convention. Numeric-name classification is off by default
and can be enabled with `setNumericNames()`. Explicit marked `hns://` URLs
remain supported. NT-1 records this policy; interoperability of the marker
and full browser-path coverage remain open.

## B.1 The numeric-TLD problem

`hns:` is registered as a **standard** custom scheme in the reference
Electron browser (Chapter 1 §5). Its Chromium integration applies domain-host
parsing to this scheme. This is an engine extension: `hns` is not one of the
WHATWG URL Standard's [special schemes](https://url.spec.whatwg.org/#special-scheme),
and a generic JavaScript `URL` parser need not treat it the same way. The registered Chromium domain-host parser runs the
["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker),
which returns true when the host's last label is non-empty and contains only
ASCII digits, and then parses the host as an
[IPv4 address](https://url.spec.whatwg.org/#concept-ipv4-parser).

A Handshake top-level name may legitimately be all digits — the free-name
registry TLD `14898` is one. Therefore:

```
hns://14898/          canonicalises to hns://0.0.58.50/
hns://hello.14898/    is not a valid URL at all
```

For comparison, `new URL('http://hello.14898')` fails under the WHATWG
parser because `http` is a special scheme. Those unmarked forms cannot be navigated through that parser.

With numeric names enabled, the classifier assigns an all-numeric final label
to Handshake. With the default setting, it assigns that host to `web`; a bare
number is a search. The switch is in `../../src/classify-host.cjs`.

## B.2 The convention

In an `hns://` URL, a **final** label consisting entirely of ASCII digits is
written with a single leading `_`:

| Handshake name | URL form |
|---|---|
| `14898` | `hns://_14898/` |
| `hello.14898` | `hns://hello._14898/` |
| `hello.world` | `hns://hello.world/` (unchanged) |

An implementation following this convention:

- **MUST** apply the marker only to the final label. Non-final labels are
  written as they are, and a `_` on a non-final label is not a marker (DNS
  owner names inside a Handshake zone routinely begin with `_` —
  `_443._tcp.…`, `_dnslink.…` — and those are not affected because they are
  never the final label).
- **MUST** treat the final label as the last **non-empty** one. The URL
  Standard's "ends in a number" checker strips a single trailing empty label
  before testing, so `hello.14898.` hits the IPv4 rule exactly as
  `hello.14898` does, and the marked form is `hns://hello._14898./`. An
  implementation that splits on `.` and marks the final element finds the empty
  string there and leaves the host unmarked and unnavigable.
- **MUST** strip the marker before the name is used for resolution, for a chain
  lookup, or for any comparison against a name as registered.
- **MUST** apply the marker when constructing a URL from a name, including from
  user input in an address bar, *before* any IDNA/punycode pass — because the
  URL constructor throws on the unmarked form and so cannot be used to perform
  that pass.
- **SHOULD** display the unmarked form wherever a URL is shown to a person
  rather than navigated.
- **SHOULD** rewrite an incoming unmarked link (`hns://hello.14898/…`, which a
  third party may reasonably have written) to the marked form before
  navigating, since the browser refuses it before any handler runs.

`_` is chosen because a Handshake label is `[a-z0-9-]` and can never contain
one (RFC 1123 §2.1 host label syntax), so the decoding is unambiguous and
cannot collide with a real name; and because `_` is not a
[forbidden host code point](https://url.spec.whatwg.org/#forbidden-host-code-point),
so the marked host parses in every browser — `_dmarc.example.com` is the
everyday proof.

## B.3 What the implementation does

`../../src/hns-url.cjs` exports the shared CommonJS helpers used by the
router and address bar:

| Function | What it does |
|---|---|
| `encodeHnsHost(name)` | name → URL host: the last non-empty label, if all digits, gains its `_`. A port suffix is preserved. |
| `decodeHnsHost(host)` | URL host → name: the `_` comes off a marked numeric final label. |
| `isEncodedNumericTld(host)` | whether a URL host carries the marker. |
| `displayHnsUrl(url)` | an `hns://` URL as a person should read it — the marker removed from the host, everything else untouched. |
| `fixHnsHref(href)` | a third party's unmarked `hns://hello.14898/…` rewritten to the form that will navigate; `null` for every other href, so a click handler leaves everything else alone. |

The convention covers `hns://` URLs and cannot cover the `http://` spelling of
the same name: `http://hello.14898/` is rejected by the URL parser before any
navigation hook runs, so the `http→hns` rewrite of Chapter 1 §3 never sees it
(`NT-3`).

## B.4 Alternatives considered

| Alternative | Why not |
|---|---|
| **Register `hns:` as a non-standard (opaque) scheme.** An opaque-host parser avoids IPv4 interpretation; the engine's custom-scheme behavior would need separate review. | It changes the origin and API privileges required by the application model. The reference application model requires a usable web origin. |
| **Percent-encode or otherwise escape the digits.** | Domain-host parsing percent-decodes the host before the numeric check, so encoding ASCII digits does not avoid that check. |
| **Use a different marker character** (`-`, `.`, a Unicode digit). | `-` is a legal Handshake label character, so it would be ambiguous. A trailing dot is stripped. A non-ASCII digit is punycoded and then *is* a valid label but an unreadable one. `_` was selected because it cannot occur in a Handshake label and is accepted by the host parser. |
| **Suffix the name into a real domain** (`hello.14898.hns.one`). | This uses a gateway domain and depends on its DNS and infrastructure. |
| **Get the URL Standard changed.** | The IPv4 rule exists for compatibility with a very long tail of the web. A per-scheme opt-out is not available to this implementation. |
| **Refuse to support numeric TLDs.** | They are valid Handshake names that people have registered and paid for. The selected policy in NT-1 disables automatic classification by default while retaining explicit URLs and an opt-in switch. |
