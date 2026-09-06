# Chapter 10 — Experimental: references

Every standard, draft or interface this chapter's implementation actually
reads, with what it is used for and where. Module paths are relative to this
file; the code lives at the repository root because it is entered from
Chapter 1.

## Handshake and pseudo-TLD delegation (Part A)

| Identifier | Title | Used for |
|---|---|---|
| [HIP-0005](https://github.com/handshake-org/HIPs/blob/master/HIP-0005.md) | Pseudo-TLD delegation to alternative naming systems | §A.1, §A.7: the mechanism `_op` extends — an NS target under a `_<chain>` pseudo-TLD is not a host but a pointer into another naming system. **Status: permanent Draft**; the HIP process is not active, which is part of why this chapter is experimental. `../../src/resolver.js`, `../../src/hip5-op.js` |
| [Handshake resource format](https://hsd-dev.org/api-docs/) | The on-chain `Resource` | §A.1: the `NS` record carrying `<address>._op.` is read from the chain resource Chapter 1 §6.1 proves. `../../src/resolver.js` |

## Ethereum and Optimism (Part A)

| Identifier | Title | Used for |
|---|---|---|
| [EIP-137](https://eips.ethereum.org/EIPS/eip-137) | Ethereum domain name service — specification | §A.2: `namehash`, and the registry interface `resolver(bytes32) returns (address)` (selector `0x0178b8bf`). Checked against the EIP's own published vectors. `../../src/hip5-op.js` |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) / [ENSIP-7](https://docs.ens.domains/ensip/7) | contenthash field | §A.2: the multicodec-prefixed content pointer read first on this route — `ipfs-ns` 0xe3, `ipns-ns` 0xe5, `swarm-ns` 0xe4, `arweave-ns` 0xb29910. `../../src/contenthash.js` |
| [ENS DNSResolver interface](https://docs.ens.domains/resolvers/interfaces) | DNS records on an ENS-shaped resolver | §A.2, §A.3: `hasDNSRecords(bytes32,bytes32)` (`0x4cbf6ba4`) and `dnsRecord(bytes32,bytes32,uint16)` (`0xa8fa5682`), where the second argument is `keccak256` of the lowercased, root-terminated, RFC 1035 wire-format owner name and the returned bytes are wire-format RRsets. `../../src/hip5-op.js` |
| [ENSIP-10](https://docs.ens.domains/ensip/10) | Wildcard resolution | §A.4: cited for what this route does **not** do — a sub-name whose own namehash has no resolver is not walked up to its parent's resolver. `OP-1` |
| [Optimism JSON-RPC](https://docs.optimism.io/) | `eth_call`, chainId 10 | §A.2, §A.6: a hand-rolled `eth_call` over the injected `fetch` — a 4-byte selector plus 32-byte words, no client library, because this runs on every navigation. Being an ordinary HTTPS request through that injected fetch is also what lets the route run unchanged while the user is anonymized. `../../src/hip5-op.js` |
| [Multiformats: multicodec, unsigned-varint, CID](https://github.com/multiformats/multicodec) | Self-describing value prefixes | §A.2: reading a contenthash value. `../../src/contenthash.js` |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain names — implementation and specification | §A.2, §A.3: the wire format stored records are in, and the owner-name encoding hashed into `nameKey`. Compression pointers are refused rather than followed. `../../src/hip5-op.js` |

## URL and host syntax (Part B)

| Identifier | Title | Used for |
|---|---|---|
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL Standard — [host parsing](https://url.spec.whatwg.org/#host-parsing), the ["ends in a number" checker](https://url.spec.whatwg.org/#ends-in-a-number-checker), the [IPv4 parser](https://url.spec.whatwg.org/#concept-ipv4-parser) and [forbidden host code points](https://url.spec.whatwg.org/#forbidden-host-code-point) | §B.1, §B.2: **the reason the convention exists.** A standard scheme's host whose last label is all ASCII digits is parsed as an IPv4 address, so `hns://14898/` becomes `hns://0.0.58.50/` and `hns://hello.14898/` is not a URL; and `_` is usable as the marker because it is not a forbidden host code point. `../../src/hns-url.cjs`, `NT-2` |
| [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) | Requirements for internet hosts — application and support | §B.2, §2.1 host label syntax: why a Handshake label can never contain `_`, which is what makes the marker unambiguous. `../../src/hns-url.cjs` |
| [Chromium URL / scheme registry](https://chromium.googlesource.com/chromium/src/+/main/url/) | The implementation of the above | §B.1: a registered standard scheme cannot opt out of IPv4 host parsing, which is why this is not fixable in the embedder. — |
