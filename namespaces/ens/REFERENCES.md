# Chapter 5 — ENS and `web3://`: references

Every standard this chapter's implementation reads, with what it is used for
and where. The rule is the spine's: **nothing is listed here that the code does
not touch**, because a padded bibliography makes the real dependencies
impossible to see. A row that says *not implemented* or *via the library* says
so in the row — it is present because its absence, or its indirection, is a
documented fact rather than an oversight.

Rows that point at `../../src/` are dependencies this chapter **shares with the
rest of the specification** and does not re-implement.

---

## Naming and records

| Identifier | Title | Used for |
|---|---|---|
| [EIP-137](https://eips.ethereum.org/EIPS/eip-137) | Ethereum Domain Name Service — Specification | `namehash`, the recursive keccak256 over labels that turns a name into the `bytes32` node every ENS read is keyed by; and the registry interface `resolver(bytes32)`, which this chapter does **not** call. Its own normalisation text (nameprep / UTS-46) is superseded by ENSIP-15. SPEC §5.1, §5.2; `src/ens-protocol.js` via `viem/ens` `namehash`. |
| [ENSIP-1](https://docs.ens.domains/ensip/1) | ENS | EIP-137 republished under the ENS numbering — the document an ENS reader is pointed at first, and the source of the "Name Syntax" clause ENSIP-15 replaced. No separate behaviour. SPEC §5.1. |
| [ENSIP-15](https://docs.ens.domains/ensip/15) | ENS Name Normalization Standard | The normalisation actually performed, before hashing and before any network request, so that this client computes the node the registration was validated under. It is also the thing that refuses a malformed name after §4's guarded percent-decode. SPEC §4, §5.1; `src/ens-protocol.js` `resolve()`. |
| [UTS #46](https://www.unicode.org/reports/tr46/) | Unicode IDNA Compatibility Processing | The processing ENSIP-15 derives from and the one EIP-137 originally specified. Bare UTS-46 is **not** applied; the row exists so a reader can see which of the two is meant. SPEC §5.1. |
| [ENSIP-10](https://docs.ens.domains/ensip/10) | Wildcard Resolution | `resolve(bytes name, bytes data)` on the Universal Resolver: the on-chain walk up to the nearest ancestor **with** a resolver, which is why `jesse.base.eth` resolves at all. SPEC §5.2; `src/ens-protocol.js` `UNIVERSAL_RESOLVER_ABI`. |
| [EIP-1577](https://eips.ethereum.org/EIPS/eip-1577) | contenthash field for ENS | The record read: the multicodec-prefixed value that names a website. SPEC §5.5; `../../src/contenthash.js`. |
| [ENSIP-7](https://docs.ens.domains/ensip/7) | Contenthash Field | EIP-1577 under the ENS numbering, and the codec assignments the decoder recognises: `ipfs-ns` 0xe3, `ipns-ns` 0xe5, `swarm-ns` 0xe4, `arweave-ns` 0xb29910. SPEC §5.5; `../../src/contenthash.js`. |
| [ENSIP-21](https://docs.ens.domains/ensip/21) | Batch Gateway Offchain Lookup | The sentinel URL `x-batch-gateway:true`, the `query((address,string[],bytes)[])` selector `0xa780bab6`, and the `(bool[],bytes[])` return. Implemented locally, so `ccip-v3.ens.xyz` is never contacted. SPEC §6; `src/ccip-read.js` `batchLocally`. |
| [EIP-181](https://eips.ethereum.org/EIPS/eip-181) | ENS support for reverse resolution of Ethereum addresses | **Not implemented** (EN-3). Listed because a reader expects it in an ENS chapter and its absence is deliberate: nothing on a browsing path has an address to reverse. |
| [ENSIP-5](https://docs.ens.domains/ensip/5) | Text Records | `text(bytes32,string)`, read **only** for the no-website page: seven keys (`url`, `description`, `avatar`, `email`, `com.twitter`, `com.github`, `org.telegram`), one call each through the same Universal Resolver, shown as escaped text capped at 512 characters. Navigation itself still reads `contenthash` and nothing else (EN-1, EN-7). SPEC §5.6a; `src/ens-protocol.js` `textRecords`, `textRecordsHtml`. |
| [ENSIP-12](https://docs.ens.domains/ensip/12) | Avatar Text Records | The `avatar` key's meaning. Its **value is shown as the text it is** and is never fetched or rendered as an image, so none of the URI schemes this ENSIP defines is resolved here. SPEC §5.6a, EN-1. |
| [ENSIP-9](https://docs.ens.domains/ensip/9) | Multichain Address Resolution | **Not read** (EN-1, EN-7). A wallet's record profile, cited so that the boundary of "resolves a name to a website" is explicit. |
| [ENS Universal Resolver](https://docs.ens.domains/resolution/universal) | ENS documentation — Universal Resolver | The contract this chapter calls, `0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe` on mainnet: a DAO-owned upgradable proxy, pinned deliberately rather than read from the bundled chain registry. SPEC §5.2; `src/ens-protocol.js` `UNIVERSAL_RESOLVER`. |

## CCIP-Read

| Identifier | Title | Used for |
|---|---|---|
| [ERC-3668](https://eips.ethereum.org/EIPS/eip-3668) | CCIP Read: Secure offchain data retrieval | The whole of `src/ccip-read.js`: the `OffchainLookup(address,string[],bytes,bytes4,bytes)` error (selector `0x556f1830`); the Client Lookup Protocol — `sender` MUST equal the reverting contract, `{sender}`/`{data}` are lowercase 0x-hex, GET when the template carries `{data}` and POST otherwise, 4xx returns an error and stops while 5xx tries the next URL; and the MUST-cap on lookups. SPEC §6. |
| [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) | IPv4 Address Blocks Reserved for Documentation | Part of the address set a gateway IP literal is checked against. SPEC §6 rule 3; `../../src/safe-address.js`. |
| [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) | Special-Purpose IP Address Registries | The SSRF guard proper: loopback, private, link-local (including `169.254.169.254`), CGNAT, benchmarking, multicast, reserved. SPEC §6 rule 3, §9.1, EN-5; `../../src/safe-address.js`. |

## Ethereum transport

| Identifier | Title | Used for |
|---|---|---|
| [JSON-RPC 2.0](https://www.jsonrpc.org/specification) | JSON-RPC 2.0 Specification | The request envelope, and critically the `error` object: a member carrying revert bytes is the chain answering, not a failure to reach it. §5.1's freedom over `error.data` is why three shapes must be accepted. SPEC §5.3, §5.6; `src/ens-protocol.js` `ethCall`, `revertDataOf`. |
| [`eth_call`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_call) | Ethereum JSON-RPC API — `eth_call` | The one method used: always `{to, data}` at block tag `latest`; no `from`, no gas parameters, no state override. SPEC §5.3; `src/ens-protocol.js`. |
| [EIP-55](https://eips.ethereum.org/EIPS/eip-55) | Mixed-case checksum address encoding | **Deliberately not relied on.** Addresses are compared and templated lowercased (ERC-3668 requires the lowercase form for `{sender}`), so a checksum mismatch can never change a decision. `src/ccip-read.js` `fillTemplate`, the sender check. |
| [EIP-1191](https://eips.ethereum.org/EIPS/eip-1191) | Add chain id to mixed-case checksum address encoding | Named only to separate it from name normalisation, which it is adjacent to in most reading lists and has nothing to do with. Not used. |
| [Contract ABI Specification](https://docs.soliditylang.org/en/latest/abi-spec.html) | Solidity documentation — Contract ABI Specification | Function selectors (`contenthash(bytes32)` → `0xbc1c58d1`) and the encode/decode of every argument and return value, including the decode whose failure is `unreachable`. SPEC §5.2, §5.4, §6; `src/ens-protocol.js`, `src/ccip-read.js`, performed by `viem`. |

## `web3://`

| Identifier | Title | Used for |
|---|---|---|
| [ERC-4804](https://eips.ethereum.org/EIPS/eip-4804) | Web3 URL to EVM Call Message Translation | The scheme itself, implemented by the third-party `web3protocol` package; the module here is a lazy loader, a `GET`-only gate and a constrained response. Its short form `w3://` is deliberately not offered. SPEC §8; `src/web3-protocol.js`. |
| [ERC-5219](https://eips.ethereum.org/EIPS/eip-5219) | Contract Resource Request Mode | Where `web3://`'s HTTP status code and response headers come from: the contract returns `(uint16, bytes, (string,string)[])`. The citation SPEC §8.3's two constraints rest on. Via `web3protocol`; clamped and filtered in `src/web3-protocol.js` `web3Response`. |
| [ERC-6821](https://eips.ethereum.org/EIPS/eip-6821) | Support ENS Name for Web3 URL | The library resolves a `.eth` host in a `web3://` URL through its **own** ENS implementation, with its own RPC list and its own normalisation. Neither implemented nor gated here — which means the browser contains two ENS clients. Via `web3protocol`. |
| [ERC-7617](https://eips.ethereum.org/EIPS/eip-7617) | Chunk support for ERC-5219 mode `web3://` | Reached the same way. The library streams further chunks by re-entering `web3://`, so one navigation can become a long chain of contract calls with no deadline of ours (EN-D1). Via `web3protocol`. |

## URLs, HTTP and namespace selection

| Identifier | Title | Used for |
|---|---|---|
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) | Domain Names — Implementation and Specification | §3.1's wire-format name encoding — length-prefixed labels, root-terminated, no compression — which ENSIP-10's `resolve()` takes as its first argument. SPEC §5.1; `viem/ens` `packetToBytes`. |
| [WHATWG URL Standard](https://url.spec.whatwg.org/) | URL — Living Standard | Two ways: `new URL()` is the parser the gateway guard refuses with (and `protocol` must be exactly `https:`), and `ens:` is a non-special scheme whose content is an opaque path, which is why the name arrives percent-encoded and must be decoded before normalisation. SPEC §4, §6 rule 3; `src/ens-protocol.js` `parseEnsUrl`, `src/ccip-read.js` `isSafeGatewayUrl`. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics | The status-code classes ERC-3668's 4xx/5xx rule is written in, the `content-length` header the gateway response cap reads, and the statuses this chapter serves (400 / 404 / 405 / 500 / 501 / 502). SPEC §5.7, §6, §8.3. |
| [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498) | The GNU Name System | §9.10's namespace precedence: resolve in the alternative namespace when its suffix matches, and do **not** continue into DNS on failure. Applied to `.eth` — no failure kind may become a lookup in another namespace. SPEC §1, §3, §5.7; `../../src/router.js` `classifyHost`. |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Key words for use in RFCs to Indicate Requirement Levels | The requirement keywords used throughout this chapter. |
| [multicodec](https://github.com/multiformats/multicodec) | Multiformats — multicodec table | The codec prefixes a contenthash value is read by, with unsigned-varint and CID. Shared with the rest of the specification. SPEC §5.5; `../../src/contenthash.js`. |

## Not a standard, but load-bearing

| Identifier | Title | Used for |
|---|---|---|
| [viem](https://viem.sh/) | viem — TypeScript interface for Ethereum | ABI encode/decode, `namehash`, `packetToBytes` and `normalize`. The only third-party dependency on the `ens://` resolution path, and it is on the critical path of a security decision (normalisation), so its version is worth pinning exactly rather than by range. |
| [@adraffy/ens-normalize](https://github.com/adraffy/ens-normalize.js) | ens-normalize.js | What viem's `normalize` actually is: ENSIP-15's reference implementation, reached through [ox](https://oxlib.sh/). Named because "we normalise with viem" hides which specification is being applied. |
| [web3protocol](https://github.com/web3-protocol/web3protocol-js) | web3protocol-js | The entire ERC-4804 implementation, **and** the bundled chain registry that supplies the Ethereum RPC endpoints `ens://` itself trusts. Both schemes depend on this package, one of them for a list of trusted third parties. |
| The bundled mainnet chain entry | `web3protocol/chains`, `chainId` 1 | `https://ethereum.publicnode.com` and `https://cloudflare-eth.com`: the endpoints trusted for every ENS mapping and the ones the trust output must name. Its `ensUniversalResolver` and `ensRegistry` addresses are **not** used (SPEC §5.2). |
| [ENS DNSSEC gasless import](https://docs.ens.domains/dns/) | ENS documentation — DNS names in ENS | Not a document implemented here, but the reason CCIP-Read is mandatory rather than optional: every ICANN domain imported into ENS answers through an offchain lookup, so a client without SPEC §6 cannot resolve any of them. |
