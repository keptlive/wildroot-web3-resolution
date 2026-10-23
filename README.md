# wildroot-web3-resolution

A specification, with its reference implementation, for how a browser resolves
web3 names: which naming system an address belongs to (Handshake, ICANN DNS,
IPFS, Arweave, ENS, Nostr, DID, Tor and others), how it is resolved, and what
was verified on the way. The code is the resolution layer of the
[Wildroot](https://wildroot.io) browser.

Status: draft for public comment. Not endorsed by any standards body.

## The specification

[`SPEC.md`](SPEC.md) holds the shared model (terminology, trust states, Fast
and Private modes). Each part after that has its own file:

| | Chapter |
|---|---|
| Part II | [Namespace selection](namespaces/router/SPEC.md) |
| 1 | [Handshake](namespaces/handshake/SPEC.md) |
| 2 | [ICANN names](namespaces/icann/SPEC.md) |
| 3 | [IPFS, IPNS and DNSLink](namespaces/ipfs/SPEC.md) |
| 4 | [Arweave](namespaces/arweave/SPEC.md) |
| 5 | [ENS and `web3://`](namespaces/ens/SPEC.md) |
| 6 | [Nostr](namespaces/nostr/SPEC.md) |
| 7 | [DID, AT Protocol and ActivityPub](namespaces/did/SPEC.md) |
| 8 | [Tor](namespaces/tor/SPEC.md) |
| 9 | [Key-addressed namespaces: hyper, SSB, Gemini, BitTorrent](namespaces/keys/SPEC.md) |
| 10 | [Experimental: HIP-5 `_op` and numeric Handshake TLDs](namespaces/experimental/SPEC.md) |
| 11 | [Native applications on a Handshake name](namespaces/apps/SPEC.md) |

Supporting documents:

- [`REFERENCES.md`](REFERENCES.md): every standard cited, and what it is used for.
- [`DEVIATIONS.md`](DEVIATIONS.md): departures from cited standards, open questions and open design decisions.
- [`DIVERGENCE.md`](DIVERGENCE.md): where the private path and the fast path differ.
- [`REVIEW.md`](REVIEW.md): open review findings.

`REFERENCES.md` and `DEVIATIONS.md` are generated from the per-chapter files
with `npm run docs`.

## Tests

Requires Node.js 20 or later and Python 3. Some tests start a local nameserver
(`tests/fixtures/resolver/nsd.py`) over frozen signed zones; the rest use
scripted fakes. The tests do not depend on public services.

```sh
npm ci
npm test
npm run lint
npm run docs:check
```

## Layout

```
SPEC.md              the shared model
namespaces/<ns>/     one chapter: SPEC.md, DEVIATIONS.md, REFERENCES.md, and src/ and tests/ if it has code
src/, tests/         the Handshake modules and the modules several chapters share
scripts/             test runner, documentation generator, browser parity check
reviews/             dated review records
```

The modules are copies of the Wildroot browser's. `npm run parity` fails if
the browser checkout is absent, so an unchecked run cannot look successful. It compares
them with a browser checkout at `../browser` (or `$WILDROOT`). The browser
source is not public, so without that checkout the command reports that
nothing was checked and exits successfully.

## Citing

> Wildroot, *Web3 name resolution: a specification*, version 0.10.0.
> https://github.com/keptlive/wildroot-web3-resolution

## Licence

The code (`src/`, `namespaces/*/src/` and the tests) is Apache-2.0
([`LICENSE`](LICENSE)). The documents are CC-BY-4.0
([`LICENSE-SPEC`](LICENSE-SPEC)). Corrections are welcome; see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
