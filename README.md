# Wildroot name resolution

This repository contains the name-resolution modules extracted from
[Wildroot](https://wildroot.io), their tests, and a draft specification.
The modules classify an address, resolve it in the selected naming system,
and report which parts of the result were verified locally.

It covers Handshake, ICANN DNS, IPFS/IPNS, Arweave, ENS, Nostr, DIDs, Tor,
and several key-addressed protocols. Handshake resolution combines an SPV
chain proof, DNSSEC validation against the on-chain DS record, and DANE
certificate pinning where available.

## Documentation

| If you want to… | Read |
|---|---|
| Understand the resolution and trust model | [Specification](SPEC.md) |
| See how an address selects a naming system | [Namespace selection](namespaces/router/SPEC.md) |
| Implement Handshake resolution | [Handshake](namespaces/handshake/SPEC.md) |
| Build an application on a Handshake name | [Application integration](namespaces/apps/SPEC.md) |
| Check limitations and design questions | [Deviations and open decisions](DEVIATIONS.md) |
| Compare Fast and Private delivery | [Privacy and transport](DIVERGENCE.md) |
| Find the standards used by each chapter | [References](REFERENCES.md) |
| Run checks or edit the documentation | [Contributing](CONTRIBUTING.md) |
| Review inconsistencies found during the rewrite | [Content review](REVIEW.md) |

The specification has a shared model, routing rules, and separate chapters
for each namespace. Each chapter keeps its technical requirements,
deviations, and references together under `namespaces/<name>/`.

## What this repository covers

Resolution includes address syntax, namespace selection, lookup rules,
verification, failure handling, and the information disclosed by a lookup.
An answer may be an IP address, a content pointer, a document, or a key.

The browser supplies the runtime integration: Electron sessions, protocol
handlers, content engines, publishing, and the user interface. The chapters
describe integration requirements where they affect resolution or security;
this repository is not a standalone browser.

## Run the checks

Requires Node.js 20 or later and Python 3. Use the lockfile to install the
dependencies:

```sh
npm ci
npm test
npm run lint
npm run docs:check
```

Tests use fixtures and local test servers. They do not require live RPC
endpoints, gateways, relays, or a running Tor service. See
[Contributing](CONTRIBUTING.md) for document generation and the optional
comparison with a browser checkout.

## Implementation status

This is an implementation-specific draft, not an endorsed standard.
Requirements describe the behavior this project expects from compatible
implementations. Known departures from external standards are recorded in
[DEVIATIONS.md](DEVIATIONS.md).

Verification depends on the route. A locally checked signature or content
hash proves a different claim from an answer received through a resolver,
RPC endpoint, or directory. The [trust model](SPEC.md#4-trust-states) records
those checks separately.

The browser is developed separately. `npm run parity` compares the mapped
modules with a selected browser checkout after normalizing relative imports;
it does not establish which code a released browser contains. Extracted
functions listed in the script's `FACTORED` table are exempt from that check.

The documentation includes the improvements present in this repository.
[REVIEW.md](REVIEW.md) records remaining inconsistencies and proposed
improvements. Documentation changes do not alter resolver behavior.

## License and citation

Code and tests: [Apache-2.0](LICENSE).
Specification documents: [CC BY 4.0](LICENSE-SPEC).

When citing the specification, include its draft version and the repository
commit. The specification version and the package version are recorded
separately in `SPEC.md` and `package.json`.
