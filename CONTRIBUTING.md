# Contributing

For a correction, identify the affected section, the expected behavior, and
the relevant source code, test, or external standard. If code and prose
disagree, describe both before proposing which one should change.

## Repository layout

| Path | Contents |
|---|---|
| `SPEC.md` | Shared model, routing summary, and chapter index |
| `namespaces/<name>/SPEC.md` | Requirements for one namespace or integration |
| `namespaces/<name>/DEVIATIONS.md` | Limitations, uncertainties, and design decisions |
| `namespaces/<name>/REFERENCES.md` | Standards and their use in that chapter |
| `DIVERGENCE.md` | Cross-namespace privacy and transport comparison |
| `src/` | Handshake modules and modules shared by several namespaces |
| `namespaces/<name>/src/` | Modules specific to a namespace |
| `tests/`, `namespaces/<name>/tests/` | Shared and namespace test suites |
| `scripts/` | Test runner, documentation generator, and browser comparison |

Handshake uses the top-level `src/` directory. The experimental chapter
also refers to top-level modules. Browser-only integration code is described
in the chapters but is not copied here.

## Documentation changes

Edit the chapter files. The root `DEVIATIONS.md` and `REFERENCES.md` are
generated indexes with the chapter text included. The generator also appends
`DIVERGENCE.md` to the consolidated deviations document.

```sh
npm run docs        # regenerate the consolidated files
npm run docs:check  # check that generated files are current
node --test tests/docs-consolidated.test.js
```

Keep requirement words (`MUST`, `SHOULD`, `MAY`), deviation identifiers, and
section links intact when making an editorial change. Record unresolved
behavioral conflicts separately. Changes to requirements need corresponding
review of the implementation and tests.

## Tests

Use Node.js 20 or later, Python 3 on `PATH`, and the checked-in lockfile:

```sh
npm ci
npm test
npm run lint
```

The test runner executes the shared and namespace suites. DNSSEC fixtures
include a local Python nameserver serving signed zones. Other services use
scripted substitutes. Network access is needed to install dependencies, but
the tests do not depend on public services.

## Comparing with the browser

The resolution modules originated in the Wildroot browser tree.
`scripts/parity.mjs` maps each copied file to its browser path. The check
reverses the relative-import rewrite and compares the file contents:

```sh
npm run parity                       # compares with ../browser
WILDROOT=/path/to/browser npm run parity
```

This reads the browser checkout. A failure means the selected checkouts
differ; it does not establish which one is correct or which one is deployed.
The `FACTORED` table lists functions extracted from larger browser files.
Those files are exempt from the file comparison and need separate review.

`npm run sync` copies mapped modules **from the browser into this repository**.
It changes source files. Use it only for an intentional source update, after
checking both working trees and the direction of the changes.
