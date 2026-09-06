// The IANA root-zone snapshot: how `src/icann-tlds.cjs` is produced and dated.
//
// EXTRACTION NOTE. Unlike the modules in the top-level `src/`, this file is NOT
// byte-identical to its Wildroot counterpart. It is `scripts/fetch-icann-tlds.mjs`
// from the browser tree with its `main()` removed — the half that reaches the
// network and writes the file. What is kept is the part the specification
// depends on: the exact parse of IANA's published file and the exact rendering
// of the committed snapshot, so that "the vendored list is what the generator
// produces" is a claim a reader can check offline
// (`tests/icann-tld-snapshot.test.js`).
//
// WHAT THIS FILE DECIDES. `src/icann-tlds.cjs` is the whole of the
// ICANN/Handshake boundary: a dotted name whose final label is in that set is
// an ICANN domain and is resolved through the ordinary DNS; every other name is
// a Handshake name (SPEC §2). Nothing else in the browser makes that call, so a
// stale snapshot misroutes names in BOTH directions:
//
//   a delegated TLD MISSING from the set  -> a real domain is resolved as a
//     Handshake name, fails, and the user is told the site does not exist
//   a TLD in the set that IANA no longer delegates -> a name that could be
//     Handshake's is sent to https:// and to the ICANN resolver, which both
//     fails AND discloses the lookup
//
// The second is the one that grows: ICANN's 2026 round drew roughly 1,600
// applications, and every delegation turns a string that resolves as a
// Handshake name today into an ICANN TLD.
//
// IT IS BUNDLED, NOT FETCHED AT RUNTIME, for the same reason the filter lists
// are: a privacy browser does not phone home on startup, and the classifier
// must answer a keystroke without waiting for the network. The cost is that the
// boundary is only as fresh as the last release (DEVIATIONS.md DI-1).

/** IANA's published root-zone TLD list — the only source of the boundary. */
export const IANA_URL = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'

/**
 * The TLD set and the version line out of IANA's own file.
 *
 * Punycode (`xn--…`) is kept exactly as published: the classifier converts a
 * Unicode host to A-labels before the lookup (SPEC §3.4), so the two agree
 * without a second table.
 *
 * @param {string} text the body of {@link IANA_URL}
 * @returns {{version: string, tlds: string[], header: string}}
 */
export function parseIana (text) {
  const lines = String(text).split('\n')
  const header = lines.find((l) => l.startsWith('#')) || ''
  const version = (/Version\s+(\d+)/.exec(header) || [])[1] || 'unknown'
  const tlds = lines
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => l.trim().toLowerCase())
    .filter(Boolean)
  return { version, tlds, header: header.replace(/^#\s*/, '').trim() }
}

/**
 * The committed file, formatted exactly as it is committed: sorted, ten per
 * line, with IANA's own version/date line carried into the header comment.
 * That date line is the snapshot's provenance — it is how a reader tells how
 * old the boundary they are running is.
 *
 * @param {{version: string, tlds: string[], header: string}} parsed
 * @returns {string} the contents of `src/icann-tlds.cjs`
 */
export function render ({ version, tlds, header }) {
  const sorted = [...new Set(tlds)].sort()
  const rows = []
  for (let i = 0; i < sorted.length; i += 10) {
    rows.push('  ' + sorted.slice(i, i + 10).map((t) => `'${t}'`).join(', ') + ',')
  }
  // Trim the trailing comma of the last row for cleanliness.
  rows[rows.length - 1] = rows[rows.length - 1].replace(/,$/, '')
  return `// IANA root zone TLD list, snapshot bundled at build time.
// Refresh: node scripts/fetch-icann-tlds.mjs   (then commit this file)
// Drift alarm: tests/hns/icann-tlds-live.test.js
//
// THE ICANN/HANDSHAKE BOUNDARY. A dotted name whose final label is in this set
// is resolved as an ICANN domain over https://; every other name is resolved as
// a Handshake name. That is the whole rule, and this is the whole of its data.
//
// IANA ${header}
module.exports = new Set([
${rows.join('\n')}
])
`
}

/**
 * The IANA version/date line carried in a rendered snapshot, or null.
 *
 * Added during extraction (it has no Wildroot counterpart) so that "how is the
 * list dated?" is answerable from the artefact itself rather than from the
 * generator, which is what a third-party implementer actually has.
 *
 * @param {string} source the contents of `src/icann-tlds.cjs`
 * @returns {{version: string, line: string}|null}
 */
export function snapshotHeader (source) {
  const line = (/^\/\/ IANA (Version .+)$/m.exec(String(source)) || [])[1]
  if (!line) return null
  const version = (/Version\s+(\d+)/.exec(line) || [])[1] || 'unknown'
  return { version, line }
}

/**
 * Rebuild the IANA file a rendered snapshot must have come from. The generator
 * is not injective in general (it lowercases, sorts and de-duplicates), but it
 * IS injective on its own output, which is what makes the offline
 * reproduction check in the tests possible without a network fetch.
 *
 * Added during extraction; no Wildroot counterpart.
 *
 * @param {Iterable<string>} tlds
 * @param {string} headerLine the `Version …` line
 */
export function ianaTextFor (tlds, headerLine) {
  return `# ${headerLine}\n` + [...tlds].map((t) => t.toUpperCase()).join('\n') + '\n'
}
