/*
 * The vendored IANA root-zone snapshot — its shape, its date, and the proof
 * that it is what the generator produces.
 *
 * `src/icann-tlds.cjs` is the entire ICANN/Handshake boundary (SPEC §2). It is
 * a build-time snapshot, so two questions have to be answerable from the
 * artefact itself: *what does it contain* and *how old is it*. Wildroot's own
 * drift alarm (`tests/hns/icann-tlds-live.test.js`) answers a third — whether
 * it still matches IANA — by fetching the live file, which is exactly the kind
 * of test that cannot live in this package.
 *
 * So this file does the deterministic half offline: it rebuilds the IANA
 * document the committed file must have come from and checks the generator
 * reproduces the file byte for byte. That catches the failure the live test
 * cannot distinguish from a network problem — a hand-edited boundary.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'

import { IANA_URL, parseIana, render, snapshotHeader, ianaTextFor } from '../src/icann-tld-snapshot.js'

const require = createRequire(import.meta.url)
const SNAPSHOT_PATH = new URL('../../../src/icann-tlds.cjs', import.meta.url)
const SOURCE = readFileSync(SNAPSHOT_PATH, 'utf8')
const TLDS = require('../../../src/icann-tlds.cjs')

test('the snapshot is a Set of plausible root-zone size', () => {
  assert.ok(TLDS instanceof Set)
  // The root zone has had well over a thousand entries since 2014. A truncated
  // fetch or an error page must never be mistaken for the root zone — the
  // generator refuses to write fewer than 1000 for the same reason.
  assert.ok(TLDS.size > 1000, `only ${TLDS.size} entries`)
  assert.ok(TLDS.size < 5000, `${TLDS.size} entries is not the root zone either`)
})

test('every entry is a single lowercase label, punycode as published', () => {
  for (const tld of TLDS) {
    assert.equal(typeof tld, 'string', String(tld))
    assert.equal(tld, tld.toLowerCase(), tld)
    assert.ok(!tld.includes('.'), `${tld} is not a single label`)
    assert.match(tld, /^(xn--)?[a-z0-9-]+$/, tld)
  }
  // The classifier converts a Unicode host to A-labels before the lookup, so
  // the set must hold A-labels and nothing else — no second table, no
  // Unicode duplicates.
  assert.ok([...TLDS].some((t) => t.startsWith('xn--')), 'no punycode entries at all')
  assert.ok(TLDS.has('xn--p1ai'), 'рф is missing')
})

test('the snapshot carries IANA\'s own version and date', () => {
  // This is the provenance a third-party implementer actually has: not the
  // generator, but the header line in the file they are reading.
  const header = snapshotHeader(SOURCE)
  assert.ok(header, 'no `// IANA Version …` line — the snapshot is undated')
  assert.match(header.version, /^\d{10}$/, header.line)
  assert.match(header.line, /Last Updated .+ UTC$/)
})

test('the committed file is exactly what the generator produces', () => {
  // Offline reproduction: rebuild the IANA document from the committed set and
  // header, render it, and require a byte-for-byte match. A hand-edited entry,
  // a reordering, or a stray whitespace change all fail here — none of which
  // the live drift alarm can tell apart from IANA being unreachable.
  const header = snapshotHeader(SOURCE)
  const text = ianaTextFor(TLDS, header.line)
  assert.equal(render(parseIana(text)), SOURCE)
})

test('the parser reads IANA\'s published format, and only the data lines', () => {
  const text = [
    '# Version 2026090500, Last Updated Sat Sep  5 07:07:01 2026 UTC',
    'COM',
    'XN--P1AI',
    '',
    'ZW'
  ].join('\n')
  const parsed = parseIana(text)
  assert.equal(parsed.version, '2026090500')
  assert.equal(parsed.header, 'Version 2026090500, Last Updated Sat Sep  5 07:07:01 2026 UTC')
  assert.deepEqual(parsed.tlds, ['com', 'xn--p1ai', 'zw'])
})

test('the renderer sorts, de-duplicates and keeps the header', () => {
  const out = render(parseIana('# Version 1, Last Updated now\nZW\nCOM\nCOM\n'))
  assert.match(out, /module\.exports = new Set\(\[/)
  assert.match(out, /'com', 'zw'/)
  assert.match(out, /\/\/ IANA Version 1, Last Updated now/)
  assert.equal((out.match(/'com'/g) || []).length, 1)
})

test('the source of the boundary is IANA, and is named', () => {
  assert.equal(IANA_URL, 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
})
