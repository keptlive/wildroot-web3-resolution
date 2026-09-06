// DEVIATIONS.md and REFERENCES.md are generated from the chapter files by
// scripts/build-docs.mjs. A hand edit to either, or a chapter edit without a
// regeneration, leaves the consolidated view saying something the chapters do
// not — so the build is checked here rather than trusted.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildDeviations, buildReferences, CHAPTERS } from '../scripts/build-docs.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

test('the consolidated documents are exactly what the chapters generate', () => {
  assert.equal(readFileSync(join(ROOT, 'DEVIATIONS.md'), 'utf8'), buildDeviations(), 'DEVIATIONS.md is stale — run npm run docs')
  assert.equal(readFileSync(join(ROOT, 'REFERENCES.md'), 'utf8'), buildReferences(), 'REFERENCES.md is stale — run npm run docs')
})

test('every chapter the spine lists has its three documents, and no chapter is missing from the spine', () => {
  const spine = readFileSync(join(ROOT, 'SPEC.md'), 'utf8')
  for (const { dir } of CHAPTERS) {
    for (const doc of ['SPEC.md', 'DEVIATIONS.md', 'REFERENCES.md']) {
      assert.ok(existsSync(join(ROOT, 'namespaces', dir, doc)), `namespaces/${dir}/${doc}`)
    }
    assert.ok(spine.includes(`namespaces/${dir}/SPEC.md`), `the spine links namespaces/${dir}/SPEC.md`)
    const first = readFileSync(join(ROOT, 'namespaces', dir, 'SPEC.md'), 'utf8').split('\n')[0]
    assert.match(first, /^# (Chapter \d+|Part II) — /, `${dir}: ${first}`)
  }
})

test('the chapter documents speak in the present tense about the current state only', () => {
  // No fix history, no dates of fixes, no leftover improvement files.
  for (const { dir } of CHAPTERS) {
    for (const doc of ['SPEC.md', 'DEVIATIONS.md', 'REFERENCES.md']) {
      const text = readFileSync(join(ROOT, 'namespaces', dir, doc), 'utf8')
      assert.doesNotMatch(text, /IMPROVEMENTS\.md/, `${dir}/${doc} references the removed improvements file`)
      assert.doesNotMatch(text, /\b(?:fixed|resolved) (?:in|by|on) (?:commit|20\d\d-\d\d-\d\d)/i, `${dir}/${doc} narrates a fix`)
    }
    assert.ok(!existsSync(join(ROOT, 'namespaces', dir, 'IMPROVEMENTS.md')), `${dir}/IMPROVEMENTS.md must not exist`)
  }
})
