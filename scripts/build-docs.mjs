#!/usr/bin/env node
// Assembles the two consolidated documents from the chapters.
//
//   DEVIATIONS.md   every chapter's DEVIATIONS.md, in chapter order, headings
//                   demoted one level under a chapter heading, with a table of
//                   contents linking to each chapter.
//   REFERENCES.md   an index of every identifier cited anywhere (one row per
//                   identifier, naming the chapters that use it), followed by
//                   each chapter's own tables — which carry what the standard
//                   is used FOR in that chapter, the part a flat list loses.
//
// The chapter files are the source; these two are generated. `npm run docs`
// regenerates them and the test in tests/docs-consolidated.test.js fails when
// they are stale, so the consolidated view cannot drift from the chapters.

import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { dirname, join, posix } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

/** Chapter order, directory, prefixes. `router` is Part II, the rest Part III. */
export const CHAPTERS = [
  { dir: 'router', label: 'Part II — Namespace selection' },
  { dir: 'handshake', label: 'Chapter 1 — Handshake' },
  { dir: 'icann', label: 'Chapter 2 — ICANN names' },
  { dir: 'ipfs', label: 'Chapter 3 — IPFS, IPNS and DNSLink' },
  { dir: 'arweave', label: 'Chapter 4 — Arweave' },
  { dir: 'ens', label: 'Chapter 5 — ENS and `web3://`' },
  { dir: 'nostr', label: 'Chapter 6 — Nostr' },
  { dir: 'did', label: 'Chapter 7 — DID, AT Protocol and ActivityPub' },
  { dir: 'tor', label: 'Chapter 8 — Tor' },
  { dir: 'keys', label: 'Chapter 9 — Key-addressed namespaces' },
  { dir: 'experimental', label: 'Chapter 10 — Experimental: HIP-5 `_op` and numeric Handshake TLDs' },
  { dir: 'apps', label: 'Chapter 11 — Native applications on a Handshake name' }
]

const read = (p) => readFileSync(join(ROOT, p), 'utf8')

/** Drop the chapter file's own H1 and demote every other heading one level. */
function body (text, sourcePath) {
  return text
    .split('\n')
    .filter((line, i, all) => !(i === 0 && line.startsWith('# ')))
    .map((line) => (/^#{1,5} /.test(line) ? '#' + line : line))
    .join('\n')
    .replace(/^\n+/, '')
    // Preserve each relative link's destination when including a chapter at root.
    // A fragment-only link still refers to the original chapter, whose headings
    // may also occur in another chapter of this consolidated document.
    .replace(/(\]\()([^\s)]+)(\))/g, (whole, open, target, close) => {
      if (/^(?:[a-z][a-z0-9+.-]*:|\/)/i.test(target)) return whole
      const hash = target.indexOf('#')
      const path = hash < 0 ? target : target.slice(0, hash)
      const fragment = hash < 0 ? '' : target.slice(hash)
      const rebased = path ? posix.normalize(posix.join(posix.dirname(sourcePath), path)) : sourcePath
      return `${open}${rebased}${fragment}${close}`
    })
}

const anchor = (heading) => heading.toLowerCase().replace(/[`*_]/g, '').replace(/[^a-z0-9 -]/g, '').trim().replace(/\s+/g, '-')

export function buildDeviations () {
  const parts = []
  const toc = []
  for (const { dir, label } of CHAPTERS) {
    const file = `namespaces/${dir}/DEVIATIONS.md`
    if (!existsSync(join(ROOT, file))) continue
    const text = read(file)
    toc.push(`- [${label}](#${anchor(label)}) — [chapter file](${file})`)
    parts.push(`<a id="${anchor(label)}"></a>\n\n## ${label}\n\n_Source: [\`${file}\`](${file})._\n\n${body(text, file)}`)
  }
  // The cross-cutting divergence inventory closes the document.
  const divergence = read('DIVERGENCE.md')
  toc.push('- [Privacy and transport](#privacy-and-transport) — [source file](DIVERGENCE.md)')
  parts.push(`<a id="cross-cutting-divergence-inventory-where-privacy-and-speed-pull-apart"></a>\n\n## Privacy and transport\n\n_Source: [\`DIVERGENCE.md\`](DIVERGENCE.md)._\n\n${body(divergence, 'DIVERGENCE.md')}`)
  return `# Deviations, uncertainties and open decisions

Known departures from cited standards, uncertainties, and design decisions,
organized by chapter. Identifiers use chapter prefixes such as \`HS-1\` and
\`IC-3\`; open design items use \`<prefix>-Dn\`.
**This document is generated from the
chapter files by \`scripts/build-docs.mjs\`; edit those.**

\`DELIBERATE\` identifies an intentional departure; \`OPEN\` identifies an
unresolved issue or proposed change. These labels describe project decisions,
not approval by the authors of the cited standards. Remaining inconsistencies
and proposed improvements are listed in [REVIEW.md](REVIEW.md).

## Contents

${toc.join('\n')}

---

${parts.join('\n\n---\n\n')}
`
}

/** Parse `| Identifier | Title | Used for |` rows out of a chapter's REFERENCES.md. */
function rows (text) {
  const out = []
  for (const line of text.split('\n')) {
    const m = /^\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*$/.exec(line)
    if (!m) continue
    if (/^-+$/.test(m[1].replace(/[:\s]/g, '')) || /^Identifier$/i.test(m[1])) continue
    out.push({ id: m[1], title: m[2], used: m[3] })
  }
  return out
}

/** The identifier stripped of markdown and link, for grouping. */
function keyOf (id) {
  return id.replace(/\*\*/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/`/g, '').trim()
}

export function buildReferences () {
  const index = new Map()
  const parts = []
  for (const { dir, label } of CHAPTERS) {
    const file = `namespaces/${dir}/REFERENCES.md`
    if (!existsSync(join(ROOT, file))) continue
    const text = read(file)
    for (const r of rows(text)) {
      const key = keyOf(r.id)
      if (!index.has(key)) index.set(key, { id: body(r.id, file), title: body(r.title, file), chapters: [] })
      const entry = index.get(key)
      if (!entry.chapters.includes(label)) entry.chapters.push(label)
    }
    parts.push(`## ${label}\n\n_Source: [\`${file}\`](${file})._\n\n${body(text, file)}`)
  }
  const sorted = [...index.values()].sort((a, b) => keyOf(a.id).localeCompare(keyOf(b.id), 'en', { numeric: true }))
  const indexRows = sorted.map((e) => `| ${e.id} | ${e.title} | ${e.chapters.map((c) => c.replace(/ — .*/, '')).join(', ')} |`)
  return `# References

Standards, specifications, and other documents cited by the chapters, with
their use in the implementation. **Generated from the chapter files by \`scripts/build-docs.mjs\`;
edit those.**

The index lists each identifier once and names the chapters that cite it.
The chapter tables follow with section references and implementation details.

## Index

${index.size} identifiers.

| Identifier | Title | Cited in |
|---|---|---|
${indexRows.join('\n')}

---

${parts.join('\n\n---\n\n')}
`
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const check = process.argv.includes('--check')
  const outputs = [['DEVIATIONS.md', buildDeviations()], ['REFERENCES.md', buildReferences()]]
  let stale = 0
  for (const [name, text] of outputs) {
    const path = join(ROOT, name)
    if (check) {
      if (!existsSync(path) || readFileSync(path, 'utf8') !== text) { stale++; console.error(`${name} is stale — run npm run docs`) }
    } else {
      writeFileSync(path, text)
      console.log(`wrote ${name} (${text.split('\n').length} lines)`)
    }
  }
  if (check && stale) process.exit(1)
}
