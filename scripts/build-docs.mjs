#!/usr/bin/env node
// Assembles the two consolidated documents from the chapters.
//
//   DEVIATIONS.md   every chapter's DEVIATIONS.md, in chapter order, headings
//                   demoted one level under a chapter heading, with a table of
//                   contents listing every deviation, uncertainty and open
//                   design item by id.
//   REFERENCES.md   an index of every identifier cited anywhere (one row per
//                   identifier, naming the chapters that use it), followed by
//                   each chapter's own tables — which carry what the standard
//                   is used FOR in that chapter, the part a flat list loses.
//
// The chapter files are the source; these two are generated. `npm run docs`
// regenerates them and the test in tests/docs-consolidated.test.js fails when
// they are stale, so the consolidated view cannot drift from the chapters.

import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
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
function body (text) {
  return text
    .split('\n')
    .filter((line, i, all) => !(i === 0 && line.startsWith('# ')))
    .map((line) => (/^#{1,5} /.test(line) ? '#' + line : line))
    .join('\n')
    .replace(/^\n+/, '')
    // Chapter files link to the consolidated files as ../../; here they are siblings.
    .replace(/\.\.\/\.\.\/(DEVIATIONS|REFERENCES|SPEC)\.md/g, '$1.md')
    .replace(/\.\.\/([a-z-]+)\/SPEC\.md/g, 'namespaces/$1/SPEC.md')
}

const anchor = (heading) => heading.toLowerCase().replace(/[`*_]/g, '').replace(/[^a-z0-9 -]/g, '').trim().replace(/\s+/g, '-')

export function buildDeviations () {
  const parts = []
  const toc = []
  for (const { dir, label } of CHAPTERS) {
    const file = `namespaces/${dir}/DEVIATIONS.md`
    if (!existsSync(join(ROOT, file))) continue
    const text = read(file)
    const ids = [...text.matchAll(/^### ([A-Z]{2}-(?:D|U)?\d+|[A-Z]{2}-\d+\.\d+|\d+\.\d+)\.? (.*)$/gm)]
      .map((m) => `  - ${m[1]} ${m[2].replace(/`/g, '')}`)
    toc.push(`- [${label}](#${anchor(label)}) — [chapter file](${file})`, ...ids)
    parts.push(`## ${label}\n\n_Source: [\`${file}\`](${file})._\n\n${body(text)}`)
  }
  // The cross-cutting divergence inventory closes the document.
  const divergence = read('DIVERGENCE.md')
  toc.push('- [Cross-cutting — Divergence inventory: where privacy and speed pull apart](#cross-cutting-divergence-inventory-where-privacy-and-speed-pull-apart) — [source file](DIVERGENCE.md)')
  parts.push(`## Cross-cutting — Divergence inventory: where privacy and speed pull apart\n\n_Source: [\`DIVERGENCE.md\`](DIVERGENCE.md)._\n\n${body(divergence)}`)
  return `# Deviations, uncertainties and open decisions

Every departure from a cited standard, every place we are not sure we are
right, and every design decision left open — per chapter, present tense, with
a recommendation for each open item. A deviation is numbered with its chapter's
prefix (\`HS-1\`, \`IC-3\`, …); an uncertainty is \`§2.n\` within its chapter;
an open design item is \`<prefix>-Dn\`. **This document is generated from the
chapter files by \`scripts/build-docs.mjs\`; edit those.**

Two rules hold throughout. A deviation is recorded whether or not we think it
is right — \`DELIBERATE\` says we would make the same choice again and why,
\`OPEN\` says we would not and what we recommend. And nothing here is history:
a departure that no longer exists is not described.

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
      if (!index.has(key)) index.set(key, { id: r.id, title: r.title, chapters: [] })
      const entry = index.get(key)
      if (!entry.chapters.includes(label)) entry.chapters.push(label)
    }
    parts.push(`## ${label}\n\n_Source: [\`${file}\`](${file})._\n\n${body(text)}`)
  }
  const sorted = [...index.values()].sort((a, b) => keyOf(a.id).localeCompare(keyOf(b.id), 'en', { numeric: true }))
  const indexRows = sorted.map((e) => `| ${e.id} | ${e.title} | ${e.chapters.map((c) => c.replace(/ — .*/, '')).join(', ')} |`)
  return `# References

Every standard, specification and document the implementation reads, with what
each is used for. **Generated from the chapter files by \`scripts/build-docs.mjs\`;
edit those.**

The index lists each identifier once, with the chapters that cite it. Each
chapter's own table follows, because *what a standard is used for* differs by
chapter — RFC 9110 is the tunnel's CONNECT in one chapter and a redirect rule in
another — and that column is the point of the file.

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
