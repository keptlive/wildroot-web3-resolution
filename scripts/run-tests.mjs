#!/usr/bin/env node
// Runs every test suite in this repository in one `node --test` process:
// the Handshake suite at the top level and one suite per chapter under
// namespaces/<ns>/tests. Walks the tree instead of hard-coding directories,
// and REFUSES to pass on an empty match — a glob that matches nothing hands
// `node --test` no files, which exits 0 and looks exactly like a green run.

import { readdirSync, statSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

function collect (dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry.startsWith('.') || entry === 'fixtures') continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) collect(full, out)
    else if (entry.endsWith('.test.js')) out.push(full)
  }
  return out
}

const files = [
  ...collect(join(ROOT, 'tests')),
  ...collect(join(ROOT, 'namespaces'))
].sort()

if (!files.length) {
  console.error('REFUSING TO PASS: no test files found.')
  process.exit(1)
}

const suites = new Map()
for (const f of files) {
  const suite = relative(ROOT, f).split('/')[0] === 'tests' ? 'handshake (top level)' : relative(ROOT, f).split('/')[1]
  suites.set(suite, (suites.get(suite) || 0) + 1)
}
console.error(`${files.length} test files in ${suites.size} suites: ` +
  [...suites].map(([s, n]) => `${s} (${n})`).join(', '))

const run = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit', cwd: ROOT })
process.exit(run.status === null ? 1 : run.status)
