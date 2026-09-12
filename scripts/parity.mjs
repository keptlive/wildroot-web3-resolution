#!/usr/bin/env node
// Every source module in this repository is a copy of a module in the Wildroot
// browser tree, byte-identical except for relative import paths (the browser
// keeps its modules in several directories; this repository flattens them).
// This script is the proof of that claim, and the tool that keeps it true.
//
//   node scripts/parity.mjs            check: every mapped module matches
//   node scripts/parity.mjs --sync     copy from the browser tree, rewriting imports
//   WILDROOT=/path/to/browser          where the browser tree is (default ../browser)
//
// The check REVERSES the rewrite: each relative import in the repository copy
// is mapped back to the specifier the browser file uses, and the result must
// equal the browser file byte for byte. Modules listed in FACTORED have no
// browser counterpart (they were lifted out of a larger browser module for
// this repository) and are exempt, and the README says so.

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const WILDROOT = resolve(process.env.WILDROOT || join(ROOT, '..', 'browser'))
const sync = process.argv.includes('--sync')

/** repository path -> browser path (both relative to their roots). */
export const MAP = {
  'src/contenthash.js': 'src/protocols/contenthash.js',
  'src/dane.js': 'src/hns/dane.js',
  'src/denial.js': 'src/hns/denial.js',
  'src/dns-query.js': 'src/hns/dns-query.js',
  'src/dnssec.js': 'src/hns/dnssec.js',
  'src/doh.js': 'src/hns/doh.js',
  'src/hip5-op.js': 'src/hns/hip5-op.js',
  'src/hns-host.js': 'src/hns/hns-host.js',
  'src/hns-url.cjs': 'src/hns/hns-url.cjs',
  'src/hsd-spv-launcher.cjs': 'src/hns/hsd-spv-launcher.cjs',
  'src/icann-tlds.cjs': 'src/ui/icann-tlds.cjs',
  'src/reserved-names.cjs': 'src/hns/reserved-names.cjs',
  'src/nsec.js': 'src/hns/nsec.js',
  'src/nsec3.js': 'src/hns/nsec3.js',
  'src/odoh-bridge.js': 'src/hns/odoh-bridge.js',
  'src/odoh.js': 'src/hns/odoh.js',
  'src/pointers.js': 'src/publish/pointers.js',
  'src/proc.js': 'src/hns/proc.js',
  'src/resolution-timing.js': 'src/hns/resolution-timing.js',
  'src/resolver.js': 'src/hns/resolver.js',
  'src/router.js': 'src/protocols/router.js',
  'src/safe-address.js': 'src/hns/safe-address.js',
  'src/safe-status.js': 'src/protocols/safe-status.js',
  'src/socks-dial.js': 'src/hns/socks-dial.js',
  'src/delivery-mode.js': 'src/hns/delivery-mode.js',
  'src/dane-connect.js': 'src/hns/dane-connect.js',
  'src/classify-host.cjs': 'src/hns/classify-host.cjs',
  'src/search-url.js': 'src/hns/search-url.js',
  'src/self-cert.js': 'src/hns/self-cert.js',
  'src/spv.js': 'src/hns/spv.js',
  'src/trust-path.js': 'src/hns/trust-path.js',
  'src/route-path.js': 'src/hns/route-path.js',
  'namespaces/arweave/src/ar.js': 'src/hns/ar.js',
  'namespaces/arweave/src/ar-merkle.js': 'src/hns/ar-merkle.js',
  'namespaces/arweave/src/ar-tx.js': 'src/hns/ar-tx.js',
  'namespaces/did/src/bsky.js': 'src/bsky/bsky.js',
  'namespaces/did/src/did-protocol.js': 'src/protocols/did-protocol.js',
  'namespaces/did/src/did-local.js': 'src/protocols/did-local.js',
  'namespaces/did/src/gate.js': 'src/protocols/gate.js',
  'namespaces/did/src/keys.js': 'src/identity/keys.js',
  'namespaces/did/src/nostr-event.js': 'src/identity/nostr-event.js',
  'namespaces/did/src/receipt.js': 'src/identity/receipt.js',
  'namespaces/did/src/record.js': 'src/identity/record.js',
  'namespaces/did/src/unimplemented-protocol.js': 'src/protocols/unimplemented-protocol.js',
  'namespaces/did/src/xrpc.js': 'src/bsky/xrpc.js',
  'namespaces/ens/src/ccip-read.js': 'src/protocols/ccip-read.js',
  'namespaces/ens/src/ens-protocol.js': 'src/protocols/ens-protocol.js',
  'namespaces/ens/src/fetch-to-handler.js': 'src/protocols/fetch-to-handler.js',
  'namespaces/ens/src/html.js': 'src/protocols/html.js',
  'namespaces/ens/src/web3-protocol.js': 'src/protocols/web3-protocol.js',
  'namespaces/icann/src/dns-policy.js': 'src/hns/dns-policy.js',
  'namespaces/ipfs/src/cid.js': 'src/files/cid.js',
  'namespaces/ipfs/src/origin-warm.js': 'src/hns/origin-warm.js',
  'namespaces/keys/src/fetch-to-handler.js': 'src/protocols/fetch-to-handler.js',
  'namespaces/keys/src/gate.js': 'src/protocols/gate.js',
  'namespaces/keys/src/gemini-protocol.js': 'src/protocols/gemini-protocol.js',
  'namespaces/keys/src/magnet-protocol.js': 'src/protocols/magnet-protocol.js',
  'namespaces/nostr/src/event.js': 'src/protocols/nostr/event.js',
  'namespaces/nostr/src/nip19.js': 'src/protocols/nostr/nip19.js',
  'namespaces/nostr/src/nostr-protocol.js': 'src/protocols/nostr-protocol.js',
  'namespaces/nostr/src/relay.js': 'src/protocols/nostr/relay.js',
  'namespaces/nostr/src/tor-websocket.js': 'src/protocols/nostr/tor-websocket.js',
  'namespaces/router/src/unimplemented-protocol.js': 'src/protocols/unimplemented-protocol.js',
  'namespaces/tor/src/anonymize.js': 'src/hns/anonymize.js',
  'namespaces/tor/src/free-port.js': 'src/hns/free-port.js',
  'namespaces/tor/src/html.js': 'src/protocols/html.js',
  'namespaces/tor/src/onion-protocol.js': 'src/protocols/onion-protocol.js',
  'namespaces/tor/src/subresource-guard.js': 'src/hns/subresource-guard.js',
  'namespaces/tor/src/tor-reload.js': 'src/hns/tor-reload.js',
  'namespaces/tor/src/tor.js': 'src/hns/tor.js',
  'namespaces/apps/src/ws-proxy.js': 'src/hns/ws-proxy.js',
  'namespaces/apps/src/ws-proxy-pac.js': 'src/hns/ws-proxy-pac.js',
  'namespaces/apps/src/free-port.js': 'src/hns/free-port.js'
}

/**
 * Modules with no browser counterpart: lifted out of a larger browser module.
 * `from` is the browser module they were lifted from, which is what a browser
 * import of that module maps to on sync and what a repository import of the
 * factored module maps back to on check.
 */
export const FACTORED = {
  'namespaces/icann/src/icann-tld-snapshot.js': { from: 'scripts/fetch-icann-tlds.mjs', note: 'the snapshot reader and drift check, without main()' },
  'namespaces/ipfs/src/byte-range.js': { from: 'src/hns/ipfs.js', note: 'the Range arithmetic' },
  'namespaces/ipfs/src/car-roots.js': { from: 'src/hns/ipfs.js', note: 'the CAR header reader' },
  'namespaces/ipfs/src/ipfs-url.js': { from: 'src/sia/restore.js', note: 'the ipfs:// root-CID grammar' },
  'namespaces/ipfs/src/source-error.js': { from: 'src/files/source.js', note: 'the SourceError class and status table' },
  'namespaces/keys/src/torrent-address.js': { from: 'src/protocols/torrent-protocol.js', note: 'the host-shape dispatch' },
  'namespaces/keys/src/torrent-input.js': { from: 'src/hns/torrent-manager.js', note: 'the dropped-file and magnet input rules' },
  'namespaces/nostr/src/nip05.js': { from: 'src/social.js', note: 'the NIP-05 lookup' }
}

// The import rewrite. A relative specifier names a file by basename; every
// basename in this repository's mapped set is unique per side, so the
// rewrite is a lookup, not a guess.
const IMPORT_RE = /((?:^|\n)\s*(?:import|export)[^'"\n]*?from\s*|(?:^|\n)\s*import\s*|require\(\s*)(['"])(\.\.?\/[^'"]+)\2/g

function relSpec (fromFile, toFile) {
  let r = relative(dirname(fromFile), toFile).split(sep).join('/')
  if (!r.startsWith('.')) r = './' + r
  return r
}

function rewrite (text, fromFile, resolveTarget) {
  return text.replace(IMPORT_RE, (whole, head, quote, spec) => {
    const target = resolveTarget(spec, head)
    if (!target) return whole
    return `${head}${quote}${target}${quote}`
  })
}

// browser -> repo: a browser relative import resolves to a browser file; find
// the repo copy of that file (by MAP), relative to the repo destination.
const byBrowser = new Map()
for (const [repo, browser] of Object.entries(MAP)) {
  if (!byBrowser.has(browser)) byBrowser.set(browser, [])
  byBrowser.get(browser).push(repo)
}
for (const [repo, { from }] of Object.entries(FACTORED)) {
  if (!byBrowser.has(from)) byBrowser.set(from, [])
  byBrowser.get(from).push(repo)
}

/** Does this repository module export every one of these names? */
function exportsAll (repoFile, names) {
  const text = readFileSync(join(ROOT, repoFile), 'utf8')
  return names.every((n) => new RegExp(`export\\s+(?:async\\s+)?(?:function|const|let|class)\\s+${n}\\b|export\\s*\\{[^}]*\\b${n}\\b`).test(text))
}

function toRepo (repoFile, browserFile) {
  return (spec, head) => {
    const target = relative(WILDROOT, resolve(WILDROOT, dirname(browserFile), spec)).split(sep).join('/')
    const copies = byBrowser.get(target)
    if (!copies) return null
    // Prefer a copy in the same namespace directory, else the top-level one;
    // between two factored modules from one browser file, the one that
    // exports what is being imported.
    const ns = repoFile.split('/').slice(0, 3).join('/')
    const braces = head.match(/\{([^}]*)\}/)
    const names = (braces ? braces[1] : '').split(',').map((n) => n.trim().split(/\s+as\s+/)[0]).filter(Boolean)
    const local = copies.filter((c) => c.startsWith(ns + '/'))
    const pick = local.find((c) => FACTORED[c] && names.length && exportsAll(c, names)) ||
      local.find((c) => !FACTORED[c]) || local[0] ||
      copies.find((c) => c.startsWith('src/')) || copies[0]
    return relSpec(join(ROOT, repoFile), join(ROOT, pick))
  }
}

function toBrowser (repoFile, browserFile) {
  return (spec) => {
    const target = relative(ROOT, resolve(ROOT, dirname(repoFile), spec)).split(sep).join('/')
    const browserTarget = MAP[target] || (FACTORED[target] && FACTORED[target].from)
    if (!browserTarget) return null
    return relSpec(join(WILDROOT, browserFile), join(WILDROOT, browserTarget))
  }
}

function walk (dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry.startsWith('.')) continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, out)
    else if (/\.(c?m?js)$/.test(entry)) out.push(relative(ROOT, full).split(sep).join('/'))
  }
  return out
}

if (!existsSync(WILDROOT)) {
  console.error(`parity: browser tree not found at ${WILDROOT} (set WILDROOT); nothing checked`)
  process.exit(sync ? 1 : 0)
}

let failures = 0
for (const [repo, browser] of Object.entries(MAP)) {
  const browserPath = join(WILDROOT, browser)
  const repoPath = join(ROOT, repo)
  if (!existsSync(browserPath)) { console.error(`MISSING in browser: ${browser}`); failures++; continue }
  const original = readFileSync(browserPath, 'utf8')
  if (sync) {
    writeFileSync(repoPath, rewrite(original, repo, toRepo(repo, browser)))
    continue
  }
  if (!existsSync(repoPath)) { console.error(`MISSING in repository: ${repo}`); failures++; continue }
  const reversed = rewrite(readFileSync(repoPath, 'utf8'), repo, toBrowser(repo, browser))
  if (reversed !== original) {
    failures++
    console.error(`DIFFERS: ${repo} vs ${browser}`)
  }
}

// Every module under src/ is either mapped or declared factored.
for (const file of walk(join(ROOT, 'src')).concat(walk(join(ROOT, 'namespaces')).filter((f) => f.includes('/src/')))) {
  if (!MAP[file] && !FACTORED[file]) {
    failures++
    console.error(`UNMAPPED: ${file} — add it to MAP or FACTORED in scripts/parity.mjs`)
  }
}

if (sync) {
  console.log(`synced ${Object.keys(MAP).length} modules from ${WILDROOT}`)
} else if (failures) {
  console.error(`parity: ${failures} problem(s)`)
  process.exit(1)
} else {
  console.log(`parity: ${Object.keys(MAP).length} modules byte-identical to the browser modulo import paths; ${Object.keys(FACTORED).length} factored modules declared`)
}
