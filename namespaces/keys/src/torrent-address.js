/*
 * bittorrent:// — turning an address into a target, with no engine.
 *
 * EXTRACTION NOTE. In the Wildroot tree these functions live inside
 * `src/protocols/torrent-protocol.js`, which is the scheme's dispatcher AND
 * the rqbit stream proxy: it spawns a supervised BitTorrent engine, proxies
 * `Range` requests to it, and renders an HTML listing. None of that is
 * resolution, and the engine is a native binary, so this module carries only
 * the address half of that file — the function bodies are copied verbatim,
 * only the module boundary and the exports are new. `mime` (content typing)
 * and `torrent-player.js` (which files the player can show) are deliberately
 * left behind: neither takes part in deciding WHICH object an address names.
 *
 * Two things happen here, and only these two:
 *
 *   1. KEY-TYPE DISPATCH. `bittorrent://<key>/…` is split on the SHAPE of the
 *      key, using the same `INFO_HASH_MATCH` the magnet parser exports — one
 *      definition of "infohash" for the whole scheme. 40 hex is a BEP-3 v1
 *      infohash and belongs to the streaming engine; anything else (the 64-hex
 *      BEP-46 public key above all) belongs to the mutable-torrent handler.
 *      This is scheme-INTERNAL dispatch on the key type, not a failure
 *      fallback: a 40-hex address the engine cannot serve is never retried
 *      through the other branch.
 *
 *   2. PATH -> FILE. A torrent is a set of files, so the URL path has to name
 *      one. The rule is a web server's rule, stated in `resolveFileIndex`.
 *      `null` means "this address names no single file", and the caller must
 *      say so rather than guess.
 *
 * Nothing here verifies anything. The infohash is what makes the BYTES
 * self-authenticating (BEP-3 §"piece verification", BEP-52 for v2), and that
 * check happens inside the engine, on arrival — not in this module and not at
 * resolution time.
 */

import { INFO_HASH_MATCH } from './magnet-protocol.js'

/**
 * The v1 infohash a `bittorrent://` host names, or null when the host is not
 * one — in which case the address belongs to the mutable/petname branch.
 *
 * Copied from torrent-protocol.js's `torrentHandler`, which does exactly this
 * and then dispatches on the result. The host is lowercased first because
 * Chromium canonicalises the host of a standard scheme to lower case anyway;
 * doing it here means the same answer under `node --test`.
 *
 * @param {string} host the URL's hostname
 * @returns {string|null} the 40-hex infohash, lowercased
 */
export function infohashOf (host) {
  const key = String(host || '').toLowerCase()
  return (INFO_HASH_MATCH.exec(`urn:btih:${key}`) || [])[1] || null
}

/** rqbit details -> [{ idx, path, length }], path joined the way rqbit names it. */
export function fileList (details) {
  return ((details && details.files) || []).map((f, idx) => ({
    idx,
    path: Array.isArray(f.components) ? f.components.join('/') : String(f.name || ''),
    length: f.length || 0
  }))
}

// A torrent can BE a website, and that is a first-class use of this scheme —
// bt-fetch never got there (`// TODO: Resolve index files`), so a site
// published as a torrent showed its own source listing instead of rendering.
// These are the index names a web server would try, in order.
const INDEX_NAMES = ['index.html', 'index.htm']

/**
 * URL path -> file index. Single-file torrents stream their one file whatever
 * the path (the magnet redirect lands on "/"). Multi-file behaves like a web
 * server: a DIRECTORY (the root, or any path ending in "/") resolves to its
 * index.html, so a torrent-hosted site renders; an exact path wins next; a
 * directory named without its trailing slash resolves to that directory's
 * index; an unambiguous basename is the last guess. null means "no file" and
 * the caller shows the honest listing.
 * @returns {number|null}
 */
export function resolveFileIndex (files, wanted) {
  if (files.length === 1) return 0
  const byPath = new Map(files.map((f) => [f.path, f.idx]))

  if (!wanted || wanted.endsWith('/')) {
    return indexUnder(byPath, wanted)
  }

  const exact = byPath.get(wanted)
  if (exact !== undefined) return exact

  // "/docs" when the torrent holds "docs/index.html".
  const asDir = indexUnder(byPath, wanted + '/')
  if (asDir !== null) return asDir

  const byName = files.filter((f) => f.path.split('/').pop() === wanted)
  if (byName.length === 1) return byName[0].idx
  return null
}

/** The index file directly inside `dir` ('' = torrent root), or null. */
function indexUnder (byPath, dir) {
  for (const name of INDEX_NAMES) {
    const hit = byPath.get(dir + name)
    if (hit !== undefined) return hit
  }
  return null
}

/**
 * Torrents almost always wrap their payload in one top-level folder named
 * after the torrent, so a published site's index is at "Site/index.html", not
 * at the root. Serving that file AT the root would break every relative link
 * in it ("style.css" would resolve to /style.css, which does not exist), so
 * the honest move is the one a web server makes: redirect to the directory.
 * @returns {string|null} the single top-level directory holding an index
 */
export function soleIndexDirectory (files) {
  const tops = new Set()
  for (const f of files) {
    const slash = f.path.indexOf('/')
    if (slash <= 0) return null // a loose file at the root: not a wrapped site
    tops.add(f.path.slice(0, slash))
  }
  if (tops.size !== 1) return null
  const dir = [...tops][0]
  const byPath = new Map(files.map((f) => [f.path, f.idx]))
  return indexUnder(byPath, dir + '/') === null ? null : dir
}
