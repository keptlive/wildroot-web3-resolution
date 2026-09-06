/*
 * User-typed BitTorrent input -> one canonical magnet, or an honest refusal.
 *
 * EXTRACTION NOTE. These functions are copied verbatim from
 * `src/hns/torrent-manager.js` in the Wildroot tree, which is otherwise the
 * view-model for the browser's torrents page (engine polling, card shapes,
 * seek-bar ranges). Only the parsing and validation are resolution, so only
 * they are here; the class around them is left behind. Nothing was rewritten.
 *
 * WHAT THIS IS FOR. Everything else in this namespace is handed a URL by
 * Chromium. This is the one place a HUMAN's string arrives: a pasted magnet, a
 * bare infohash, a `bittorrent://` address, or a dropped `.torrent` file. The
 * rule is that ambiguity is refused BY NAME rather than guessed — a 64-hex
 * mutable key is not silently handed to an engine that cannot serve it, and a
 * magnet with no v1 infohash is not silently dropped.
 */

import { INFO_HASH_MATCH, PUBLIC_KEY_MATCH } from './magnet-protocol.js'

// A pasted .torrent is bencoded and starts with 'd' (0x64). The cap is
// generous — real metainfo for even huge content is well under a megabyte.
export const MAX_TORRENT_FILE_BYTES = 10 * 1024 * 1024

function magnetFor (infohash, name) {
  const dn = name && name !== infohash ? `&dn=${encodeURIComponent(name)}` : ''
  return `magnet:?xt=urn:btih:${infohash}${dn}`
}

/**
 * User input -> the magnet link the engine gets, or a thrown honest refusal.
 * Accepts a magnet link, a bare 40-hex infohash, or a bittorrent://<infohash>
 * URL. A btpk (BEP-46 mutable) form is refused BY NAME — those live on the
 * bt-fetch branch and are browsed, not managed here; silently accepting one
 * would hand it to an engine that cannot serve it (the L2 shape again).
 * @param {unknown} input
 * @returns {string} a normalized magnet link
 */
export function normalizeAddInput (input) {
  const text = String(input || '').trim()
  if (!text) throw new Error('Paste a magnet link or infohash.')
  if (/^[a-f0-9]{40}$/i.test(text)) return magnetFor(text.toLowerCase(), null)
  if (/^[a-f0-9]{64}$/i.test(text)) {
    throw new Error('That is a mutable-torrent key (BEP-46). Open it as bittorrent://' + text.toLowerCase() + ' instead — mutable torrents are browsed, not managed here.')
  }
  let url
  try { url = new URL(text) } catch {
    throw new Error('Not a magnet link or infohash.')
  }
  if (url.protocol === 'magnet:') {
    const xt = url.searchParams.get('xt') || ''
    if (INFO_HASH_MATCH.test(xt)) return text
    if (PUBLIC_KEY_MATCH.test(url.searchParams.get('xs') || '')) {
      throw new Error('That magnet names a mutable torrent (BEP-46) — open it from the address bar instead; mutable torrents are browsed, not managed here.')
    }
    throw new Error('That magnet link carries no v1 infohash (urn:btih).')
  }
  if (url.protocol === 'bittorrent:' || url.protocol === 'bt:') {
    const key = url.hostname.toLowerCase()
    if (/^[a-f0-9]{40}$/.test(key)) return magnetFor(key, null)
    throw new Error('Only bittorrent:// infohash addresses can be added here.')
  }
  throw new Error('Not a magnet link or infohash.')
}

/**
 * A dropped/pasted .torrent file's bytes, validated. Returns a Buffer-free
 * Uint8Array ready to POST as the add body.
 * @param {unknown} bytes
 */
export function validateTorrentFile (bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new Error('That file is empty or unreadable.')
  }
  if (bytes.length > MAX_TORRENT_FILE_BYTES) {
    throw new Error('That file is too large to be a .torrent.')
  }
  if (bytes[0] !== 0x64) { // bencode dictionaries start with 'd'
    throw new Error('That is not a .torrent file.')
  }
  return bytes
}
