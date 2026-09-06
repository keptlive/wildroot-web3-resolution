// A human's string -> one canonical magnet, or an honest refusal.
//
// Adapted from tests/hns/torrent-manager.test.js in the Wildroot tree: the
// three parsing/validation tests, unchanged. The rest of that suite drives the
// torrents page's view-model against a fake engine and is not resolution.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  normalizeAddInput, validateTorrentFile, MAX_TORRENT_FILE_BYTES
} from '../src/torrent-input.js'

const HASH = 'aa'.repeat(20)

test('add input normalizes: magnet passes, bare hash and bittorrent:// become magnets', () => {
  const magnet = `magnet:?xt=urn:btih:${HASH}&dn=x`
  assert.equal(normalizeAddInput(magnet), magnet)
  assert.equal(normalizeAddInput(HASH.toUpperCase()), `magnet:?xt=urn:btih:${HASH}`)
  assert.equal(normalizeAddInput(`  ${HASH}  `), `magnet:?xt=urn:btih:${HASH}`)
  assert.equal(normalizeAddInput(`bittorrent://${HASH}/path/file.mp4`), `magnet:?xt=urn:btih:${HASH}`)
  assert.equal(normalizeAddInput(`bt://${HASH}`), `magnet:?xt=urn:btih:${HASH}`)
})

test('mutable (btpk) forms are refused by name, garbage is refused honestly', () => {
  const pubkey = 'cd'.repeat(32)
  assert.throws(() => normalizeAddInput(pubkey), /mutable/i)
  assert.throws(() => normalizeAddInput(`magnet:?xs=urn:btpk:${pubkey}`), /mutable/i)
  assert.throws(() => normalizeAddInput(`bittorrent://${pubkey}`), /infohash/i)
  assert.throws(() => normalizeAddInput(''), /magnet link or infohash/i)
  assert.throws(() => normalizeAddInput('not a link'), /magnet link or infohash/i)
  assert.throws(() => normalizeAddInput('https://example.com/file.torrent'), /magnet link or infohash/i)
  assert.throws(() => normalizeAddInput('magnet:?dn=nothing'), /no v1 infohash/i)
  assert.throws(() => normalizeAddInput(HASH.slice(0, 39)), /magnet link or infohash/i)
})

test('.torrent bytes are validated: bencode dict, non-empty, capped', () => {
  const good = new TextEncoder().encode('d8:announce0:e')
  assert.equal(validateTorrentFile(good), good)
  assert.throws(() => validateTorrentFile(new Uint8Array(0)), /empty/i)
  assert.throws(() => validateTorrentFile('d8:announce'), /empty or unreadable/i)
  assert.throws(() => validateTorrentFile(new TextEncoder().encode('<html>')), /not a \.torrent/i)
  assert.throws(() => validateTorrentFile(new Uint8Array(MAX_TORRENT_FILE_BYTES + 1).fill(0x64)), /too large/i)
})

test('the .torrent check is a SHAPE check and claims nothing more', () => {
  // One byte is the whole test: any bencoded dictionary passes, including one
  // that is not metainfo at all. Nothing here verifies that the file's `info`
  // dictionary hashes to any particular infohash — the engine does that when
  // it adds the torrent. DEVIATIONS.md KY-6.
  const notMetainfo = new TextEncoder().encode('d5:hello5:worlde')
  assert.equal(validateTorrentFile(notMetainfo), notMetainfo)
})
