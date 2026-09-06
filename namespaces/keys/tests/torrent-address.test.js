// `bittorrent://<key>/<path>` — which object the address names.
//
// Adapted from tests/hns/torrent-proxy.test.js in the Wildroot tree. That
// suite drives the whole handler against a real TorrentEngine with an injected
// spawner and a scripted rqbit HTTP API; here the engine is gone entirely
// (src/torrent-address.js is engine-free by construction), so what remains is
// the two decisions that ARE resolution: which branch of the scheme owns this
// key, and which file inside the torrent this path names. The stream proxying,
// the Range pass-through, the content typing and the HTML listing stayed
// behind with the engine.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  infohashOf, fileList, resolveFileIndex, soleIndexDirectory
} from '../src/torrent-address.js'

const INFOHASH = 'c0ffee0123456789abcdef0123456789abcdef01'
const PUBKEY = 'd'.repeat(64)

// --- key-type dispatch ------------------------------------------------------

test('40 hex is an infohash; everything else belongs to the other branch', () => {
  assert.equal(infohashOf(INFOHASH), INFOHASH)
  assert.equal(infohashOf(INFOHASH.toUpperCase()), INFOHASH, 'normalised to lower case')
  assert.equal(infohashOf(PUBKEY), null, 'the 64-hex BEP-46 key is not an infohash')
  assert.equal(infohashOf('a'.repeat(39)), null)
  assert.equal(infohashOf('a'.repeat(41)), null)
  assert.equal(infohashOf('g'.repeat(40)), null, 'not hex')
  assert.equal(infohashOf('mysite'), null, 'a bt-fetch petname')
  assert.equal(infohashOf(''), null)
  assert.equal(infohashOf(null), null)
})

test('a v2 (BEP-52) infohash is indistinguishable from a BEP-46 public key', () => {
  // A v2 infohash is SHA-256 — 32 bytes, 64 hex characters — which is exactly
  // the shape of an ed25519 public key. In the URL form there is no URN to
  // tell them apart, so a v2 address is read as a mutable key and handed to
  // the wrong engine. Stated, not resolved: DEVIATIONS.md KY-3.
  const v2 = 'a'.repeat(64)
  assert.equal(infohashOf(v2), null)
})

// --- path -> file -----------------------------------------------------------

const one = fileList({ files: [{ name: 'bunny.mp4', length: 5000 }] })
const multi = fileList({
  files: [
    { name: 'readme.txt', components: ['readme.txt'], length: 10 },
    { name: 'movie.mp4', components: ['dir', 'movie.mp4'], length: 5000 }
  ]
})
const site = fileList({
  files: [
    { components: ['index.html'], length: 300 },
    { components: ['style.css'], length: 40 },
    { components: ['docs', 'index.html'], length: 120 }
  ]
})
const wrapped = fileList({
  files: [
    { components: ['My Site', 'index.html'], length: 300 },
    { components: ['My Site', 'style.css'], length: 40 }
  ]
})

test('fileList joins path components the way the engine names them', () => {
  assert.deepEqual(multi.map((f) => f.path), ['readme.txt', 'dir/movie.mp4'])
  assert.deepEqual(one.map((f) => f.path), ['bunny.mp4'])
  assert.deepEqual(fileList(null), [])
  assert.deepEqual(fileList({}), [])
})

test('a single-file torrent streams its one file whatever the path', () => {
  assert.equal(resolveFileIndex(one, ''), 0)
  assert.equal(resolveFileIndex(one, 'anything/at/all'), 0)
})

test('multi-file: exact path, then directory index, then unambiguous basename', () => {
  assert.equal(resolveFileIndex(multi, 'dir/movie.mp4'), 1, 'exact')
  assert.equal(resolveFileIndex(multi, 'readme.txt'), 0, 'exact at the root')
  assert.equal(resolveFileIndex(site, ''), 0, 'the root is index.html')
  assert.equal(resolveFileIndex(site, 'docs/'), 2, 'a directory is its index')
  assert.equal(resolveFileIndex(site, 'docs'), 2, 'without the trailing slash too')
  assert.equal(resolveFileIndex(multi, 'movie.mp4'), 1, 'unambiguous basename')
})

test('no match is null — the caller must say so, never guess', () => {
  assert.equal(resolveFileIndex(multi, ''), null, 'no index.html, so no root file')
  assert.equal(resolveFileIndex(multi, 'nope.bin'), null)
  const ambiguous = fileList({
    files: [{ components: ['a', 'x.txt'] }, { components: ['b', 'x.txt'] }]
  })
  assert.equal(resolveFileIndex(ambiguous, 'x.txt'), null, 'two candidates is not a match')
})

test('a site wrapped in one top folder names that folder, so the caller can redirect', () => {
  assert.equal(soleIndexDirectory(wrapped), 'My Site')
  assert.equal(soleIndexDirectory(site), null, 'a loose file at the root is not a wrapped site')
  assert.equal(soleIndexDirectory(multi), null)
  const twoTops = fileList({
    files: [{ components: ['a', 'index.html'] }, { components: ['b', 'index.html'] }]
  })
  assert.equal(soleIndexDirectory(twoTops), null, 'two top folders is not one site')
  const noIndex = fileList({ files: [{ components: ['Folder', 'movie.mp4'] }] })
  assert.equal(soleIndexDirectory(noIndex), null, 'a folder with no index is not a site')
})
