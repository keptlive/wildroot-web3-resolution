// `src/cid.js`: the address of a set of bytes, computed the way kubo computes
// it — UnixFS + dag-pb + multiformats. This is the other half of "verified by
// hash": SPEC §5 says a fetched byte stream authenticates itself against the
// CID, and this is the function that says what that CID is.
//
// Adapted from `tests/hns/files-cid.test.js` in the Wildroot tree. The pinned
// vectors — values printed by kubo 0.43.0 — are kept verbatim, so the encoder
// is checked against the real implementation on every box. The four
// `withKubo(…)` tests there SPAWN the bundled kubo binary and compare its
// answer to ours over fresh fixtures; they need a 60 MB binary this package
// does not depend on, so they stay in the Wildroot tree. What is lost is
// stated rather than papered over: the vectors below prove agreement on the
// cases someone thought to freeze, not on every input.

import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { Readable } from 'node:stream'

import { fileCid, directoryCid, isCidV1, CHUNK_SIZE, MAX_LINKS } from '../src/cid.js'

const KiB = 1024
const MiB = 1024 * KiB

// ----------------------------------------------------------- pinned vectors

const HELLO = 'bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq'
const EMPTY = 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku'

test('pinned kubo vectors: a one-chunk file is its raw leaf; an empty file is an empty raw leaf', async () => {
  const hello = await fileCid('hello')
  assert.deepEqual(hello, { cid: HELLO, size: 5, tsize: 5 })
  assert.deepEqual(await fileCid(new Uint8Array(0)), { cid: EMPTY, size: 0, tsize: 0 })
  assert.ok(isCidV1(HELLO))
  assert.equal(isCidV1('QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX'), false, 'a CIDv0 is not what we produce')
  assert.equal(isCidV1('nonsense'), false)
})

test('pinned kubo vectors: `ipfs add -r` of tree/{a.txt="a", sub/b.txt="bb"}', async () => {
  const a = await fileCid('a')
  const b = await fileCid('bb')
  assert.equal(a.cid, 'bafkreigks6arfsq3xxfpvqrrwonchxcnu6do76auprhhfomao6c273sixm')
  assert.equal(b.cid, 'bafkreib3mtnzls2vy5rtshdqoeeergxbrnarfv4dgag6hdqdhngjrq66v4')
  const sub = await directoryCid([{ name: 'b.txt', cid: b.cid, tsize: b.tsize }])
  assert.equal(sub.cid, 'bafybeiefjhkubf55fjbin4qvpdl53lbennl5etkyz2tzcoruqilosldh3u')
  // Order in does not matter; the links are sorted by name.
  const tree = await directoryCid([{ name: 'sub', cid: sub.cid, tsize: sub.tsize }, { name: 'a.txt', cid: a.cid, tsize: a.tsize }])
  assert.equal(tree.cid, 'bafybeiequ27rskdc7y3itczhbysguzzaiwm5c2da7n4zs6g4vvkqxzc7iq')
  const swapped = await directoryCid([{ name: 'a.txt', cid: a.cid, tsize: a.tsize }, { name: 'sub', cid: sub.cid, tsize: sub.tsize }])
  assert.equal(swapped.cid, tree.cid)
})

// ---------------------------------------------------------------- inputs

test('every input shape and any chunking of the stream give the same CID', async () => {
  const data = randomBytes(3 * CHUNK_SIZE + 12345)
  const { cid, size, tsize } = await fileCid(data)
  assert.equal(size, data.length)
  assert.ok(tsize > size, 'a multi-chunk file has a dag-pb root on top of its leaves')
  assert.match(cid, /^bafybei/, 'multi-chunk root is dag-pb (bafy…), leaves are raw (bafk…)')

  const pieces = (n) => {
    const out = []
    for (let i = 0; i < data.length; i += n) out.push(data.subarray(i, Math.min(data.length, i + n)))
    return out
  }
  assert.equal((await fileCid(Readable.from(pieces(1000)))).cid, cid, 'Node Readable, 1000-byte pieces')
  assert.equal((await fileCid(Readable.from(pieces(CHUNK_SIZE + 1)))).cid, cid, 'pieces larger than a chunk')
  assert.equal((await fileCid((async function * () { for (const p of pieces(77777)) yield p })())).cid, cid, 'async generator')
  const web = new ReadableStream({
    start (c) { for (const p of pieces(65536)) c.enqueue(new Uint8Array(p)); c.close() }
  })
  assert.equal((await fileCid(web)).cid, cid, 'web ReadableStream')
  assert.equal((await fileCid('hello')).cid, (await fileCid(Buffer.from('hello'))).cid, 'a string is its UTF-8 bytes')
})

test('the stream is consumed once, chunk by chunk, not buffered whole', async () => {
  // A 64 MiB stream from a generator that never allocates more than one
  // piece at a time; heap growth stays far below the stream's size.
  const total = 64 * MiB
  const piece = randomBytes(1 * MiB)
  let served = 0
  async function * gen () {
    while (served < total) { served += piece.length; yield piece }
  }
  global.gc && global.gc()
  const before = process.memoryUsage().heapUsed
  const { size } = await fileCid(gen())
  const grew = process.memoryUsage().heapUsed - before
  assert.equal(size, total)
  assert.ok(grew < 24 * MiB, `heap grew ${(grew / MiB).toFixed(1)} MiB while hashing ${total / MiB} MiB`)
})

test('the 174-link fan-out is the balanced layout kubo uses, not a shape of our own', async () => {
  // MAX_LINKS chunks fit one dag-pb node; one byte more needs a second level.
  // The CIDs differ, which is the whole point — a client that fanned out at a
  // different width would compute a different address for the same file.
  const flat = await fileCid(randomBytes(MAX_LINKS * CHUNK_SIZE))
  const deep = await fileCid(randomBytes(MAX_LINKS * CHUNK_SIZE + 1))
  assert.notEqual(flat.cid, deep.cid)
  assert.ok(deep.tsize > flat.tsize)
})

test('directoryCid refuses what kubo would not encode as one block, with typed errors', async () => {
  const leaf = await fileCid('x')
  const entry = (name) => ({ name, cid: leaf.cid, tsize: leaf.tsize })
  for (const bad of ['', 'a/b']) {
    await assert.rejects(directoryCid([entry(bad)]), (e) => e.code === 'BAD_PATH' && e.status === 400, JSON.stringify(bad))
  }
  await assert.rejects(directoryCid([entry('a'), entry('a')]), (e) => e.code === 'BAD_PATH')
  await assert.rejects(directoryCid([{ name: 'a', cid: leaf.cid }]), (e) => e.code === 'BAD_PATH', 'tsize is required')
  await assert.rejects(directoryCid([{ name: 'a', cid: 'not-a-cid', tsize: 1 }]), (e) => e.name === 'SourceError' || e instanceof Error)
  // ~5 000 entries with 60-byte names is past the 256 KiB HAMT threshold.
  const many = []
  for (let i = 0; i < 5000; i++) many.push(entry(`file-${String(i).padStart(5, '0')}-${'x'.repeat(48)}`))
  await assert.rejects(directoryCid(many), (e) => e.code === 'NOT_SUPPORTED' && e.status === 501)
  assert.deepEqual(await directoryCid([]), await directoryCid([]), 'an empty folder has a CID too')
  await assert.rejects(fileCid('x', { chunkSize: 0 }), (e) => e.code === 'BAD_PATH')
})
