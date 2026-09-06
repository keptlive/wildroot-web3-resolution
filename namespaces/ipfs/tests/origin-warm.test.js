// A `.pinthis` name warms the local node from our own gateway, once, bounded,
// checked — and nothing else does (src/hns/origin-warm.js).

import test from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import { mkdtemp, rm, readdir, readFile } from 'node:fs/promises'

import { makeOriginWarmer, originFor, MAX_WARM_BYTES } from '../src/origin-warm.js'

const CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
const OTHER = 'bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku'
const CAR = Buffer.from('a CAR, notionally')

function fakeFetch ({ status = 200, body = CAR, length = body.length, fail = false } = {}) {
  const calls = []
  const fn = async (url, opts) => {
    calls.push({ url, opts })
    if (fail) throw new Error('ENOTFOUND pinthis.cloud')
    const headers = new Map()
    if (length != null) headers.set('content-length', String(length))
    let sent = false
    const stream = new ReadableStream({
      pull (ctrl) { if (sent) return ctrl.close(); sent = true; ctrl.enqueue(new Uint8Array(body)) },
      cancel () { fn.cancelled = true }
    })
    return { ok: status >= 200 && status < 300, status, headers: { get: (k) => headers.get(k) || null }, body: stream }
  }
  fn.calls = calls
  return fn
}

function fakeNode ({ has = false, roots = [CID], fail = false } = {}) {
  const imports = []
  return {
    imports,
    has,
    async hasLocally () { return this.has },
    async importCar (file) {
      imports.push({ file, bytes: await readFile(file) })
      if (fail) throw new Error('dag/import failed: HTTP 500')
      this.has = true
      return roots
    }
  }
}

async function world ({ fetchImpl = fakeFetch(), node = fakeNode(), maxBytes } = {}) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'origin-warm-'))
  const log = []
  const warm = makeOriginWarmer({ node: async () => node, fetchImpl, log: (m) => log.push(m), tmpDir: dir, maxBytes })
  return { warm, node, fetchImpl, log, dir, close: () => rm(dir, { recursive: true, force: true }) }
}

test('only <label>.pinthis is ours — the apex, deeper names and every other TLD are not', () => {
  assert.equal(originFor('site.pinthis'), 'https://pinthis.cloud')
  assert.equal(originFor('Site.Pinthis.'), 'https://pinthis.cloud')
  assert.equal(originFor('pinthis'), null, 'the apex is the service itself')
  assert.equal(originFor('a.b.pinthis'), null)
  assert.equal(originFor('alice.w3'), null)
  assert.equal(originFor('pinthis.cloud'), null, 'an ICANN name never reaches this')
  assert.equal(originFor(''), null)
})

test('a name that is not ours costs nothing — no node, no fetch', async () => {
  const w = await world()
  try {
    assert.deepEqual(await w.warm('alice.w3', CID), { state: 'not-ours' })
    assert.equal(w.fetchImpl.calls.length, 0)
    assert.equal(w.node.imports.length, 0)
  } finally { await w.close() }
})

test('blocks already on the node are never fetched', async () => {
  const w = await world({ node: fakeNode({ has: true }) })
  try {
    assert.deepEqual(await w.warm('site.pinthis', CID), { state: 'present' })
    assert.equal(w.fetchImpl.calls.length, 0)
  } finally { await w.close() }
})

test('a missing archive is fetched from our gateway ONCE and imported; the scratch file is gone', async () => {
  const w = await world()
  try {
    const out = await w.warm('site.pinthis', CID)
    assert.deepEqual(out, { state: 'warmed', size: CAR.length })
    assert.equal(w.fetchImpl.calls.length, 1)
    assert.equal(w.fetchImpl.calls[0].url, `https://pinthis.cloud/ipfs/${CID}?format=car&dag-scope=all`)
    assert.equal(w.node.imports.length, 1)
    assert.equal(w.node.imports[0].bytes.equals(CAR), true)
    assert.deepEqual(await readdir(w.dir), [], 'the scratch CAR outlived the call')
    // Again: present, no second fetch.
    assert.deepEqual(await w.warm('site.pinthis', CID), { state: 'present' })
    assert.equal(w.fetchImpl.calls.length, 1)
    assert.ok(w.log.some((l) => /imported from https:\/\/pinthis\.cloud/.test(l)))
  } finally { await w.close() }
})

test('concurrent requests for one CID share one download', async () => {
  const w = await world()
  try {
    const [a, b, c] = await Promise.all([w.warm('site.pinthis', CID), w.warm('site.pinthis', CID), w.warm('site.pinthis', CID)])
    assert.equal(a.state, 'warmed'); assert.equal(b.state, 'warmed'); assert.equal(c.state, 'warmed')
    assert.equal(w.fetchImpl.calls.length, 1)
    assert.equal(w.node.imports.length, 1)
  } finally { await w.close() }
})

test('an archive over the cap, or of unknown size, is left to the block path', async () => {
  const big = await world({ fetchImpl: fakeFetch({ length: MAX_WARM_BYTES + 1 }) })
  try {
    assert.deepEqual(await big.warm('site.pinthis', CID), { state: 'too-large', size: MAX_WARM_BYTES + 1 })
    assert.equal(big.node.imports.length, 0)
    assert.equal(big.fetchImpl.cancelled, true, 'the body was cancelled, not drained')
  } finally { await big.close() }
  const unknown = await world({ fetchImpl: fakeFetch({ length: null }) })
  try {
    assert.equal((await unknown.warm('site.pinthis', CID)).state, 'too-large')
  } finally { await unknown.close() }
})

test('a CAR whose root is not the CID asked for is refused', async () => {
  const w = await world({ node: fakeNode({ roots: [OTHER] }) })
  try {
    const out = await w.warm('site.pinthis', CID)
    assert.equal(out.state, 'failed')
    assert.match(out.why, /root is/)
    assert.deepEqual(await readdir(w.dir), [])
  } finally { await w.close() }
})

test('a gateway that is down, or answers 404, is a state — never a throw', async () => {
  const down = await world({ fetchImpl: fakeFetch({ fail: true }) })
  try {
    const out = await down.warm('site.pinthis', CID)
    assert.equal(out.state, 'failed')
    assert.match(out.why, /ENOTFOUND/)
  } finally { await down.close() }
  const missing = await world({ fetchImpl: fakeFetch({ status: 404 }) })
  try {
    assert.deepEqual(await missing.warm('site.pinthis', CID), { state: 'failed', why: 'HTTP 404' })
  } finally { await missing.close() }
  const noNode = await world({ node: null })
  try {
    assert.deepEqual(await noNode.warm('site.pinthis', CID), { state: 'no-node' })
  } finally { await noNode.close() }
})

test('disabled: the warmer makes no request and reports so', async () => {
  let fetched = 0
  const warm = makeOriginWarmer({
    node: async () => ({ hasLocally: async () => false, importCar: async () => [] }),
    fetchImpl: async () => { fetched++; return { ok: true, body: null, headers: new Map() } },
    enabled: false
  })
  const out = await warm('alice.pinthis', 'bafyanything')
  assert.equal(out.state, 'disabled')
  assert.equal(fetched, 0, 'nothing was fetched from the origin')
})

test('a name that STATES its origin (car=) is warmed from that url, whatever the TLD; the .pinthis table is the fallback', async () => {
  const w = await world()
  try {
    const stated = 'https://indexer.example/share/abc?sig=1'
    const out = await w.warm('alice.w3', CID, { origin: stated })
    assert.equal(out.state, 'warmed')
    assert.equal(w.fetchImpl.calls[0].url, stated, 'fetched exactly the stated origin, not a gateway form')
    // Without a stated origin a .w3 name has nowhere to warm from…
    assert.deepEqual(await w.warm('bob.w3', 'bafyother'), { state: 'not-ours' })
  } finally { await w.close() }
  // …and a .pinthis name without one still uses the gateway form.
  const w2 = await world()
  try {
    await w2.warm('site.pinthis', CID)
    assert.match(w2.fetchImpl.calls[0].url, /^https:\/\/pinthis\.cloud\/ipfs\/.*\?format=car/)
  } finally { await w2.close() }
})

test('a seek on a large archive is answered from a 2 MiB slice at the seek point; the window and the next one follow in the background', async () => {
  const { gatewayBase, windowFor, sliceFor, WINDOW_BYTES, SLICE_BYTES } = await import('../src/origin-warm.js')
  assert.equal(gatewayBase(`https://pinthis.cloud/ipfs/${CID}`, CID), `https://pinthis.cloud/ipfs/${CID}`)
  assert.equal(gatewayBase(`https://pinthis.cloud/ipfs/${CID}/`, CID), `https://pinthis.cloud/ipfs/${CID}`)
  assert.equal(gatewayBase('https://indexer.example/share/abc', CID), null, 'a share link is not a gateway')
  assert.equal(gatewayBase(`https://pinthis.cloud/ipfs/${OTHER}`, CID), null, 'another archive is not this one')
  assert.deepEqual(windowFor('bytes=300000000-300999999'), { from: Math.floor(300000000 / WINDOW_BYTES) * WINDOW_BYTES, to: Math.floor(300000000 / WINDOW_BYTES) * WINDOW_BYTES + WINDOW_BYTES - 1 })
  assert.deepEqual(windowFor(null), { from: 0, to: WINDOW_BYTES - 1 })
  assert.deepEqual(sliceFor('bytes=300000000-'), { from: Math.floor(300000000 / SLICE_BYTES) * SLICE_BYTES, to: Math.floor(300000000 / SLICE_BYTES) * SLICE_BYTES + SLICE_BYTES - 1 })

  const w = await world()
  try {
    const at = (re) => w.fetchImpl.calls.filter((c) => re.test(c.url)).length
    // A ranged read of one file: ONE request for the slice at the seek point
    // before the answer (~0.3 s cold, not a whole window), imported, not "whole".
    const out = await w.warm('alice.w3', CID, { origin: `https://pinthis.cloud/ipfs/${CID}`, sub: '/videos/meeting.mp4', range: 'bytes=300000000-' })
    assert.equal(out.state, 'windowed')
    const s = sliceFor('bytes=300000000-')
    assert.equal(w.fetchImpl.calls[0].url, `https://pinthis.cloud/ipfs/${CID}/videos/meeting.mp4?format=car&dag-scope=entity&entity-bytes=${s.from}:${s.to}`)
    // That slice ends its window and sits in the window's last quarter, so the
    // NEXT window is read ahead in the background: its first slice, then its rest.
    await w.warm.idle()
    const win = windowFor('bytes=300000000-')
    assert.equal(s.to, win.to, 'this slice is the last of its window')
    assert.equal(at(new RegExp(`entity-bytes=${win.to + 1}:${win.to + SLICE_BYTES}$`)), 1, 'next window: its first slice')
    assert.equal(at(new RegExp(`entity-bytes=${win.to + 1 + SLICE_BYTES}:${win.to + WINDOW_BYTES}$`)), 1, 'next window: the rest')
    assert.equal(w.fetchImpl.calls.length, 3)
    // A slice already imported this session is answered from memory; a
    // different position is another download.
    const [again, ahead, other] = await Promise.all([
      w.warm('alice.w3', CID, { origin: `https://pinthis.cloud/ipfs/${CID}`, sub: 'videos/meeting.mp4', range: 'bytes=300000100-' }),
      w.warm('alice.w3', CID, { origin: `https://pinthis.cloud/ipfs/${CID}`, sub: 'videos/meeting.mp4', range: `bytes=${win.to + 5000000}-` }),
      w.warm('alice.w3', CID, { origin: `https://pinthis.cloud/ipfs/${CID}`, sub: 'videos/meeting.mp4', range: 'bytes=0-' })
    ])
    assert.deepEqual(again, { state: 'present' })
    assert.deepEqual(ahead, { state: 'present' }, 'inside the window that was read ahead')
    assert.equal(other.state, 'windowed')
    assert.equal(at(/entity-bytes=0:2097151$/), 1, 'the head slice')
    await w.warm.idle()
    assert.equal(at(new RegExp(`entity-bytes=${SLICE_BYTES}:${WINDOW_BYTES - 1}$`)), 1, 'then the rest of the head window, in the background')
    assert.equal(w.fetchImpl.calls.length, 5)
  } finally { await w.close() }
  // A plain read (no range) of a small archive still warms it whole.
  const w2 = await world({ node: fakeNode({ roots: [OTHER] }) })
  try {
    const whole = await w2.warm('alice.w3', OTHER, { origin: `https://pinthis.cloud/ipfs/${OTHER}` })
    assert.equal(whole.state, 'warmed')
    assert.equal(w2.fetchImpl.calls[0].url, `https://pinthis.cloud/ipfs/${OTHER}?format=car&dag-scope=all`)
  } finally { await w2.close() }
})

test('an archive too large to hold whole warms the head of the file being opened instead', async () => {
  const w = await world({ maxBytes: 4 })
  try {
    const out = await w.warm('alice.w3', CID, { origin: `https://pinthis.cloud/ipfs/${CID}`, sub: 'talk.mp4' })
    assert.equal(out.state, 'windowed')
    assert.equal(out.from, 0)
    assert.match(w.fetchImpl.calls[0].url, /dag-scope=all$/)
    assert.match(w.fetchImpl.calls[1].url, /\/talk\.mp4\?format=car&dag-scope=entity&entity-bytes=0:/)
  } finally { await w.close() }
})

test('a ranged read and the head-of-file warm of the same window share ONE download and one temp file; a repeated range is free', async () => {
  // 2.78.11: the two ran at once with different keys and the same temp path;
  // one unlinked it under the other's dag/import and the page waited 117 s.
  const big = 554_142_995
  const fetchImpl = fakeFetch({ length: big })
  const small = new Uint8Array(CAR)
  let calls = 0
  const real = fetchImpl
  const fn = async (url, opts) => {
    calls++
    fn.calls.push({ url, opts })
    if (/dag-scope=all/.test(url)) return real(url, opts)
    // the window CAR: small, and slow enough for the two asks to overlap
    await new Promise((resolve) => setTimeout(resolve, 30))
    const headers = new Map([['content-length', String(small.length)]])
    return { ok: true, status: 200, headers: { get: (k) => headers.get(k) || null }, body: new ReadableStream({ start (c) { c.enqueue(small); c.close() } }) }
  }
  fn.calls = []
  const w = await world({ fetchImpl: fn })
  try {
    const [head, ranged] = await Promise.all([
      w.warm('alice.pinthis', CID, { sub: '/talk.mp3' }),
      w.warm('alice.pinthis', CID, { sub: '/talk.mp3', range: 'bytes=0-99999' })
    ])
    assert.equal(head.state, 'windowed')
    assert.equal(ranged.state, 'windowed')
    await w.warm.idle()
    const urls = w.fetchImpl.calls.map((c) => c.url)
    assert.equal(urls.filter((u) => /dag-scope=all/.test(u)).length, 1, 'one whole-archive probe (too large)')
    assert.equal(urls.filter((u) => /entity-bytes=0:2097151$/.test(u)).length, 1, 'ONE head slice, shared by both asks')
    assert.equal(urls.filter((u) => /entity-bytes=2097152:16777215$/.test(u)).length, 1, 'the rest of the head window once, in the background')
    assert.equal(calls, 3)
    assert.equal(w.node.imports.length, 2, 'slice, then rest')
    assert.deepEqual(await readdir(w.dir), [], 'temp files gone')
    // The same bytes again: answered from memory, nothing fetched.
    assert.deepEqual(await w.warm('alice.pinthis', CID, { sub: '/talk.mp3', range: 'bytes=50000-' }), { state: 'present' })
    assert.deepEqual(await w.warm('alice.pinthis', CID, { sub: '/talk.mp3', range: 'bytes=9000000-' }), { state: 'present' }, 'covered by the rest of the window')
    assert.equal(calls, 3)
    // A different file's slice is its own download, into its own temp file.
    const other = await w.warm('alice.pinthis', CID, { sub: '/other.mp4', range: 'bytes=0-' })
    assert.equal(other.state, 'windowed')
    await w.warm.idle()
    assert.equal(calls, 5)
    assert.equal(new Set(w.node.imports.map((i) => i.file)).size, w.node.imports.length, 'never the same temp path')
  } finally { await w.close() }
})
