import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  createResolutionTimers, percentile, formatReport, METHODS
} from '../src/resolution-timing.js'

// Wildroot resolves a name several ways — SPV chain proof, plain DoH, oblivious
// DoH, then DANE on top, then IPFS/Arweave for content — and none of it was
// measured. "Handshake feels slow" could not be attributed to a step, and the
// fair question ("what does the trustless path actually cost?") had no answer.
//
// The clock is injected so these are deterministic.

function fakeClock (...ticks) {
  let i = 0
  return () => ticks[Math.min(i++, ticks.length - 1)]
}

test('a typo cannot silently create a category nobody reads', async () => {
  const t = createResolutionTimers({ now: fakeClock(0, 1) })
  assert.throws(() => t.record('spvv', 5), /unknown method/)
  // And it fails BEFORE running the work, not after.
  let ran = false
  await assert.rejects(() => t.time('dhoh', async () => { ran = true }), /unknown method/)
  assert.equal(ran, false, 'the work must not run under an unknown method')
})

test('a method that FAILS slowly is still measured', async () => {
  // The most useful sample here — a DoH server black-holing, an SPV node still
  // syncing — is exactly what a success-only timer hides.
  const t = createResolutionTimers({ now: fakeClock(0, 3000) })
  await assert.rejects(() => t.time('doh', async () => { throw new Error('timeout') }))
  const s = t.stats('doh')
  assert.equal(s.count, 1)
  assert.equal(s.failed, 1)
  assert.equal(s.ok, 0)
  assert.equal(s.p50, 3000)
})

test('time() returns the value and records the duration', async () => {
  const t = createResolutionTimers({ now: fakeClock(0, 42) })
  assert.equal(await t.time('spv', async () => 'answer'), 'answer')
  assert.equal(t.stats('spv').p50, 42)
})

test('percentiles are nearest-rank, and pinned rather than assumed', () => {
  const sorted = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
  assert.equal(percentile(sorted, 50), 50)
  assert.equal(percentile(sorted, 95), 100)
  assert.equal(percentile([7], 50), 7)
  assert.equal(percentile([], 50), 0)
})

test('the report is ordered slowest-median first', () => {
  const t = createResolutionTimers({ now: fakeClock(0, 5, 5, 500, 500, 60) })
  t.record('spv', 5); t.record('doh', 500); t.record('dane', 60)
  const rows = t.report()
  assert.deepEqual(rows.map((r) => r.method), ['doh', 'dane', 'spv'])
})

test('samples are capped so a long session cannot grow without bound', () => {
  const t = createResolutionTimers({ cap: 3 })
  for (const ms of [1, 2, 3, 4, 5]) t.record('ipfs', ms)
  const s = t.stats('ipfs')
  assert.equal(s.count, 3, 'only the most recent samples are kept')
  assert.equal(s.min, 3)
  assert.equal(s.max, 5)
})

test('an unused method is absent, not reported as zero', () => {
  const t = createResolutionTimers()
  assert.equal(t.stats('arweave'), null)
  assert.equal(t.report().length, 0)
  assert.match(t.format(), /nothing measured yet/)
})

test('every METHOD name is usable, and the list is frozen', () => {
  const t = createResolutionTimers()
  for (const m of METHODS) t.record(m, 1)
  assert.equal(t.report().length, METHODS.length)
  assert.throws(() => { METHODS.push('sneaky') })
})

test('the published table shows n, p50, p95, max and failures', () => {
  const out = formatReport([
    { method: 'doh', count: 10, ok: 8, failed: 2, min: 5, max: 900, p50: 120, p95: 800 }
  ])
  assert.match(out, /doh/)
  assert.match(out, /n=\s*10/)
  assert.match(out, /p50\s+120ms/)
  assert.match(out, /p95\s+800ms/)
  assert.match(out, /max\s+900ms/)
  assert.match(out, /\(2 failed\)/)
})

test('no sample carries the name that was looked up', () => {
  // Privacy floor: a browser shipping a timing log of everywhere you went would
  // be a tracking product. Only method and duration are retained.
  const t = createResolutionTimers({ now: fakeClock(0, 1) })
  t.record('spv', 12)
  const serialized = JSON.stringify(t.report())
  assert.equal(serialized.includes('matt.w3'), false)
  assert.deepEqual(Object.keys(t.report()[0]).sort(),
    ['count', 'failed', 'max', 'method', 'min', 'ok', 'p50', 'p95'])
})
