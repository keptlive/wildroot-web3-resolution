/*
 * The DNSSEC verification clock is a security boundary, so it is enforced here
 * rather than trusted to reviewers.
 *
 * An RRSIG carries an inception/expiration window, and checking it is a gate:
 * a caller who controls "now" can make an EXPIRED — or revoked — signature
 * verify forever. src/hns/dnssec.js therefore splits the surface:
 *
 *   verifyRRSIG / validateChain      production. No clock argument at all.
 *                                    Always reads the real clock.
 *   verifyRRSIGAt / validateChainAt  test-only. Clock is the FIRST POSITIONAL
 *                                    argument, so an attacker-controlled
 *                                    object can never become the clock by
 *                                    being spread into an options bag.
 *
 * This file fails the build if production code ever reaches for the *At form,
 * and pins the fail-closed behaviour of the clock argument itself.
 *
 * Deterministic: it reads the source, it does not execute the browser.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { verifyRRSIGAt, validateChainAt } from '../src/dnssec.js'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SRC = path.join(HERE, '..', 'src')
const DNSSEC = path.join(SRC, 'dnssec.js')

function sourceFiles (dir) {
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'vendor' || entry.name.startsWith('.')) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...sourceFiles(full))
    else if (/\.(js|cjs|mjs)$/.test(entry.name)) out.push(full)
  }
  return out
}

test('no production code passes its own clock to DNSSEC verification', () => {
  const offenders = []
  for (const file of sourceFiles(SRC)) {
    if (file === DNSSEC) continue // the module defines them; that is the point
    const source = readFileSync(file, 'utf8')
    for (const name of ['verifyRRSIGAt', 'validateChainAt']) {
      if (source.includes(name)) {
        offenders.push(`${path.relative(SRC, file)}: calls ${name}`)
      }
    }
  }
  assert.deepEqual(offenders, [],
    'Production must use verifyRRSIG / validateChain, which read the real ' +
    'clock and cannot be overridden. Supplying "now" would let an expired or ' +
    'revoked RRSIG verify forever:\n  ' + offenders.join('\n  '))
})

test('the production entry points expose no clock parameter', () => {
  // A trailing optional `now` would be reachable by an over-long argument list
  // or, on validateChain, by a field spread in from untrusted data. Neither
  // function may take one.
  const source = readFileSync(DNSSEC, 'utf8')
  const verify = source.match(/export function verifyRRSIG \(([^)]*)\)/)
  assert.ok(verify, 'verifyRRSIG signature not found')
  assert.ok(!/\bnow\b/.test(verify[1]),
    `verifyRRSIG must take no clock argument, got: (${verify[1]})`)

  const chain = source.match(/export function validateChain \(([^)]*)\)/)
  assert.ok(chain, 'validateChain signature not found')
  assert.ok(!/\bnow\b/.test(chain[1]),
    `validateChain must take no clock argument, got: (${chain[1]})`)
})

test('the clock is positional-first, so an options object can never become it', () => {
  const source = readFileSync(DNSSEC, 'utf8')
  for (const name of ['verifyRRSIGAt', 'validateChainAt']) {
    const sig = source.match(new RegExp(`export function ${name} \\(([^,)]*)`))
    assert.ok(sig, `${name} signature not found`)
    assert.equal(sig[1].trim(), 'now',
      `${name} must take the clock as its FIRST positional argument, so it ` +
      'cannot arrive via { ...untrusted }')
  }
})

test('an out-of-range or non-integer clock FAILS CLOSED', () => {
  // NaN is the dangerous one: `NaN < x` and `NaN > x` are both false, so a
  // bare comparison would skip the window check entirely and accept anything.
  const rrsig = {
    algorithm: 13,
    inception: 1000,
    expiration: 2000,
    labels: 1,
    originalTtl: 3600,
    keyTag: 1,
    signer: 'example',
    signature: Buffer.alloc(64)
  }
  const args = [rrsig, 'example', [Buffer.alloc(4)], Buffer.alloc(64)]
  for (const bad of [NaN, undefined, null, Infinity, -1, 1.5, '1500', {}, []]) {
    assert.equal(verifyRRSIGAt(bad, ...args), false,
      `verifyRRSIGAt accepted a bogus clock: ${String(bad)}`)
    assert.equal(validateChainAt(bad, {}).ok, false,
      `validateChainAt accepted a bogus clock: ${String(bad)}`)
  }
})

test('a signature outside its window is rejected on both sides', () => {
  const rrsig = {
    algorithm: 13,
    inception: 1000,
    expiration: 2000,
    labels: 1,
    originalTtl: 3600,
    keyTag: 1,
    signer: 'example',
    signature: Buffer.alloc(64)
  }
  const args = [rrsig, 'example', [Buffer.alloc(4)], Buffer.alloc(64)]
  assert.equal(verifyRRSIGAt(999, ...args), false, 'accepted a not-yet-valid RRSIG')
  assert.equal(verifyRRSIGAt(2001, ...args), false, 'accepted an EXPIRED RRSIG')
})
