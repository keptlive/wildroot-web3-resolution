/*
 * What the trust model is allowed to say about an onion page.
 *
 * The onion address authenticates the SERVICE at the Tor layer — that is a real
 * cryptographic property, and it is the only one. The page itself is plain HTTP
 * inside the tunnel: no certificate, no DANE pin, no content address. So the
 * lock is honestly OPEN, and must stay open even though the scheme was made
 * `standard` + `secure` so that real web apps can use storage and crypto.
 *
 * The browser proves this at two sources of truth. Only ONE of them is
 * extractable here: the per-scheme trust path. The other is the privilege
 * registration in the browser's Electron entry point (`src/main.cjs`), which is
 * not in this package — see ../../../DEVIATIONS.md §4 (what the Tor chapter leaves out).
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { schemeSteps, summarize } from '../../../src/trust-path.js'

const ONION = 'onion://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion/'

test('onion is an OPEN, unverified lock — never a verified one', () => {
  const steps = schemeSteps(ONION)
  const { state } = summarize(steps)
  assert.notEqual(state, 'verified', 'onion must NOT read as a closed lock')
  assert.ok(steps.some((s) => s.state === 'unverified' || s.state === 'none'),
    'onion must carry an open/unverified step')
})

test('and it says why, in the words a user is owed', () => {
  const detail = schemeSteps(ONION).map((s) => `${s.source} ${s.detail || ''}`).join(' ')
  assert.match(detail, /Tor/i)
  assert.match(detail, /HTTP inside Tor|not otherwise verified/i)
  // The device-local rule is part of the honest claim, not marketing copy.
  assert.match(detail, /on this device/i)
  assert.match(detail, /never a hosted relay/i)
})

test('the open verdict is a real distinction, not a constant', () => {
  // A genuinely verified scheme reads as verified; onion does not.
  assert.equal(summarize(schemeSteps('ipfs://bafybeigdyrhonestcid/')).state, 'verified')
  assert.notEqual(summarize(schemeSteps(ONION)).state, 'verified')
})

test('the trust state is decided by SCHEME, so no onion page can talk itself up', () => {
  // Every onion address gets the identical step list. Nothing the service
  // sends — a header, a certificate, a claim in the body — can change it.
  const a = schemeSteps(ONION)
  const b = schemeSteps('onion://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/deep/path?q=1')
  assert.deepEqual(a, b)
  // Even a malformed address, which will never reach a service at all.
  assert.deepEqual(schemeSteps('onion://typod.onion/'), a)
})
