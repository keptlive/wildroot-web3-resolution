/*
 * The circuit-ready -> auto-reload decision. Pure logic, no Electron: given a
 * window's tab snapshot, which tabs should reload the moment the Tor circuit
 * comes up.
 *
 * This exists because of how the gate behaves. A user who navigates to an
 * onion address while Tor is still bootstrapping gets a tab that either errored
 * or is showing the interstitial. The moment the circuit is up those tabs must
 * load themselves — a user should never have to know to press reload. The rule
 * is deliberately conservative so it does not stomp a page being read.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { tabsToReloadOnTorReady, isTorScheme } from '../src/tor-reload.js'

const ONION = 'onion://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion/'

test('isTorScheme matches onion:// only', () => {
  assert.equal(isTorScheme(ONION), true)
  assert.equal(isTorScheme('ONION://ABC.onion/'), true)
  assert.equal(isTorScheme('https://example.com/'), false)
  assert.equal(isTorScheme('hns://nb.hns/'), false)
  // The SCHEME is the signal, not the host: an http URL on an onion host has
  // already been rewritten to onion:// by the time a tab holds it.
  assert.equal(isTorScheme(`http://${ONION.slice(8)}`), false)
  assert.equal(isTorScheme(''), false)
  assert.equal(isTorScheme(null), false)
})

test('reloads onion tabs and errored tabs, leaves good pages alone', () => {
  const good = { url: 'https://example.com/', loadFailed: false, active: true }
  const onion = { url: ONION, loadFailed: false, active: false }
  const errored = { url: 'https://slow.example/', loadFailed: true, active: false }
  assert.deepEqual(tabsToReloadOnTorReady([good, onion, errored]), [onion, errored])
})

test('scheme, not load status, is the honest signal for an onion tab', () => {
  // The interstitial is a 200 with a real HTML body, so did-fail-load never
  // fires for it. Only the scheme distinguishes "this tab needed Tor".
  const interstitial = { url: ONION, loadFailed: false, active: true }
  assert.deepEqual(tabsToReloadOnTorReady([interstitial]), [interstitial])
})

test('an errored onion tab is reloaded once, not twice', () => {
  const onionErr = { url: ONION, loadFailed: true, active: true }
  const out = tabsToReloadOnTorReady([onionErr])
  assert.equal(out.length, 1)
  assert.equal(out[0], onionErr)
})

test('a good active tab is NOT needlessly reloaded', () => {
  const good = { url: 'https://example.com/', loadFailed: false, active: true }
  assert.deepEqual(tabsToReloadOnTorReady([good]), [])
})

test('empty / junk input is safe', () => {
  assert.deepEqual(tabsToReloadOnTorReady([]), [])
  assert.deepEqual(tabsToReloadOnTorReady(null), [])
  assert.deepEqual(tabsToReloadOnTorReady([null, undefined]), [])
})
