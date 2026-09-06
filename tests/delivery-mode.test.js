/*
 * Settings › Content delivery › Mode: Fast / Private — the one switch
 * (src/hns/delivery-mode.js, docs/MODES.md).
 *
 * What is pinned: the policy table each consumer reads (one row per surviving
 * divergence), the disclosure wording, and the ORDER the controller moves in
 * — restrictive state first in both directions — because a window in which
 * the mode says Private and the session is still direct is exactly the leak
 * the single switch exists to remove.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  DELIVERY_MODES, normalizeDeliveryMode, policyFor, DISCLOSURE, SWITCH_HINT, DeliveryMode, privateRefusal
} from '../src/delivery-mode.js'

test('two modes; anything that is not private is fast', () => {
  assert.deepEqual([...DELIVERY_MODES], ['fast', 'private'])
  assert.equal(normalizeDeliveryMode('private'), 'private')
  assert.equal(normalizeDeliveryMode(' Private '), 'private')
  for (const v of ['fast', 'FAST', '', undefined, null, 'tor', 'on', 42]) {
    assert.equal(normalizeDeliveryMode(v), 'fast', `${String(v)} -> fast`)
  }
})

test('the policy table: Fast is today\'s defaults, Private is the five private paths together', () => {
  const fast = policyFor('fast')
  assert.deepEqual(fast, {
    mode: 'fast',
    ipProtection: 'off',
    strictOblivious: false,
    icannDns: null,
    nostrThroughTor: false,
    p2pDiscovery: 'allowed',
    contentNode: 'dhtclient'
  })
  const priv = policyFor('private')
  assert.deepEqual(priv, {
    mode: 'private',
    ipProtection: 'tor',
    strictOblivious: true,
    icannDns: 'secure',
    nostrThroughTor: true,
    p2pDiscovery: 'refused',
    contentNode: 'offline'
  })
  assert.ok(Object.isFrozen(priv), 'a consumer cannot edit the table it reads')
})

test('the disclosure says each side\'s cost in plain words, and that the lock is unchanged', () => {
  assert.equal(DISCLOSURE.heading, 'Mode')
  assert.match(DISCLOSURE.fast, /^Fast — /)
  assert.match(DISCLOSURE.fast, /see this device's address/)
  assert.match(DISCLOSURE.fast, /falls back to your network's DNS/)
  assert.match(DISCLOSURE.private, /^Private — /)
  assert.match(DISCLOSURE.private, /Tor client on this device/)
  assert.match(DISCLOSURE.private, /nothing is looked up in the clear/)
  assert.match(DISCLOSURE.private, /fails rather than falling back/)
  assert.match(DISCLOSURE.private, /load more slowly/)
  assert.match(DISCLOSURE.private, /some sites block Tor/)
  assert.match(DISCLOSURE.private, /peer-to-peer content \(hyper, SSB, BitTorrent\) is refused, with the reason shown/)
  assert.match(DISCLOSURE.private, /Handshake names keep their chain proof either way/)
  assert.match(DISCLOSURE.neither, /^Neither mode changes what the lock says/)
  assert.match(DISCLOSURE.neither, /the mode only decides the route/)
  assert.match(SWITCH_HINT, /Settings › Content delivery/)
})

function fakeAnonymizer () {
  const calls = []
  return { calls, mode: 'off', async setMode (m) { calls.push(m); this.mode = m; return { mode: m } }, isOn () { return this.mode !== 'off' } }
}

test('entering Private flips the mode BEFORE the anonymizer routes; leaving it routes off BEFORE the mode flips', async () => {
  const anonymizer = fakeAnonymizer()
  const seen = []
  const dm = new DeliveryMode({ anonymizer, mode: 'fast' })
  anonymizer.setMode = async function (m) {
    seen.push(`setMode(${m}) while mode=${dm.mode}`)
    this.mode = m
  }
  await dm.set('private')
  assert.equal(dm.mode, 'private')
  assert.equal(dm.policy.strictOblivious, true)
  await dm.set('fast')
  assert.equal(dm.mode, 'fast')
  assert.deepEqual(seen, [
    'setMode(tor) while mode=private',
    'setMode(off) while mode=private'
  ])
})

test('set() persists the choice and emits one change per switch with the policy attached', async () => {
  const anonymizer = fakeAnonymizer()
  const stored = []
  const changes = []
  const dm = new DeliveryMode({ anonymizer, persist: async (m) => stored.push(m) })
  dm.on('change', (c) => changes.push(c))
  await dm.set('private')
  await dm.set('PRIVATE')
  await dm.set('fast')
  assert.deepEqual(stored, ['private', 'private', 'fast'])
  assert.equal(changes.length, 3)
  assert.equal(changes[0].mode, 'private')
  assert.equal(changes[0].policy.ipProtection, 'tor')
  assert.equal(changes[2].policy.ipProtection, 'off')
  assert.deepEqual(anonymizer.calls, ['tor', 'tor', 'off'])
})

test('apply() at startup drives the anonymizer to the stored mode without persisting again', async () => {
  const anonymizer = fakeAnonymizer()
  const stored = []
  const dm = new DeliveryMode({ anonymizer, mode: 'private', persist: async (m) => stored.push(m) })
  assert.equal(dm.isPrivate(), true)
  await dm.apply()
  assert.deepEqual(anonymizer.calls, ['tor'])
  assert.deepEqual(stored, [])
  const fast = new DeliveryMode({ anonymizer: fakeAnonymizer(), mode: 'garbage' })
  assert.equal((await fast.apply()).ipProtection, 'off')
})

test('every Private-mode refusal names the mode, says nothing was sent, does not blame the site, and points at the switch', () => {
  const lookup = privateRefusal('lookup', { host: 'friend.14898', reason: 'relay unreachable' })
  assert.equal(lookup.title, 'friend.14898 could not be looked up privately')
  assert.match(lookup.detail, /obliviously or not at all/)
  assert.match(lookup.detail, /\(relay unreachable\)/)
  assert.match(lookup.detail, /did not fall back to an unprotected one/)
  assert.match(lookup.detail, /Nothing is known about the site itself/)
  const site = privateRefusal('site', { host: 'pxls' })
  assert.equal(site.title, 'pxls is not loaded in Private mode')
  assert.match(site.detail, /Nothing was sent to the site/)
  const ipfs = privateRefusal('ipfs', { host: 'hello.w3', reason: 'this name publishes no stated origin' })
  assert.match(ipfs.detail, /stated origin for its content loads from that origin in Private mode/)
  const p2p = privateRefusal('p2p', { label: 'Hyper' })
  assert.equal(p2p.title, 'Hyper is refused in Private mode')
  assert.match(p2p.detail, /peer-to-peer network/)
  const named = privateRefusal('p2p', { host: 'drive.w3', label: 'Hyper', reason: 'hyperswarm dials peers directly' })
  assert.equal(named.title, 'drive.w3 is not loaded in Private mode')
  for (const copy of [lookup, site, ipfs, p2p, named]) {
    assert.match(copy.detail, /Settings › Content delivery/, `${copy.title}: points at the control`)
    assert.doesNotMatch(copy.detail, /anonymiz/i, 'the old vocabulary is gone: the mode is named, not the mechanism')
  }
})
