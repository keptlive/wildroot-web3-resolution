/*
 * "NEVER DNS" is not one check in one place — it is four, and this file drives
 * all four with the same address:
 *
 *   1. the classifier            (typed input)          ../../../src/router.js
 *   2. the reserved-host guard   (link click, main frame) ../../../src/hns-host.js
 *   3. the subresource guard     (<img>, <script>, xhr)   ../src/subresource-guard.js
 *   4. the handler's own gate    (IP Protection off)      ../src/onion-protocol.js
 *
 * A miss in any ONE of them puts an onion address in a DNS query, which
 * discloses the hidden service somebody tried to reach. That disclosure cannot
 * be undone by a lock state, which is why it is guarded structurally rather
 * than reported honestly.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { decide } from '../src/subresource-guard.js'
import { classify, classifyHost, NAMESPACES } from '../../../src/router.js'
import { rewriteToHns, isHnsHost } from '../../../src/hns-host.js'
import createOnionHandler from '../src/onion-protocol.js'

const V3 = 'p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion'
const TYPO = 'typod.onion'
const V2 = 'expyuzz4wqqyqhjn.onion' // a dead v2 address; still an onion, still guarded

// --- 3. subresources: cancelled, zero network, zero DNS --------------------

test('.onion subresources are cancelled outright', () => {
  assert.deepEqual(decide(`http://${V3}/pixel.gif`, 'image'), { cancel: true })
  assert.deepEqual(decide(`https://${V3}/lib.js`, 'script'), { cancel: true })
  assert.deepEqual(decide(`http://${V3}/api`, 'xhr'), { cancel: true })
  // A malformed or obsolete onion leaks exactly as effectively as a valid one.
  assert.deepEqual(decide(`http://${TYPO}/x`, 'subFrame'), { cancel: true })
  assert.deepEqual(decide(`http://${V2}/x`, 'image'), { cancel: true })
})

test('a main-frame load that slipped through is re-routed to onion://, not cancelled', () => {
  assert.deepEqual(decide(`http://${V3}/`, 'mainFrame'), { redirectURL: `onion://${V3}/` })
  assert.deepEqual(decide(`http://${TYPO}/x`, 'mainFrame'), { redirectURL: `onion://${TYPO}/x` })
})

test('the guard leaves everything that is not a reserved or Handshake host alone', () => {
  assert.deepEqual(decide('https://example.com/a.png', 'image'), {})
  assert.deepEqual(decide('http://192.168.1.1/x', 'xhr'), {})
  assert.deepEqual(decide('http://localhost:8010/app.js', 'script'), {})
  // A host merely CONTAINING "onion" is an ordinary ICANN name.
  assert.deepEqual(decide('https://onion.example.com/x.png', 'image'), {})
})

// --- 1 + 2: the same address through every other entry point ---------------

test('one address, four entry points, one namespace', () => {
  for (const host of [V3, TYPO, V2]) {
    // typed
    assert.equal(classifyHost(host), NAMESPACES.TOR, `classifyHost ${host}`)
    assert.equal(classify(host).scheme, 'onion', `classify ${host}`)
    // link click / main-frame rewrite
    assert.equal(rewriteToHns(`http://${host}/`), `onion://${host}/`, `rewrite ${host}`)
    // never Handshake
    assert.equal(isHnsHost(host), false, `isHnsHost ${host}`)
    // subresource
    assert.deepEqual(decide(`http://${host}/x`, 'image'), { cancel: true }, `subresource ${host}`)
  }
})

test('an explicit non-Tor scheme on an onion host is NOT reclassified (L1)', () => {
  // The scheme wins. https://<onion>/ stays https — the user named a protocol,
  // and we do not sniff a better one out of the host. It will fail as HTTPS.
  const c = classify(`https://${V3}/`)
  assert.equal(c.explicit, true)
  assert.equal(c.scheme, 'https')
  assert.equal(c.url, `https://${V3}/`)
})

// --- 4. the handler's own gate ---------------------------------------------

test('with IP Protection off the handler makes no request of any kind', async () => {
  let fetched = 0
  const { handler } = createOnionHandler({
    fetchImpl: async () => { fetched++; return new Response('') },
    ipProtectionOn: () => false
  })
  // A well-formed address gets the interstitial: a navigable page, not an
  // error. A malformed one is refused for its own reason before the gate is
  // even consulted. Both answers are generated locally.
  assert.equal((await handler(new Request(`onion://${V3}/`))).status, 200)
  for (const host of [TYPO, V2]) {
    assert.equal((await handler(new Request(`onion://${host}/`))).status, 400, host)
  }
  assert.equal(fetched, 0)
})

test('a malformed address is refused locally whether protection is on or off', async () => {
  // The address check runs before the gate, so the answer does not depend on
  // the mode — and neither answer costs a circuit.
  let fetched = 0
  for (const on of [true, false]) {
    const { handler } = createOnionHandler({
      fetchImpl: async () => { fetched++; return new Response('') },
      ipProtectionOn: () => on
    })
    for (const host of [TYPO, V2]) {
      const res = await handler(new Request(`onion://${host}/`))
      assert.equal(res.status, 400, `${host} with protection ${on ? 'on' : 'off'}`)
      assert.equal(res.headers.get('X-Resolution-Namespace'), 'tor')
    }
  }
  assert.equal(fetched, 0, 'no circuit is spent on an address that cannot exist')
})

// --- the edge of the chain -------------------------------------------------

test('an IP literal is not the onion path at all', () => {
  // Recorded so the boundary is explicit: the guard only ever acts on hosts the
  // classifier calls reserved or Handshake. Everything else is Chromium's.
  assert.equal(classifyHost('127.0.0.1'), NAMESPACES.WEB)
  assert.deepEqual(decide('http://127.0.0.1/x.png', 'image'), {})
})
