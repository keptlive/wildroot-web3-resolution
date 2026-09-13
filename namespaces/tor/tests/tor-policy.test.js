/*
 * The policy that gates the onion path: IP Protection, in ../src/anonymize.js.
 *
 * This is where "onion resolution is only ever device-local" is enforced. There
 * are exactly two modes — off and tor — and there is deliberately no third one
 * pointing at anybody else's SOCKS endpoint. The controller owns the session
 * proxy; the onion handler only ever ASKS it whether the mode is on.
 *
 * Sessions are duck-typed here ({ setProxy, closeAllConnections }), which is the
 * whole interface the controller uses. Electron is not imported or required.
 *
 * The last three tests pin the ORDER the gate and the proxy change in: every
 * transition into "off" closes the gate first and re-routes after, so there is
 * no instant in which the handler's gate says "route" while the session is
 * already direct.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'

import { resolveProxy, detectTor, applyProxy, AnonymizeController, MODES, BLACKHOLE_RULES } from '../src/anonymize.js'

/** A fake TorNode: fully controllable, no real tor process anywhere. */
function fakeTor ({ state = 'ready', socks = 'socks5://127.0.0.1:41000', ready = null } = {}) {
  let _ready = ready === null ? (state === 'ready') : ready
  const waiters = []
  return {
    started: 0,
    async start () { this.started++; return state },
    isReady () { return _ready },
    socksUrl () { return state === 'unavailable' ? null : socks },
    whenReady () { return new Promise((resolve) => waiters.push(resolve)) },
    _settle (ok) { _ready = ok; while (waiters.length) waiters.shift()(ok) }
  }
}

function fakeSession () {
  const calls = { setProxy: [], closed: 0 }
  return {
    calls,
    setProxy: async (cfg) => { calls.setProxy.push(cfg) },
    closeAllConnections: async () => { calls.closed++ }
  }
}

// --- there are two modes, and no hosted relay ------------------------------

test('there are exactly two modes: off and tor', () => {
  assert.deepEqual(Object.values(MODES).sort(), ['blocked', 'off', 'tor'])
  // No remote/VPS/hosted mode exists. This is the design rule in code: a mode
  // pointing at somebody else's SOCKS endpoint would let that operator learn
  // which hidden service was asked for.
  assert.equal(MODES.VPS, undefined)
  assert.equal(MODES.REMOTE, undefined)
})

test('every proxy rule this module can produce is a loopback SOCKS URL', () => {
  const on = resolveProxy(MODES.TOR, { torAvailable: true, torSocks: 'socks5://127.0.0.1:41000' })
  assert.match(on.rules, /^socks5:\/\/127\.0\.0\.1:\d+$/)
  assert.equal(resolveProxy(MODES.OFF, {}).rules, null)
  assert.equal(resolveProxy(MODES.TOR, { torAvailable: false }).rules, null)
  assert.equal(resolveProxy('nonsense', {}).rules, null)
})

test('an unknown mode fails safe to a direct connection', () => {
  assert.equal(resolveProxy('nonsense', {}).mode, 'off')
  assert.match(resolveProxy('nonsense', {}).note, /staying direct/i)
})

test('the honest note leads with the benefit and states the limitation', () => {
  const note = resolveProxy(MODES.TOR, { torAvailable: true, torSocks: 'socks5://127.0.0.1:41000' }).note
  assert.match(note, /hides your IP/i)
  assert.match(note, /not full anonymity/i)
  assert.match(note, /fingerprint/i)
  assert.match(resolveProxy(MODES.OFF, {}).note, /sites can see your IP/i)
})

test('detectTor is false when the connect throws, true when it succeeds', async () => {
  assert.equal(await detectTor({ connectImpl: async () => { throw new Error('refused') } }), false)
  assert.equal(await detectTor({ connectImpl: async () => {} }), true)
})

// --- the controller: what the onion handler's gate is reading --------------

test('mode tor + a ready TorNode -> the session proxy IS the local SOCKS port', async () => {
  const s = fakeSession()
  const tor = fakeTor({ state: 'ready', socks: 'socks5://127.0.0.1:41000' })
  const c = new AnonymizeController({ sessions: s, tor })
  const st = await c.setMode(MODES.TOR)
  assert.equal(tor.started, 1)
  assert.equal(st.mode, 'tor')
  assert.equal(c.isOn(), true, 'this is what the onion handler asks')
  assert.equal(s.calls.setProxy.at(-1).proxyRules, 'socks5://127.0.0.1:41000')
  // <-loopback> SUBTRACTS the implicit loopback bypass, so even a request to
  // 127.0.0.1 goes through Tor rather than around it.
  assert.equal(s.calls.setProxy.at(-1).proxyBypassRules, '<-loopback>')
  // Existing sockets are torn down so an in-flight direct connection cannot
  // outlive the switch.
  assert.ok(s.calls.closed >= 1)
})

test('mid-bootstrap the proxy is ALREADY tor, so there is no leak window', async () => {
  const s = fakeSession()
  const tor = fakeTor({ state: 'connecting', socks: 'socks5://127.0.0.1:41000', ready: false })
  const c = new AnonymizeController({ sessions: s, tor })
  const st = await c.setMode(MODES.TOR)
  assert.equal(c.mode, 'tor')
  assert.equal(st.rules, 'socks5://127.0.0.1:41000')
  assert.match(st.note, /connecting/i)
  assert.equal(c.isOn(), true, 'the onion handler routes; the request waits for the circuit')
})

test('an unavailable tor never silently becomes a direct onion attempt', async () => {
  const s = fakeSession()
  const c = new AnonymizeController({ sessions: s, tor: fakeTor({ state: 'unavailable' }) })
  const st = await c.setMode(MODES.TOR)
  assert.equal(st.mode, 'off')
  assert.equal(c.isOn(), false, 'so the onion handler serves the interstitial')
  assert.match(st.note, /unavailable/i)
  assert.equal(s.calls.setProxy.at(-1).mode, 'direct')
})

test('a failed bootstrap ends in direct + off, honestly, not in a fallback', async () => {
  const s = fakeSession()
  const tor = fakeTor({ state: 'connecting', socks: 'socks5://127.0.0.1:41000', ready: false })
  const c = new AnonymizeController({ sessions: s, tor })
  await c.setMode(MODES.TOR)
  tor._settle(false)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(c.mode, 'off')
  assert.equal(c.isOn(), false)
  assert.match(c.status.note, /could not reach the Tor network/i)
  assert.equal(s.calls.setProxy.at(-1).mode, 'direct')
})

test('a late bootstrap cannot re-route a session the user has switched off', async () => {
  const s = fakeSession()
  const tor = fakeTor({ state: 'connecting', socks: 'socks5://127.0.0.1:41000', ready: false })
  const c = new AnonymizeController({ sessions: s, tor })
  await c.setMode(MODES.TOR)
  await c.setMode(MODES.OFF)
  tor._settle(true)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(c.mode, 'off')
  assert.equal(s.calls.setProxy.at(-1).mode, 'direct')
})

// --- live progress, and the reload that makes a stuck onion tab load -------

class FakeEmittingTor extends EventEmitter {
  constructor ({ socks = 'socks5://127.0.0.1:41000' } = {}) {
    super()
    this.socks = socks
    this._ready = false
    this._percent = 0
    this._phase = ''
    this._waiters = []
  }

  async start () { return 'connecting' }
  isReady () { return this._ready }
  socksUrl () { return this.socks }
  bootstrapProgress () { return { percent: this._percent, phase: this._phase } }
  whenReady () { return new Promise((resolve) => this._waiters.push(resolve)) }
  tick (percent, phase) {
    this._percent = percent
    this._phase = phase
    this.emit('bootstrap', { percent, phase })
  }

  settle (ok) { this._ready = ok; while (this._waiters.length) this._waiters.shift()(ok) }
}

test('live bootstrap progress is relayed, and is display-only', async () => {
  const s = fakeSession()
  const tor = new FakeEmittingTor()
  const c = new AnonymizeController({ sessions: s, tor })
  const notes = []
  c.on('change', (st) => notes.push(st))
  await c.setMode(MODES.TOR)
  const proxyCalls = s.calls.setProxy.length
  tor.tick(45, 'Loading relay descriptors')
  tor.tick(90, 'Establishing a Tor circuit')
  assert.ok(notes.some((st) => st.percent === 45 && /45%/.test(st.note)))
  assert.ok(notes.some((st) => st.percent === 90 && /Establishing a Tor circuit/.test(st.note)))
  assert.equal(s.calls.setProxy.length, proxyCalls, 'progress changes nothing about routing')
})

test('tor-ready fires exactly once, so a stuck onion tab can be re-loaded', async () => {
  const s = fakeSession()
  const tor = new FakeEmittingTor()
  const c = new AnonymizeController({ sessions: s, tor })
  let readyCount = 0
  c.on('tor-ready', () => { readyCount++ })
  await c.setMode(MODES.TOR)
  tor.tick(50, 'half')
  assert.equal(readyCount, 0)
  tor.settle(true)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(readyCount, 1)
  assert.equal(c.status.percent, 100)
  assert.match(c.status.note, /hides your IP/i)
})

test('a failed bootstrap does NOT emit tor-ready and stops relaying progress', async () => {
  const s = fakeSession()
  const tor = new FakeEmittingTor()
  const c = new AnonymizeController({ sessions: s, tor })
  let readyCount = 0
  c.on('tor-ready', () => { readyCount++ })
  await c.setMode(MODES.TOR)
  tor.settle(false)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(readyCount, 0)
  assert.equal(c.mode, 'off')
  const before = c.status.note
  tor.tick(99, 'too late')
  assert.equal(c.status.note, before)
})

test('applyProxy, the controller-free form, sets the same rules', async () => {
  const s = fakeSession()
  const r = await applyProxy(s, MODES.TOR, { tor: { connectImpl: async () => {} } })
  assert.equal(r.mode, 'tor')
  assert.equal(s.calls.setProxy[0].proxyRules, 'socks5://127.0.0.1:9050')
  assert.equal(s.calls.setProxy[0].proxyBypassRules, '<-loopback>')
  assert.equal(s.calls.closed, 1)
  const s2 = fakeSession()
  await applyProxy(s2, MODES.OFF, {})
  assert.equal(s2.calls.setProxy[0].mode, 'direct')
})

test('applyProxy with no reachable tor stays direct rather than trying anyway', async () => {
  const s = fakeSession()
  const r = await applyProxy(s, MODES.TOR, { tor: { connectImpl: async () => { throw new Error('refused') } } })
  assert.equal(r.mode, 'off')
  assert.equal(s.calls.setProxy[0].mode, 'direct')
})

// --- the order the gate and the proxy change in -----------------------------

test('turning protection OFF closes the gate BEFORE the proxy goes direct', async () => {
  // isOn() is what the onion handler consults before routing. If the session
  // were made direct while isOn() still said true, a request admitted across
  // that await would be sent unproxied and Chromium would hand the .onion host
  // to a system resolver. Turning protection ON is the mirror image — route
  // first, announce after — so that in both directions the restrictive state
  // is entered before the permissive one.
  const seen = []
  const c = new AnonymizeController({
    sessions: {
      setProxy: async (cfg) => { seen.push({ cfg, isOnAtThatMoment: c.isOn() }) },
      closeAllConnections: async () => {}
    },
    tor: fakeTor({ state: 'ready' })
  })
  await c.setMode(MODES.TOR)
  assert.equal(seen.at(-1).cfg.proxyRules, 'socks5://127.0.0.1:41000')
  assert.equal(seen.at(-1).isOnAtThatMoment, false, 'turning ON routes first and announces after')
  assert.equal(c.isOn(), true)

  await c.setMode(MODES.OFF)
  const direct = seen.at(-1)
  assert.equal(direct.cfg.mode, 'direct')
  assert.equal(direct.isOnAtThatMoment, false, 'the gate was already closed when the proxy went direct')
  assert.equal(c.isOn(), false)
})

test('an unknown mode closes the gate before it falls back to direct', async () => {
  const seen = []
  const c = new AnonymizeController({
    sessions: {
      setProxy: async (cfg) => { seen.push({ cfg, isOnAtThatMoment: c.isOn() }) },
      closeAllConnections: async () => {}
    },
    tor: fakeTor({ state: 'ready' })
  })
  await c.setMode(MODES.TOR)
  await c.setMode('vps') // there is no such mode, and there deliberately never was
  assert.equal(seen.at(-1).cfg.mode, 'direct')
  assert.equal(seen.at(-1).isOnAtThatMoment, false)
  assert.equal(c.isOn(), false)
  assert.match(c.status.note, /Unknown mode/)
})

test('a failed bootstrap closes the gate before it returns to a direct connection', async () => {
  const seen = []
  const tor = fakeTor({ state: 'connecting', ready: false })
  const c = new AnonymizeController({
    sessions: {
      setProxy: async (cfg) => { seen.push({ cfg, isOnAtThatMoment: c.isOn() }) },
      closeAllConnections: async () => {}
    },
    tor
  })
  await c.setMode(MODES.TOR)
  assert.equal(c.isOn(), true)
  tor._settle(false)
  await new Promise((resolve) => setImmediate(resolve))
  const direct = seen.at(-1)
  assert.equal(direct.cfg.mode, 'direct')
  assert.equal(direct.isOnAtThatMoment, false, 'R9: no onion request is admitted onto a direct session')
  assert.match(c.status.note, /could not reach the Tor network/)
})

// ---------------------------------------------------------------- fail closed
// Private mode's promise: "if a private lookup fails, the page fails rather
// than falling back." With failClosed the controller enters BLOCKED — every
// session pointed at a loopback port nothing listens on — instead of OFF.

test('failClosed: bundled tor unavailable -> BLOCKED on the blackhole, isOn stays true, torSocks is null', async () => {
  const s = fakeSession()
  const tor = fakeTor({ state: 'unavailable' })
  const c = new AnonymizeController({ sessions: s, tor, failClosed: true })
  const st = await c.setMode(MODES.TOR)
  assert.equal(st.mode, 'blocked')
  assert.equal(st.rules, BLACKHOLE_RULES)
  assert.match(st.note, /Private mode cannot connect/)
  assert.match(st.note, /switch to Fast/i)
  assert.equal(s.calls.setProxy.at(-1).proxyRules, BLACKHOLE_RULES, 'the session is pointed at the blackhole, never left direct')
  assert.equal(c.isOn(), true, 'the gates keep refusing')
  assert.equal(c.torSocks(), null, 'no raw-socket path dials the blackhole and reports a network fault')
})

test('failClosed: a failed bootstrap -> BLOCKED, not direct', async () => {
  const s = fakeSession()
  const tor = fakeTor({ state: 'starting', ready: false })
  const c = new AnonymizeController({ sessions: s, tor, failClosed: true })
  await c.setMode(MODES.TOR)
  tor._settle(false)
  await new Promise((resolve) => setTimeout(resolve, 5))
  assert.equal(c.mode, 'blocked')
  assert.match(c.status.note, /could not reach the Tor network/)
  assert.equal(s.calls.setProxy.at(-1).proxyRules, BLACKHOLE_RULES)
})

test('failClosed: OFF still goes direct, and a routed TOR still reports its SOCKS URL', async () => {
  const s = fakeSession()
  const c = new AnonymizeController({ sessions: s, tor: fakeTor(), failClosed: true })
  await c.setMode(MODES.TOR)
  assert.equal(c.torSocks(), 'socks5://127.0.0.1:41000')
  await c.setMode(MODES.OFF)
  assert.equal(c.mode, 'off')
  assert.equal(c.torSocks(), null)
  assert.equal(s.calls.setProxy.at(-1).mode, 'direct')
})

test('the blackhole is a loopback port, never a routable address', () => {
  assert.match(BLACKHOLE_RULES, /^socks5:\/\/127\.0\.0\.1:\d+$/)
})

// --- a route that stops existing is revoked, not left standing -------------

class RevocableTor extends FakeEmittingTor {
  async start () { return 'ready' }
  isReady () { return true }
  revoke (reason) { this.emit('route-unavailable', { reason }) }
}

test('route-unavailable revokes the route immediately: failClosed blackholes it', async () => {
  // A tor that dies mid-session is not a slow tor. Until the node says so the
  // controller would go on handing torSocks() to raw-socket callers that would
  // dial a port nothing is listening on.
  const s = fakeSession()
  const tor = new RevocableTor()
  const c = new AnonymizeController({ sessions: s, tor, failClosed: true })
  await c.setMode(MODES.TOR)
  assert.equal(c.torSocks(), 'socks5://127.0.0.1:41000')

  tor.revoke('Tor process exited')
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(c.mode, 'blocked')
  assert.equal(c.isOn(), true, 'the gates keep refusing')
  assert.equal(c.torSocks(), null, 'no raw-socket path can reuse a route that is gone')
  assert.equal(s.calls.setProxy.at(-1).proxyRules, BLACKHOLE_RULES)
})

test('route-unavailable while OFF changes nothing', async () => {
  const s = fakeSession()
  const tor = new RevocableTor()
  const c = new AnonymizeController({ sessions: s, tor, failClosed: true })
  const before = s.calls.setProxy.length
  tor.revoke('Tor stopped')
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(c.mode, 'off')
  assert.equal(s.calls.setProxy.length, before, 'a node the user is not using cannot change the session')
})

// --- the switching interval -------------------------------------------------

test('isSwitchingToTor is the narrower question the raw-socket paths ask', async () => {
  // Between "the user asked for Tor" and "the session proxy is installed"
  // there is an interval in which a raw socket must not dial directly. isOn()
  // keeps its own meaning across it — a gate for onion loads, true only once
  // the session actually has a proxy.
  const seen = []
  const tor = fakeTor({ state: 'ready' })
  const c = new AnonymizeController({
    sessions: {
      setProxy: async () => {
        seen.push({ isOn: c.isOn(), switching: c.isSwitchingToTor(), socks: c.torSocks() })
      },
      closeAllConnections: async () => {}
    },
    tor
  })
  assert.equal(c.isSwitchingToTor(), false)
  const pending = c.setMode(MODES.TOR)
  assert.equal(c.isSwitchingToTor(), true, 'set before the first await, not after it')
  assert.equal(c.torSocks(), null, 'so no raw socket dials directly in the interval')
  await pending
  assert.equal(c.isSwitchingToTor(), false)
  assert.equal(c.torSocks(), 'socks5://127.0.0.1:41000')
  // While the proxy was being applied the gate was still closed and the SOCKS
  // URL still withheld.
  assert.deepEqual(seen, [{ isOn: false, switching: true, socks: null }])
})

test('a slow bootstrap cannot land after a later switch', async () => {
  // Every await in setMode is followed by a sequence check, so a tor that
  // takes its time starting cannot route a session the user has since sent
  // back to Fast.
  let release
  const slow = {
    start: () => new Promise((resolve) => { release = () => resolve('ready') }),
    isReady: () => true,
    socksUrl: () => 'socks5://127.0.0.1:41000',
    whenReady: async () => true
  }
  const s = fakeSession()
  const c = new AnonymizeController({ sessions: s, tor: slow })
  const pending = c.setMode(MODES.TOR)
  await c.setMode(MODES.OFF)
  release()
  await pending
  assert.equal(c.mode, 'off')
  assert.equal(c.isSwitchingToTor(), false)
  assert.equal(s.calls.setProxy.at(-1).mode, 'direct')
})
