/*
 * The ICANN transport plan: what the engine's host resolver is told, and what
 * is therefore true about the lookups it makes.
 *
 * The failures guarded here are all of one kind — a configuration that reads
 * as private and is not:
 *
 *   - `mode: 'secure'` with nothing to point it at must fail CLOSED, never
 *     leave the engine on its plaintext default;
 *   - a typo'd or oddly-cased mode must not silently turn encryption on with
 *     a plaintext fallback, and must not pass unreported;
 *   - the any-host certificate must be minted only for a bridge that runs, so
 *     the certificate gate and the bridge gate must be ONE predicate;
 *   - the plan the engine was configured with must be recorded, because it is
 *     what the interface is allowed to describe (SPEC §6.2).
 *
 * Every expectation is traced to a line of `../src/dns-policy.js`, which is
 * the Wildroot module the composition layer calls at both gates.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  DNS_MODES,
  normalizeDnsMode,
  wantsObliviousBridge,
  planDnsTransport,
  recordDnsPlan,
  effectiveDnsPlan,
  icannBridgeState,
  privateDns
} from '../src/dns-policy.js'
import { schemeSteps } from '../../../src/trust-path.js'

// The shipped defaults (src/config.js `dns` and `odoh` blocks).
const POOL = [
  'https://dns.quad9.net/dns-query',
  'https://cloudflare-dns.com/dns-query',
  'https://doh.tiar.app/dns-query',
  'https://nyc01.dnscry.pt/dns-query'
]
const DEFAULT_DNS = { mode: 'automatic', servers: POOL }
const DEFAULT_ODOH = {
  enabled: true,
  icann: true,
  targets: [{ host: 'odoh.hns.one', path: '/dns-query' }],
  relays: ['https://odoh-relay.numa.rs/relay', 'https://odoh-relay.edgecompute.app/']
}
const BRIDGE = { template: 'https://127.0.0.1:54321/deadbeef/dns-query' }

// --- mode -------------------------------------------------------------------

test('the three modes are the only ones, and anything else becomes automatic', () => {
  assert.deepEqual([...DNS_MODES], ['off', 'automatic', 'secure'])
  for (const m of DNS_MODES) assert.equal(normalizeDnsMode(m), m)
  for (const m of [undefined, null, '', 'strict', 42]) {
    assert.equal(normalizeDnsMode(m), 'automatic', String(m))
  }
})

test('case and surrounding whitespace are forgiven', () => {
  // `'Off'` written in a hand-edited config file means off. Reading it as
  // `automatic` would turn encryption ON — with a plaintext fallback — for
  // somebody who was trying to turn it off.
  assert.equal(normalizeDnsMode('Off'), 'off')
  assert.equal(normalizeDnsMode(' off '), 'off')
  assert.equal(normalizeDnsMode('SECURE'), 'secure')
  assert.equal(normalizeDnsMode('\tAutomatic\n'), 'automatic')
  assert.equal(planDnsTransport({ dns: { mode: 'Off ', servers: POOL } }).configure, false)
})

test('a value that is not a mode is REPORTED, and an absent one is not', () => {
  const seen = []
  assert.equal(normalizeDnsMode('strict', (raw) => seen.push(raw)), 'automatic')
  assert.deepEqual(seen, ['strict'], 'the raw value is handed back for the message')
  // Empty is the documented default, not a typo: there is nothing to warn about.
  for (const quiet of [undefined, null, '', '   ']) {
    assert.equal(normalizeDnsMode(quiet, (raw) => seen.push(raw)), 'automatic')
  }
  assert.equal(seen.length, 1)
})

// --- the plan ---------------------------------------------------------------

test('the default configuration encrypts ICANN lookups to the pool', () => {
  const plan = planDnsTransport({ dns: DEFAULT_DNS, odoh: DEFAULT_ODOH, bridge: null })
  assert.equal(plan.mode, 'automatic')
  assert.deepEqual(plan.servers, POOL)
  assert.equal(plan.oblivious, false)
  assert.equal(plan.configure, true)
  assert.equal(plan.failClosed, false)
  // `automatic` is the captive-portal accommodation, and it is a real hole:
  // if none of the four answer, the lookup goes out in the clear.
  assert.equal(plan.plaintextFallback, true)
})

test('a non-string server is dropped rather than handed to the engine', () => {
  const plan = planDnsTransport({ dns: { mode: 'automatic', servers: [null, '', 'https://a/dns-query', 7] } })
  assert.deepEqual(plan.servers, ['https://a/dns-query'])
})

test('a live bridge REPLACES the pool — it does not join it', () => {
  // The single most surprising property of this design, and the reason
  // SPEC §5.4 has to state it: with the bridge up, the four encrypted
  // resolvers are not reachable by the engine at all. In `automatic`
  // mode the only thing below a failed oblivious lookup is system DNS.
  // Whether leading the pool would be better is IC-D1 — it wants a
  // measurement of the engine on a mixed list first.
  const plan = planDnsTransport({ dns: DEFAULT_DNS, odoh: DEFAULT_ODOH, bridge: BRIDGE })
  assert.deepEqual(plan.servers, [BRIDGE.template])
  assert.equal(plan.oblivious, true)
  assert.equal(plan.plaintextFallback, true)
})

test('a bridge that failed to start leaves the pool in place', () => {
  for (const bridge of [null, undefined, {}, { template: '' }]) {
    const plan = planDnsTransport({ dns: DEFAULT_DNS, odoh: DEFAULT_ODOH, bridge })
    assert.deepEqual(plan.servers, POOL)
    assert.equal(plan.oblivious, false)
  }
})

test('mode secure removes the plaintext fallback, and only that', () => {
  const pool = planDnsTransport({ dns: { mode: 'secure', servers: POOL }, odoh: DEFAULT_ODOH })
  assert.equal(pool.plaintextFallback, false)
  assert.equal(pool.failClosed, false)
  const bridged = planDnsTransport({ dns: { mode: 'secure', servers: POOL }, odoh: DEFAULT_ODOH, bridge: BRIDGE })
  assert.equal(bridged.oblivious, true)
  assert.equal(bridged.plaintextFallback, false)
  // …which means a relay outage in `secure` mode is a total ICANN outage.
  // That is the honest trade, not a defect: the alternative is resolving in
  // the clear after the user asked us not to.
})

test('mode secure with no server FAILS CLOSED: configured, empty list, never plaintext', () => {
  // A setting that says "never plaintext" must not silently mean nothing. The
  // engine is configured for secure mode with an EMPTY server list, so no
  // ICANN name resolves at all, rather than left on its default — which is
  // system DNS, in the clear.
  const plan = planDnsTransport({ dns: { mode: 'secure', servers: [] }, odoh: DEFAULT_ODOH })
  assert.equal(plan.configure, true, 'the engine is configured, not left on its default')
  assert.deepEqual(plan.servers, [])
  assert.equal(plan.failClosed, true)
  assert.equal(plan.plaintextFallback, false)
  // Same when the bridge was wanted and did not start.
  const noBridge = planDnsTransport({ dns: { mode: 'secure' }, odoh: DEFAULT_ODOH, bridge: null })
  assert.equal(noBridge.failClosed, true)
  assert.equal(noBridge.plaintextFallback, false)
})

test('mode automatic with no server configures nothing, and says so', () => {
  // `automatic` with an empty pool is not a contradiction — it is "resolve the
  // way the platform would". Nothing is configured, and the plan admits that
  // the lookup can go out in the clear.
  const plan = planDnsTransport({ dns: { mode: 'automatic', servers: [] } })
  assert.equal(plan.configure, false)
  assert.equal(plan.failClosed, false)
  assert.equal(plan.plaintextFallback, true)
})

test('mode off configures nothing and starts no bridge', () => {
  const cfg = { dns: { mode: 'off', servers: POOL }, odoh: DEFAULT_ODOH }
  assert.equal(wantsObliviousBridge(cfg), false)
  const plan = planDnsTransport({ ...cfg, bridge: BRIDGE })
  assert.equal(plan.configure, false)
  assert.equal(plan.failClosed, false)
  assert.equal(plan.plaintextFallback, true)
  assert.equal(plan.oblivious, false, 'a bridge must not be used when DNS is off')
})

// --- the bridge gate, which is also the certificate gate ---------------------

test('the bridge is wanted only with a relay and an on switch', () => {
  assert.equal(wantsObliviousBridge({ dns: DEFAULT_DNS, odoh: DEFAULT_ODOH }), true)
  assert.equal(wantsObliviousBridge({ dns: DEFAULT_DNS, odoh: { ...DEFAULT_ODOH, enabled: false } }), false)
  assert.equal(wantsObliviousBridge({ dns: DEFAULT_DNS, odoh: { ...DEFAULT_ODOH, icann: false } }), false)
  assert.equal(wantsObliviousBridge({ dns: DEFAULT_DNS, odoh: { ...DEFAULT_ODOH, relays: [] } }), false)
  assert.equal(wantsObliviousBridge({ dns: DEFAULT_DNS, odoh: { ...DEFAULT_ODOH, relays: undefined } }), false)
  assert.equal(wantsObliviousBridge({ dns: { mode: 'off' }, odoh: DEFAULT_ODOH }), false)
  assert.equal(wantsObliviousBridge({ dns: { mode: 'Off' }, odoh: DEFAULT_ODOH }), false)
  assert.equal(wantsObliviousBridge(), false)
})

test('ONE predicate answers the certificate gate and the bridge gate', () => {
  // The loopback certificate must be minted before the engine is ready,
  // because its SPKI pin goes on the command line and command-line switches
  // are read once. That pin makes the engine accept the key FOR ANY HOST, so
  // it must never be minted for a bridge that is not going to run — which is
  // exactly the question the ready-time gate asks. Both call sites ask this
  // function, so the two answers cannot drift.
  const noRelays = { dns: DEFAULT_DNS, odoh: { ...DEFAULT_ODOH, relays: [] } }
  assert.equal(wantsObliviousBridge(noRelays), false, 'no relay: no bridge, and therefore no anchor')
  const wanted = { dns: DEFAULT_DNS, odoh: DEFAULT_ODOH }
  assert.equal(wantsObliviousBridge(wanted), true)
})

// --- what was actually applied ----------------------------------------------

test('the plan the engine was given is recorded, and is what the interface reads', () => {
  assert.equal(effectiveDnsPlan(), null, 'nothing is claimed before configuration')
  const plan = planDnsTransport({ dns: DEFAULT_DNS, odoh: DEFAULT_ODOH, bridge: BRIDGE })
  recordDnsPlan(plan)
  const seen = effectiveDnsPlan()
  assert.deepEqual(seen.servers, [BRIDGE.template])
  assert.equal(seen.oblivious, true)
  // A copy, so a caller that mutates its own plan cannot rewrite history.
  plan.mode = 'off'
  assert.equal(effectiveDnsPlan().mode, 'automatic')
  recordDnsPlan(null)
  assert.equal(effectiveDnsPlan(), null)
})

// --- what the interface may claim -------------------------------------------

test('obliviousness is claimed per NAME answered, never per setting', () => {
  const bridge = {
    server: {},
    transport: {
      relays: ['https://odoh-relay.numa.rs/relay'],
      targets: [{ host: 'odoh.hns.one', path: '/dns-query' }]
    },
    servedRecently: (host) => host === 'example.com' || host === 'sub.example.com'
  }
  const state = icannBridgeState(bridge, 'example.com')
  assert.deepEqual(state, { live: true, relay: 'odoh-relay.numa.rs', target: 'odoh.hns.one' })
  // A name the bridge never answered gets no claim, even with the bridge up.
  assert.equal(icannBridgeState(bridge, 'other.example.net'), null)
  // A bridge that failed to start gets no claim at all.
  assert.equal(icannBridgeState({ ...bridge, server: null }, 'example.com'), null)
  assert.equal(icannBridgeState(null, 'example.com'), null)
})

test('a hostile probe object can never make the panel throw', () => {
  const nasty = { server: {}, get transport () { throw new Error('boom') }, servedRecently: () => true }
  assert.equal(icannBridgeState(nasty, 'example.com'), null)
  assert.equal(icannBridgeState({ server: {}, servedRecently: () => { throw new Error('x') } }, 'a'), null)
})

// ---------------------------------------------------------------- Private mode
// Settings › Content delivery › Mode (src/hns/delivery-mode.js): Private
// forces `secure` with the oblivious bridge as the ONLY server. The pool is
// dropped — an encrypted resolver still learns every name and who asked —
// so with no bridge the plan fails closed rather than resolving anywhere else.

// The browser suite's names for the shipped defaults, so the tests below read the same there and here.
const ODOH = DEFAULT_ODOH
test('privateDns: secure, and no pool, whatever the configured block said', () => {
  assert.deepEqual(privateDns({ mode: 'automatic', servers: POOL }), { mode: 'secure', servers: [] })
  assert.deepEqual(privateDns({ mode: 'off', servers: POOL }), { mode: 'secure', servers: [] })
  assert.deepEqual(privateDns(), { mode: 'secure', servers: [] })
  // The bridge is WANTED for the private block even when the configured
  // mode is off — so main starts it at launch for a later switch.
  assert.equal(wantsObliviousBridge({ dns: privateDns({ mode: 'off' }), odoh: ODOH }), true)
})

test('Private with the bridge up: oblivious only, nothing plaintext, never a pool server', () => {
  const plan = planDnsTransport({ dns: { mode: 'automatic', servers: POOL }, odoh: ODOH, bridge: BRIDGE, privateMode: true })
  assert.equal(plan.mode, 'secure')
  assert.deepEqual(plan.servers, [BRIDGE.template])
  assert.equal(plan.oblivious, true)
  assert.equal(plan.plaintextFallback, false)
  assert.equal(plan.failClosed, false)
  assert.equal(plan.configure, true)
  // The panel, for a name the bridge did not answer: refused, not "in the clear".
  const [step] = schemeSteps('https://example.com/', plan, null)
  assert.match(step.detail, /unencrypted DNS is refused/i)
  assert.doesNotMatch(step.detail, /in the clear/)
})

test('Private with NO bridge fails closed: configured secure with an empty list, and the panel says refused', () => {
  const plan = planDnsTransport({ dns: { mode: 'automatic', servers: POOL }, odoh: ODOH, bridge: null, privateMode: true })
  assert.equal(plan.configure, true)
  assert.deepEqual(plan.servers, [], 'the configured pool is never used as a fallback in Private mode')
  assert.equal(plan.failClosed, true)
  assert.equal(plan.plaintextFallback, false)
  const [step] = schemeSteps('https://example.com/', plan, null)
  assert.equal(step.state, 'failed')
  assert.match(step.source, /refused/i)
})

test('Fast is the configured plan, untouched', () => {
  const fast = planDnsTransport({ dns: { mode: 'automatic', servers: POOL }, odoh: ODOH, bridge: BRIDGE, privateMode: false })
  const plain = planDnsTransport({ dns: { mode: 'automatic', servers: POOL }, odoh: ODOH, bridge: BRIDGE })
  assert.deepEqual(fast, plain)
  const off = planDnsTransport({ dns: { mode: 'off', servers: POOL }, privateMode: false })
  assert.equal(off.configure, false)
})
