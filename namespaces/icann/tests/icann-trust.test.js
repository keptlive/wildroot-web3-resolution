/*
 * What the lock says about an ICANN name.
 *
 * The claim this package makes about ordinary web browsing is a modest one and
 * it has to stay modest: the address was somebody's word, the certificate was a
 * certificate authority's word, and the only thing we can add is whether the
 * lookup was encrypted, oblivious, refused, or in the clear. The failures
 * worth guarding are all overclaims — a step that says "oblivious" for a lookup
 * that was not, or that names a resolver the engine is not using.
 *
 * SPEC §6. The interface is handed the plan the engine was CONFIGURED with
 * (`effectiveDnsPlan()`), never the static configuration, so every wording
 * below is driven from a `planDnsTransport()` result rather than from a
 * `dns` block. One test pins an aggregation rule the code does not implement
 * where the security panel reads it (../../DEVIATIONS.md IC-10).
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { schemeSteps, summarize } from '../../../src/trust-path.js'
import {
  icannBridgeState, planDnsTransport, recordDnsPlan, effectiveDnsPlan
} from '../src/dns-policy.js'

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
  relays: ['https://odoh-relay.numa.rs/relay']
}

const plan = (dns, bridge = null) => planDnsTransport({ dns, odoh: DEFAULT_ODOH, bridge })
const byLabel = (steps, label) => steps.find((s) => s.label === label)
const nameStep = (url, dns, bridge) => byLabel(schemeSteps(url, dns, bridge), 'Domain name')

function liveBridge (served = () => true) {
  return {
    server: {},
    template: 'https://127.0.0.1:54321/deadbeef/dns-query',
    transport: { relays: DEFAULT_ODOH.relays, targets: DEFAULT_ODOH.targets },
    servedRecently: served
  }
}

// --- the transport branches -------------------------------------------------

test('an https ICANN page reports the name and the connection, both unverified', () => {
  const steps = schemeSteps('https://example.com', plan(DEFAULT_DNS))
  assert.deepEqual(steps.map((s) => s.label), ['Domain name', 'Connection'])
  assert.equal(steps[0].state, 'unverified')
  assert.equal(steps[1].state, 'unverified')
  // The whole point of the second step: an ordinary padlock means a CA
  // vouched, and the panel says so in words rather than in a colour.
  assert.match(steps[1].source, /certificate signed by a public CA/)
  assert.match(steps[1].detail, /trusting that authority/)
})

test('encrypted DNS is named, and is loudly NOT oblivious', () => {
  const step = nameStep('https://example.com', plan(DEFAULT_DNS))
  assert.match(step.source, /Encrypted DNS to dns\.quad9\.net \(\+3 more\)/)
  assert.match(step.source, /NOT oblivious/)
  assert.match(step.detail, /that resolver saw your address and the name together/)
  // `automatic` says the fallback out loud; `secure` says it is refused.
  assert.match(step.detail, /falls back to\s+unencrypted system DNS \(mode: automatic\)/)
  assert.match(nameStep('https://example.com', plan({ mode: 'secure', servers: POOL })).detail,
    /Unencrypted DNS is refused/)
})

test('no encrypted DNS at all is reported as plaintext, in plain words', () => {
  for (const dns of [{ mode: 'off', servers: POOL }, { mode: 'automatic', servers: [] }]) {
    const step = nameStep('https://example.com', plan(dns))
    assert.equal(step.source, 'System DNS, unencrypted')
    assert.match(step.detail, /looked up in the clear/)
  }
  // …and so is a page whose transport is not known to the caller at all.
  assert.equal(nameStep('https://example.com', null).source, 'System DNS, unencrypted')
})

test('a fail-closed plan is reported as a refusal, never as system DNS', () => {
  // `secure` with nothing to point at configures the engine for secure mode
  // with an empty list, so no ICANN name resolves. The step must say that the
  // lookup was REFUSED — reporting it as "system DNS, unencrypted" would
  // describe the exact thing that did not happen.
  const step = nameStep('https://example.com', plan({ mode: 'secure', servers: [] }))
  assert.equal(step.state, 'failed')
  assert.match(step.source, /refused/i)
  assert.doesNotMatch(step.source, /System DNS/)
  assert.match(step.detail, /Unencrypted DNS was refused rather than used/)
})

test('an oblivious lookup names BOTH the relay and the target', () => {
  const step = nameStep('https://example.com', plan(DEFAULT_DNS, liveBridge()),
    icannBridgeState(liveBridge(), 'example.com'))
  assert.match(step.source, /Oblivious DoH/)
  assert.match(step.source, /odoh-relay\.numa\.rs/)
  assert.match(step.source, /odoh\.hns\.one/)
  // …and still calls the ANSWER unverified. Obliviousness is a privacy
  // property, never an integrity one: there is no DNSSEC validation on this
  // path (SPEC §7).
  assert.equal(step.state, 'unverified')
  assert.match(step.detail, /still the resolver's word/)
})

test('no ICANN step ever claims obliviousness it did not have', () => {
  const cases = [
    [plan(DEFAULT_DNS), null],
    [plan({ mode: 'secure', servers: POOL }), null],
    [plan({ mode: 'off', servers: [] }), null],
    [plan({ mode: 'secure', servers: [] }), null],
    [plan(DEFAULT_DNS, liveBridge()), icannBridgeState(liveBridge(() => false), 'example.com')]
  ]
  for (const [dns, bridge] of cases) {
    for (const url of ['https://example.com', 'http://example.com']) {
      const step = nameStep(url, dns, bridge)
      if (/oblivious/i.test(step.source)) {
        assert.match(step.source, /NOT oblivious|not determined|not answered by it/, `${url}: ${step.source}`)
      }
    }
  }
})

// --- the plan the engine was given, not the setting -------------------------

test('the panel describes the plan that was applied, not the configured pool', () => {
  // When the bridge starts, the engine's server list is REPLACED by the
  // loopback template, so the four configured resolvers are not reachable by
  // the engine at all. Naming them would be a false statement made by the
  // component whose entire purpose is to be the true one.
  recordDnsPlan(plan(DEFAULT_DNS, liveBridge()))
  assert.deepEqual(effectiveDnsPlan().servers, ['https://127.0.0.1:54321/deadbeef/dns-query'])

  const step = nameStep('https://unserved.example', effectiveDnsPlan(),
    icannBridgeState(liveBridge(() => false), 'unserved.example'))
  assert.doesNotMatch(step.source, /quad9|cloudflare|dnscry/)
  assert.ok(!step.source.includes('127.0.0.1'), 'a loopback template is not a resolver name')
  recordDnsPlan(null)
})

test('a name the bridge did not answer gets the honest "we cannot tell" wording', () => {
  // In `automatic` mode the engine can resolve a name by other means at any
  // moment, and the bridge is the only encrypted resolver it was given — so
  // the truthful thing to say is that this lookup may have gone out in the
  // clear. The panel reports the event, not the setting.
  const bridge = icannBridgeState(liveBridge((h) => h === 'served.example'), 'other.example')
  assert.equal(bridge, null)
  const auto = nameStep('https://other.example', plan(DEFAULT_DNS, liveBridge()), bridge)
  assert.equal(auto.state, 'unverified')
  assert.match(auto.source, /not determined/)
  assert.match(auto.detail, /may have gone out in the clear/)

  // In `secure` mode nothing else could have answered it, so the wording says
  // that instead — and must not suggest plaintext, which is refused.
  const secure = nameStep('https://other.example',
    plan({ mode: 'secure', servers: POOL }, liveBridge()), bridge)
  assert.match(secure.source, /Oblivious bridge only/)
  assert.match(secure.detail, /unencrypted DNS is refused/i)
  assert.doesNotMatch(secure.detail, /gone out in the clear/)
})

// --- the aggregate ----------------------------------------------------------

test('an ICANN page is TRUSTED, never trustless', () => {
  // SPEC §6.3. Nothing on this path is checked on this computer, so the lock
  // must never reach the state a chain-proven, DANE-pinned Handshake name
  // reaches. `partial` is the honest verdict and it is the ceiling.
  const { state } = summarize(schemeSteps('https://example.com', plan(DEFAULT_DNS)))
  assert.equal(state, 'partial')
  const oblivious = summarize(schemeSteps('https://example.com', plan(DEFAULT_DNS, liveBridge()),
    icannBridgeState(liveBridge(), 'example.com')))
  assert.equal(oblivious.state, 'partial', 'obliviousness must not upgrade the lock')
})

test('a refused lookup fails the whole page, and the aggregate says so', () => {
  const { state, summary } = summarize(schemeSteps('https://example.com', plan({ mode: 'secure', servers: [] })))
  assert.equal(state, 'failed')
  assert.match(summary, /Domain name failed/)
})

test('DIVERGENCE IC-10: summarize() gives http and https the same verdict', () => {
  // The top-level SPEC §4.1 says a plaintext connection aggregates to OPEN.
  // `summarize` does not implement that: `none` and `unverified` are both
  // "weak", so `http://` and `https://` both come back `partial` with the same
  // sentence. The address bar derives the open lock separately (`secure` is
  // false when the Connection step is `none`, src/index.js:1512-1513); the
  // security panel, which calls `summarize` directly (src/window.js:2766),
  // does not — it lists the plaintext step but heads the page with the same
  // verdict an HTTPS page gets. ../../DEVIATIONS.md IC-10.
  const https = summarize(schemeSteps('https://example.com', plan(DEFAULT_DNS)))
  const http = summarize(schemeSteps('http://example.com', plan(DEFAULT_DNS)))
  assert.deepEqual(http, https)
  // The information is present — just not in the aggregate.
  assert.equal(byLabel(schemeSteps('http://example.com', plan(DEFAULT_DNS)), 'Connection').state, 'none')
})
