/*
 * What the lock says about an ICANN name.
 *
 * The claim this package makes about ordinary web browsing is a modest one and
 * it has to stay modest: the address was somebody's word, the certificate was a
 * certificate authority's word, and the only thing we can add is what the
 * engine was CONFIGURED to do and which exact hostnames the oblivious bridge
 * has a record of answering. Neither of those is the route this page's lookup
 * took — the engine resolves, and its cache is not visible from here. The
 * failures worth guarding are all overclaims: a step that says "oblivious" for
 * a host the bridge never answered, a step that names a resolver the engine is
 * not using, and a step that reports a configuration as an observed event.
 *
 * SPEC §6. The interface is handed the plan the engine was CONFIGURED with
 * (`effectiveDnsPlan()`), never the static configuration, so every wording
 * below is driven from a `planDnsTransport()` result rather than from a
 * `dns` block. A plaintext connection aggregates to its own verdict, `open`,
 * in the model (summarize), so the panel and the lock cannot disagree on it.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { schemeSteps, summarize } from '../../../src/trust-path.js'
import { schemeRoute, summarizeRoute } from '../../../src/route-path.js'
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

/** What the bridge records for a host it answered: the exact host, the route
 * that answered it, an acceptable rcode, and when. */
const evidenceFor = (host) => ({
  host,
  queryType: 1,
  relay: 'odoh-relay.numa.rs',
  target: 'odoh.hns.one',
  rcode: 0,
  at: Date.now(),
  withinMs: 10 * 60 * 1000,
  evidence: 'recent-lookup'
})

function liveBridge (answered = () => true) {
  return {
    server: {},
    template: 'https://127.0.0.1:54321/deadbeef/dns-query',
    transport: { relays: DEFAULT_ODOH.relays, targets: DEFAULT_ODOH.targets },
    recentEvidence: (host) => answered(host) ? evidenceFor(host) : null
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

test('a configured resolver pool is named as CONFIGURATION, and is loudly NOT oblivious', () => {
  const step = nameStep('https://example.com', plan(DEFAULT_DNS))
  assert.match(step.source, /Secure DNS configured: dns\.quad9\.net \(\+3 more\)/)
  assert.match(step.source, /NOT oblivious/)
  // The list is what the engine was told to use, not what was seen answering
  // this page. Saying the second would be a measurement nobody made.
  assert.match(step.detail, /not the endpoint observed serving this page/)
  // `automatic` says the fallback out loud; `secure` says it is refused.
  assert.match(step.detail, /falls back to\s+unencrypted system DNS \(mode: automatic\)/)
  assert.match(nameStep('https://example.com', plan({ mode: 'secure', servers: POOL })).detail,
    /Unencrypted DNS is refused/)
})

test('with no resolver configured, the step says the lookup path was not observed', () => {
  // Nothing is configured, so the engine keeps its own default. What that
  // default did for this page — the OS resolver, an encrypted one it found,
  // or its own cache — is not visible from here, and the step says that
  // rather than asserting a plaintext lookup nobody watched.
  for (const dns of [{ mode: 'off', servers: POOL }, { mode: 'automatic', servers: [] }]) {
    const step = nameStep('https://example.com', plan(dns))
    assert.equal(step.state, 'unverified')
    assert.equal(step.source, 'DNS lookup path not observed')
    assert.match(step.detail, /not observed here/)
    assert.doesNotMatch(step.detail, /looked up in the clear/)
  }
  // …and so is a page whose transport is not known to the caller at all.
  assert.equal(nameStep('https://example.com', null).source, 'DNS lookup path not observed')
})

test('a fail-closed plan is reported as configuration, never as an observed refusal', () => {
  // `secure` with nothing to point at configures the engine for secure mode
  // with an empty list. That is a configured policy: no lookup was watched
  // being refused from here, and the engine may still answer from its cache.
  // So the step is `unverified` and names the configuration — reporting it as
  // "system DNS, unencrypted" would describe the opposite of what was asked
  // for, and reporting a `failed` refusal would report an unobserved event.
  const step = nameStep('https://example.com', plan({ mode: 'secure', servers: [] }))
  assert.equal(step.state, 'unverified')
  assert.equal(step.source, 'Secure DNS configured to refuse new lookups')
  assert.doesNotMatch(step.source, /System DNS/)
  assert.match(step.detail, /configured policy, not an observed lookup failure/)
  assert.match(step.detail, /cached answers may still exist/)
  // No past-tense claim that a lookup happened and was turned away.
  assert.doesNotMatch(step.detail, /could not be looked up|was refused rather than used/)
})

test('an oblivious step needs exact-host evidence, and names BOTH endpoints of the route that answered', () => {
  const step = nameStep('https://example.com', plan(DEFAULT_DNS, liveBridge()),
    icannBridgeState(liveBridge(), 'example.com'))
  assert.match(step.source, /Recent Oblivious DoH lookup/)
  assert.match(step.source, /odoh-relay\.numa\.rs/)
  assert.match(step.source, /odoh\.hns\.one/)
  // …and still calls the ANSWER unverified. Obliviousness is a privacy
  // property, never an integrity one: there is no DNSSEC validation on this
  // path (SPEC §7).
  assert.equal(step.state, 'unverified')
  assert.match(step.detail, /resolver.s word/)
  // …and says what the record is: activity, not provenance for this page.
  assert.match(step.detail, /not proof that this page used that answer/)

  // A parent name does not vouch for a child. Even handed evidence for
  // `example.com`, the step for `a.example.com` refuses the oblivious form,
  // because the evidence names a host nobody asked about here.
  const parent = { live: true, ...evidenceFor('example.com') }
  const child = nameStep('https://a.example.com', plan(DEFAULT_DNS, liveBridge()), parent)
  assert.doesNotMatch(child.source, /Recent Oblivious DoH lookup/)
  // And evidence with half a route is not a route: both endpoints or nothing.
  const halfRoute = { live: true, ...evidenceFor('example.com'), target: null }
  assert.doesNotMatch(nameStep('https://example.com', plan(DEFAULT_DNS, liveBridge()), halfRoute).source,
    /Recent Oblivious DoH lookup/)
})

test('no ICANN step ever claims obliviousness it did not have', () => {
  const cases = [
    [plan(DEFAULT_DNS), null],
    [plan({ mode: 'secure', servers: POOL }), null],
    [plan({ mode: 'off', servers: [] }), null],
    [plan({ mode: 'secure', servers: [] }), null],
    [plan(DEFAULT_DNS, liveBridge()), icannBridgeState(liveBridge(() => false), 'example.com')],
    [plan({ mode: 'secure', servers: POOL }, liveBridge()), icannBridgeState(liveBridge(() => false), 'example.com')],
    // Evidence for a different host must not carry a claim across names.
    [plan(DEFAULT_DNS, liveBridge()), { live: true, ...evidenceFor('example.com') }]
  ]
  for (const [dns, bridge] of cases) {
    for (const url of ['https://other.example', 'http://other.example']) {
      const step = nameStep(url, dns, bridge)
      if (/oblivious/i.test(step.source)) {
        assert.match(step.source, /NOT oblivious|not determined|no recent lookup evidence/, `${url}: ${step.source}`)
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
  // The bridge is the only resolver the engine was given and has no record of
  // this host. What happened instead — a cached answer, or, in `automatic`,
  // the fallback the mode permits — is not visible from here, so the step
  // names the configuration and says the lookup path was not established.
  const bridge = icannBridgeState(liveBridge((h) => h === 'served.example'), 'other.example')
  assert.equal(bridge, null)
  const auto = nameStep('https://other.example', plan(DEFAULT_DNS, liveBridge()), bridge)
  assert.equal(auto.state, 'unverified')
  assert.match(auto.source, /not determined/)
  assert.match(auto.detail, /cannot establish the lookup path/)
  assert.match(auto.detail, /Automatic DNS permits system fallback/)
  assert.match(auto.detail, /does not show that fallback occurred/)

  // In `secure` mode the configuration refuses unencrypted fallback, so the
  // wording says that about the configuration — and must not suggest that a
  // plaintext lookup was seen, which nothing here could have seen.
  const secure = nameStep('https://other.example',
    plan({ mode: 'secure', servers: POOL }, liveBridge()), bridge)
  assert.match(secure.source, /Oblivious bridge configured — no recent lookup evidence/)
  assert.match(secure.detail, /configured to refuse unencrypted fallback/i)
  assert.doesNotMatch(secure.detail, /in the clear/)
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

test('a fail-closed plan does not fail the page: nothing was observed failing', () => {
  // The aggregate follows the steps, and the Domain name step for a
  // fail-closed plan is `unverified` (a configuration), not `failed` (an
  // event). A page that loaded anyway — from the engine's cache, say — must
  // not be shown a broken lock on the strength of a setting.
  const { state, summary } = summarize(schemeSteps('https://example.com', plan({ mode: 'secure', servers: [] })))
  assert.equal(state, 'partial')
  assert.doesNotMatch(summary, /Domain name failed/)
})

// --- the route view ---------------------------------------------------------

test('the ICANN name hop is route `unknown` in every branch, and the summary says so first', () => {
  // SPEC §6.4. The route view answers "who saw this request". For an ICANN
  // name nobody here saw the lookup leave, so the hop cannot be `direct`
  // (someone was shown this computer's address) or `oblivious` (nobody was) —
  // both are measurements. `unknown` is the honest fifth value.
  const cases = [
    [plan(DEFAULT_DNS), null],
    [plan({ mode: 'secure', servers: POOL }), null],
    [plan({ mode: 'off', servers: POOL }), null],
    [plan({ mode: 'secure', servers: [] }), null],
    [plan(DEFAULT_DNS, liveBridge()), icannBridgeState(liveBridge(() => false), 'example.com')],
    [plan(DEFAULT_DNS, liveBridge()), icannBridgeState(liveBridge(), 'example.com')]
  ]
  for (const [dns, bridge] of cases) {
    const [name] = schemeRoute('https://example.com/', dns, bridge)
    assert.equal(name.label, 'Domain name')
    assert.equal(name.route, 'unknown', name.source)
  }
  // Even with the bridge's own record, the hop reports recorded ACTIVITY and
  // refuses to describe the route this page's lookup took.
  const [answered] = schemeRoute('https://example.com/', plan(DEFAULT_DNS, liveBridge()),
    icannBridgeState(liveBridge(), 'example.com'))
  assert.match(answered.source, /Recent ODoH activity/)
  assert.match(answered.detail, /not the DNS route or cache used by this page/)

  // And an unknown hop is the first thing the one-liner says, ahead of any
  // count of the hops that ARE known: a partial route must not read as a
  // complete one.
  const { summary } = summarizeRoute('fast', schemeRoute('https://example.com/', plan(DEFAULT_DNS), null))
  assert.match(summary, /^Some route details were not recorded/)
  assert.match(summary, /cannot establish every party that saw this page request/)
})

test('a plaintext connection aggregates to OPEN — a verdict of its own, not the https one', () => {
  // The spine's §4.1: a plaintext connection is the third lock state. It is
  // in the model (summarize) so the address bar and the security panel cannot
  // disagree about it.
  const https = summarize(schemeSteps('https://example.com', plan(DEFAULT_DNS)))
  const http = summarize(schemeSteps('http://example.com', plan(DEFAULT_DNS)))
  assert.equal(https.state, 'partial')
  assert.equal(http.state, 'open')
  assert.match(http.summary, /not encrypted/)
  assert.equal(byLabel(schemeSteps('http://example.com', plan(DEFAULT_DNS)), 'Connection').state, 'none')
})
