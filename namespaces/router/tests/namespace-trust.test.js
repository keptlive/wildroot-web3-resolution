/*
 * The cross-namespace trust model (Part II §10).
 *
 * The top-level tests/trust-path.test.js and tests/lock-semantics.test.js prove
 * the Handshake step list and the lock verdicts. This file proves the property
 * that only exists ACROSS namespaces: that every namespace the router can
 * dispatch reports into one vocabulary, that none of them returns an empty step
 * list, that a scheme's REGISTRATION never decides its verdict, and that no
 * step claims a property (obliviousness, verification) it did not have.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { schemeSteps, summarize } from '../../../src/trust-path.js'
import { SCHEME_TABLE, NAMESPACES, schemeInfo } from '../../../src/router.js'

const STATES = new Set(['verified', 'unverified', 'failed', 'none'])

/** The verdict the way a lock indicator computes it. */
function verdict (url) {
  const steps = schemeSteps(url)
  const { state } = summarize(steps)
  const connection = steps.find((s) => s.label === 'Connection')
  return { state, steps, open: state === 'failed' || !!(connection && connection.state === 'none') }
}

/** One representative URL per scheme in the table. */
function sampleUrl (scheme) {
  switch (scheme) {
    case 'magnet': return 'magnet:?xt=urn:btih:abc'
    case 'did': return 'did:plc:abc'
    case 'nostr': return 'nostr:npub1xyz'
    case 'at': return 'at://alice.example/x'
    case 'activitypub': return 'activitypub://alice.example/x'
    default: return `${scheme}://example-host/path`
  }
}

// --- one vocabulary ---------------------------------------------------------

test('every scheme in the registry produces a non-empty, well-formed step list', () => {
  for (const row of SCHEME_TABLE) {
    const steps = schemeSteps(sampleUrl(row.scheme))
    assert.ok(steps.length > 0, `${row.scheme}: no scheme may return an empty list`)
    for (const s of steps) {
      assert.equal(typeof s.label, 'string', `${row.scheme}: label`)
      assert.ok(s.label.length > 0, `${row.scheme}: label is not empty`)
      assert.ok(STATES.has(s.state), `${row.scheme}: state "${s.state}" is one of the four`)
      assert.equal(typeof s.source, 'string', `${row.scheme}: names who told us`)
      assert.ok(s.source.length > 0, `${row.scheme}: the source is not empty`)
    }
  }
})

test('a scheme with no verification path says so, rather than saying nothing', () => {
  // The default branch is the point: an empty list summarizes to "nothing is
  // known", which a naive indicator renders as neutral.
  for (const scheme of ['gemini', 'web3', 'magnet', 'did', 'at', 'activitypub']) {
    const steps = schemeSteps(sampleUrl(scheme))
    assert.equal(steps.length > 0, true, scheme)
    assert.equal(steps.some((s) => s.state === 'verified'), false,
      `${scheme}: an unverified namespace must not report a verified step`)
  }
  // Every scheme with a verification story worth naming has its own arm, so
  // the default branch is reached only by schemes that genuinely have none.
  for (const scheme of ['web3', 'at', 'activitypub']) {
    const fallback = schemeSteps(sampleUrl(scheme))
    assert.equal(fallback.length, 1, scheme)
    assert.equal(fallback[0].state, 'none', scheme)
    assert.equal(fallback[0].label, 'Address', scheme)
    assert.match(fallback[0].detail, /no verification path/i, scheme)
  }
})

test('each scheme names its OWN verification step, not a generic one', () => {
  // The step a scheme reports and the row the registry holds for it are two
  // statements of one fact, and they are checked against each other here.
  const named = {
    gemini: [/Connection/, /nothing establishes who answered/, 'unverified'],
    pubsub: [/Content/, /not a content address/, 'none'],
    ssb: [/Content/, /feed key/, 'verified'],
    magnet: [/Address/, /only a pointer to a torrent/, 'none'],
    did: [/Identifier/, /not audited/, 'unverified'],
    ar: [/Content/, /not checked against the/, 'unverified'],
    onion: [/Connection/, /plain HTTP inside the tunnel/, 'unverified']
  }
  for (const [scheme, [label, detail, state]] of Object.entries(named)) {
    const [first] = schemeSteps(sampleUrl(scheme))
    assert.match(first.label, label, scheme)
    assert.match(first.detail, detail, scheme)
    assert.equal(first.state, state, scheme)
  }
  assert.match(schemeSteps('gemini://example-host/path')[0].source,
    /certificate not verified/)
  // gemini is not TOFU: nothing is pinned, so nothing can be compared.
  const [gemini] = schemeSteps('gemini://example-host/path')
  assert.match(gemini.detail, /neither checked against an authority nor remembered/)
  assert.doesNotMatch(`${gemini.source} ${gemini.detail}`, /trust on first use|TOFU/i)
})

test('nostr proves the object and cannot prove the answer set', () => {
  const steps = schemeSteps('nostr:npub1xyz')
  assert.deepEqual(steps.map((s) => [s.label, s.state]),
    [['Authorship', 'verified'], ['Completeness', 'unverified']])
  assert.match(steps[0].source, /BIP-340/)
  assert.match(steps[1].detail, /Relays can withhold events/)
  assert.equal(summarize(steps).state, 'partial', 'so the lock never closes green')
})

test('hyper is one step for a key and two for a DNSLink name', () => {
  // A hypercore key verifies its own feed. A DOTTED host is a DNSLink name,
  // and the name→key mapping is a DoH resolver's unsigned answer — the same
  // shape as ens://, and it must be reported the same way.
  const key = schemeSteps('hyper://deadbeef/')
  assert.deepEqual(key.map((s) => s.state), ['verified'])
  assert.equal(summarize(key).state, 'verified')

  const dnslink = schemeSteps('hyper://example.com/')
  assert.deepEqual(dnslink.map((s) => [s.label, s.state]),
    [['Name records', 'unverified'], ['Content', 'verified']])
  assert.match(dnslink[0].source, /DNSLink name example\.com/)
  assert.match(dnslink[0].detail, /no DNSSEC, no chain proof/)
  assert.equal(summarize(dnslink).state, 'partial')
})

test('an unparseable URL is a FAILED step, never an empty one', () => {
  const steps = schemeSteps('not a url')
  assert.equal(steps.length, 1)
  assert.equal(steps[0].state, 'failed')
  assert.equal(summarize(steps).state, 'failed')
})

// --- privilege is not trust -------------------------------------------------

test('a standard, secure scheme can still report an OPEN lock', () => {
  // onion:// is registered standard+secure so real web apps can use storage.
  // That buys a secure CONTEXT, not a verdict. If the verdict were derived from
  // registration, this page would read as authenticated; it is not.
  const v = verdict('onion://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion/')
  assert.equal(v.state, 'partial')
  assert.equal(v.steps[0].state, 'unverified')
  assert.match(v.steps[0].detail, /plain HTTP inside the tunnel/)
  assert.equal(schemeInfo('onion').namespace, NAMESPACES.TOR)
})

test('the three lock states are distinguishable, and https is not trustless', () => {
  assert.equal(verdict('ipfs://bafyfoo/').state, 'verified', 'TRUSTLESS')
  assert.equal(verdict('https://example.com/').state, 'partial', 'TRUSTED, not trustless')
  assert.equal(verdict('https://example.com/').open, false, 'and still closed')
  assert.equal(verdict('http://example.com/').open, true, 'OPEN')
  // Arweave and ENS are the two that are easiest to over-claim: both are
  // TRUSTED — closed, neutral — and neither is TRUSTLESS.
  for (const url of ['ar://sometxid/', 'ens://vitalik.eth/']) {
    assert.equal(verdict(url).state, 'partial', url)
    assert.equal(verdict(url).open, false, url)
  }
})

test('the lock opens on exactly two conditions: a failed step, or a Connection of `none`', () => {
  // The rule the indicator applies (`secure = state !== 'failed' && !(connection
  // && connection.state === 'none')`). It is deliberately NOT "any unverified
  // step": an https:// page has an unverified step and is still a closed lock.
  assert.equal(verdict('http://example.com/').steps.find((s) => s.label === 'Connection').state, 'none')
  assert.equal(verdict('http://example.com/').open, true, 'plaintext transport')
  assert.equal(verdict('not a url').open, true, 'a failed step')
  assert.equal(verdict('https://example.com/').open, false, 'unverified is not open')
  assert.equal(verdict('onion://abc.onion/').open, false,
    'the onion Connection step is `unverified`, not `none` — closed, and never green')
  // A DNS plan that fails closed makes the name step FAIL, which opens the
  // lock on a page that never loaded.
  const failedDns = schemeSteps('https://example.com/', { mode: 'secure', servers: [], failClosed: true })
  assert.equal(failedDns[0].state, 'failed')
  assert.equal(summarize(failedDns).state, 'failed')
})

test('the lock follows the weakest link, and a failure never closes it', () => {
  const strongest = [
    { label: 'A', state: 'verified', source: 'x' },
    { label: 'B', state: 'verified', source: 'x' }
  ]
  assert.equal(summarize(strongest).state, 'verified')
  assert.equal(summarize([...strongest, { label: 'C', state: 'none', source: 'x' }]).state, 'partial')
  assert.equal(summarize([...strongest, { label: 'C', state: 'unverified', source: 'x' }]).state, 'partial')
  const failed = summarize([...strongest, { label: 'C', state: 'failed', source: 'x' }])
  assert.equal(failed.state, 'failed')
  assert.match(failed.summary, /^C failed/)
  assert.equal(summarize([]).state, 'unknown')
})

test('the summary NAMES the weak steps rather than counting them silently', () => {
  const one = summarize([{ label: 'Domain name', state: 'unverified', source: 'x' }])
  assert.match(one.summary, /Domain name is not verified/)
  const two = summarize([
    { label: 'Domain name', state: 'unverified', source: 'x' },
    { label: 'Connection', state: 'unverified', source: 'x' }
  ])
  assert.match(two.summary, /domain name, connection/)
})

// --- no step claims a property it did not have ------------------------------

test('no scheme step ever claims obliviousness', () => {
  // Only the Handshake path and the ICANN bridge can be oblivious, and each
  // says which relay and target it used. A generic scheme step must not imply
  // the property by vocabulary.
  for (const row of SCHEME_TABLE) {
    for (const s of schemeSteps(sampleUrl(row.scheme))) {
      assert.doesNotMatch(`${s.source} ${s.detail || ''}`, /oblivious/i, row.scheme)
    }
  }
})

test('the ICANN name step distinguishes unencrypted, encrypted and oblivious', () => {
  const plain = schemeSteps('https://example.com/', { mode: 'off', servers: [] })[0]
  assert.equal(plain.state, 'unverified')
  assert.match(plain.source, /System DNS, unencrypted/)

  const encrypted = schemeSteps('https://example.com/',
    { mode: 'secure', servers: ['https://dns.example/dns-query'] })[0]
  assert.match(encrypted.source, /NOT oblivious/)
  assert.match(encrypted.detail, /Unencrypted DNS is refused/)

  const automatic = schemeSteps('https://example.com/',
    { mode: 'automatic', servers: ['https://dns.example/dns-query'] })[0]
  assert.match(automatic.detail, /falls back to unencrypted system DNS/)

  const oblivious = schemeSteps('https://example.com/', null,
    { live: true, relay: 'relay.example', target: 'target.example' })[0]
  assert.match(oblivious.source, /Oblivious DoH — relay relay\.example → target target\.example/)
  assert.equal(oblivious.state, 'unverified', 'oblivious is a privacy property, not a verification')
})

test('the ICANN step describes the transport PLAN the engine was given', () => {
  // The plan is decided once and recorded (the sibling ICANN chapter's
  // src/dns-policy.js); the panel and the lock read the plan that was applied,
  // never the static configuration — which could name resolvers the engine
  // stopped using. Two arms exist only because a plan can be recorded.
  //
  // Bridge configured, but it did not answer THIS name. In `secure` mode
  // nothing else could have; in `automatic` mode the engine may have fallen
  // back to system DNS in the clear, and there is no way to tell from here.
  const secureOnly = schemeSteps('https://example.com/',
    { mode: 'secure', servers: ['https://bridge.local/dns-query'], oblivious: true })[0]
  assert.equal(secureOnly.state, 'unverified')
  assert.match(secureOnly.source, /Oblivious bridge only — this name was not answered by it/)
  assert.match(secureOnly.detail, /the bridge has no record of answering it/)

  const automatic = schemeSteps('https://example.com/',
    { mode: 'automatic', servers: ['https://bridge.local/dns-query'], oblivious: true })[0]
  assert.match(automatic.source, /Resolver not determined/)
  assert.match(automatic.detail, /this lookup may have gone out in the clear/)

  // `secure` with no server FAILS CLOSED: nothing resolves, rather than
  // quietly resolving in the clear. That is a FAILED step, not an unverified
  // one — the name was never looked up.
  const failClosed = schemeSteps('https://example.com/',
    { mode: 'secure', servers: [], failClosed: true })[0]
  assert.equal(failClosed.state, 'failed')
  assert.match(failClosed.source, /Secure DNS with no server — lookups refused/)
  assert.match(failClosed.detail, /Unencrypted DNS was refused rather than used/)

  // A live bridge outranks every plan arm: it is the one case where the
  // lookup really was oblivious.
  const live = schemeSteps('https://example.com/',
    { mode: 'secure', servers: [], failClosed: true },
    { live: true, relay: 'r.example', target: 't.example' })[0]
  assert.match(live.source, /Oblivious DoH/)
})

test('ens:// is TRUSTED and never green', () => {
  const steps = schemeSteps('ens://vitalik.eth/')
  assert.equal(steps.length, 2)
  assert.equal(steps[0].state, 'unverified')
  assert.match(steps[0].detail, /does not run an Ethereum light client/)
  assert.equal(steps[1].state, 'verified', 'the CONTENT is still content-addressed')
  // The verdict is `partial` — the neutral closed lock an https:// page gets —
  // because the name→content binding rests on an RPC endpoint's word. The
  // registry row says the same sentence, and the two are checked against each
  // other so neither can drift into claiming the trustless state.
  assert.equal(summarize(steps).state, 'partial')
  assert.equal(verdict('ens://vitalik.eth/').open, false, 'closed, and not green')
  assert.match(schemeInfo('ens').verify, /never green/)
})

test('the built-in pages are trustless because they never touched the network', () => {
  for (const scheme of ['wildroot', 'agregore', 'browser', 'editor', 'paste']) {
    const steps = schemeSteps(`${scheme}://settings/`)
    assert.equal(steps[0].state, 'verified', scheme)
    assert.match(steps[0].detail, /never touched the network/, scheme)
  }
})

test('search:// promises nothing, and says so', () => {
  const steps = schemeSteps('search://web/?q=kittens')
  assert.equal(steps.length, 1)
  assert.equal(steps[0].state, 'none')
  assert.equal(steps[0].label, 'Search')
})

// --- the model and the registry say the same thing --------------------------

test('the ar:// step reports exactly what the registry says is checked', () => {
  // The transaction id is immutable, so it names one set of bytes — but the
  // bytes came from a gateway and were never checked against the transaction.
  // TRUSTLESS means "nobody was believed"; a gateway was believed, so ar:// is
  // TRUSTED, in the same class as an ordinary https:// page.
  const row = schemeInfo('ar')
  assert.equal(row.status, 'partial')
  assert.match(row.verify, /gateway-trusted/)

  const steps = schemeSteps('ar://sometxid/')
  assert.equal(steps.length, 1)
  assert.equal(steps[0].label, 'Content')
  assert.equal(steps[0].state, 'unverified')
  assert.match(steps[0].source, /fetched from a gateway over HTTPS/)
  assert.match(steps[0].detail, /gateway is trusted the way any HTTPS site is/)
  assert.doesNotMatch(steps[0].detail, /checked against the transaction id/)
  assert.equal(summarize(steps).state, 'partial', 'TRUSTED, not TRUSTLESS')
})

test('every partial-status scheme keeps its lock off the trustless state', () => {
  // The registry's `status` and the trust model's verdict are two statements
  // of one fact. No exceptions: a `partial` row may never report TRUSTLESS.
  const partial = SCHEME_TABLE.filter((r) => r.status === 'partial').map((r) => r.scheme)
  assert.ok(partial.includes('ar') && partial.includes('ens'), 'the awkward two are in the set')
  for (const scheme of partial) {
    const state = summarize(schemeSteps(sampleUrl(scheme))).state
    assert.notEqual(state, 'verified',
      `${scheme} is 'partial' in the registry and must not report a trustless lock`)
  }
})
