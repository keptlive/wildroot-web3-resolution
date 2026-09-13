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
    ipns: [/Content/, /signed pointer/, 'verified'],
    ssb: [/Content/, /feed key/, 'verified'],
    magnet: [/Address/, /only a pointer to a torrent/, 'none'],
    did: [/Identifier/, /not audited/, 'unverified'],
    ar: [/Content/, /trusted the way any HTTPS site is/, 'unverified'],
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
  // A DNS policy that refuses new lookups is a SETTING, not an observation: the
  // page in front of the user may have loaded from cache, so the step is
  // `unverified` and names the policy, and the lock stays closed. Only a step
  // that was actually checked and did not pass opens it.
  const failClosed = schemeSteps('https://example.com/', { mode: 'secure', servers: [], failClosed: true })
  assert.equal(failClosed[0].state, 'unverified')
  assert.match(failClosed[0].detail, /configured policy, not an observed lookup failure/)
  assert.equal(summarize(failClosed).state, 'partial')
  assert.equal(verdict('https://example.com/').open, false)
  // ...and an observed failure still does open it.
  assert.equal(summarize([{ label: 'Domain name', state: 'failed', source: 'x' }]).state, 'failed')
})

test('summarize drops only steps marked NOT APPLICABLE, never a missing one', () => {
  // `applicable: false` says "this check does not apply to this kind of page".
  // It must never be reachable from "we could not run it": a `none` step with
  // no flag still weakens the verdict, which is what keeps an absent
  // protection from reading as a present one.
  const base = [{ label: 'Page', state: 'verified', source: 'x' }]
  assert.equal(summarize(base).state, 'verified')
  assert.equal(summarize([...base, { label: 'Connection', state: 'none', source: 'x' }]).state, 'open')
  assert.equal(summarize([...base, { label: 'Content', state: 'none', source: 'x' }]).state, 'partial')
  assert.equal(summarize([...base, { label: 'Content', state: 'none', source: 'x', applicable: false }]).state,
    'verified', 'an explicitly inapplicable step is the only kind that drops out')
  assert.equal(summarize([{ label: 'Content', state: 'none', source: 'x', applicable: false }]).state,
    'unknown', 'and dropping every step leaves nothing known, not a pass')
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
  assert.match(one.summary, /Not verified: domain name\./)
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

test('the ICANN name step distinguishes configured, unconfigured and oblivious — and never claims to have watched', () => {
  // Every arm is `unverified`: none of them observed the lookup this page used.
  // What varies is the sentence, and each one has to be honest about which of
  // "configured", "recently active" and "answered this name" it is stating.
  const plain = schemeSteps('https://example.com/', { mode: 'off', servers: [] })[0]
  assert.equal(plain.state, 'unverified')
  assert.match(plain.source, /DNS lookup path not observed/)
  assert.match(plain.detail, /secure DNS is disabled/i)

  const encrypted = schemeSteps('https://example.com/',
    { mode: 'secure', servers: ['https://dns.example/dns-query'] })[0]
  assert.match(encrypted.source, /Secure DNS configured: dns\.example — NOT oblivious/)
  assert.match(encrypted.detail, /configured resolver list, not the endpoint observed/)
  assert.match(encrypted.detail, /Unencrypted DNS is refused/)

  const automatic = schemeSteps('https://example.com/',
    { mode: 'automatic', servers: ['https://dns.example/dns-query'] })[0]
  assert.match(automatic.detail, /falls back to unencrypted system DNS/)

  // The oblivious arm needs a RECENT LOOKUP OF THIS HOST, with both endpoints.
  const oblivious = schemeSteps('https://example.com/', null,
    { live: true, evidence: 'recent-lookup', host: 'example.com', relay: 'relay.example', target: 'target.example' })[0]
  assert.match(oblivious.source, /Recent Oblivious DoH lookup — relay relay\.example → target target\.example/)
  assert.equal(oblivious.state, 'unverified', 'oblivious is a privacy property, not a verification')
  assert.match(oblivious.detail, /not proof that this page used that answer/)

  // A live bridge with no record of THIS host does not license the word.
  const otherHost = schemeSteps('https://example.com/', { oblivious: true, mode: 'secure', servers: [] },
    { live: true, evidence: 'recent-lookup', host: 'elsewhere.example', relay: 'relay.example', target: 'target.example' })[0]
  assert.doesNotMatch(otherHost.source, /Recent Oblivious DoH lookup/)
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
  assert.match(secureOnly.source, /Oblivious bridge configured — no recent lookup evidence/)
  assert.match(secureOnly.detail, /no recent successful bridge lookup recorded for example\.com/)
  assert.match(secureOnly.detail, /may have reused a cached answer/)

  const automatic = schemeSteps('https://example.com/',
    { mode: 'automatic', servers: ['https://bridge.local/dns-query'], oblivious: true })[0]
  assert.match(automatic.source, /Resolver not determined — no recent oblivious lookup evidence/)
  assert.match(automatic.detail, /does not show that fallback occurred/)

  // `secure` with no server is a POLICY to refuse new lookups. The panel says
  // exactly that and no more: it did not watch a lookup fail, and a cached
  // answer may be what the page in front of the user loaded from.
  const failClosed = schemeSteps('https://example.com/',
    { mode: 'secure', servers: [], failClosed: true })[0]
  assert.equal(failClosed.state, 'unverified')
  assert.match(failClosed.source, /Secure DNS configured to refuse new lookups/)
  assert.match(failClosed.detail, /configured policy, not an observed lookup failure/)
  assert.match(failClosed.detail, /cached answers may still exist/)

  // A recorded oblivious lookup of this host outranks every plan arm: it is the
  // one case where anything was actually observed.
  const live = schemeSteps('https://example.com/',
    { mode: 'secure', servers: [], failClosed: true },
    { live: true, evidence: 'recent-lookup', host: 'example.com', relay: 'r.example', target: 't.example' })[0]
  assert.match(live.source, /Oblivious DoH/)
})

test('ens:// is TRUSTED and never green', () => {
  const steps = schemeSteps('ens://vitalik.eth/')
  assert.equal(steps.length, 2)
  assert.equal(steps[0].state, 'unverified')
  assert.match(steps[0].detail, /does not run an Ethereum light client/)
  // The content step is a SECOND question, and the scheme does not answer it:
  // an ENS name may point at IPFS, IPNS or Arweave, and which checks a given
  // fetch completed is not known when this step is written.
  assert.equal(steps[1].state, 'unverified',
    'no byte check is claimed from the scheme alone')
  assert.match(steps[1].detail, /scheme alone does not establish/)

  // With a recorded result for THIS request, from the component that did the
  // work, the step may say verified — and says which half is still trusted.
  const evidence = { ens: { url: 'ens://vitalik.eth/', ok: true, protocol: 'ipfs', verifiedBytes: true } }
  const withEvidence = schemeSteps('ens://vitalik.eth/', null, null, evidence)
  assert.equal(withEvidence[1].state, 'verified')
  assert.match(withEvidence[1].detail, /name-to-content mapping remains RPC-trusted/)
  assert.equal(summarize(withEvidence).state, 'partial', 'and the lock still never goes green')
  // A record for a DIFFERENT url, or one that did not verify bytes, does not.
  for (const wrong of [
    { ens: { url: 'ens://someone-else.eth/', ok: true, protocol: 'ipfs', verifiedBytes: true } },
    { ens: { url: 'ens://vitalik.eth/', ok: true, protocol: 'arweave' } },
    { ens: { url: 'ens://vitalik.eth/', ok: false, protocol: 'ipfs', verifiedBytes: true } }
  ]) {
    assert.equal(schemeSteps('ens://vitalik.eth/', null, null, wrong)[1].state, 'unverified')
  }
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
