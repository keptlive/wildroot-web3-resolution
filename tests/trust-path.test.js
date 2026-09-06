// What the lock is allowed to claim.
//
// These tests exist because the failure mode here is silent and one-directional:
// a padlock that over-claims teaches people to trust something that was never
// checked, and nobody ever gets an error message about it. So the assertions
// below are mostly about what must NOT be reported as verified.

import test from 'node:test'
import assert from 'node:assert/strict'

import { hnsSteps, schemeSteps, summarize } from '../src/trust-path.js'

const byLabel = (steps, label) => steps.find((s) => s.label === label)

const chainSite = (over = {}) => ({
  trust: 'spv',
  kind: 'site',
  address: '203.0.113.7',
  ns: 'ns1.hns.one',
  tlsa: [{ usage: 3 }],
  dnssecValidated: true,
  ...over
})

test('the complete path: chain proof, signed zone, pin, pinned TLS', () => {
  const steps = hnsSteps('14898', chainSite(), { transport: 'https-dane' })
  assert.deepEqual(steps.map((s) => s.state), ['verified', 'verified', 'verified', 'verified', 'verified'])
  assert.deepEqual(summarize(steps),
    { state: 'verified', summary: 'Every step was verified on this computer.' })
  // Every step must name its source — that is the point of the window.
  for (const s of steps) assert.ok(s.source && s.source.length > 8, `${s.label} has no source`)
})

test('a pin from an UNSIGNED zone is not the same as a proven one', () => {
  // The gap this whole module was written for: `dnssecValidated` was computed
  // and then thrown away, so "TLS pinned by DANE" was shown whether or not
  // the pin itself was anchored to the chain.
  const steps = hnsSteps('x.tld', chainSite({ dnssecValidated: false }), { transport: 'https-dane' })
  assert.equal(byLabel(steps, 'DNSSEC').state, 'none')
  assert.match(byLabel(steps, 'DNSSEC').detail, /only as trustworthy as/)
  assert.equal(byLabel(steps, 'Zone records').state, 'unverified')
  assert.equal(summarize(steps).state, 'partial')
})

test('DoH resolution is never reported as chain-verified', () => {
  const steps = hnsSteps('x.tld', {
    trust: 'doh',
    kind: 'site',
    address: '203.0.113.7',
    tlsa: [],
    allowInsecure: true,
    endpoint: 'https://dns.example/dns-query'
  }, { transport: 'http' })
  const name = byLabel(steps, 'Handshake name')
  assert.equal(name.state, 'unverified')
  assert.match(name.source, /dns\.example/)
  assert.equal(byLabel(steps, 'Connection').state, 'none')
  assert.equal(summarize(steps).state, 'partial')
})

test('an oblivious DoH resolver is labelled as such', () => {
  const steps = hnsSteps('x.tld', {
    trust: 'doh',
    kind: 'site',
    tlsa: [],
    allowInsecure: true,
    endpoint: 'https://odoh.hns.one',
    oblivious: true
  }, { transport: 'http' })
  assert.match(byLabel(steps, 'Handshake name').source, /Oblivious DoH/)
})

test('a failed DNSSEC validation is reported as failed, not merely absent', () => {
  const steps = hnsSteps('x.tld',
    { trust: 'spv', kind: 'dnssec-fail', ns: 'ns1.example', reason: 'TLSA RRSIG missing' })
  assert.equal(byLabel(steps, 'DNSSEC').state, 'failed')
  assert.equal(summarize(steps).state, 'failed')
  assert.match(summarize(steps).summary, /DNSSEC failed/)
})

test('an inconclusive TLSA lookup fails — it must never read as "no pin"', () => {
  // allowInsecure false + no records = we could not find out. Reporting that
  // as "this zone has no pin" is the downgrade the resolver refuses to make,
  // so the lock must not make it either.
  const steps = hnsSteps('x.tld',
    { trust: 'spv', kind: 'site', address: '203.0.113.7', tlsa: [], allowInsecure: false },
    { transport: 'refused' })
  assert.equal(byLabel(steps, 'DANE pin (TLSA)').state, 'failed')
  assert.equal(summarize(steps).state, 'failed')
})

test('an authoritative "no TLSA" is `none`, and says the connection is unprotected', () => {
  const steps = hnsSteps('x.tld',
    { trust: 'spv', kind: 'site', address: '203.0.113.7', tlsa: [], allowInsecure: true },
    { transport: 'http' })
  assert.equal(byLabel(steps, 'DANE pin (TLSA)').state, 'none')
  assert.match(byLabel(steps, 'Connection').detail, /read or change this page/)
})

test('content-addressed pages separate CONTENT integrity from POINTER trust', () => {
  const chain = hnsSteps('x.tld', { trust: 'spv', kind: 'ipfs', cid: 'bafyfoo' })
  assert.equal(byLabel(chain, 'Content').state, 'verified')
  assert.equal(byLabel(chain, 'Pointer'), undefined)

  const doh = hnsSteps('x.tld', { trust: 'doh', kind: 'ipfs', cid: 'bafyfoo' })
  assert.equal(byLabel(doh, 'Content').state, 'verified', 'bytes are still CID-checked')
  assert.equal(byLabel(doh, 'Pointer').state, 'unverified', 'but the name→CID claim is not')
  assert.equal(summarize(doh).state, 'partial')
})

test('https is honest about trusting the CA system', () => {
  const steps = schemeSteps('https://example.com/page')
  assert.equal(byLabel(steps, 'Connection').state, 'unverified')
  assert.match(byLabel(steps, 'Connection').detail, /certificate authority/)
  assert.equal(summarize(steps).state, 'partial')
})

test('every other scheme gets an answer rather than an empty window', () => {
  for (const url of ['http://x.test/', 'ipfs://bafyfoo', 'ipns://k51', 'ar://tx',
    'hyper://abc', 'wildroot://welcome', 'editor://new/', 'search://?q=x',
    'file:///tmp/x', 'gemini://x.test/', 'not a url']) {
    const steps = schemeSteps(url)
    assert.ok(steps.length >= 1, `${url} produced no steps`)
    for (const s of steps) {
      assert.ok(s.label && s.source, `${url}: a step is missing label/source`)
      assert.ok(['verified', 'unverified', 'failed', 'none'].includes(s.state))
    }
    assert.ok(summarize(steps).summary)
  }
})

test('the summary follows the WEAKEST link, never the strongest', () => {
  const mixed = [
    { label: 'A', state: 'verified', source: 's' },
    { label: 'B', state: 'unverified', source: 's' }
  ]
  assert.equal(summarize(mixed).state, 'partial')
  const withFailure = [...mixed, { label: 'C', state: 'failed', source: 's' }]
  assert.equal(summarize(withFailure).state, 'failed')
})

test('an oblivious Handshake lookup NAMES the relay and says so', () => {
  const steps = hnsSteps('x.tld', {
    trust: 'doh',
    kind: 'site',
    address: '203.0.113.7',
    tlsa: [],
    allowInsecure: true,
    oblivious: true,
    via: 'odoh-relay.numa.rs'
  }, { transport: 'http' })
  const name = byLabel(steps, 'Handshake name')
  assert.match(name.source, /Oblivious DoH/)
  assert.match(name.source, /odoh-relay\.numa\.rs/, 'the relay must be named')
  assert.match(name.detail, /Neither\s+alone can link you/)
})

test('a NON-oblivious Handshake lookup says NOT oblivious, loudly', () => {
  // The fallback case. It must never be mistakable for the oblivious one:
  // that resolver saw the address and the name together.
  const steps = hnsSteps('x.tld', {
    trust: 'doh',
    kind: 'site',
    address: '203.0.113.7',
    tlsa: [],
    allowInsecure: true,
    endpoint: 'query.hns.one'
  }, { transport: 'http' })
  const name = byLabel(steps, 'Handshake name')
  assert.match(name.source, /NOT oblivious/)
  assert.match(name.detail, /saw your address and the name together/)
})

test('ICANN names name the real resolver, and never imply obliviousness', () => {
  // What the user actually asked for: the lock must say how THIS name was
  // resolved, for every name — and https:// does not use our oblivious path.
  const dns = {
    mode: 'automatic',
    servers: ['https://dns.quad9.net/dns-query', 'https://cloudflare-dns.com/dns-query']
  }
  const step = byLabel(schemeSteps('https://example.com', dns), 'Domain name')
  assert.match(step.source, /dns\.quad9\.net/, 'name the resolver that did it')
  assert.match(step.source, /NOT oblivious/)
  assert.match(step.detail, /falls back to/, 'automatic mode must disclose the plaintext fallback')

  const strict = byLabel(schemeSteps('https://example.com', { mode: 'secure', servers: dns.servers }), 'Domain name')
  assert.match(strict.detail, /refused/)

  const none = byLabel(schemeSteps('https://example.com', { mode: 'off', servers: [] }), 'Domain name')
  assert.match(none.source, /unencrypted/i)
  assert.match(none.detail, /in the clear/)
})

test('no scheme step ever claims obliviousness it did not have', () => {
  for (const url of ['https://x.test/', 'http://x.test/', 'ipfs://bafy', 'ar://tx']) {
    for (const s of schemeSteps(url, { mode: 'automatic', servers: ['https://r.example/dns-query'] })) {
      if (/oblivious/i.test(s.source)) {
        assert.match(s.source, /NOT oblivious/, `${url}: ${s.source}`)
      }
    }
  }
})

test('an _op record is never reported as verified, pin or no pin', () => {
  // The whole risk of the HIP-5 route (docs/HIP5-OP.md): the chain proves WHICH
  // contract answers, and nothing proves its answer. A DANE pin that arrived
  // over that hop must not close the lock — the pin is only as good as the RPC
  // that handed it over.
  const op = { registry: '0x233b4fbf4e8f0e60bff0a5f1a24ffa257987dbf2', rpc: 'mainnet.optimism.io' }
  const steps = hnsSteps('maya.persist',
    { trust: 'spv', kind: 'site', address: '198.44.116.200', tlsa: [{ usage: 3 }], op },
    { transport: 'https-dane' })
  const record = byLabel(steps, 'Name records')
  assert.equal(record.state, 'unverified')
  assert.match(record.source, /Optimism registry 0x233b/)
  assert.match(record.source, /mainnet\.optimism\.io/)
  assert.match(record.detail, /light client/)
  assert.equal(summarize(steps).state, 'partial')
  // And no "missing DS record" step: there was no zone and no DNS answer, so
  // naming DNSSEC as the gap would point at the wrong one.
  assert.equal(byLabel(steps, 'DNSSEC'), undefined)
})

test('an _op content pointer keeps CONTENT verified and the POINTER not', () => {
  const steps = hnsSteps('ark.persist', {
    trust: 'spv',
    kind: 'ipfs',
    cid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
    op: { registry: '0x233b', rpc: 'mainnet.optimism.io' }
  })
  assert.equal(byLabel(steps, 'Content').state, 'verified')
  assert.equal(byLabel(steps, 'Name records').state, 'unverified')
  assert.equal(summarize(steps).state, 'partial')
})

test('an ar= pointer never reports its bytes as verified', () => {
  // The ar:// handler fetches from a gateway and does not check the bytes
  // against the transaction's data_root. The chain proves the POINTER; the
  // panel must not let that proof spill over onto bytes nobody checked.
  const steps = hnsSteps('ark.w3', {
    trust: 'spv', kind: 'arweave', txid: 'MJ7GaCvE_nndW-WpgX1HutkjHpDyEp1RkAgHL_P4MOg'
  })
  const content = byLabel(steps, 'Content')
  assert.equal(content.state, 'unverified')
  assert.match(content.source, /gateway/)
  assert.doesNotMatch(content.detail, /checked against the address/)
  assert.equal(byLabel(steps, 'Handshake name').state, 'verified')
  assert.equal(summarize(steps).state, 'partial')
  const dohSteps = hnsSteps('ark.w3', { trust: 'doh', kind: 'arweave', txid: 'x' })
  assert.equal(byLabel(dohSteps, 'Pointer').state, 'unverified')
})

// ---------------------------------------------------------------------------
// The panel must not describe a connection that did not happen, a zone that is
// not what it says, or a failure as a success. All three were live 2026-09-04.
// ---------------------------------------------------------------------------

test('a signed zone we could NOT validate is not called unsigned', () => {
  // The chain carries a DS for this zone; validation did not happen. Saying
  // "No DS record on chain / this zone is not signed" is false, and it
  // understates the situation in exactly the case that matters.
  const steps = hnsSteps('site.w3',
    chainSite({ dnssecValidated: false, dnssecAnchored: true }),
    { transport: 'https-dane' })
  const dnssec = byLabel(steps, 'DNSSEC')
  assert.equal(dnssec.state, 'unverified')
  assert.match(dnssec.source, /DS record on the Handshake chain/)
  assert.doesNotMatch(`${dnssec.source} ${dnssec.detail}`, /not signed|No DS record/,
    'an anchored zone was described as an unsigned one')
})

test('a genuinely unsigned zone still says so', () => {
  const steps = hnsSteps('site.w3',
    chainSite({ dnssecValidated: false, dnssecAnchored: false }),
    { transport: 'https-dane' })
  const dnssec = byLabel(steps, 'DNSSEC')
  assert.equal(dnssec.state, 'none')
  assert.match(dnssec.source, /No DS record on chain/)
})

test('the pin step does not claim a match before the handshake', () => {
  // Seen live on hns://lumeweb during a key rotation: the panel showed
  // "the certificate had to match this pin, and did" directly above
  // "Refused before connecting — the certificate did not match the pin".
  const refused = hnsSteps('lumeweb', chainSite(),
    { transport: 'refused', detail: 'The certificate did not match the pin.' })
  const pin = byLabel(refused, 'DANE pin (TLSA)')
  assert.equal(pin.state, 'unverified')
  assert.doesNotMatch(pin.detail, /and did/,
    'the panel claimed a certificate match on a connection that was refused')
  assert.equal(byLabel(refused, 'Connection').state, 'failed')

  // ...and when the handshake DID happen, it still says so.
  const ok = hnsSteps('14898', chainSite(), { transport: 'https-dane' })
  const okPin = byLabel(ok, 'DANE pin (TLSA)')
  assert.equal(okPin.state, 'verified')
  assert.match(okPin.detail, /and did/)
})

test('a failed resolution never summarizes as a verified padlock', () => {
  for (const resolution of [
    { trust: 'spv', kind: 'unregistered' },
    { trust: 'spv', kind: 'blocked', address: '169.254.169.254' },
    { trust: 'spv', kind: 'unreachable', reason: 'no reachable nameserver for pinner.hns' }
  ]) {
    const steps = hnsSteps('x.w3', resolution, {})
    const { state, summary } = summarize(steps)
    assert.notEqual(state, 'verified',
      `${resolution.kind} showed a fully green lock over an error page: ${summary}`)
    assert.ok(steps.length > 1,
      `${resolution.kind} produced only the name step, so there was nothing to be honest with`)
  }
})

test('a blocked address is named in the panel, not just in the error page', () => {
  const steps = hnsSteps('x.w3', { trust: 'spv', kind: 'blocked', address: '10.0.0.1' }, {})
  assert.match(byLabel(steps, 'Address').source, /10\.0\.0\.1/)
})

test('an unreachable zone carries its REASON into the panel', () => {
  const steps = hnsSteps('pinner.hns',
    { trust: 'spv', kind: 'unreachable', reason: 'DS lookup for pinner.hns failed' }, {})
  const records = byLabel(steps, 'Records')
  assert.equal(records.state, 'failed')
  assert.match(records.detail, /DS lookup for pinner\.hns failed/)
})

test('ens:// names the RPC hop instead of claiming no verification path', () => {
  // ens-protocol.js marks its responses `ens-rpc-unverified` and keeps the
  // lock open for it. Nothing read that header, and schemeSteps had no case,
  // so the panel fell through to "this browser has no verification path for
  // this scheme" — silent about the one hop that needs saying, on a page whose
  // content IS verified. The `_op` route already gets this right.
  const steps = schemeSteps('ens://vitalik.eth/')
  const records = steps.find((s) => s.label === 'Name records')
  assert.equal(records.state, 'unverified')
  assert.match(records.source, /RPC/)
  assert.equal(steps.find((s) => s.label === 'Content').state, 'verified')
  assert.equal(summarize(steps).state, 'partial')
  assert.ok(!steps.some((s) => /no verification path/i.test(s.detail || '')))
})
