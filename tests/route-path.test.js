/*
 * src/hns/route-path.js — the route workup beside the trust workup: per hop,
 * who saw what, in the mode the page loaded under, with what the other mode
 * would have done. The rule under test: the same page yields the same hops
 * in both modes, and only the ROUTE column (and its sentence) differs.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { hnsRoute, schemeRoute, summarizeRoute } from '../src/route-path.js'

const site = { kind: 'site', address: '203.0.113.5', ns: '198.51.100.1', tlsa: [{}], dnssecValidated: true }
const FAST = { mode: 'fast', anonymized: false, transport: 'https-dane' }
const PRIVATE = { mode: 'private', anonymized: true, transport: 'https-dane' }

test('an A-record site: the same three hops in both modes, direct in Fast, through Tor in Private', () => {
  const fast = hnsRoute('alice.w3', site, FAST)
  const priv = hnsRoute('alice.w3', site, PRIVATE)
  assert.deepEqual(fast.map((h) => h.label), ['Handshake name', 'Zone records', 'Connection'])
  assert.deepEqual(priv.map((h) => h.label), fast.map((h) => h.label), 'the hops are the same; only the route differs')
  assert.deepEqual(fast.map((h) => h.route), ['direct', 'direct', 'direct'])
  assert.deepEqual(priv.map((h) => h.route), ['tor', 'tor', 'tor'])
  for (const h of [...fast, ...priv]) {
    assert.ok(h.source && h.detail && h.alt, `${h.label}: source, detail and the other mode's sentence are all present`)
  }
  assert.match(fast[2].alt, /In Private/)
  assert.match(priv[2].alt, /In Fast/)
  assert.match(priv[2].detail, /Tor exit/)
  assert.match(fast[2].detail, /this computer's address/)
})

test('the summary counts the hops that showed the address, and Private shows none', () => {
  const fast = summarizeRoute('fast', hnsRoute('alice.w3', site, FAST))
  assert.equal(fast.label, 'Fast — the quickest route')
  assert.match(fast.summary, /Every step showed someone/)
  const priv = summarizeRoute('private', hnsRoute('alice.w3', site, PRIVATE))
  assert.equal(priv.label, 'Private — through Tor')
  assert.match(priv.summary, /No step showed anyone/)
})

test('a DoH-resolved name says whether the lookup was oblivious, and what the other mode does about the fallback', () => {
  const obl = hnsRoute('x.w3', { kind: 'site', trust: 'doh', oblivious: true, via: 'relay.example', address: '203.0.113.1', tlsa: [] }, { ...FAST, transport: 'http' })
  assert.equal(obl[0].route, 'oblivious')
  assert.match(obl[0].alt, /In Private this is the only route/)
  const plain = hnsRoute('x.w3', { kind: 'site', trust: 'doh', endpoint: 'doh.example', address: '203.0.113.1', tlsa: [] }, { ...FAST, transport: 'http' })
  assert.equal(plain[0].route, 'direct')
  assert.match(plain[0].alt, /never taken/)
})

test('a content pointer: peers in Fast; the stated origin through Tor, or refused without one, in Private', () => {
  const withOrigin = { kind: 'ipfs', cid: 'bafy', origin: 'https://store.example/x.car' }
  const fast = hnsRoute('v.w3', withOrigin, { mode: 'fast', anonymized: false })
  assert.equal(fast[1].label, 'Content')
  assert.equal(fast[1].route, 'direct')
  assert.match(fast[1].source, /store\.example/)
  const priv = hnsRoute('v.w3', withOrigin, { mode: 'private', anonymized: true })
  assert.equal(priv[1].route, 'tor')
  assert.match(priv[1].source, /stated origin store\.example, through Tor/)
  const refused = hnsRoute('v.w3', { kind: 'ipfs', cid: 'bafy' }, { mode: 'private', anonymized: true })
  assert.equal(refused[1].route, 'refused')
  assert.match(summarizeRoute('private', refused).summary, /refused rather than sent unprotected/)
})

test('peer-to-peer kinds are direct in Fast and refused in Private; a registry read and a refused connection are named', () => {
  assert.equal(hnsRoute('t.w3', { kind: 'bittorrent' }, { mode: 'fast' })[1].route, 'direct')
  assert.equal(hnsRoute('t.w3', { kind: 'hyper' }, { mode: 'private', anonymized: true })[1].route, 'refused')
  const op = hnsRoute('a.persist', { kind: 'site', op: { registry: '0xabc', rpc: 'rpc.example' }, address: '203.0.113.9', tlsa: [] }, { ...FAST, transport: 'http' })
  assert.equal(op[1].label, 'Name records')
  assert.equal(op[1].route, 'direct')
  const refused = hnsRoute('r.w3', { kind: 'site', address: '203.0.113.9', tlsa: [] }, { mode: 'fast', transport: 'refused' })
  assert.equal(refused.at(-1).route, 'refused')
})

test('an ordinary web page: the connection is known, the name lookup is not', () => {
  // Chromium resolves an http(s) host itself, and this process sees neither
  // the query nor a cache hit. The DNS setting says what was CONFIGURED; it
  // cannot say which endpoint answered for this page. So the hop is `unknown`
  // in every branch, and the row names the configuration as configuration.
  const plain = schemeRoute('https://example.com/', { mode: 'automatic', servers: [] }, null, { mode: 'fast' })
  assert.deepEqual(plain.map((h) => [h.label, h.route]), [['Domain name', 'unknown'], ['Connection', 'direct']])
  assert.match(plain[0].source, /Automatic DNS configured — lookup not recorded/)
  const off = schemeRoute('https://example.com/', { mode: 'off', servers: [] }, null, { mode: 'fast' })
  assert.match(off[0].source, /System DNS configured/)
  const encrypted = schemeRoute('https://example.com/', { mode: 'secure', servers: ['https://dns.example/dns-query'] }, null, { mode: 'fast' })
  assert.equal(encrypted[0].route, 'unknown', 'a configured resolver is not an observed one')
  assert.match(encrypted[0].source, /Secure DNS configured — no matching lookup recorded/)
  assert.match(encrypted[0].detail, /dns\.example/, 'the configured endpoints are still named')
  // With the bridge's own record for this exact host, the row names the relay
  // and the target — and still says what that record is and is not.
  const priv = schemeRoute('https://example.com/', { mode: 'secure', servers: ['https://127.0.0.1:1/'], oblivious: true }, { live: true, relay: 'relay.example', target: 'odoh.hns.one' }, { mode: 'private', anonymized: true })
  assert.deepEqual(priv.map((h) => h.route), ['unknown', 'tor'])
  assert.match(priv[0].source, /Recent ODoH activity — relay relay\.example → target odoh\.hns\.one/)
  assert.match(priv[0].detail, /records a lookup, not the DNS route or cache used by this page/)
  // One unrecorded hop decides the summary: it may not claim the page was
  // routed the way the rest of the hops were.
  assert.match(summarizeRoute('private', priv).summary, /Some route details were not recorded/)
})

test('other schemes: built-in pages are local, onion needs Tor, peers are refused in Private', () => {
  assert.equal(schemeRoute('wildroot://welcome', null, null, { mode: 'fast' })[0].route, 'local')
  assert.equal(schemeRoute('http://abc.onion/', null, null, { mode: 'fast', anonymized: false })[0].route, 'refused')
  assert.equal(schemeRoute('http://abc.onion/', null, null, { mode: 'private', anonymized: true })[0].route, 'tor')
  assert.equal(schemeRoute('ipfs://bafy', null, null, { mode: 'fast' })[0].route, 'direct')
  assert.equal(schemeRoute('ipfs://bafy', null, null, { mode: 'private', anonymized: true })[0].route, 'refused')
  assert.equal(schemeRoute('magnet:?xt=urn:btih:abc', null, null, { mode: 'fast' })[0].route, 'direct')
  assert.equal(schemeRoute('not a url', null, null, {}).length, 0)
})
