import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { schnorr } from '@noble/curves/secp256k1'
import {
  queryRelay, queryRelays, matchesFilter, isSafeRelayUrl, normalizeRelayUrl
} from '../src/relay.js'
import { eventId } from '../src/event.js'

// A relay is a transport, not an authority. These tests exercise that claim
// against a relay that actively misbehaves, because "we verify signatures" is
// only worth what the code does when a relay lies.

function signedEvent (content = 'hello', sk = schnorr.utils.randomPrivateKey()) {
  const pubkey = Buffer.from(schnorr.getPublicKey(sk)).toString('hex')
  const base = { pubkey, created_at: 1700000000, kind: 1, tags: [], content }
  const id = eventId(base)
  return { ...base, id, sig: Buffer.from(schnorr.sign(id, sk)).toString('hex') }
}

/** Scripted relay: replays the frames it is given, then EOSE. */
function FakeRelay (frames, { failOpen = false, silent = false } = {}) {
  return class {
    constructor (url) {
      this.url = url
      setTimeout(() => {
        if (failOpen) { this.onerror && this.onerror(new Error('refused')); return }
        this.onopen && this.onopen()
      }, 0)
    }

    send (raw) {
      if (silent) return
      const [type, subId] = JSON.parse(raw)
      if (type !== 'REQ') return
      setTimeout(() => {
        for (const f of frames) {
          this.onmessage && this.onmessage({ data: JSON.stringify(['EVENT', subId, f]) })
        }
        this.onmessage && this.onmessage({ data: JSON.stringify(['EOSE', subId]) })
      }, 0)
    }

    close () {}
  }
}

test('a well-behaved relay returns its events', async () => {
  const ev = signedEvent()
  const res = await queryRelay('wss://good.example', { ids: [ev.id] },
    { WebSocketImpl: FakeRelay([ev]) })
  assert.equal(res.events.length, 1)
  assert.equal(res.events[0].id, ev.id)
})

test('a relay that TAMPERS with content has its event discarded', async () => {
  const ev = signedEvent('the original')
  const tampered = { ...ev, content: 'the relay rewrote this' }
  const res = await queryRelay('wss://liar.example', { ids: [ev.id] },
    { WebSocketImpl: FakeRelay([tampered]) })
  assert.deepEqual(res.events, [], 'tampered content must never reach the page')
  assert.equal(res.rejected.length, 1)
  assert.match(res.rejected[0].reason, /id does not match/)
})

test('a relay that FORGES an event from another author has it discarded', async () => {
  const victim = signedEvent()
  const forged = { ...signedEvent('I did not write this'), pubkey: victim.pubkey }
  forged.id = eventId(forged) // make the id self-consistent; only the sig can catch this
  const res = await queryRelay('wss://forger.example', {},
    { WebSocketImpl: FakeRelay([forged]) })
  assert.deepEqual(res.events, [])
  assert.match(res.rejected[0].reason, /does not verify/)
})

test('junk frames and non-JSON do not crash or resolve into events', async () => {
  const Junk = class {
    constructor () { setTimeout(() => this.onopen && this.onopen(), 0) }
    send (raw) {
      const [, subId] = JSON.parse(raw)
      setTimeout(() => {
        this.onmessage({ data: 'not json at all' })
        this.onmessage({ data: JSON.stringify({ not: 'an array' }) })
        this.onmessage({ data: JSON.stringify(['EVENT', subId, null]) })
        this.onmessage({ data: JSON.stringify(['NOTICE', 'chatter']) })
        this.onmessage({ data: JSON.stringify(['EOSE', subId]) })
      }, 0)
    }

    close () {}
  }
  const res = await queryRelay('wss://junk.example', {}, { WebSocketImpl: Junk })
  assert.deepEqual(res.events, [])
})

test('a dead relay resolves as an error, it does not hang or throw', async () => {
  const res = await queryRelay('wss://dead.example', {},
    { WebSocketImpl: FakeRelay([], { failOpen: true }) })
  assert.deepEqual(res.events, [])
  assert.ok(res.error)
})

test('a silent relay times out rather than hanging forever', async () => {
  const res = await queryRelay('wss://blackhole.example', {},
    { WebSocketImpl: FakeRelay([], { silent: true }), timeout: 60 })
  assert.equal(res.error, 'timed out')
})

test('missing WebSocket is reported, never silently zero results', async () => {
  // Deliberately NOT a real connection: this test must never touch the
  // network, so the global is removed for the duration rather than letting
  // the call fall through to it.
  const saved = globalThis.WebSocket
  delete globalThis.WebSocket
  try {
    const res = await queryRelay('wss://x.example', {}, {})
    assert.ok(res.error, 'a runtime with no WebSocket must say so')
    assert.match(res.error, /WebSocket/)
    assert.deepEqual(res.events, [])
  } finally {
    if (saved) globalThis.WebSocket = saved
  }
})

test('one hostile relay cannot poison a fan-out; the honest one still wins', async () => {
  const ev = signedEvent('genuine')
  const tampered = { ...ev, content: 'poisoned' }
  // Both relays answer; only the honest event survives verification.
  const perUrl = {
    'wss://honest.example': FakeRelay([ev]),
    'wss://hostile.example': FakeRelay([tampered])
  }
  const Multi = class {
    constructor (url) {
      const Impl = perUrl[url]
      this.inner = new Impl(url)
      this.inner.onopen = () => this.onopen && this.onopen()
      this.inner.onmessage = (m) => this.onmessage && this.onmessage(m)
    }

    send (raw) { this.inner.send(raw) }
    close () {}
  }
  const res = await queryRelays(
    ['wss://honest.example', 'wss://hostile.example'], { ids: [ev.id] },
    { WebSocketImpl: Multi })
  assert.equal(res.events.length, 1)
  assert.equal(res.events[0].content, 'genuine')
  assert.equal(res.rejected.length, 1)
  assert.equal(res.rejected[0].relay, 'wss://hostile.example')
})

test('duplicate events across relays are de-duplicated by id', async () => {
  const ev = signedEvent()
  const Same = FakeRelay([ev])
  const res = await queryRelays(['wss://a.example', 'wss://b.example'], {},
    { WebSocketImpl: Same })
  assert.equal(res.events.length, 1)
  assert.equal(res.verifiedCount, 2, 'both relays verified it; only one is shown')
})

test('the event id really is sha256 of the NIP-01 serialization', () => {
  const ev = signedEvent('canonical check')
  const serial = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content])
  assert.equal(ev.id, createHash('sha256').update(serial, 'utf8').digest('hex'))
})

// ------------------------------------------------- the answer must be an answer

test('matchesFilter: an event answers only the question it was returned for', () => {
  const ev = {
    id: 'a'.repeat(64),
    pubkey: 'b'.repeat(64),
    kind: 1,
    created_at: 1700000000,
    tags: [['d', 'my-article'], ['e', 'c'.repeat(64)]],
    content: ''
  }
  assert.equal(matchesFilter(ev, {}), true, 'an empty filter asks nothing and refuses nothing')
  assert.equal(matchesFilter(ev, { ids: [ev.id] }), true)
  assert.equal(matchesFilter(ev, { ids: ['d'.repeat(64)] }), false)
  assert.equal(matchesFilter(ev, { authors: [ev.pubkey] }), true)
  assert.equal(matchesFilter(ev, { authors: ['d'.repeat(64)] }), false)
  assert.equal(matchesFilter(ev, { kinds: [1] }), true)
  assert.equal(matchesFilter(ev, { kinds: [0] }), false)
  assert.equal(matchesFilter(ev, { '#d': ['my-article'] }), true)
  assert.equal(matchesFilter(ev, { '#d': ['another'] }), false)
  assert.equal(matchesFilter(ev, { since: ev.created_at }), true)
  assert.equal(matchesFilter(ev, { since: ev.created_at + 1 }), false)
  assert.equal(matchesFilter(ev, { until: ev.created_at }), true)
  assert.equal(matchesFilter(ev, { until: ev.created_at - 1 }), false)
  assert.equal(matchesFilter(null, { ids: [] }), false)
  assert.equal(matchesFilter(ev, null), false)
})

test('a relay that answers a DIFFERENT question has its event discarded and reported', async () => {
  // The event is genuinely signed — by somebody else, about something else.
  // A signature check cannot catch this and is not what catches it.
  const asked = signedEvent('what was asked for')
  const substitute = signedEvent('what the relay wanted you to read')
  const res = await queryRelay('wss://substitute.example', { ids: [asked.id] },
    { WebSocketImpl: FakeRelay([substitute]) })
  assert.deepEqual(res.events, [])
  assert.equal(res.rejected.length, 1)
  assert.match(res.rejected[0].reason, /does not match the filter/)
})

// ---------------------------------------------------------- attacker-chosen URLs

test('isSafeRelayUrl: only a public wss:// host may be dialled', () => {
  for (const good of ['wss://relay.example.com', 'wss://nos.lol/', 'wss://8.8.8.8:4848']) {
    assert.equal(isSafeRelayUrl(good), true, good)
  }
  for (const bad of [
    'ws://relay.example.com', // plaintext
    'http://relay.example.com', // not a websocket at all
    'wss://localhost:7000',
    'wss://box.localhost',
    'wss://nas.local',
    'wss://printer.lan',
    'wss://intranet.internal',
    'wss://router.home',
    'wss://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion',
    'wss://1.0.0.127.in-addr.arpa',
    'wss://127.0.0.1:9999',
    'wss://192.168.1.1:8080',
    'wss://10.0.0.1',
    'wss://169.254.169.254', // the cloud metadata service
    'wss://[::1]:9999',
    'wss://[fd00::1]',
    'not a url at all',
    '',
    null
  ]) {
    assert.equal(isSafeRelayUrl(bad), false, String(bad))
  }
})

test('normalizeRelayUrl: one spelling per relay, so one socket per relay', () => {
  assert.equal(normalizeRelayUrl('wss://nos.lol/'), 'wss://nos.lol')
  assert.equal(normalizeRelayUrl('wss://NOS.LOL'), 'wss://nos.lol')
  assert.equal(normalizeRelayUrl('  wss://nos.lol  '), 'wss://nos.lol')
  assert.equal(normalizeRelayUrl('wss://nos.lol/#frag'), 'wss://nos.lol')
  assert.equal(normalizeRelayUrl('wss://nos.lol/inbox'), 'wss://nos.lol/inbox')
  // A string that will not parse comes back as it came, for the caller's
  // safety check to refuse — never silently repaired into something dialable.
  assert.equal(normalizeRelayUrl('nonsense'), 'nonsense')
  assert.equal(isSafeRelayUrl(normalizeRelayUrl('nonsense')), false)
})
