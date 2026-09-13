/*
 * What the oblivious bridge is allowed to record, and therefore what the
 * panel is allowed to say about an ICANN name (SPEC §5.3, §6.2).
 *
 * The failure this guards is the quiet one. HPKE authenticates the bytes that
 * travelled between this process and the target; it says nothing about what
 * those bytes MEAN as DNS. A relay or target that returns an empty body, a
 * truncated packet, or a perfectly well-formed answer to a DIFFERENT question
 * still produces an HPKE-valid decryption — and if that counted as "the
 * bridge answered this host", the security panel could be made to name a
 * relay and a target for a lookup that was never answered.
 *
 * So the bridge binds the reply to the question it asked (RFC 1035 §4.1.1's
 * header and §4.1.2's question section) before anything is recorded, and a
 * reply that fails the binding is a failure: SERVFAIL to the engine, and an
 * entry that also clears whatever success came before it, so an older answer
 * cannot stay current for a host whose most recent lookup failed.
 *
 * The wire-format parser itself (compression pointers, the 255-octet name
 * limit, trailing bytes) is exercised by the top-level bridge suite. What is
 * here is the ICANN-chapter consequence: an unbound reply must never become a
 * claim in the interface.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import https from 'node:https'

import { OdohBridge } from '../../../src/odoh-bridge.js'
import { generateLoopbackCert } from '../../../src/self-cert.js'
import { schemeSteps } from '../../../src/trust-path.js'
import { icannBridgeState, planDnsTransport } from '../src/dns-policy.js'

const ODOH = {
  enabled: true,
  icann: true,
  targets: [{ host: 'odoh.example', path: '/dns-query' }],
  relays: ['https://relay.example/relay']
}

// One certificate for the whole file: minting is per launch in the browser,
// and nothing here is testing the certificate.
const TLS = generateLoopbackCert()

/** `example.com. IN A`, the question every test below asks. */
const query = (id = 0xabcd) => Buffer.concat([
  Buffer.from([id >> 8, id & 0xff, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]),
  Buffer.from([7]), Buffer.from('example'), Buffer.from([3]), Buffer.from('com'),
  Buffer.from([0, 0, 1, 0, 1])
])

/** The reply that answers it, before a test breaks the binding. */
function reply () {
  const packet = Buffer.from(query())
  packet[2] |= 0x80 // QR
  return packet
}

/** A transport that answers from memory, naming the route that answered. */
function fakeTransport (answerFor = () => reply()) {
  return {
    async query (wire) {
      return { answer: answerFor(wire), via: 'answering-relay.example', target: 'answering-target.example' }
    }
  }
}

async function withBridge (transport, fn) {
  const bridge = new OdohBridge({ transport, targets: [], relays: [], tls: TLS })
  await bridge.start()
  try {
    return await fn(bridge)
  } finally {
    await bridge.stop()
  }
}

/** One DoH GET, exactly as the engine would make it. */
function doh (bridge, wire = query()) {
  const agent = new https.Agent({ ca: bridge._tls.cert, checkServerIdentity: () => undefined })
  const path = bridge.secretPath + '?dns=' + wire.toString('base64url')
  return new Promise((resolve, reject) => {
    const req = https.request(`https://127.0.0.1:${bridge.port}${path}`, { agent }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }))
    })
    req.on('error', reject)
    req.end()
  })
}

/** The Domain name step the panel would render for this bridge state. */
function nameStep (bridge, host = 'example.com') {
  const plan = planDnsTransport({ dns: { mode: 'secure', servers: [] }, odoh: ODOH, bridge })
  const [step] = schemeSteps(`https://${host}/`, plan, icannBridgeState(bridge, host))
  return step
}

test('a reply bound to its question is evidence, and the panel names the route that answered', async () => {
  await withBridge(fakeTransport(), async (bridge) => {
    const answer = await doh(bridge)
    assert.equal(answer.status, 200)
    const evidence = bridge.recentEvidence('example.com')
    assert.equal(evidence.host, 'example.com')
    assert.equal(evidence.queryType, 1)
    assert.equal(evidence.rcode, 0)
    assert.equal(evidence.evidence, 'recent-lookup', 'the record says what kind of thing it is')
    // The route recorded is the one the transport reported, not the first
    // configured relay and target.
    assert.equal(evidence.relay, 'answering-relay.example')
    assert.equal(evidence.target, 'answering-target.example')
    const step = nameStep(bridge)
    assert.match(step.source, /Recent Oblivious DoH lookup/)
    assert.match(step.source, /answering-relay\.example/)
    assert.match(step.source, /answering-target\.example/)
    assert.match(step.detail, /not proof that this page used that answer/)
  })
})

test('a reply that does not answer this query is a failure, not evidence', async () => {
  // Each of these decrypts perfectly well. None of them answers
  // `example.com. IN A` asked with this id, so none of them may put a relay
  // and a target in front of a user.
  const broken = (update) => () => {
    const packet = reply()
    update(packet)
    return packet
  }
  const variants = {
    'an empty body': () => Buffer.alloc(0),
    'a truncated packet': () => reply().subarray(0, 11),
    'a reply with trailing bytes': () => Buffer.concat([reply(), Buffer.from([0])]),
    'a query, not a reply (QR clear)': broken((packet) => { packet[2] &= 0x7f }),
    'a truncated-flag reply': broken((packet) => { packet[2] |= 0x02 }),
    'a reply to another id': broken((packet) => { packet[0] ^= 0xff }),
    'an answer about another name': broken((packet) => { packet[13] = 0x78 }),
    'an answer of another type': broken((packet) => { packet.writeUInt16BE(28, packet.length - 4) }),
    'an answer in another class': broken((packet) => { packet.writeUInt16BE(3, packet.length - 2) }),
    'a reply carrying two questions': broken((packet) => { packet.writeUInt16BE(2, 4) })
  }
  for (const [what, answerFor] of Object.entries(variants)) {
    await withBridge(fakeTransport(answerFor), async (bridge) => {
      const answer = await doh(bridge)
      // The engine is told SERVFAIL and decides what to do next by its own
      // secure-DNS mode — the bridge never resolves by some other route.
      assert.equal(answer.status, 200, what)
      assert.equal(answer.body[3] & 15, 2, `${what}: SERVFAIL`)
      assert.equal(bridge.recentEvidence('example.com'), null, `${what}: no evidence`)
      // …and the panel says nothing about a relay or a target.
      const step = nameStep(bridge)
      assert.doesNotMatch(step.source, /Recent Oblivious DoH lookup/, what)
      assert.doesNotMatch(step.source, /answering-relay\.example/, what)
    })
  }
})

test('a failed lookup clears the earlier success, so no stale claim stays current', async () => {
  // Without this, one good answer would keep vouching for the host for ten
  // minutes while every lookup after it failed — the interface saying
  // "oblivious" for exactly the lookups that were not.
  let answerFor = () => reply()
  await withBridge(fakeTransport((wire) => answerFor(wire)), async (bridge) => {
    await doh(bridge)
    assert.ok(bridge.recentEvidence('example.com'), 'the good answer is evidence')
    answerFor = () => Buffer.alloc(0)
    await doh(bridge)
    assert.equal(bridge.recentEvidence('example.com'), null, 'the failure masks it')
    assert.doesNotMatch(nameStep(bridge).source, /Recent Oblivious DoH lookup/)
  })
})

test('only an answered or a denied name is evidence, and only that exact name', async () => {
  await withBridge(fakeTransport(), async (bridge) => {
    // NXDOMAIN is an answer: the lookup happened and the route is known.
    answerWith(bridge, 3)
    assert.equal(bridge.recentEvidence('example.com').rcode, 3)
    // A server failure is not: nothing was resolved, so nothing is claimed.
    answerWith(bridge, 2)
    assert.equal(bridge.recentEvidence('example.com'), null)
    // And a name the bridge answered never vouches for a name below it.
    answerWith(bridge, 0)
    assert.ok(bridge.recentEvidence('example.com'))
    assert.equal(bridge.recentEvidence('sub.example.com'), null)
    assert.match(nameStep(bridge, 'sub.example.com').source, /no recent lookup evidence/)
  })
})

/** Record one exchange for `example.com. IN A` with the given rcode. */
function answerWith (bridge, rcode) {
  bridge._remember('example.com', {
    queryType: 1,
    via: 'answering-relay.example',
    target: 'answering-target.example',
    rcode
  })
}
