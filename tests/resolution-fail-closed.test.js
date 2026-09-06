/*
 * The two ways resolution could be talked out of protecting someone.
 *
 * Both were live on 2026-09-04 and both were found by audit rather than by a
 * failing test, which is the part worth fixing permanently.
 *
 * 1. DROP ONE PACKET AND DNSSEC STOPS HAPPENING.
 *    The TLSA validation used to sit inside the same try/catch as the TLSA
 *    QUERY, and that catch turned every throw into `tlsaKnown = false`. So a
 *    DNSKEY fetch that failed skipped the `dnssec-fail` return entirely and
 *    fell through to a normal `site` carrying an UNVALIDATED pin. The exploit
 *    was one dropped query type: answer A and TLSA with your own address and
 *    your own pin, reset the DNSKEY connection, and the browser pins to your
 *    certificate while the padlock calls the zone unsigned. The on-chain DS
 *    was never consulted.
 *
 *    The rule being restored is dnssec-e2e.test.js's own: a resolver that
 *    validates when it can and shrugs when it cannot is a resolver an attacker
 *    simply makes unable to validate. So the test below does exactly what an
 *    attacker would — a proxy that forwards everything except QTYPE 48.
 *
 * 2. A TLD's OWN ADDRESS WAS SERVED FOR EVERY NAME UNDER IT.
 *    The SYNTH4 branch was gated on neither `host === tld` nor "the zone names
 *    no nameserver", though the sibling apex branch three lines above has
 *    both. So `www.example` never reached ns1.example: it got the TLD apex's
 *    IP over PLAINTEXT, justified in the comment by "the IP came straight from
 *    the chain" — true of the apex, false of every name beneath it. With an
 *    apex `ipfs=` TXT, every subdomain served the TLD's own site. The audit
 *    found no test anywhere that drove __resolve through a SYNTH4 record.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import net from 'node:net'

import { HNSResolver } from '../src/resolver.js'
import { dsDigest, dnskeyRdata } from '../src/dnssec.js'
import { TYPES } from '../src/dns-query.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE, withNsd as runNsd } from './nsd.js'

const PORT = await freeUdpPort()
const withNsd = (fn) => runNsd({ port: PORT }, fn)

/** The DS the chain would carry for the frozen signed fixture. */
function chainDs () {
  const signed = JSON.parse(fs.readFileSync(FIXTURE.signed, 'utf8'))
  const raw = Buffer.from(signed.dnskey, 'base64').subarray(4)
  return {
    type: 'DS',
    keyTag: signed.key_tag,
    algorithm: 13,
    digestType: 2,
    digest: dsDigest(signed.zone, dnskeyRdata(raw, 257))
  }
}

function resolverAt (port, records) {
  return new HNSResolver({
    spv: { getResource: async () => ({ records }), isSynced: async () => true },
    authoritative: { server: '127.0.0.1', port },
    timeout: 4000
  })
}

/**
 * The qtype of a length-prefixed DNS query, by walking the QNAME.
 * @param {Buffer} msg the DNS message WITHOUT the 2-byte TCP length prefix
 */
function qtypeOf (msg) {
  let i = 12
  while (i < msg.length && msg[i] !== 0) i += msg[i] + 1
  return i + 2 < msg.length ? msg.readUInt16BE(i + 1) : 0
}

/**
 * A TCP DNS proxy in front of `upstream` that DROPS one query type — the
 * on-path attacker, reduced to its smallest useful form.
 * @param {number} upstream
 * @param {number} dropType
 */
async function droppingProxy (upstream, dropType) {
  const server = net.createServer((client) => {
    client.once('data', (chunk) => {
      const msg = chunk.subarray(2)
      if (qtypeOf(msg) === dropType) return client.destroy()
      const up = net.connect({ host: '127.0.0.1', port: upstream }, () => up.write(chunk))
      up.on('error', () => client.destroy())
      client.on('error', () => up.destroy())
      up.pipe(client)
    })
    client.on('error', () => {})
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    close: () => new Promise((resolve) => server.close(resolve))
  }
}

// ---------------------------------------------------------------------------
// 1. dropping DNSKEY must not disable DNSSEC
// ---------------------------------------------------------------------------

test('BASELINE: the signed fixture validates its TLSA up to the on-chain DS', () =>
  withNsd(async () => {
    const out = await resolverAt(PORT, [{ type: 'NS', ns: 'ns1.hns.one.' }, chainDs()])
      .resolve(FIXTURE.siteHost)
    assert.equal(out.kind, 'site')
    assert.equal(out.dnssecValidated, true,
      'the fixture must validate, or the next test proves nothing')
    assert.ok(out.tlsa.length > 0)
  }))

test('dropping ONLY the DNSKEY query fails closed — it does not silently unpin', () =>
  withNsd(async () => {
    const proxy = await droppingProxy(PORT, TYPES.DNSKEY)
    try {
      const out = await resolverAt(proxy.port, [{ type: 'NS', ns: 'ns1.hns.one.' }, chainDs()])
        .resolve(FIXTURE.siteHost)
      assert.equal(out.kind, 'dnssec-fail',
        'a TLSA that could not be validated was served as a usable pin: ' +
        JSON.stringify(out))
      assert.notEqual(out.dnssecValidated, true)
    } finally {
      await proxy.close()
    }
  }))

test('dropping DNSKEY on the POINTER path fails closed too', () =>
  withNsd(async () => {
    const proxy = await droppingProxy(PORT, TYPES.DNSKEY)
    try {
      const out = await resolverAt(proxy.port, [{ type: 'NS', ns: 'ns1.hns.one.' }, chainDs()])
        .resolve(FIXTURE.pointerHost)
      assert.equal(out.kind, 'dnssec-fail', JSON.stringify(out))
    } finally {
      await proxy.close()
    }
  }))

test('an UNSIGNED zone is unaffected — there is no guarantee to downgrade FROM', () =>
  withNsd(async () => {
    const proxy = await droppingProxy(PORT, TYPES.DNSKEY)
    try {
      // No DS on chain, so nothing claims this zone is signed and the missing
      // DNSKEY is not evidence of anything. It must still resolve.
      const out = await resolverAt(proxy.port, [{ type: 'NS', ns: 'ns1.hns.one.' }])
        .resolve(FIXTURE.siteHost)
      assert.equal(out.kind, 'site')
      assert.equal(out.dnssecValidated, false)
    } finally {
      await proxy.close()
    }
  }))

// ---------------------------------------------------------------------------
// 2. a TLD's own address is the TLD's own
// ---------------------------------------------------------------------------

const SYNTH = { type: 'SYNTH4', address: '198.51.100.10' }
const APEX_POINTER = { type: 'TXT', txt: ['ipfs=bafkreiabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopq'] }
const NS = { type: 'NS', ns: 'ns1.example.' }

/** No `authoritative`, so a SYNTH4 answer must come from the chain alone. */
function chainOnly (records) {
  return new HNSResolver({
    spv: { getResource: async () => ({ records }), isSynced: async () => true },
    timeout: 1000
  })
}

test('a SYNTH4 TLD serves its own apex', async () => {
  const out = await chainOnly([SYNTH]).resolve('example')
  assert.equal(out.kind, 'site')
  assert.equal(out.address, SYNTH.address)
  assert.equal(out.allowInsecure, true, 'consensus attests this IP, so plaintext is allowed')
})

test('a SUBDOMAIN never inherits the TLD\'s SYNTH4 address', async () => {
  const out = await chainOnly([SYNTH]).resolve('www.example')
  assert.notEqual(out.kind, 'site',
    `www.example was served the TLD's own IP: ${JSON.stringify(out)}`)
  assert.notEqual(out.allowInsecure, true, 'and over plaintext, at that')
})

test('a SUBDOMAIN never inherits the TLD\'s apex content pointer', async () => {
  const out = await chainOnly([SYNTH, APEX_POINTER]).resolve('www.example')
  assert.notEqual(out.kind, 'ipfs',
    `www.example served the TLD's own site: ${JSON.stringify(out)}`)
})

test('with no NS and no authority, a subdomain is unregistered — not the apex', async () => {
  const out = await chainOnly([APEX_POINTER]).resolve('www.example')
  assert.notEqual(out.kind, 'ipfs', JSON.stringify(out))
})

test('a TLD that names a nameserver is ASKED, even when it also has SYNTH4', async () => {
  // A nameserver can be asked for a TLSA; this branch cannot. The sibling apex
  // branch already refuses to answer from the chain when NS is present, and
  // the SYNTH4 copy must follow the same rule rather than pre-empting it with
  // a plaintext answer.
  //
  // `ns1.example` does not exist, so taking the nameserver route THROWS here —
  // and that throw is the evidence: before the fix this returned a cheerful
  // plaintext `site` without ever trying to ask anyone.
  let out = null
  try {
    out = await chainOnly([SYNTH, NS]).resolve('example')
  } catch (err) {
    assert.match(String(err.message), /ENOTFOUND|nameserver|EAI_AGAIN/,
      'it should have failed while trying to REACH the nameserver')
    return
  }
  assert.notEqual(out.allowInsecure, true,
    `the plaintext shortcut won over an askable nameserver: ${JSON.stringify(out)}`)
})

test('a private SYNTH4 address is still blocked at the apex', async () => {
  const out = await chainOnly([{ type: 'SYNTH4', address: '169.254.169.254' }]).resolve('example')
  assert.equal(out.kind, 'blocked')
})

// ---------------------------------------------------------------------------
// 3. saying the TRUE thing when we cannot verify
// ---------------------------------------------------------------------------

test('a zone signed with an algorithm we cannot check is not accused of tampering', async () => {
  // dsRecords of every algorithm used to be carried through as "this zone is
  // signed"; validation then found no usable DS and the user was told someone
  // was "tampering with its DNS answers" about a zone that had simply chosen
  // an algorithm we did not do. Still fail closed — we cannot verify it — but
  // say what is true. (RSASHA256 was the example here until 2026-09-05, when
  // it became supported per RFC 8624; ED448 (16) is the stand-in now.)
  const out = await chainOnly([
    { type: 'NS', ns: 'ns1.example.' },
    { type: 'DS', keyTag: 1, algorithm: 16, digestType: 2, digest: 'ab'.repeat(32) }
  ]).resolve('www.example')
  assert.equal(out.kind, 'dnssec-unsupported', JSON.stringify(out))
  assert.match(out.reason, /algorithm 16/)
})

test('a supported DS alongside an unsupported one is still verifiable', async () => {
  // A zone mid-rollover publishes both. One usable anchor is enough, and this
  // must NOT take the refusal branch above.
  const out = await chainOnly([
    { type: 'NS', ns: 'ns1.example.' },
    { type: 'DS', keyTag: 1, algorithm: 16, digestType: 2, digest: 'ab'.repeat(32) },
    { type: 'DS', keyTag: 2, algorithm: 13, digestType: 2, digest: 'cd'.repeat(32) }
  ]).resolve('www.example').catch((err) => ({ kind: 'threw', reason: err.message }))
  assert.notEqual(out.kind, 'dnssec-unsupported', JSON.stringify(out))
})

// ---------------------------------------------------------------------------
// 4. an answer must be ABOUT the name that was asked for
// ---------------------------------------------------------------------------

test('a TXT published for a DIFFERENT name is not this name\'s pointer', () =>
  withNsd(async () => {
    // Nothing requires a nameserver's answer section to be about the question,
    // and nothing checked. On an unsigned zone that meant a record for
    // `other.example` was accepted as `host.example`'s content pointer — the
    // signed case was already covered, because the RRSIG's owner would differ.
    const { answersAbout } = await import('../src/resolver.js')
    const answers = [
      { name: 'somewhere.else', type: TYPES.TXT, txt: ['ipfs=stolen'] },
      { name: 'mine.example', type: TYPES.TXT, txt: ['ipfs=real'] }
    ]
    const mine = answersAbout(answers, 'mine.example', TYPES.CNAME)
    assert.deepEqual(mine.map((r) => r.txt[0]), ['ipfs=real'])
  }))

test('a CNAME chain IS followed — pointing a name at a name is a real setup', async () => {
  const { answersAbout } = await import('../src/resolver.js')
  const answers = [
    { name: 'a.example', type: TYPES.CNAME, target: 'b.example' },
    { name: 'b.example', type: TYPES.CNAME, target: 'c.example' },
    { name: 'c.example', type: TYPES.TXT, txt: ['ipfs=followed'] },
    { name: 'unrelated.example', type: TYPES.TXT, txt: ['ipfs=no'] }
  ]
  const mine = answersAbout(answers, 'a.example', TYPES.CNAME)
  assert.ok(mine.some((r) => r.txt && r.txt[0] === 'ipfs=followed'))
  assert.ok(!mine.some((r) => r.txt && r.txt[0] === 'ipfs=no'))
})

test('a CNAME loop terminates instead of hanging the resolution', async () => {
  const { answersAbout } = await import('../src/resolver.js')
  const mine = answersAbout([
    { name: 'a.example', type: TYPES.CNAME, target: 'b.example' },
    { name: 'b.example', type: TYPES.CNAME, target: 'a.example' }
  ], 'a.example', TYPES.CNAME)
  assert.equal(mine.length, 2)
})

test('owner matching ignores case and the trailing root dot', async () => {
  const { answersAbout } = await import('../src/resolver.js')
  const mine = answersAbout(
    [{ name: 'Mine.Example.', type: TYPES.TXT, txt: ['ipfs=x'] }],
    'mine.example', TYPES.CNAME)
  assert.equal(mine.length, 1)
})
