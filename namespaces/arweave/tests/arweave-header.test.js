import test from 'node:test'
import assert from 'node:assert/strict'
import { constants, createHash, generateKeyPairSync, randomBytes } from 'node:crypto'
import createArHandler, { headerMatchesId, verifyTransactionHeader } from '../src/ar.js'
import { dataRootB64 } from '../src/ar-merkle.js'
import { tag, transaction, transactionV1 } from './ar-transaction-fixture.js'

test('4096-bit Arweave RSA owners verify with both SDK salt settings', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 65537 })
  for (const saltLength of [32, constants.RSA_PSS_SALTLEN_MAX_SIGN]) {
    const { id, header } = transaction(Buffer.from('example'), { owner: publicKey.export({ format: 'jwk' }).n }, privateKey, saltLength)
    assert.equal(headerMatchesId(header, id), true)
  }
})

test('a genuine owner signature authenticates every format-2 payload field', () => {
  const { id, header } = transaction(Buffer.from('original page'), {
    target: randomBytes(32).toString('base64url'),
    last_tx: randomBytes(48).toString('base64url'),
    quantity: '42',
    tags: [tag('Content-Type', 'text/plain')]
  })
  assert.equal(headerMatchesId(header, id), true)
  assert.equal(verifyTransactionHeader(header, id).dataSize, 13n)
  const changed = {
    data_root: dataRootB64(Buffer.from('modified page')),
    data_size: '14',
    tags: [tag('Content-Type', 'text/html')],
    owner: Buffer.alloc(256, 129).toString('base64url'),
    target: randomBytes(32).toString('base64url'),
    quantity: '43',
    reward: '1001',
    last_tx: randomBytes(48).toString('base64url'),
    denomination: '1',
    format: 1
  }
  for (const [field, value] of Object.entries(changed)) {
    const tampered = { ...header, [field]: value }
    assert.equal(createHash('sha256').update(Buffer.from(tampered.signature, 'base64url')).digest('base64url'), id, field + ': old signature-hash check still passes')
    assert.equal(headerMatchesId(tampered, id), false, field + ': owner authentication must fail')
  }
})

test('denomination is included in the signature payload, not ignored metadata', () => {
  const { id, header } = transaction(Buffer.from('example'), { denomination: '2' })
  assert.equal(headerMatchesId(header, id), true)
  assert.equal(headerMatchesId({ ...header, denomination: '3' }, id), false)
  const absent = { ...header }
  delete absent.denomination
  assert.equal(headerMatchesId(absent, id), false)
})

test('strict fields, unsupported formats and account types fail honestly', () => {
  const { id, header } = transaction(Buffer.from('example'))
  // A `mismatch` is a finding — this document is not the transaction the id
  // names. An `unsupported` is a limit of ours — nothing was proven, and
  // nothing may be claimed. The handler refuses the first and shrugs at the
  // second, so which verdict each case gets is part of the contract.
  const cases = [
    [{ format: 1 }, /format 1 header without the data it signed/, 'unsupported'],
    [{ format: 3 }, /unsupported transaction format/, 'unsupported'],
    [{ format: '2' }, /unsupported transaction format/, 'unsupported'],
    [{ owner: '' }, /unsupported owner\/signature/, 'unsupported'],
    [{ owner: randomBytes(32).toString('base64url') }, /unsupported owner\/signature/, 'unsupported'],
    [{ owner: Buffer.alloc(256, 129).toString('base64url') }, /unsupported owner\/signature/, 'unsupported'],
    [{ signature_type: 'secp256k1' }, /unsupported signature type/, 'unsupported'],
    [{ signature: randomBytes(65).toString('base64url') }, /does not hash to the id/, 'mismatch'],
    [{ signature: header.signature + '=' }, /base64url/, 'mismatch'],
    [{ owner: header.owner + ' ' }, /base64url/, 'mismatch'],
    [{ data_size: 7 }, /decimal/, 'mismatch'],
    [{ data_size: '07' }, /decimal/, 'mismatch'],
    [{ data_size: '-7' }, /decimal/, 'mismatch'],
    [{ data_root: '' }, /size\/root/, 'mismatch'],
    [{ tags: [tag('name', 'x'.repeat(2049))] }, /base64url/, 'mismatch'],
    [{ denomination: '0' }, /denomination/, 'mismatch'],
    [{ id: randomBytes(32).toString('base64url') }, /id mismatch/, 'mismatch']
  ]
  for (const [fields, reason, verdict] of cases) {
    const result = verifyTransactionHeader({ ...header, ...fields }, id)
    assert.equal(result.ok, false)
    assert.match(result.reason, reason)
    assert.equal(result.verdict, verdict, JSON.stringify(fields))
  }
})

test('the legacy format is verified, not assumed: a format-1 transaction signs its data', () => {
  const bytes = Buffer.from('a page from 2018')
  const { id, header } = transactionV1(bytes, { tags: [tag('Content-Type', 'text/plain')] })
  const result = verifyTransactionHeader(header, id)
  assert.equal(result.verdict, 'verified')
  assert.deepEqual(result.data, bytes)
  assert.equal(result.dataRoot, null, 'format 1 commits to no Merkle root')
  for (const fields of [
    { data: Buffer.from('another page').toString('base64url') },
    { tags: [tag('Content-Type', 'text/html')] },
    { reward: '2000' },
    { target: randomBytes(32).toString('base64url') }
  ]) {
    assert.equal(headerMatchesId({ ...header, ...fields }, id), false, JSON.stringify(Object.keys(fields)))
  }
})

test('substituted matching root and body cannot obtain verified bytes for another signature', async () => {
  const original = Buffer.from('original page')
  const altered = Buffer.from('modified page')
  const { id, header } = transaction(original)
  const forged = { ...header, data_root: dataRootB64(altered), tags: [tag('Content-Type', 'text/html')] }
  const { handler } = createArHandler({
    gateways: ['https://data.example', 'https://header.example'],
    verifyHeader: true,
    fetchImpl: async (url) => url.includes('/tx/') ? Response.json(forged) : new Response(altered)
  })
  const res = await handler(new Request(`ar://${id}`))
  assert.equal(res.status, 502)
  assert.equal(res.headers.get('X-Arweave-Verified'), 'none')
  assert.match(await res.text(), /owner signature does not authenticate/)
})

test('a header this implementation cannot check claims nothing, and is not refused', async () => {
  // The standing of a header gateway that did not answer, which any header
  // gateway can reach by not answering — so refusing here would stop no
  // attack and would only make honest unverifiable content unopenable. What
  // it must never do is report `header` or `bytes`.
  const { id, header } = transaction(Buffer.from('example'))
  for (const fields of [{ format: 3 }, { signature_type: 'secp256k1' }, { owner: Buffer.alloc(256, 129).toString('base64url') }]) {
    const { handler } = createArHandler({
      gateways: ['https://data.example', 'https://header.example'],
      verifyHeader: true,
      fetchImpl: async (url) => url.includes('/tx/') ? Response.json({ ...header, ...fields }) : new Response('example')
    })
    const res = await handler(new Request(`ar://${id}`))
    assert.equal(res.status, 200, JSON.stringify(fields))
    assert.equal(res.headers.get('X-Arweave-Verified'), 'none')
    assert.equal(await res.text(), 'example')
  }
})

test('a format-1 transaction gets verified bytes from the signature itself', async () => {
  const bytes = Buffer.from('a page from 2018')
  const { id, header } = transactionV1(bytes)
  const gateways = (served) => async (url) => url.includes('/tx/') ? Response.json(header) : new Response(served)
  const { handler } = createArHandler({
    gateways: ['https://data.example', 'https://header.example'], verifyHeader: true, fetchImpl: gateways(bytes)
  })
  const res = await handler(new Request(`ar://${id}`))
  assert.equal(res.headers.get('X-Arweave-Verified'), 'bytes')
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), bytes)

  const liar = createArHandler({
    gateways: ['https://data.example', 'https://header.example'],
    verifyHeader: true,
    fetchImpl: gateways(Buffer.from('a page from 2026'))
  })
  const refused = await liar.handler(new Request(`ar://${id}`))
  assert.equal(refused.status, 502)
  assert.match(await refused.text(), /not the data this transaction signed/)
})
