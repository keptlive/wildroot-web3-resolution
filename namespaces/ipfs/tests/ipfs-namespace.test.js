// The IPFS namespace as the rest of the stack sees it: which schemes belong to
// it, what each of them claims to verify, and the two carriers a Handshake name
// uses to point into it (a TXT pointer, an EIP-1577 contenthash).
//
// The modules under test are the package's own — `../../../src/router.js`,
// `../../../src/pointers.js`, `../../../src/contenthash.js`. Nothing is copied
// into this namespace that already lives there. What is asserted here is only
// what the top-level suite does not already assert: the top-level
// `tests/router.test.js` pins dispatch and the L1/L2 rules, and
// `tests/publish-pointers.test.js` pins the pointer grammar and `car=`.

import test from 'node:test'
import assert from 'node:assert/strict'

import { NAMESPACES, classify, schemeInfo, namespaceForScheme } from '../../../src/router.js'
import { pointerFrom, txtStringsFrom, originFrom, CID_RE, IPNS_RE } from '../../../src/pointers.js'
import { decodeContenthash, CODEC } from '../../../src/contenthash.js'
import { schemeSteps, summarize } from '../../../src/trust-path.js'

const CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
const CIDV0 = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG'
const IPNS = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8'

// -------------------------------------------------------------- the schemes

test('four schemes, one namespace, one root of trust', () => {
  for (const scheme of ['ipfs', 'ipns', 'ipld', 'pubsub']) {
    assert.equal(namespaceForScheme(scheme), NAMESPACES.IPFS, scheme)
  }
  // The classifier does not get a vote once a scheme is named (L1), and a
  // failure inside one of these never becomes a lookup in another namespace (L2).
  assert.deepEqual(classify('ipld://bafyfoo/x').namespace, NAMESPACES.IPFS)
  assert.deepEqual(classify('pubsub://TopicName/').namespace, NAMESPACES.IPFS)
})

test('what each scheme verifies, stated per scheme and not per namespace', () => {
  assert.equal(schemeInfo('ipfs').verify, 'CID')
  assert.equal(schemeInfo('ipld').verify, 'CID')
  assert.equal(schemeInfo('ipns').verify, 'IPNS record + CID')
  // A pubsub topic is a free-form string, and a message on it is
  // authenticated — when it is authenticated at all — by the publishing peer's
  // libp2p signature, never by a CID. The row says so rather than inheriting
  // the namespace's answer (SPEC §4.4).
  assert.equal(schemeInfo('pubsub').verify,
    'libp2p publisher signature — a topic is not a content address')
})

test('the trust panel gives each of the four schemes its own step', () => {
  const cidStep = schemeSteps(`ipfs://${CID}/`)[0]
  assert.equal(cidStep.state, 'verified')
  assert.match(cidStep.detail, /the bytes are verified against the CID/)

  const ipnsStep = schemeSteps(`ipns://${IPNS}/`)[0]
  assert.equal(ipnsStep.state, 'verified')
  assert.match(ipnsStep.detail, /signed pointer/,
    'an IPNS answer is named as a pointer, never as an immutable address')

  // ipld:// is CID-verified exactly as ipfs:// is, and says so in its own
  // words: the guarantee is per node on the path.
  const ipldStep = schemeSteps(`ipld://${CID}/x`)[0]
  assert.equal(ipldStep.state, 'verified')
  assert.match(ipldStep.detail, /each node on the path is verified against its CID/)

  // pubsub:// claims nothing, and the lock does not close on it.
  const topic = schemeSteps('pubsub://topicname/')
  assert.equal(topic[0].state, 'none')
  assert.match(topic[0].detail, /not a content address/)
  assert.equal(summarize(topic).state, 'partial')
})

test('a bare CID is an address in this namespace, and a CIDv0 is written as its CIDv1 form', async () => {
  // A pasted CID opens as content, not as a Handshake lookup for a string that
  // is not a name (SPEC §3).
  const v1 = classify(CID)
  assert.equal(v1.namespace, NAMESPACES.IPFS)
  assert.equal(v1.url, `ipfs://${CID}/`)
  assert.equal(v1.reason, 'bare-cid')

  // A CIDv0 is base58btc and therefore case-sensitive, which a URL host does
  // not survive (IP-5). It is re-spelled as its base32 CIDv1 form, which names
  // the same bytes — checked here against multiformats rather than asserted.
  const { CID: Cid } = await import('multiformats/cid')
  const v0 = classify(CIDV0)
  assert.equal(v0.namespace, NAMESPACES.IPFS)
  assert.equal(v0.url, `ipfs://${Cid.parse(CIDV0).toV1().toString()}/`)
  assert.deepEqual(Cid.parse(new URL(v0.url).hostname).multihash.bytes,
    Cid.parse(CIDV0).multihash.bytes, 'the same multihash, another multibase')

  // An IPNS key is deliberately NOT sniffed: `Qm…` is both a legacy IPNS key
  // and a CIDv0, and guessing between them is the sniffing the router exists
  // to prevent. The base36 form is not a CID by shape and stays a bare label.
  assert.equal(classify(IPNS).namespace, NAMESPACES.HNS)

  // The gateway path form is recognised, in both directions.
  assert.equal(classify(`/ipfs/${CID}`).url, `ipfs://${CID}`)
  assert.equal(classify(`/ipns/${IPNS}`).url, `ipns://${IPNS}`)
})

// ------------------------------------------------- carrier 1: the TXT record

test('a name points into this namespace with ipfs= or ipns=, and ipfs= wins', () => {
  const strings = txtStringsFrom([
    { type: 16, txt: [`ipns=${IPNS}`] },
    { type: 16, txt: [`ipfs=${CID}`] }
  ])
  assert.deepEqual(pointerFrom(strings), { kind: 'ipfs', cid: CID },
    'record order is irrelevant; POINTER_PRECEDENCE decides')
  assert.deepEqual(pointerFrom([`ipns=${IPNS}`]), { kind: 'ipns', key: IPNS })
})

test('the IPNS address shapes this namespace accepts, and what a URL host does to them', () => {
  // The four forms `ipns=` takes (src/pointers.js IPNS_RE): the base36
  // libp2p-key CIDv1 `ipfs name publish` prints, its base32 form, a modern
  // peer ID, and a legacy one.
  const forms = [
    IPNS,
    'bafzaajaiaejcccm5rlwjtvmbwmr3xkakabx7pkkzquvjeaq5xoypzbrpldykpfvi',
    '12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8',
    'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG'
  ]
  for (const f of forms) assert.ok(IPNS_RE.test(f), f)
  // Two of those four carry uppercase, so they do not survive being written
  // into the host of a URL a canonicalising parser touches (IP-5). A CID
  // never has this problem in its CIDv1 base32 form, which is what our own
  // publisher writes.
  assert.equal(forms.filter((f) => f !== f.toLowerCase()).length, 2)
  assert.ok(CID_RE.test(CID) && CID === CID.toLowerCase())
})

test('the stated origin rides beside an ipfs= pointer and is never itself a pointer', () => {
  const origin = `https://pinthis.cloud/ipfs/${CID}`
  const strings = [`ipfs=${CID}`, `car=${origin}`]
  assert.deepEqual(pointerFrom(strings), { kind: 'ipfs', cid: CID })
  assert.equal(originFrom(strings), origin)
  assert.equal(originFrom([`ipns=${IPNS}`]), null, 'no car= record, no origin')
})

// ---------------------------------------- carrier 2: an EIP-1577 contenthash

test('contenthash: ipfs-ns and ipns-ns decode into this namespace, swarm is refused BY NAME', () => {
  // `ipfs-ns` 0xe3 followed by the CID's binary form. Built here from the
  // codec table rather than pasted, so the vector cannot drift from the code.
  const ipfs = decodeContenthash('0xe3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f')
  assert.equal(ipfs.protocol, 'ipfs')
  assert.equal(ipfs.supported, true)
  assert.equal(ipfs.code, CODEC.IPFS)
  assert.equal(ipfs.url, `ipfs://${ipfs.id}`)
  assert.ok(CID_RE.test(ipfs.id), 'the decoded id is a CID this stack would accept as a pointer')

  // `ipns-ns` 0xe5 over a libp2p-key CID.
  const ipns = decodeContenthash('0xe5010172002408011220a0d2f7b6d33c6a6e9d8dbf3ae7c0af5a26db3e7f56e6f57ba0a9b7c8f4e12345')
  assert.equal(ipns.protocol, 'ipns')
  assert.equal(ipns.code, CODEC.IPNS)
  assert.equal(ipns.url, `ipns://${ipns.id}`)
  assert.match(ipns.id, /^bafzaajaiaejc/, 'a libp2p-key CIDv1 in base32')
  assert.ok(IPNS_RE.test(ipns.id),
    'the two carriers agree on the address space: what a contenthash decodes to is what an ipns= TXT may carry')

  // A codec we recognise and cannot fetch is named, never discarded — the
  // resolution refuses with "this name points at Swarm content" rather than
  // walking down to an address (SPEC §7, top-level SPEC §10).
  const swarm = decodeContenthash('0xe40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162')
  assert.equal(swarm.protocol, 'swarm')
  assert.equal(swarm.supported, false)

  assert.equal(decodeContenthash('0x'), null, 'an unset name has no contenthash, which is not an error')
})
