// `ipfs://<cid>[/path]` → the root CID it names (SPEC §4.1).

import test from 'node:test'
import assert from 'node:assert/strict'

import { rootCidOf } from '../src/ipfs-url.js'

const V1 = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
const V0 = 'QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX'

test('the host of an ipfs:// URL is the root CID; the path is not part of the address', () => {
  assert.equal(rootCidOf(`ipfs://${V1}`), V1)
  assert.equal(rootCidOf(`ipfs://${V1}/`), V1)
  assert.equal(rootCidOf(`ipfs://${V1}/videos/talk.mp4?x=1#t=30`), V1)
  assert.equal(rootCidOf(`ipfs://${V0}/index.html`), V0, 'a CIDv0 keeps its case here')
})

test('only ipfs:// — the sibling scheme in the same namespace is not a CID', () => {
  // ipns:// names a KEY, not a content address (SPEC §4.2) — even when the key
  // is spelled as a CID, which a libp2p-key CIDv1 is. It is not a root CID,
  // and answering as though it were is how a mutable name gets cached as
  // immutable content.
  assert.equal(rootCidOf(`ipns://${V1}`), null)
  assert.equal(rootCidOf('ipns://k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8'), null)
  assert.equal(rootCidOf(`https://ipfs.io/ipfs/${V1}`), null, 'a gateway URL is an HTTPS URL')
  assert.equal(rootCidOf(`hns://alice.w3/?cid=${V1}`), null)
})

test('a host that is not a CID is not a CID — the shared shape, no local copy', () => {
  // The three ways a hand-rolled copy of this shape had already drifted in the
  // Wildroot tree, each of which let a non-address through (src/pointers.js).
  assert.equal(rootCidOf(`ipfs://b${'a'.repeat(200)}`), null, 'no upper bound')
  assert.equal(rootCidOf('ipfs://babcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz01'), null,
    'base32 has no 0, 1, 8 or 9')
  assert.equal(rootCidOf(`ipfs://${V1.slice(1)}`), null, 'no multibase prefix')
  assert.equal(rootCidOf('ipfs://'), null)
  assert.equal(rootCidOf('ipfs://example.com/'), null)
  assert.equal(rootCidOf(null), null)
  assert.equal(rootCidOf('not a url'), null)
})

test('a lowercased CIDv0 is not a CID, which is the shape of the hazard in IP-5', () => {
  // Base58btc is case-sensitive; base32 (a CIDv1) is not. A URL parser that
  // canonicalises the host — which is what a *standard* scheme gets in
  // Chromium, and what Wildroot registers `ipfs:` as — destroys a CIDv0 and
  // leaves a CIDv1 intact. This assertion is the failure mode, pinned.
  assert.equal(rootCidOf(`ipfs://${V0.toLowerCase()}`), null)
  assert.equal(rootCidOf(`ipfs://${V1.toLowerCase()}`), V1, 'a CIDv1 in base32 survives it')
})
