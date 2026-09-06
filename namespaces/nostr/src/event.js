// Nostr event verification (NIP-01).
//
// THE WHOLE POINT. A relay is a transport, not an authority. An event carries
// its author's pubkey and a schnorr signature over the event's id, and the id
// is a hash of the event's own contents — so a relay that alters a single byte
// of content produces an id that no longer matches, and a relay that forges an
// event cannot produce a signature for someone else's key. Verifying here, in
// this process, is what lets us query ANY relay (including ours) without
// trusting it.
//
// This is why nostr was the cheap one to add: `@noble/curves` was already a
// dependency, and its secp256k1 schnorr is exactly NIP-01's signature scheme.

import { schnorr } from '@noble/curves/secp256k1'
import { createHash } from 'node:crypto'

const HEX32 = /^[0-9a-f]{64}$/
const HEX64 = /^[0-9a-f]{128}$/

/**
 * The canonical serialization an event id is the sha256 of (NIP-01):
 *   [0, pubkey, created_at, kind, tags, content]
 * JSON.stringify of that array is the spec's own definition — no spacing, and
 * UTF-8 escaping left to JSON.
 */
export function eventId (event) {
  const serial = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ])
  // node:crypto rather than @noble/hashes: the latter is only a TRANSITIVE
  // dependency here (it arrives under @noble/curves), and importing a package
  // we do not declare breaks the moment that tree reshuffles.
  return createHash('sha256').update(serial, 'utf8').digest('hex')
}

/**
 * Is this a well-formed, correctly-signed event?
 * Total: never throws, returns { ok: false, reason } instead — every event
 * here came off a network someone else controls.
 *
 * @returns {{ok: true, id: string} | {ok: false, reason: string}}
 */
export function verifyEvent (event) {
  if (!event || typeof event !== 'object') return { ok: false, reason: 'not an object' }
  const { id, pubkey, sig, created_at: createdAt, kind, tags, content } = event
  if (!HEX32.test(String(pubkey || ''))) return { ok: false, reason: 'malformed pubkey' }
  if (!HEX32.test(String(id || ''))) return { ok: false, reason: 'malformed id' }
  if (!HEX64.test(String(sig || ''))) return { ok: false, reason: 'malformed signature' }
  if (!Number.isInteger(createdAt)) return { ok: false, reason: 'malformed created_at' }
  if (!Number.isInteger(kind)) return { ok: false, reason: 'malformed kind' }
  if (!Array.isArray(tags)) return { ok: false, reason: 'malformed tags' }
  if (typeof content !== 'string') return { ok: false, reason: 'malformed content' }

  // Check the id BEFORE the signature. The signature is over the id, so an
  // event whose id does not match its contents is one where a valid signature
  // would still be signing something other than what we are about to display.
  const computed = eventId(event)
  if (computed !== id) return { ok: false, reason: 'id does not match contents (event was altered)' }

  try {
    if (!schnorr.verify(sig, id, pubkey)) return { ok: false, reason: 'signature does not verify' }
  } catch (err) {
    return { ok: false, reason: `signature check failed: ${err.message}` }
  }
  return { ok: true, id: computed }
}
