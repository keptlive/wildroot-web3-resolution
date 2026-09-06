// NIP-01 events: build, sign, verify. The signing counterpart of the
// verify-only module in ~/hns/nostr/src/nostr-event.js — the canonical
// serialization here MUST stay byte-identical to that resolver's, because
// what this file signs is exactly what that file (and every other Nostr
// client on earth) recomputes: sha256 of [0,pubkey,created_at,kind,tags,
// content], BIP-340 schnorr over that id.

import { createHash } from 'node:crypto'
import { schnorr } from '@noble/curves/secp256k1'

const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/

/** Canonical NIP-01 serialization used for the id. */
export function serializeEvent (event) {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags || [],
    event.content || ''
  ])
}

/** Recompute the event id from its fields. */
export function computeEventId (event) {
  return createHash('sha256').update(serializeEvent(event), 'utf8').digest('hex')
}

/**
 * Sign an unsigned event { pubkey, created_at, kind, tags, content } with the
 * 32-byte private key. Returns the complete event with id + sig. Throws if
 * the private key does not match the event's claimed pubkey — an event that
 * names one key and is signed by another is never a mistake worth shipping.
 */
export function finalizeEvent (event, privateKey) {
  const expected = Buffer.from(schnorr.getPublicKey(privateKey)).toString('hex')
  if (event.pubkey !== expected) {
    throw new Error('event pubkey does not match the signing key')
  }
  const id = computeEventId(event)
  const sig = Buffer.from(schnorr.sign(Buffer.from(id, 'hex'), privateKey)).toString('hex')
  return { ...event, tags: event.tags || [], content: event.content || '', id, sig }
}

/**
 * Full structural + cryptographic check. Returns {ok} or {ok:false, reason}.
 * Malformed input is a reason, never a throw: this runs on untrusted data.
 */
export function verifyEvent (event) {
  if (!event || typeof event !== 'object') return { ok: false, reason: 'not an object' }
  if (typeof event.pubkey !== 'string' || !HEX64.test(event.pubkey)) {
    return { ok: false, reason: 'bad pubkey' }
  }
  if (typeof event.id !== 'string' || !HEX64.test(event.id)) {
    return { ok: false, reason: 'bad id' }
  }
  if (typeof event.sig !== 'string' || !HEX128.test(event.sig)) {
    return { ok: false, reason: 'bad sig' }
  }
  if (!Number.isInteger(event.created_at)) return { ok: false, reason: 'bad created_at' }
  if (!Number.isInteger(event.kind)) return { ok: false, reason: 'bad kind' }
  if (!Array.isArray(event.tags)) return { ok: false, reason: 'bad tags' }
  if (computeEventId(event) !== event.id) return { ok: false, reason: 'id mismatch' }
  try {
    const ok = schnorr.verify(
      Buffer.from(event.sig, 'hex'), Buffer.from(event.id, 'hex'), Buffer.from(event.pubkey, 'hex'))
    return ok ? { ok: true } : { ok: false, reason: 'signature invalid' }
  } catch (err) {
    return { ok: false, reason: `signature error: ${err.message || err}` }
  }
}

/** First value of a tag, e.g. tagValue(event, 'd'). */
export function tagValue (event, name) {
  for (const tag of event.tags || []) {
    if (Array.isArray(tag) && tag[0] === name && typeof tag[1] === 'string') return tag[1]
  }
  return null
}
