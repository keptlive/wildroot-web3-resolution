// The owner's half of the SLD binding, as ORDINARY NOSTR EVENTS.
//
// An SLD has no on-chain existence, so "this key controls alice.wildroot" is
// mutual attestation (IDENTITY.md §1): the registry publishes a DNSSEC-signed
// `_hns` control record naming the key (record.js), and the KEYHOLDER signs a
// claim receipt naming the name. DNSSEC alone proves only that the registry
// published the binding; the receipt proves the owner asked for it. This file
// defines the receipt payload nostr/DESIGN.md §2 (INF-4) left pending.
//
// NOTHING HERE IS A NEW SIGNATURE FORMAT (Matt, 2026-08-20). Both objects are
// plain NIP-01 events with existing kinds:
//   claim receipt  kind 30078 (NIP-78 app data), d-tag "hns:<name>", an
//                  "epoch" tag — replaceable per name, storable on any relay
//   API auth       kind 27235 (NIP-98 HTTP Auth), u/method/payload tags,
//                  sent as `Authorization: Nostr <base64(event)>`
// so any Nostr library can verify them, and RES-1's event verifier already
// does. The receipt is reconstructible from (name, pubkey, epoch,
// created_at) alone — that is what lets a 255-byte TXT record carry it as
// just `receipt=<created_at>.<sig>` (record.js) and still verify offline.
//
// The signer is the name's CONTROL key (keys.js), not the user's social
// identity: these signatures authorize domain operations, and the key that
// can do that is the one a delegate may hold.

import { createHash, randomBytes } from 'node:crypto'

import { normalizeName, isPublicKeyHex } from './keys.js'
import { finalizeEvent, verifyEvent, computeEventId, tagValue } from './nostr-event.js'

/** NIP-78 application-specific data — the claim receipt's kind. */
export const CLAIM_KIND = 30078
/** NIP-98 HTTP Auth. */
export const AUTH_KIND = 27235
/** NIP-98 verifiers must reject events older/newer than this window. */
export const AUTH_WINDOW_SECONDS = 60

function requireEpoch (epoch) {
  if (!Number.isInteger(epoch) || epoch < 1) throw new Error('epoch must be an integer >= 1')
}

/**
 * The unsigned claim-receipt event, reconstructed the same way by signer and
 * verifier. The d-tag makes it parameterized-replaceable PER NAME, so a
 * relay keeps only the newest claim for each name — exactly the semantics a
 * transfer wants.
 */
export function claimEvent ({ name, publicKey, epoch, createdAt }) {
  if (!isPublicKeyHex(publicKey)) throw new Error('publicKey must be 64 lowercase hex')
  requireEpoch(epoch)
  if (!Number.isInteger(createdAt) || createdAt <= 0) {
    throw new Error('createdAt must be a unix timestamp in seconds')
  }
  return {
    pubkey: publicKey,
    created_at: createdAt,
    kind: CLAIM_KIND,
    // The `v` tag is FIRST and is load-bearing. Kind 30078 is NIP-78's generic
    // "application data", and we deliberately tell users to move this key into
    // other Nostr apps — so separation from those apps rested only on a d-tag
    // naming convention. Any app that will sign a kind-30078 event with a
    // chosen `d` tag and an `epoch` tag could be walked into producing a valid
    // claim receipt for an attacker's name. An explicit version tag makes the
    // preimage unmistakable and gives a future format somewhere to say so.
    tags: [['v', 'hns1'], ['d', `hns:${normalizeName(name)}`], ['epoch', String(epoch)]],
    content: ''
  }
}

/**
 * Sign a claim receipt. Returns the full event (publishable to any relay)
 * plus the compact { createdAt, sig } pair the `_nostr` record embeds.
 */
export function signClaim ({ name, publicKey, epoch, createdAt }, privateKey) {
  const event = finalizeEvent(claimEvent({ name, publicKey, epoch, createdAt }), privateKey)
  return { event, receipt: { createdAt, sig: event.sig } }
}

/**
 * Verify a compact receipt against exactly these fields: rebuild the event,
 * recompute its id, check the BIP-340 signature. Malformed input is `false`,
 * never an exception — this runs on untrusted zone data.
 */
export function verifyClaim ({ name, publicKey, epoch, createdAt, sig }) {
  try {
    if (typeof sig !== 'string' || !/^[0-9a-f]{128}$/.test(sig)) return false
    const event = claimEvent({ name, publicKey, epoch, createdAt })
    const id = computeEventId(event)
    return verifyEvent({ ...event, id, sig }).ok
  } catch {
    return false
  }
}

// ------------------------------------------------------ atproto binding receipt
//
// The owner's half of an atproto binding, mirroring the claim receipt. Handing
// a name's handle to a Bluesky account is a STRONGER statement than binding a
// key -- whoever answers `/.well-known/atproto-did` owns that handle on the
// network -- so it is authorized the same provable way: a kind-30078 event
// signed by the name's CONTROL key, verifiable offline.
//
// The `d` tag prefix is `hns:atproto:`, NOT `hns:`. That single difference is
// load-bearing: it makes a claim receipt and an atproto binding
// non-interchangeable, so neither can be replayed as the other -- the same
// separation the `v` tag comment on `claimEvent` describes. A `did` tag binds
// the exact account, so the signature can only mean "this control key
// authorized THIS did".

/**
 * The unsigned atproto-binding event, reconstructed the same way by signer and
 * verifier. Version 1 retains the historical lowercase preimage EXACTLY.
 * Version 2 is explicit: a verifier must get its version from the receipt,
 * never infer it or retry another version after a failed signature.
 */
export function atprotoEvent ({ name, publicKey, did, epoch, createdAt, version = 1 }) {
  if (!isPublicKeyHex(publicKey)) throw new Error('publicKey must be 64 lowercase hex')
  requireEpoch(epoch)
  if (!Number.isInteger(createdAt) || createdAt <= 0) {
    throw new Error('createdAt must be a unix timestamp in seconds')
  }
  if (typeof did !== 'string' || !did.trim()) throw new Error('did is required')
  if (version !== 1 && version !== 2) throw new Error('unsupported atproto receipt version')
  return {
    pubkey: publicKey,
    created_at: createdAt,
    kind: CLAIM_KIND,
    tags: [['v', `hns${version}`], ['d', `hns:atproto:${normalizeName(name)}`],
      ['epoch', String(epoch)], ['did', version === 1 ? did.trim().toLowerCase() : canonicalAtprotoDid(did)]],
    content: ''
  }
}

/**
 * Sign an atproto binding receipt with the name's CONTROL key. Returns the
 * full event plus the compact { createdAt, sig } the API and the `_atproto`
 * record embed.
 */
export function signAtproto ({ name, publicKey, did, epoch, createdAt, version = 1 }, privateKey) {
  did = canonicalAtprotoDid(did)
  // The deployed registry reconstructs hns1 receipts. Its lowercase subject
  // cannot represent a case-sensitive web path safely, even when THIS path
  // happens to be lowercase. New path bindings need coordinated v2 support.
  if (version === 1 && did.startsWith('did:web:') && did.slice(8).includes(':')) {
    throw new Error('did:web path bindings require atproto receipt version 2 and registry support')
  }
  const event = finalizeEvent(
    atprotoEvent({ name, publicKey, did, epoch, createdAt, version }), privateKey)
  return { event, receipt: { createdAt, sig: event.sig, ...(version === 2 ? { version } : {}) } }
}

/** Supported binding subjects. Domain case folds; web path case never does. */
export function canonicalAtprotoDid (value) {
  if (typeof value !== 'string') throw new Error('did is required')
  const did = value.trim()
  if (/^did:plc:[a-z2-7]{24}$/.test(did)) return did
  if (!did.startsWith('did:web:')) throw new Error('expected a canonical did:plc or did:web identifier')
  const [authority, ...path] = did.slice(8).split(':')
  const match = /^([a-z0-9.-]+)(?:%3[aA]([0-9]{1,5}))?$/i.exec(authority)
  if (!match) throw new Error('did:web requires a domain and an optional percent-encoded port')
  const [, domain, port] = match
  if (domain.length > 253 || /^[0-9.]+$/.test(domain) || domain.split('.').some((label) =>
    label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) {
    throw new Error('did:web has an invalid domain')
  }
  if (port && (Number(port) < 1 || Number(port) > 65535)) throw new Error('did:web has an invalid port')
  if (path.some((part) => {
    if (!part || !/^(?:[A-Za-z0-9._-]|%[0-9a-fA-F]{2})+$/.test(part)) return true
    const decoded = decodeURIComponent(part)
    return decoded === '.' || decoded === '..' || /[/#?\\]/.test(decoded) ||
      [...decoded].some((char) => char.charCodeAt(0) <= 32 || char.charCodeAt(0) === 127)
  })) {
    throw new Error('did:web has an invalid path')
  }
  return `did:web:${domain.toLowerCase()}${port ? `%3A${Number(port)}` : ''}${path.length ? ':' + path.join(':') : ''}`
}

/**
 * Verify a compact atproto receipt against exactly these fields. Malformed
 * input is `false`, never an exception -- this runs on untrusted zone data.
 */
export function verifyAtproto ({ name, publicKey, did, epoch, createdAt, sig, version = 1 }) {
  try {
    if (typeof sig !== 'string' || !/^[0-9a-f]{128}$/.test(sig)) return false
    const event = atprotoEvent({ name, publicKey, did, epoch, createdAt, version })
    const id = computeEventId(event)
    return verifyEvent({ ...event, id, sig }).ok
  } catch {
    return false
  }
}

// ----------------------------------------------------------- NIP-98 HTTP auth

/** sha256 hex of a request body, for the NIP-98 `payload` tag. */
export function payloadHash (body) {
  return createHash('sha256').update(body, 'utf8').digest('hex')
}

/**
 * Build + sign the NIP-98 event for one HTTP request, and the Authorization
 * header value that carries it. `body` is the exact string being sent.
 *
 * A `nonce` tag makes every event unique: two identical requests signed in
 * the same second would otherwise share an event id, and the tenant's
 * replay ledger (which remembers ids it has seen) refuses the second — a
 * deposit and a drain of the inbox in one tick hit exactly that. Verifiers
 * on both sides read tags by name and ignore the ones they do not know
 * (verifyAuth below; the tenant's tests pin the same).
 */
export function signAuth ({ url, method, body = null, createdAt, nonce = randomBytes(8).toString('hex') }, privateKey, publicKey) {
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) throw new Error('url must be absolute http(s)')
  const tags = [['u', url], ['method', method.toUpperCase()], ['nonce', String(nonce)]]
  if (body !== null) tags.push(['payload', payloadHash(body)])
  const event = finalizeEvent({
    pubkey: publicKey,
    created_at: createdAt ?? Math.floor(Date.now() / 1000),
    kind: AUTH_KIND,
    tags,
    content: ''
  }, privateKey)
  return { event, header: `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}` }
}

/**
 * Verify a NIP-98 Authorization header for a request actually received.
 * Returns { ok:true, publicKey } or { ok:false, reason }. The caller still
 * decides whether that key is AUTHORIZED — this only proves who signed.
 */
export function verifyAuth (header, { url, method, body = null, nowSeconds }) {
  try {
    if (typeof header !== 'string' || !header.startsWith('Nostr ')) {
      return { ok: false, reason: 'not a Nostr authorization header' }
    }
    const event = JSON.parse(Buffer.from(header.slice(6), 'base64').toString('utf8'))
    const valid = verifyEvent(event)
    if (!valid.ok) return { ok: false, reason: valid.reason }
    if (event.kind !== AUTH_KIND) return { ok: false, reason: 'wrong kind' }
    if (tagValue(event, 'u') !== url) return { ok: false, reason: 'url mismatch' }
    if ((tagValue(event, 'method') || '').toUpperCase() !== method.toUpperCase()) {
      return { ok: false, reason: 'method mismatch' }
    }
    const expectPayload = body === null ? null : payloadHash(body)
    if ((tagValue(event, 'payload') || null) !== expectPayload) {
      return { ok: false, reason: 'payload hash mismatch' }
    }
    const now = nowSeconds ?? Math.floor(Date.now() / 1000)
    if (Math.abs(now - event.created_at) > AUTH_WINDOW_SECONDS) {
      return { ok: false, reason: 'expired' }
    }
    return { ok: true, publicKey: event.pubkey }
  } catch (err) {
    return { ok: false, reason: `malformed: ${err.message || err}` }
  }
}
