// NIP-19 bech32 identifiers (npub / note / nprofile / nevent / naddr).
//
// WHY A LOCAL BECH32 RATHER THAN A DEPENDENCY. The two candidates already in
// the tree are transitive (bcrypto arrives under hsd) and both enforce the
// BIP-173 90-character limit. NIP-19 routinely exceeds it: an `nevent` with a
// relay hint and an author is comfortably past 90 chars, and an `naddr` with a
// long `d` tag more so. A limit-enforcing decoder rejects perfectly valid
// nostr identifiers, so the limit is deliberately NOT applied here. Everything
// else is BIP-173 exactly, checksum included.
//
// The decoder is total: it never throws for untrusted input, it returns
// { error } instead, because every caller here is handling a URL somebody
// typed or a page linked to.

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

function polymod (values) {
  let chk = 1
  for (const v of values) {
    const top = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GENERATOR[i]
    }
  }
  return chk
}

function hrpExpand (hrp) {
  const out = []
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5)
  out.push(0)
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31)
  return out
}

/** 5-bit groups -> 8-bit bytes, rejecting non-zero padding (BIP-173). */
function convertBits (data, from, to, pad) {
  let acc = 0
  let bits = 0
  const out = []
  const maxv = (1 << to) - 1
  for (const value of data) {
    if (value < 0 || value >> from !== 0) return null
    acc = (acc << from) | value
    bits += from
    while (bits >= to) {
      bits -= to
      out.push((acc >> bits) & maxv)
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv)
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return null
  }
  return out
}

/**
 * Decode a bech32 string into { hrp, bytes }.
 * @returns {{hrp: string, bytes: Uint8Array} | {error: string}}
 */
export function bech32Decode (input) {
  if (typeof input !== 'string' || !input) return { error: 'not a string' }
  // Mixed case is invalid per BIP-173; lower-casing a uniform-case string is
  // the spec's own normalisation.
  const hasLower = /[a-z]/.test(input)
  const hasUpper = /[A-Z]/.test(input)
  if (hasLower && hasUpper) return { error: 'mixed case' }
  const s = input.toLowerCase()
  const sep = s.lastIndexOf('1')
  if (sep < 1 || sep + 7 > s.length) return { error: 'malformed: no separator' }
  const hrp = s.slice(0, sep)
  const dataPart = s.slice(sep + 1)
  const values = []
  for (const ch of dataPart) {
    const idx = CHARSET.indexOf(ch)
    if (idx === -1) return { error: `invalid character '${ch}'` }
    values.push(idx)
  }
  if (polymod([...hrpExpand(hrp), ...values]) !== 1) return { error: 'bad checksum' }
  const bytes = convertBits(values.slice(0, -6), 5, 8, false)
  if (!bytes) return { error: 'bad padding' }
  return { hrp, bytes: Uint8Array.from(bytes) }
}

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

/** TLV stream used by nprofile / nevent / naddr. */
function parseTLV (bytes) {
  const out = {}
  let i = 0
  while (i + 2 <= bytes.length) {
    const type = bytes[i]
    const len = bytes[i + 1]
    const start = i + 2
    const end = start + len
    if (end > bytes.length) return { error: 'truncated TLV' }
    ;(out[type] ||= []).push(bytes.slice(start, end))
    i = end
  }
  // A stray trailing byte is not a TLV: refuse rather than silently drop it.
  if (i !== bytes.length) return { error: 'trailing bytes in TLV' }
  return out
}

const TLV_SPECIAL = 0
const TLV_RELAY = 1
const TLV_AUTHOR = 2
const TLV_KIND = 3

const decodeRelays = (tlv) =>
  (tlv[TLV_RELAY] || []).map((b) => new TextDecoder().decode(b)).filter(Boolean)

/**
 * Decode a NIP-19 identifier.
 *
 * Returns one of:
 *   { type: 'npub',    pubkey }
 *   { type: 'note',    id }
 *   { type: 'nprofile', pubkey, relays }
 *   { type: 'nevent',  id, relays, author?, kind? }
 *   { type: 'naddr',   identifier, pubkey, kind, relays }
 *   { error }
 */
export function decodeNip19 (input) {
  const res = bech32Decode(input)
  if (res.error) return res
  const { hrp, bytes } = res

  // A private key must never be resolved, fetched, or echoed back. Naming it
  // explicitly is better than letting it fall through to "unknown prefix",
  // because the useful thing to tell someone who pasted one is that it is a
  // SECRET, not that it is unsupported.
  if (hrp === 'nsec') {
    return { error: 'that is a PRIVATE KEY (nsec). It was not sent anywhere. Never paste it into a browser or share it.' }
  }

  if (hrp === 'npub') {
    if (bytes.length !== 32) return { error: 'npub must be 32 bytes' }
    return { type: 'npub', pubkey: toHex(bytes) }
  }
  if (hrp === 'note') {
    if (bytes.length !== 32) return { error: 'note must be 32 bytes' }
    return { type: 'note', id: toHex(bytes) }
  }

  const tlv = parseTLV(bytes)
  if (tlv.error) return tlv
  const special = (tlv[TLV_SPECIAL] || [])[0]

  if (hrp === 'nprofile') {
    if (!special || special.length !== 32) return { error: 'nprofile missing 32-byte pubkey' }
    return { type: 'nprofile', pubkey: toHex(special), relays: decodeRelays(tlv) }
  }
  if (hrp === 'nevent') {
    if (!special || special.length !== 32) return { error: 'nevent missing 32-byte id' }
    const author = (tlv[TLV_AUTHOR] || [])[0]
    const kindBytes = (tlv[TLV_KIND] || [])[0]
    return {
      type: 'nevent',
      id: toHex(special),
      relays: decodeRelays(tlv),
      ...(author && author.length === 32 ? { author: toHex(author) } : {}),
      ...(kindBytes && kindBytes.length === 4
        ? { kind: new DataView(kindBytes.buffer, kindBytes.byteOffset, 4).getUint32(0, false) }
        : {})
    }
  }
  if (hrp === 'naddr') {
    const author = (tlv[TLV_AUTHOR] || [])[0]
    const kindBytes = (tlv[TLV_KIND] || [])[0]
    if (!author || author.length !== 32) return { error: 'naddr missing 32-byte author' }
    if (!kindBytes || kindBytes.length !== 4) return { error: 'naddr missing kind' }
    const kind = new DataView(kindBytes.buffer, kindBytes.byteOffset, 4).getUint32(0, false)
    return {
      type: 'naddr',
      identifier: special ? new TextDecoder().decode(special) : '',
      pubkey: toHex(author),
      kind,
      relays: decodeRelays(tlv)
    }
  }

  return { error: `unsupported NIP-19 prefix '${hrp}'` }
}

/**
 * Parse a `nostr:` URI (NIP-21) or a bare NIP-19 identifier.
 * Accepts `nostr:npub1…`, `nostr://npub1…` (Electron may hand us that shape),
 * and a bare `npub1…`.
 */
export function parseNostrURI (url) {
  let s = String(url || '').trim()
  if (/^nostr:\/\//i.test(s)) s = s.slice('nostr://'.length)
  else if (/^nostr:/i.test(s)) s = s.slice('nostr:'.length)
  // Strip any trailing path/query Chromium may append to a bare authority.
  s = s.replace(/[/?#].*$/, '')
  if (!s) return { error: 'empty nostr: URI' }
  return decodeNip19(s)
}
