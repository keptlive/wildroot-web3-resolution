// The content-pointer record convention, in one place.
//
// A Handshake name says where its content lives with a TXT record. There is
// one such convention, and until now it was implemented twice — once in
// src/hns/resolver.js (the SPV/authoritative path) and once in src/hns/doh.js
// (the DoH/ODoH path) — with their own copies of the regexes and their own
// ordering. The two disagreed: doh.js returned on the first ANSWER that
// matched, so a name carrying `ar=` before `ipfs=` resolved to Arweave over
// DoH and to IPFS over SPV. One parser, used by both, cannot disagree with
// itself.
//
// Writing is the mirror of reading and lives here too, so a target added to
// the publish page can never drift from what the resolver understands.
//
//   ipfs=<cid>            immutable content address — verified by CID
//   ipns=<key>            mutable IPFS name — the address survives re-publishes
//   bt=<40hex|64hex>      torrent: infohash (immutable) or BEP-46 btpk pubkey
//   hyper=<z32|64hex>     hypercore drive key
//   ar=<txid>             Arweave permanent archive
//
// and, at the `_dnslink.<label>` owner, the DNSLink standard everyone else
// reads (Brave, IPFS Companion, public gateways, kubo itself):
//
//   dnslink=/ipns/<key>   preferred: the TXT never changes on a re-publish
//   dnslink=/ipfs/<cid>   when there is no IPNS key
//
// PRECEDENCE, when a name carries several. `ipfs=` first: a direct CID is the
// cheapest hop and the one the browser can verify outright. `ipns=` next —
// same network, one extra resolution step. Then the peer-to-peer swarms, which
// need a peer to be online: `bt=`, then `hyper=`. `ar=` last, unchanged from
// the rule it has always had: the paid, permanent archive is the backstop
// behind the free live pointers, not the thing you serve first.

/**
 * Every pointer VALUE in a set of TXT answers, in answer order.
 *
 * The parser below was already shared; the INPUT to it was not, and that is
 * where the two paths still disagreed. A TXT record's RDATA is one or more
 * character-strings (RFC 1035 §3.3.14), and a value longer than 255 bytes is
 * split across several — so the strings of ONE record are a single value and
 * must be CONCATENATED, while separate values are separate records. doh.js
 * joined; resolver.js and hip5-op.js spread. Measured 2026-09-04:
 *
 *   one RR carrying "ipfs=<cid>" + "ar=<txid>"
 *       spread -> ipfs pointer      join -> nothing (one garbled string)
 *   one RR whose value is split across two strings
 *       spread -> nothing           join -> the pointer
 *
 * Joining is the one that matches the RFC and the convention everything else
 * on the internet reads TXT with (SPF, DKIM, DNSLink), and it is what our own
 * publisher writes: one value per record. So: join within a record, one entry
 * per record, and no caller assembles strings itself.
 *
 * Accepts either shape the codebase produces: `txt` (already-split strings,
 * from src/hns/dns-query.js) or raw `rdata` (from src/hns/hip5-op.js).
 *
 * @param {Array<{type?: number, txt?: string[], rdata?: Buffer}>} answers
 * @param {number} [txtType] the TXT rrtype, 16 — passed so this module needs
 *   no dependency on a DNS constants table.
 * @returns {string[]}
 */
export function txtStringsFrom (answers, txtType = 16) {
  const out = []
  for (const r of answers || []) {
    if (!r) continue
    if (r.type != null && r.type !== txtType) continue
    if (Array.isArray(r.txt)) {
      out.push(r.txt.join('').trim())
      continue
    }
    if (r.rdata && typeof r.rdata.length === 'number') {
      const parts = []
      let p = 0
      while (p < r.rdata.length) {
        const len = r.rdata[p]
        parts.push(r.rdata.toString('utf8', p + 1, p + 1 + len))
        p += 1 + len
      }
      out.push(parts.join('').trim())
    }
  }
  return out.filter(Boolean)
}

/** The public address shapes. Reused, never re-inlined — see the header. */
export const CID_RE = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,110})$/
export const ARTX_RE = /^[A-Za-z0-9_-]{43}$/

/**
 * Is this the ONE spelling of an Arweave transaction id? 43 base64url
 * characters carry 258 bits for a 32-byte id, so the final character's two
 * low bits must be zero (RFC 4648 §3.5) — otherwise sixteen distinct strings
 * name every transaction, and a pointer would not round-trip to one spelling.
 * @param {string} id
 */
export function isCanonicalTxid (id) {
  if (!ARTX_RE.test(String(id || ''))) return false
  const bytes = Buffer.from(id, 'base64url')
  return bytes.length === 32 && bytes.toString('base64url') === id
}
/**
 * An IPNS name: the base36 libp2p-key CIDv1 `ipfs name publish` returns
 * (`k51…` — base36, NOT base32, which is why the leading `k` is followed by
 * digits), its base32 form, or a legacy peer ID.
 */
export const IPNS_RE = /^(k[0-9a-z]{48,110}|b[a-z2-7]{50,110}|12D3[1-9A-HJ-NP-Za-km-z]{40,50}|Qm[1-9A-HJ-NP-Za-km-z]{44})$/
export const BT_INFOHASH_RE = /^[a-f0-9]{40}$/i
export const BT_PUBKEY_RE = /^[a-f0-9]{64}$/i
/**
 * A hypercore key as it appears in a `hyper://` host: z-base-32 (what
 * hyper-sdk builds `drive.url` from, 52 chars of the z32 alphabet) or the
 * same 32 bytes as hex, which hypercore-fetch also accepts as a host.
 */
export const HYPER_KEY_RE = /^([a-f0-9]{64}|[ybndrfg8ejkmcpqxot1uwisza345h769]{52})$/i

/** Highest priority first. The single source of truth for pointer ordering. */
export const POINTER_PRECEDENCE = Object.freeze(
  ['ipfs', 'ipns', 'bittorrent', 'hyper', 'arweave'])

/** The TXT prefix each pointer kind is written and read under. */
export const POINTER_TAG = Object.freeze({
  ipfs: 'ipfs',
  ipns: 'ipns',
  bittorrent: 'bt',
  hyper: 'hyper',
  arweave: 'ar'
})

/** The owner name DNSLink is served from, relative to the published label. */
export const DNSLINK_PREFIX = '_dnslink'

/**
 * THE STATED ORIGIN — `car=<https url>` — is where the published archive can
 * be fetched from as a CAR and verified against `ipfs=`: a public share
 * capability from the user's OWN storage provider (decision D-P2,
 * STORAGE-PUBLISH-SHARE.md). It is a HINT about where bytes are, never an
 * address a name resolves TO — so it is not a pointer kind, has no place in
 * POINTER_PRECEDENCE, and parsePointer() returns null for it: nothing that
 * trusts a pointer can be handed a URL by mistake. https only; a bearer URL
 * over plaintext would hand the capability to the network.
 */
export const ORIGIN_TAG = 'car'
export const ORIGIN_MAX_BYTES = 480

/** `car=<url>` → the url, or null when the string is not a usable origin. */
export function parseOrigin (value) {
  const raw = String(value == null ? '' : value).trim()
  if (!raw.toLowerCase().startsWith(`${ORIGIN_TAG}=`)) return null
  const url = raw.slice(ORIGIN_TAG.length + 1).trim()
  if (!url || Buffer.byteLength(url, 'utf8') > ORIGIN_MAX_BYTES) return null
  try {
    const u = new URL(url)
    if (u.protocol !== 'https:' || !u.hostname) return null
    return u.href
  } catch { return null }
}

/** The one `car=` among a name's TXT strings, or null. */
export function originFrom (strings) {
  for (const s of strings || []) {
    const url = parseOrigin(s)
    if (url) return url
  }
  return null
}

/** The TXT value that states `url` as the archive's origin — what parseOrigin reads back. */
export function originRecord (url) {
  const parsed = parseOrigin(`${ORIGIN_TAG}=${String(url || '').trim()}`)
  if (!parsed) throw new Error(`not a usable origin url: ${String(url).slice(0, 80)}`)
  return `${ORIGIN_TAG}=${parsed}`
}

/**
 * One TXT string -> a pointer, or null when it is not one of ours or its
 * address is malformed. A pointer whose address fails its shape check is NOT
 * a pointer: half-trusting a garbled record is how a name ends up serving
 * something nobody published.
 *
 * @param {string} value one TXT string, already joined
 * @returns {{kind:string}&Record<string,any>|null}
 */
export function parsePointer (value) {
  const raw = String(value == null ? '' : value).trim()
  const eq = raw.indexOf('=')
  if (eq <= 0) return null
  const tag = raw.slice(0, eq).toLowerCase()
  const id = raw.slice(eq + 1).trim()
  if (!id) return null

  if (tag === 'ipfs') return CID_RE.test(id) ? { kind: 'ipfs', cid: id } : null
  if (tag === 'ipns') return IPNS_RE.test(id) ? { kind: 'ipns', key: id } : null
  if (tag === 'ar') return isCanonicalTxid(id) ? { kind: 'arweave', txid: id } : null
  if (tag === 'hyper') {
    return HYPER_KEY_RE.test(id) ? { kind: 'hyper', key: id.toLowerCase() } : null
  }
  if (tag === 'bt') {
    // Key length is the whole dispatch, exactly as it is for bittorrent://
    // (docs/TORRENT-DESIGN.md §2.1): 40 hex is an immutable infohash, 64 hex
    // is a BEP-46 public key whose content can be updated in place.
    if (BT_INFOHASH_RE.test(id)) {
      return { kind: 'bittorrent', key: id.toLowerCase(), mutable: false }
    }
    if (BT_PUBKEY_RE.test(id)) {
      return { kind: 'bittorrent', key: id.toLowerCase(), mutable: true }
    }
    return null
  }
  return null
}

/**
 * The winning pointer among a name's TXT strings, by POINTER_PRECEDENCE.
 * Order of the RECORDS is irrelevant — only the precedence table decides, so
 * every resolution path agrees regardless of how DNS happened to order them.
 *
 * @param {string[]} strings every TXT string on the name
 * @returns {object|null}
 */
export function pointerFrom (strings) {
  const found = new Map()
  for (const s of strings || []) {
    const p = parsePointer(s)
    if (p && !found.has(p.kind)) found.set(p.kind, p)
  }
  for (const kind of POINTER_PRECEDENCE) {
    if (found.has(kind)) return found.get(kind)
  }
  return null
}

/**
 * The TXT value that publishes `id` as `kind` — the exact string parsePointer
 * will read back.
 * @param {string} kind one of POINTER_PRECEDENCE
 * @param {string} id   the address
 */
export function pointerRecord (kind, id) {
  const tag = POINTER_TAG[kind]
  if (!tag) throw new Error(`unknown pointer kind: ${String(kind).slice(0, 24)}`)
  const parsed = parsePointer(`${tag}=${String(id || '').trim()}`)
  if (!parsed || parsed.kind !== kind) {
    throw new Error(`not a valid ${kind} address: ${String(id).slice(0, 80)}`)
  }
  // Written in the SAME normalized form the parser hands back (hex keys
  // lowercased), so a record round-trips byte-for-byte through a re-publish
  // and never shows up as a spurious change in a zone diff.
  return `${tag}=${parsed.cid || parsed.key || parsed.txid}`
}

/**
 * The DNSLink TXT value. Prefers the IPNS key: a DNSLink pointing at IPNS
 * never has to be rewritten again, while one pointing at a CID is a DNS write
 * on every single publish.
 * @param {{ipns?:string|null, cid?:string|null}} target
 * @returns {string|null} the value, or null when there is nothing to link to
 */
export function dnslinkValue ({ ipns = null, cid = null } = {}) {
  if (ipns && IPNS_RE.test(ipns)) return `dnslink=/ipns/${ipns}`
  if (cid && CID_RE.test(cid)) return `dnslink=/ipfs/${cid}`
  return null
}

/**
 * The relative owner DNSLink is written at for a published label.
 * `@` (the zone apex) -> `_dnslink`; a label -> `_dnslink.<label>`.
 * @param {string} label the published label, or '@' for the apex
 */
export function dnslinkOwner (label) {
  const l = String(label || '@').trim() || '@'
  return l === '@' ? DNSLINK_PREFIX : `${DNSLINK_PREFIX}.${l}`
}

/**
 * A DNSLink TXT value read back (dnslink.dev): `dnslink=/ipfs/<cid>[/path]`
 * or `dnslink=/ipns/<key>[/path]`. The same address shapes as the `ipfs=` and
 * `ipns=` pointers, so a site published for IPFS Companion, Brave or kubo —
 * which read nothing but this record — opens here, and a Wildroot site (which
 * writes both records) opens there. A path suffix is carried as `path`.
 * Any other namespace (`/hyper/`, `/dnslink/`) is not a pointer here.
 * @param {string} value one TXT string
 * @returns {object|null}
 */
export function parseDnslink (value) {
  const raw = String(value == null ? '' : value).trim()
  const m = /^dnslink=\/(ipfs|ipns)\/([^/\s]+)(\/.*)?$/i.exec(raw)
  if (!m) return null
  const ns = m[1].toLowerCase()
  const id = m[2]
  const path = m[3] && m[3] !== '/' ? m[3] : ''
  const pointer = ns === 'ipfs'
    ? (CID_RE.test(id) ? { kind: 'ipfs', cid: id } : null)
    : (IPNS_RE.test(id) ? { kind: 'ipns', key: id } : null)
  if (!pointer) return null
  return path ? { ...pointer, path } : pointer
}

/**
 * The DNSLink pointer among the TXT strings at `_dnslink.<name>`. DNSLink
 * says a name carries ONE dnslink value; when several parse, the first in
 * record order wins, which is what every other DNSLink reader does.
 * @param {string[]} strings
 */
export function dnslinkPointerFrom (strings) {
  for (const s of strings || []) {
    const p = parseDnslink(s)
    if (p) return p
  }
  return null
}

/**
 * Two pointer sources, one answer. A name may carry an `ipfs=`/`ipns=` TXT at
 * the name and a `dnslink=` TXT at `_dnslink.<name>`; Wildroot writes both.
 * Agreement is the normal case and either alone is fine. DISAGREEMENT IS
 * NEVER RESOLVED BY PICKING: two records naming different content is a
 * broken or tampered zone, and the honest answer is to say so rather than
 * render whichever one a rule happens to prefer.
 *
 * @param {object|null} direct the `ipfs=`-family pointer at the name
 * @param {object|null} dnslink the `dnslink=` pointer at `_dnslink.<name>`
 * @returns {{pointer: object|null, conflict?: {direct: object, dnslink: object}}}
 */
export function mergePointers (direct, dnslink) {
  if (!direct && !dnslink) return { pointer: null }
  if (!dnslink) return { pointer: direct }
  if (!direct) return { pointer: { ...dnslink, dnslink: true } }
  const same = direct.kind === dnslink.kind &&
    (direct.cid || direct.key || direct.txid) === (dnslink.cid || dnslink.key) &&
    // An absent path and '/' both identify the root. Preserve every other
    // path exactly: decoding/normalizing here can select different content.
    (direct.path === '/' ? '' : direct.path || '') === (dnslink.path === '/' ? '' : dnslink.path || '')
  if (same) return { pointer: { ...direct, dnslink: true } }
  // A non-IPFS direct pointer (ar=, bt=, hyper=) beside a dnslink is not a
  // disagreement about the same content: DNSLink can only name IPFS content,
  // and POINTER_PRECEDENCE already ranks ipfs first. It is still two
  // different answers, and the rule is the same: surface it.
  return { pointer: null, conflict: { direct, dnslink } }
}
