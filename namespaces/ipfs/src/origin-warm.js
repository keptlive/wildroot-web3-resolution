// A name we KNOW is served by our own storage fetches its archive from that
// storage over HTTPS, once, before the local node is asked for it.
//
// WHY. The cold first byte of a `.pinthis` site through the local kubo is a
// DHT walk plus a bitswap dial — measured 1.2–1.7 s from outside, ~1.4 s even
// from a fresh node bootstrapped straight to our provider (docs/COOP-DELIVERY.md
// F2). But for a `.pinthis` name the browser already knows where the bytes
// are: pinthis.cloud serves the name, wrote its `ipfs=` pointer, and holds the
// archive. One HTTPS GET of the CAR and a `dag import` puts every block on
// the node, hash-checked by kubo on the way in, and the fetch that follows is
// local — the same shape src/sia/restore.js uses for a person's own Sia copy.
//
// WHY THIS AND NOT A DELEGATED ROUTER. kubo's HTTP retrieval would do this for
// every CID if `Routing.DelegatedRouters` named pinthis.cloud — and would
// tell pinthis.cloud every CID the person browses. That list is deliberately
// empty (docs/BUNDLED-DEPENDENCIES.md). Here the only CIDs that reach our
// gateway are those of names our gateway already serves, which it knows by
// definition; nothing about the person's other browsing leaves the machine.
//
// THE RULES, the restorer's (src/sia/restore.js) with one addition:
//   1. Invisible when it has nothing to do: not a name we serve, no node, or
//      the blocks are already here — a local check and the normal fetch.
//   2. Once per CID per session; concurrent requests share one download.
//   3. It never fails the request; a warm that could not happen is logged.
//   4. The import is checked: the CAR's root must be the CID asked for.
//   5. BOUNDED. The archive is fetched whole, so a size cap protects the
//      person's disk and bandwidth: the gateway states Content-Length for a
//      pin's verbatim archive, and anything larger — or of unknown size — is
//      left to the node's ordinary block-by-block path, which seeks.
//   6. No Electron. The node, the fetch and the disk are injected.

import { createWriteStream } from 'node:fs'
import { unlink } from 'node:fs/promises'
import { pipeline } from 'node:stream/promises'
import { Readable } from 'node:stream'
import { randomBytes } from 'node:crypto'
import os from 'node:os'
import { parseByteRange } from './byte-range.js'
import path from 'node:path'

/** The names our own storage serves: `<label>.pinthis` (pinthis `DECISIONS.md` D2). */
export const ORIGINS = Object.freeze([
  { suffix: 'pinthis', gateway: 'https://pinthis.cloud' }
])

/** Archives above this are not fetched whole — a WINDOW around the bytes asked for is fetched instead. */
export const MAX_WARM_BYTES = 64 * 1024 * 1024
/**
 * The byte window warmed around a ranged read of one file inside a large
 * archive (IPIP-402 `entity-bytes`, which pinthis's gateway serves — D12). A
 * seek lands anywhere in a 478 MB recording; the window is what a cold node
 * needs to answer it and the next few seconds of play, fetched over one HTTPS
 * request and verified by CID on import. Measured 2026-09-06: without it a cold
 * node never got a middle block at all.
 */
export const WINDOW_BYTES = 16 * 1024 * 1024
/**
 * What a seek is answered from FIRST: a slice this wide at the seek point —
 * a keyframe and a few seconds of picture (2 MiB is 4–20 s at 0.8–4 Mbit/s)
 * — fetched and imported before the read is served, so a cold jump costs one
 * small request (~0.3 s) instead of the whole window (~1 s, measured on
 * 2.78.12). The rest of the window follows in the background, and a read
 * near the end of a window fetches the next one ahead of the player.
 */
export const SLICE_BYTES = 2 * 1024 * 1024

/** The gateway that serves `host`, or null when no storage of ours does. */
export function originFor (host, origins = ORIGINS) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '')
  if (!h) return null
  const labels = h.split('.')
  if (labels.length !== 2) return null // <label>.pinthis exactly: the apex is the site itself
  const tld = labels[1]
  const hit = origins.find((o) => o.suffix === tld)
  return hit ? hit.gateway : null
}

/**
 * Is this stated origin a trustless GATEWAY for the archive (`https://…/ipfs/<cid>`),
 * which can serve a byte window and a path, or a plain archive URL (a share link
 * to the whole CAR), which can only be fetched whole?
 */
export function gatewayBase (origin, cid) {
  const m = /^(https:\/\/[^/?#]+(?:\/[^?#]*)?\/ipfs\/([^/?#]+))\/?$/.exec(String(origin || ''))
  return m && m[2] === cid ? m[1] : null
}

/** The aligned window a ranged read falls in: [from, to] inclusive, `WINDOW_BYTES` wide. */
export function windowFor (range, window = WINDOW_BYTES) {
  const start = rangeStart(range)
  const from = Math.floor(start / window) * window
  return { from, to: from + window - 1 }
}

/** The aligned slice a ranged read falls in: [from, to] inclusive, `SLICE_BYTES` wide. */
export function sliceFor (range, slice = SLICE_BYTES) {
  const start = rangeStart(range)
  const from = Math.floor(start / slice) * slice
  return { from, to: from + slice - 1 }
}

function rangeStart (range) {
  const want = parseByteRange(range)
  return want && Number.isFinite(want.start) ? want.start : 0
}

/**
 * @param {object} deps
 * @param {() => Promise<object|null>} deps.node  the local kubo (IPFSNode, started), null when unavailable
 * @param {typeof fetch} [deps.fetchImpl]
 * @param {(msg: string) => void} [deps.log]
 * @param {string} [deps.tmpDir]
 * @param {number} [deps.maxBytes]
 * @param {ReadonlyArray<{suffix: string, gateway: string}>} [deps.origins]
 * @returns {(host: string, cid: string) => Promise<{state: string, size?: number, why?: string}>}
 *   states: not-ours | no-node | present | warmed | too-large | failed
 */
export function makeOriginWarmer ({
  node, fetchImpl = (...a) => globalThis.fetch(...a), log = () => {},
  tmpDir = os.tmpdir(), maxBytes = MAX_WARM_BYTES, origins = ORIGINS,
  enabled = true
}) {
  const present = new Set()
  /** Slices already imported this session, by `${cid}|${file}|${slice start}`: a repeated range is free. */
  const slices = new Set()
  const inflight = new Map()
  /** Background work (finishing a window, reading ahead), so a test — or a shutdown — can wait for it. */
  const background = new Set()

  async function warm (url, cid, window = null) {
    const gateway = url
    if (!window && present.has(cid)) return { state: 'present' }
    const ipfs = await node()
    if (!ipfs) return { state: 'no-node' }
    if (!window) {
      // A daemon that answers the probe but not yet the blockstore, or any
      // other hiccup here, must not silently cost the warm: unknown = go on.
      let local = false
      try { local = await ipfs.hasLocally(cid) } catch (err) { log(`warm: could not ask the node about ${cid} — ${err && err.message}; warming anyway`) }
      if (local) {
        present.add(cid)
        return { state: 'present' }
      }
    }
    // One temp file per warm, never shared: the un-ranged head-window warm and
    // a ranged warm of the same window ran at once on 2.78.11, wrote the same
    // path, and one unlinked it under the other's dag/import upload — the
    // import then hung to its abort (117 s) before the page got its bytes.
    const file = path.join(tmpDir, `warm-${cid}-${window ? window.from : 'all'}-${process.pid}-${randomBytes(4).toString('hex')}.car`)
    let res
    try {
      res = await fetchImpl(url, {
        headers: { accept: 'application/vnd.ipld.car' },
        signal: AbortSignal.timeout(30_000)
      })
    } catch (err) {
      log(`warm: ${gateway} unreachable for ${cid} — ${err && err.message}`)
      return { state: 'failed', why: String((err && err.message) || err) }
    }
    if (!res.ok || !res.body) {
      return { state: 'failed', why: `HTTP ${res.status}` }
    }
    const size = Number(res.headers.get('content-length'))
    // A whole archive is bounded by maxBytes; a window's CAR is bounded by the
    // window plus its path blocks (a gateway that ignored entity-bytes would
    // send the whole thing — refused the same way).
    const cap = window ? WINDOW_BYTES * 2 : maxBytes
    if (!window && (!Number.isFinite(size) || size <= 0)) {
      try { await res.body.cancel() } catch {}
      return { state: 'too-large', size: undefined }
    }
    if (Number.isFinite(size) && size > cap) {
      try { await res.body.cancel() } catch {}
      return { state: 'too-large', size }
    }
    try {
      await pipeline(Readable.fromWeb(res.body), createWriteStream(file))
      const roots = await ipfs.importCar(file)
      if (!roots.includes(cid)) throw new Error(`the archive's root is ${roots.join(', ')}, not ${cid}`)
      if (!window) present.add(cid)
      else for (const k of window.marks || []) slices.add(k)
      log(`warm: ${cid}${window ? ` bytes ${window.from}-${window.to}` : ''} imported from ${gateway}`)
      return window ? { state: 'windowed', from: window.from, to: window.to } : { state: 'warmed', size }
    } catch (err) {
      log(`warm: could not import ${cid} from ${gateway} — ${err && err.message}`)
      return { state: 'failed', why: String((err && err.message) || err) }
    } finally {
      try { await unlink(file) } catch {}
    }
  }

  function warmIfOurs (host, cid, { origin = null, sub = '', range = null } = {}) {
    // Settings -> Content delivery, off: the name still opens over the network,
    // the first frame just waits on the peer-to-peer fetch (config originWarm).
    if (!enabled) return Promise.resolve({ state: 'disabled' })
    if (typeof cid !== 'string' || !cid) return Promise.resolve({ state: 'not-ours' })
    // A name that STATES its origin (`car=`, decision D-P2) is served from the
    // publisher's own provider, whoever that is — no vendor list needed. The
    // `.pinthis` table stays for names published before origins existed.
    const table = origin ? null : originFor(host, origins)
    const base = origin ? gatewayBase(origin, cid) : (table ? `${table}/ipfs/${cid}` : null)
    // A plain archive URL (a share link): whole or nothing.
    if (origin && !base) return once(cid, () => warm(origin, cid))
    if (!base) return Promise.resolve({ state: 'not-ours' })
    const file = String(sub || '').replace(/^\/+/, '')
    // A ranged read of one file inside the archive — a seek — warms the
    // window it lands in, so a cold node answers it from a single HTTPS
    // request. The whole-archive warm is tried first only when the archive
    // is small enough to have; `present` then short-circuits every later read.
    // One file, one byte position: the SLICE around it is fetched and
    // imported before the read is served (the same key whether a ranged
    // read or the head-of-file warm below asked, so the two share one
    // download, and a slice already imported this session is free). The
    // rest of the window follows in the background, and a read in the last
    // quarter of a window fetches the next window ahead of the player.
    const encoded = file.split('/').map(encodeURIComponent).join('/')
    const url = (from, to) => `${base}/${encoded}?format=car&dag-scope=entity&entity-bytes=${from}:${to}`
    const sliceKey = (from) => `${cid}|${file}|${from}`
    const marksBetween = (from, to) => {
      const out = []
      for (let f = Math.floor(from / SLICE_BYTES) * SLICE_BYTES; f <= to; f += SLICE_BYTES) out.push(sliceKey(f))
      return out
    }
    const later = (run) => {
      const p = run().catch((err) => log(`warm: background — ${err && err.message}`)).finally(() => background.delete(p))
      background.add(p)
    }
    const sliceWarm = async (start) => {
      const s = { from: Math.floor(start / SLICE_BYTES) * SLICE_BYTES, to: Math.floor(start / SLICE_BYTES) * SLICE_BYTES + SLICE_BYTES - 1 }
      const w = { from: Math.floor(start / WINDOW_BYTES) * WINDOW_BYTES, to: Math.floor(start / WINDOW_BYTES) * WINDOW_BYTES + WINDOW_BYTES - 1 }
      const nearEnd = start >= w.to - WINDOW_BYTES / 4
      let out = { state: 'present' }
      if (!present.has(cid) && !slices.has(sliceKey(s.from))) {
        out = await once(sliceKey(s.from), () => warm(url(s.from, s.to), cid, { ...s, marks: [sliceKey(s.from)] }))
        // The rest of this window, after the slice, so play continues without a wait.
        if (out.state === 'windowed' && s.to < w.to) {
          later(() => once(`${cid}|${file}|${w.from}|rest`, async () => {
            const from = s.to + 1
            if (marksBetween(from, w.to).every((k) => slices.has(k))) return
            await warm(url(from, w.to), cid, { from, to: w.to, marks: marksBetween(from, w.to) })
          }))
        }
      }
      // Reading near the end of a window: have the next one on the way.
      if (nearEnd && !present.has(cid) && !slices.has(sliceKey(w.to + 1))) later(() => sliceWarm(w.to + 1))
      return out
    }
    if (range && file) return sliceWarm(rangeStart(range))
    return once(cid, async () => {
      const whole = await warm(`${base}?format=car&dag-scope=all`, cid)
      // Too large to hold whole: warm the head of the file being opened, so
      // its index and first seconds arrive now and seeks warm their windows.
      if (whole.state === 'too-large' && file) return sliceWarm(0)
      return whole
    })
  }
  /** Wait for background fetches (tests, shutdown). */
  warmIfOurs.idle = async () => { while (background.size) await Promise.allSettled([...background]) }
  return warmIfOurs

  /** One in-flight warm per key; a second ask joins it. */
  function once (key, run) {
    let p = inflight.get(key)
    if (!p) {
      p = run().finally(() => inflight.delete(key))
      inflight.set(key, p)
    }
    return p
  }
}
