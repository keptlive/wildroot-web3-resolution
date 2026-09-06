// One function, lifted out of the Wildroot browser's `src/hns/ipfs.js` so that
// `origin-warm.js` can be extracted without the kubo daemon it lives beside.
// In the browser tree these are the same file; here the daemon half is
// transport and out of scope (SPEC §1.1), and this half decides *which bytes
// of a DAG an address is being asked for*, which is not.
//
// The body below is byte-identical to `src/hns/ipfs.js` in the Wildroot tree.

/**
 * `bytes=500-999` → `{start: 500, end: 999}`; `bytes=500-` → `{start:500, end:null}`.
 * Anything else (multi-range, suffix ranges, junk) → null, which means
 * "serve the whole thing" — a correct 200 beats a wrong 206.
 * @param {string|null} header
 */
export function parseByteRange (header) {
  const h = String(header || '').trim()
  // `bytes=-500`: the LAST 500 bytes — how a player finds an MP4's index when
  // the file was written with the `moov` atom at the end, and how a download
  // resumes. Needs the file size, which fetch() asks the node for.
  const suffix = /^bytes=-(\d+)$/.exec(h)
  if (suffix) {
    const n = Number(suffix[1])
    return Number.isFinite(n) && n > 0 ? { suffix: n } : null
  }
  const m = /^bytes=(\d+)-(\d*)$/.exec(h)
  if (!m) return null
  const start = Number(m[1])
  const end = m[2] === '' ? null : Number(m[2])
  if (!Number.isFinite(start) || start < 0) return null
  if (end != null && (!Number.isFinite(end) || end < start)) return null
  return { start, end }
}
