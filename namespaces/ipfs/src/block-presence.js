// What this process believes is in the local blockstore — and for how long it
// may go on believing that without asking kubo again.
//
// WHY THIS EXISTS (2026-09-11). The browser's kubo now runs with
// `--enable-gc` (src/hns/ipfs.js daemonArgs), and GC removes every UNPINNED
// block. The two unpinned importers — origin-warm.js (archives, and windows of
// large files) and sia/restore.js (copies kept in online storage) — each kept
// a Set of what they had imported for the life of the process. After a GC they
// would have gone on answering "present" and never fetched again: the content
// stays broken until a restart, and for good in Private mode, where kubo is
// offline and cannot fetch the missing blocks itself.
//
// So a CID is trusted for `ttlMs` after it was last confirmed, then confirmed
// again with ONE offline block/stat of its root. GC takes a root together with
// its leaves, so a missing root is a sound signal to forget the CID and every
// slice recorded under it. Kubo collects at most once per GCPeriod (1 h), and
// only once the repo passes 90 % of StorageMax, so a short TTL costs one local
// stat per CID per TTL and keeps repeated reads — video seeks — free between.

/** Short against kubo's GCPeriod (1 h): a GC is noticed within minutes. */
export const PRESENCE_TTL_MS = 5 * 60 * 1000

/**
 * @param {{now?: () => number, ttlMs?: number}} [options]
 */
export function makeBlockPresence ({ now = Date.now, ttlMs = PRESENCE_TTL_MS } = {}) {
  /** CID -> when kubo last confirmed (or we imported) its root. */
  const checkedAt = new Map()
  /** Whole DAGs on the node. */
  const whole = new Set()
  /** Slices imported this session, keyed `${cid}|…` so they can be dropped per CID. */
  const slices = new Set()

  function forget (cid) {
    whole.delete(cid)
    checkedAt.delete(cid)
    const prefix = `${cid}|`
    for (const key of slices) if (key.startsWith(prefix)) slices.delete(key)
  }

  return {
    has: (cid) => whole.has(cid),
    hasSlice: (key) => slices.has(key),
    /** Is what we remember about `cid` old enough to be worth re-confirming? */
    stale (cid) {
      const at = checkedAt.get(cid)
      return at != null && now() - at >= ttlMs
    },
    remember (cid) {
      whole.add(cid)
      checkedAt.set(cid, now())
    },
    rememberSlice (cid, key) {
      slices.add(key)
      checkedAt.set(cid, now())
    },
    forget,
    /**
     * Re-confirm `cid` with the node when its memory is stale.
     * @returns {Promise<boolean>} false when it was garbage-collected — and
     *   then everything remembered under it has been forgotten
     */
    async revalidate (cid, ipfs, log = () => {}) {
      if (!checkedAt.has(cid) || now() - checkedAt.get(cid) < ttlMs) return true
      let local
      try {
        local = await ipfs.hasLocally(cid)
      } catch {
        // A node that cannot answer is not evidence of eviction. Keep
        // believing; the next read asks again.
        return true
      }
      if (local) {
        checkedAt.set(cid, now())
        return true
      }
      forget(cid)
      log(`presence: ${cid} was garbage-collected from the node; it will be fetched again`)
      return false
    }
  }
}
