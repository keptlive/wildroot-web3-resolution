// Per-method resolution timing.
//
// WHY. Wildroot resolves a name several different ways — a chain proof from the
// local SPV node, plain DoH, oblivious DoH, then DANE/TLSA on top, then content
// from IPFS or Arweave — and until now none of it was measured. So "Handshake
// feels slow" could not be attributed to a step, and the honest question a
// sceptic asks ("how much does the trustless path actually cost you?") had no
// answer at all.
//
// It is also the most interesting number this project can publish. Nobody has
// credible latency figures for Handshake resolution; we are in a position to
// measure it from the inside, per method, with the proof path separated from
// the trust-the-resolver path.
//
// PRIVACY. This records METHOD and DURATION. It never records the name looked
// up, the address, or anything about the content — a browser that shipped a
// timing log of everywhere you went would be a tracking product. The only
// identifiers are the fixed method names below. Aggregates are what leaves this
// module; individual samples never carry a subject.
//
// Electron-free and clock-injected so it is unit-testable, like
// src/startup-timing.js.

/** The methods worth separating. Anything else is rejected, so a typo cannot
 *  silently create a category nobody reads. */
export const METHODS = Object.freeze([
  'spv', // chain proof from the local hsd SPV node
  'doh', // plain DNS-over-HTTPS (no chain proof)
  'odoh', // oblivious DoH (resolver cannot see who asked)
  'dane', // TLSA fetch + validation
  'dnssec', // DNSSEC chain validation over a fetched RRset
  'ipfs', // content fetch for an ipfs= pointer
  'ipns', // content fetch for an ipns= pointer
  'bittorrent', // content fetch for a bt= pointer (torrent-hosted site)
  'hyper', // content fetch for a hyper= pointer
  'arweave', // content fetch for an ar= pointer
  'https' // plain A-record fetch, DANE-pinned TLS
])

const PERCENTILES = [50, 95]

/**
 * @param {{now?: () => number, cap?: number}} [options]
 *   `cap` bounds the samples kept PER METHOD. Unbounded, a long session would
 *   grow this without limit for data nobody reads at that resolution.
 */
export function createResolutionTimers ({ now = () => Date.now(), cap = 512 } = {}) {
  /** @type {Map<string, {ok: number[], fail: number[]}>} */
  const samples = new Map()

  const bucket = (method) => {
    if (!METHODS.includes(method)) {
      throw new Error(`resolution-timing: unknown method ${JSON.stringify(method)} — ` +
        `add it to METHODS, do not invent one (known: ${METHODS.join(', ')})`)
    }
    if (!samples.has(method)) samples.set(method, { ok: [], fail: [] })
    return samples.get(method)
  }

  const push = (method, ms, ok) => {
    const b = bucket(method)
    const list = ok ? b.ok : b.fail
    list.push(ms)
    if (list.length > cap) list.shift()
  }

  /**
   * Time one resolution attempt. Records on BOTH paths: a method that fails
   * slowly (a DoH server that black-holes, an SPV node still syncing) is the
   * most useful measurement here, and the one a success-only timer hides.
   * @template T
   * @param {string} method
   * @param {() => Promise<T>} fn
   */
  const time = async (method, fn) => {
    bucket(method) // validate the name BEFORE running, so a typo fails loudly
    const start = now()
    try {
      const out = await fn()
      push(method, now() - start, true)
      return out
    } catch (err) {
      push(method, now() - start, false)
      throw err
    }
  }

  /** Record a duration measured elsewhere. */
  const record = (method, ms, ok = true) => push(method, ms, ok)

  return {
    time,
    record,
    /** Aggregates for one method, or null when it has never been used. */
    stats: (method) => summarize(samples.get(method)),
    /** Every method that has data, worst p50 first — the publishable shape. */
    report: () => METHODS
      .map((method) => ({ method, ...(summarize(samples.get(method)) || {}) }))
      .filter((row) => row.count)
      .sort((a, b) => b.p50 - a.p50),
    format: () => formatReport(METHODS
      .map((method) => ({ method, ...(summarize(samples.get(method)) || {}) }))
      .filter((row) => row.count)
      .sort((a, b) => b.p50 - a.p50)),
    reset: () => samples.clear()
  }
}

/** @param {{ok: number[], fail: number[]}|undefined} b */
function summarize (b) {
  if (!b) return null
  const all = [...b.ok, ...b.fail]
  if (!all.length) return null
  const sorted = [...all].sort((x, y) => x - y)
  const out = {
    count: all.length,
    ok: b.ok.length,
    failed: b.fail.length,
    min: sorted[0],
    max: sorted[sorted.length - 1]
  }
  for (const p of PERCENTILES) out[`p${p}`] = percentile(sorted, p)
  return out
}

/** Nearest-rank percentile. Exported so the definition is testable rather than
 *  assumed — an off-by-one here quietly misreports every number we publish. */
export function percentile (sorted, p) {
  if (!sorted.length) return 0
  const rank = Math.ceil((p / 100) * sorted.length)
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))]
}

/** @param {any[]} rows */
export function formatReport (rows) {
  if (!rows.length) return 'resolution: nothing measured yet'
  const width = Math.max(...rows.map((r) => r.method.length))
  const lines = rows.map((r) =>
    `  ${r.method.padEnd(width)}  n=${String(r.count).padStart(4)}  ` +
    `p50 ${String(r.p50).padStart(6)}ms  p95 ${String(r.p95).padStart(6)}ms  ` +
    `max ${String(r.max).padStart(6)}ms` + (r.failed ? `  (${r.failed} failed)` : ''))
  return ['resolution timings (slowest median first)', ...lines].join('\n')
}

/**
 * The instance the browser records into.
 *
 * A module singleton rather than a threaded parameter: the resolvers are built
 * in several places and the point is ONE table covering the whole session.
 * createResolutionTimers() is the tested unit — this is just where the app's
 * samples land, so a report can be asked for from anywhere.
 */
export const timers = createResolutionTimers()
