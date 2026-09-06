// The ICANN transport policy: which resolver an ordinary web lookup goes to,
// and what the interface is allowed to say about it.
//
// WHY THIS IS ITS OWN MODULE. The decisions below used to be inline in the
// Electron composition layer (src/index.js), in three places, next to the I/O
// that acts on them — minting the loopback certificate, starting the
// oblivious bridge, calling `app.configureHostResolver`. Two of those places
// evaluated the same predicate in two different ways, and the security panel
// read the STATIC configuration rather than the plan that was actually
// applied, so it could name four resolvers the engine had stopped using.
//
// The I/O stays in index.js. The decisions live here, Electron-free and
// tested, and the plan that was applied is recorded here so the panel and
// the address-bar lock read the same fact the engine was configured with.

/** The three values `dns.mode` may take. */
export const DNS_MODES = Object.freeze(['off', 'automatic', 'secure'])

/**
 * `dns.mode`, normalised. Case and surrounding whitespace are forgiven
 * (`'Off '` means off); anything else is reported through `onUnknown` and
 * becomes `automatic` — the default, and the one that still encrypts.
 * @param {unknown} mode
 * @param {(raw: unknown) => void} [onUnknown]
 * @returns {'off'|'automatic'|'secure'}
 */
export function normalizeDnsMode (mode, onUnknown) {
  const raw = String(mode ?? '').trim().toLowerCase()
  if (DNS_MODES.includes(raw)) return raw
  if (raw && typeof onUnknown === 'function') onUnknown(mode)
  return 'automatic'
}

/**
 * The `dns` block as Private mode applies it (src/hns/delivery-mode.js):
 * `secure`, and the oblivious bridge as the ONLY server. The configured pool
 * is dropped — an encrypted-but-not-oblivious resolver still learns every
 * name and the address asking — so with no bridge running the plan fails
 * closed and ordinary web addresses do not resolve until it is. That is the
 * mode's promise ("nothing is looked up in the clear: if a private lookup
 * fails, the page fails") applied to ICANN names.
 * @param {{mode?: string, servers?: string[]}} [dns]
 */
export function privateDns (dns = {}) {
  return { ...dns, mode: 'secure', servers: [] }
}

/**
 * Should the oblivious loopback bridge be started — and, equivalently, should
 * a loopback certificate be minted and its key handed to the engine as
 * trusted for any host? ONE predicate for both gates: a key the engine
 * trusts for every host must never be minted for a bridge that is not going
 * to run, so the certificate gate asks exactly this question.
 * @param {{dns?: object, odoh?: object}} config
 */
export function wantsObliviousBridge ({ dns = {}, odoh = {} } = {}) {
  return normalizeDnsMode(dns.mode) !== 'off' &&
    odoh.enabled !== false &&
    odoh.icann !== false &&
    Array.isArray(odoh.relays) && odoh.relays.length > 0
}

/**
 * The transport plan for ICANN lookups: what the engine's host resolver is
 * told, and what is therefore true about the lookups it makes.
 *
 * `secure` with no server to point at FAILS CLOSED: the engine is configured
 * for secure mode with an empty list, so nothing resolves, rather than left
 * on its default, which resolves in the clear. A setting that says "never
 * plaintext" must not silently mean nothing.
 *
 * @param {object} args
 * @param {{mode?: string, servers?: string[]}} [args.dns] the `dns` config block
 * @param {{enabled?: boolean, icann?: boolean, relays?: string[]}} [args.odoh]
 * @param {{template?: string}|null} [args.bridge] the STARTED bridge, or null
 *   if it was not wanted or failed to start. Starting it is the caller's job.
 * @returns {{mode: 'off'|'automatic'|'secure', servers: string[],
 *   oblivious: boolean, configure: boolean, failClosed: boolean,
 *   plaintextFallback: boolean}}
 *   `configure` is whether `app.configureHostResolver` is called at all; when
 *   it is false the engine keeps its default, which is system DNS.
 * @param {boolean} [args.privateMode] Private mode (delivery-mode.js): the
 *   block is replaced by privateDns() first
 */
export function planDnsTransport ({ dns = {}, odoh = {}, bridge = null, privateMode = false } = {}) {
  // Private mode rewrites the block before anything else reads it, so every
  // fact below (configure, failClosed, plaintextFallback) is computed for the
  // configuration the engine is actually given.
  if (privateMode) dns = privateDns(dns)
  const mode = normalizeDnsMode(dns.mode)
  let servers = Array.isArray(dns.servers) ? dns.servers.filter((s) => typeof s === 'string' && s) : []
  let oblivious = false

  if (wantsObliviousBridge({ dns, odoh }) && bridge && bridge.template) {
    // The bridge REPLACES the pool rather than leading it. Whether the engine
    // would fall from an oblivious template to a plain one in a mixed list,
    // silently, has not been measured, and until it is the panel's per-name
    // claim (icannBridgeState) is the only thing that could tell them apart.
    servers = [bridge.template]
    oblivious = true
  }

  const failClosed = mode === 'secure' && servers.length === 0
  const configure = mode !== 'off' && (servers.length > 0 || failClosed)
  return {
    mode,
    servers,
    oblivious,
    configure,
    failClosed,
    // True whenever an ICANN lookup can still leave this machine in the clear:
    // either nothing was configured at all, or the mode permits the fallback.
    plaintextFallback: !configure || mode === 'automatic'
  }
}

// --- What was actually applied ----------------------------------------------

let effective = null

/** Record the plan the engine was configured with, for the interface to read. */
export function recordDnsPlan (plan) {
  effective = plan && typeof plan === 'object' ? { ...plan } : null
}

/** The plan the engine was configured with, or null before configuration. */
export function effectiveDnsPlan () {
  return effective
}

/**
 * May the interface say THIS page's name was looked up obliviously?
 *
 * The rule is the point: obliviousness is claimed for a name the bridge
 * actually answered, never because the feature is switched on. In `automatic`
 * mode the engine can resolve a name by other means at any moment, and a panel
 * that reported the setting rather than the event would be making exactly the
 * kind of claim this browser exists to stop making.
 *
 * @param {object|null} bridge the live bridge (exposes `server`,
 *   `servedRecently(host)`, `transport.relays`, `transport.targets`)
 * @param {string} [host]
 * @returns {{live: true, relay: string|null, target: string|null}|null}
 */
export function icannBridgeState (bridge, host) {
  try {
    if (!bridge || !bridge.server) return null
    if (host && !bridge.servedRecently(host)) return null
    return {
      live: true,
      relay: bridge.transport && bridge.transport.relays && bridge.transport.relays[0]
        ? hostOf(bridge.transport.relays[0])
        : null,
      target: bridge.transport && bridge.transport.targets && bridge.transport.targets[0]
        ? bridge.transport.targets[0].host
        : null
    }
  } catch {
    return null
  }
}

function hostOf (url) {
  try { return new URL(url).host } catch { return String(url) }
}
