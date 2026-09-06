/*
 * IP Protection: route all browser traffic through Tor to hide the user's IP.
 *
 * Honest scope, stated once here and echoed in the UI:
 *   - What it does: every request rides a SOCKS proxy into the Tor network, so
 *     sites (and the metasearch fan-out) see a Tor exit IP, not the user's.
 *   - What it does NOT do: make the user anonymous. This browser does not yet
 *     resist fingerprinting the way Tor Browser does. It hides your IP; it is
 *     not a cloak of invisibility.
 *
 * Two ways to get a Tor SOCKS proxy, in preference order:
 *   1. the browser's OWN bundled Tor client (TorNode) — so a user who has
 *      never installed Tor still gets IP protection. Its SOCKS port is chosen
 *      per session (not 9050), so it coexists with any system Tor.
 *   2. an EXTERNAL tor the user already runs on 127.0.0.1:9050 (detected as a
 *      fallback when no client is bundled).
 *
 * Applied with session.setProxy, which routes EVERYTHING on that session —
 * page loads, the metasearch fan-out, protocol fetches. DNS is proxied too
 * (proxy-side resolution) so a name lookup does not leak around the tunnel.
 *
 * This module owns the selection + proxy-rule logic (pure, tested) and the
 * controller that drives a TorNode. Session wiring lives in the main process.
 */

import { EventEmitter } from 'node:events'

// `blocked` is the fail-closed state: Private mode asked for Tor and there is
// none, so the session is pointed at a proxy that answers nothing rather than
// left direct. Nothing loads; nothing leaks; the note says which.
export const MODES = { OFF: 'off', TOR: 'tor', BLOCKED: 'blocked' }

/**
 * The proxy every session gets while BLOCKED: a loopback port nothing
 * listens on, so every connection fails at once (ERR_PROXY_CONNECTION_FAILED)
 * instead of going out directly. The same rule the PAC decorator folds in,
 * so a wss:// to a Handshake name is blocked the same way.
 */
export const BLACKHOLE_RULES = 'socks5://127.0.0.1:9'

// User-facing status text. Leads with the honest benefit ("hide your IP")
// and the MODE the person chose (Settings › Content delivery), and always
// pairs it with the limitation.
const NOTE_OFF = 'Fast mode — IP protection is off: connecting directly, so sites can see your IP address.'
const NOTE_ON = 'Private mode — your traffic routes through Tor, so sites see a Tor exit IP, not yours. This hides your IP; it is not full anonymity (this browser does not yet resist fingerprinting the way Tor Browser does).'
// The connecting note is live now (it carries the real bootstrap percent), so
// it is built per-tick by connectingNote() below rather than being a constant.
// Live variant of the connecting note: the same honest promise, but carrying
// the real bootstrap percent + phase so the user can SEE it working instead of
// staring at a static "up to a minute" line and assuming it hung.
function connectingNote (percent, phase) {
  const pct = Number.isFinite(percent) ? Math.max(0, Math.min(100, Math.round(percent))) : 0
  const where = phase ? ` — ${phase}` : ''
  return `Private mode — connecting to hide your IP… ${pct}%${where}. The first connection can take up to a minute. ` +
    'Nothing loads until the tunnel is ready, so your real IP is not exposed while you wait.'
}
const NOTE_UNAVAILABLE = 'IP protection is unavailable — no Tor client is bundled or running, so staying on a direct connection.'
const NOTE_FAILED = 'IP protection could not reach the Tor network — staying on a direct connection. Try turning it on again.'
// The fail-closed counterparts (Private mode): nothing loads, and the note
// says what to do about it.
const NOTE_BLOCKED_UNAVAILABLE = 'Private mode cannot connect — no Tor client is bundled or running. Nothing loads until it can; switch to Fast in Settings › Content delivery to connect directly.'
const NOTE_BLOCKED_FAILED = 'Private mode could not reach the Tor network. Nothing loads until it can — try again, or switch to Fast in Settings › Content delivery to connect directly.'

const EXTERNAL_HOST = '127.0.0.1'
const EXTERNAL_PORT = 9050

/** Is a local Tor SOCKS proxy accepting connections? (external-tor fallback) */
export async function detectTor ({ host = EXTERNAL_HOST, port = EXTERNAL_PORT, timeout = 1500, connectImpl } = {}) {
  const connect = connectImpl || defaultConnect
  try {
    await connect(host, port, timeout)
    return true
  } catch {
    return false
  }
}

function defaultConnect (host, port, timeout) {
  return new Promise((resolve, reject) => {
    import('node:net').then(({ default: net }) => {
      const socket = net.connect({ host, port })
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('timeout')) }, timeout)
      socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolve() })
      socket.once('error', (err) => { clearTimeout(timer); reject(err) })
    }).catch(reject)
  })
}

/**
 * Resolve a requested mode to a concrete Electron proxyRules string (or null
 * for a direct connection). Pure and testable: the caller supplies whether a
 * Tor SOCKS proxy is available and, if so, its URL.
 *
 * Electron proxyRules over SOCKS also proxies DNS, avoiding leaks.
 * @returns {{ mode:string, rules:string|null, note:string }}
 */
export function resolveProxy (mode, { torAvailable = false, torSocks = null } = {}) {
  switch (mode) {
    case MODES.OFF:
      return { mode: MODES.OFF, rules: null, note: NOTE_OFF }
    case MODES.TOR:
      if (!torAvailable || !torSocks) {
        return { mode: MODES.OFF, rules: null, note: NOTE_UNAVAILABLE }
      }
      return { mode: MODES.TOR, rules: torSocks, note: NOTE_ON }
    default:
      return { mode: MODES.OFF, rules: null, note: `Unknown mode '${mode}', staying direct.` }
  }
}

/**
 * Stateful controller the main process holds: tracks the current mode, drives
 * the bundled TorNode, applies the proxy to the browser sessions, and reports
 * status for the UI/menu.
 */
export class AnonymizeController extends EventEmitter {
  constructor ({ sessions, tor = null, proxyConfigFor = null, failClosed = false } = {}) {
    super()
    this.sessions = Array.isArray(sessions) ? sessions : [sessions].filter(Boolean)
    this.tor = tor // an optional TorNode
    // Private mode's promise is "the page fails rather than falling back".
    // With failClosed, a TOR request that cannot be met enters BLOCKED (the
    // blackhole proxy) instead of OFF (direct). Off by default so the
    // controller-only callers and the older tests keep the direct fallback.
    this.failClosed = !!failClosed
    // Optional per-session decorator: given (session, rules, baseConfig) it
    // returns the proxy config actually applied. This is how hns:// WebSocket
    // routing composes with anonymization — the controller stays the SINGLE
    // owner of session.setProxy (Electron allows one proxy config per session),
    // and the WS PAC is folded into the config rather than a clobbering second
    // setProxy call. See src/hns/ws-proxy-pac.js and docs/WEBSOCKETS.md.
    this.proxyConfigFor = proxyConfigFor
    this.mode = MODES.OFF
    this.status = { mode: MODES.OFF, rules: null, note: NOTE_OFF, percent: 0, phase: '' }
    this._switchSeq = 0 // guards against a slow bootstrap landing after a later switch
    this._bootstrapListener = null // live-progress subscription on the TorNode
  }

  /** Stop relaying bootstrap ticks (switched away, or settled). */
  _unsubscribeBootstrap () {
    if (this._bootstrapListener && this.tor && typeof this.tor.off === 'function') {
      this.tor.off('bootstrap', this._bootstrapListener)
    }
    this._bootstrapListener = null
  }

  async setMode (mode) {
    const seq = ++this._switchSeq
    // Any in-flight connecting cycle is superseded by this switch.
    this._unsubscribeBootstrap()

    if (mode === MODES.OFF) {
      // THE GATE CLOSES FIRST. isOn() is what the onion handler consults
      // before routing; across the await below the session proxy is already
      // direct, and a request admitted in that window would hand a .onion
      // host to the system resolver. Turning protection ON is the mirror
      // image — route first, announce after — so that in both directions the
      // restrictive state is entered before the permissive one.
      this.mode = MODES.OFF
      await this._applyRules(null)
      this.status = { mode: MODES.OFF, rules: null, note: NOTE_OFF, percent: 0, phase: '' }
      this.emit('change', this.status)
      return this.status
    }

    if (mode === MODES.TOR) {
      // With a bundled TorNode, ensure it is started and route through it.
      if (this.tor) {
        const state = await this.tor.start()
        if (state === 'unavailable') {
          return this._cannotRoute(NOTE_UNAVAILABLE, NOTE_BLOCKED_UNAVAILABLE)
        }
        // Route to the chosen SOCKS port NOW — even mid-bootstrap. Requests
        // wait for the circuit rather than escaping direct, so there is no
        // leak window while "connecting…" is showing.
        const torSocks = this.tor.socksUrl()
        await this._applyRules(torSocks)
        this.mode = MODES.TOR
        if (this.tor.isReady()) {
          this.status = { mode: MODES.TOR, rules: torSocks, note: NOTE_ON, percent: 100, phase: '' }
        } else {
          const p = typeof this.tor.bootstrapProgress === 'function'
            ? this.tor.bootstrapProgress()
            : { percent: 0, phase: '' }
          this.status = { mode: MODES.TOR, rules: torSocks, note: connectingNote(p.percent, p.phase), percent: p.percent || 0, phase: p.phase || '' }
          this._subscribeBootstrap(seq, torSocks)
          this._awaitReady(seq, torSocks)
        }
        this.emit('change', this.status)
        return this.status
      }

      // No bundled TorNode: fall back to an external tor the user runs.
      const torAvailable = await detectTor()
      const torSocks = torAvailable ? `socks5://${EXTERNAL_HOST}:${EXTERNAL_PORT}` : null
      const resolved = resolveProxy(MODES.TOR, { torAvailable, torSocks })
      if (resolved.mode === MODES.OFF) {
        return this._cannotRoute(NOTE_UNAVAILABLE, NOTE_BLOCKED_UNAVAILABLE)
      }
      // Entering TOR routes before announcing.
      await this._applyRules(resolved.rules)
      this.mode = resolved.mode
      this.status = resolved
      this.emit('change', this.status)
      return this.status
    }

    // Unknown mode: fail safe to direct — gate first, then the proxy.
    this.mode = MODES.OFF
    await this._applyRules(null)
    this.status = { mode: MODES.OFF, rules: null, note: `Unknown mode '${mode}', staying direct.` }
    this.emit('change', this.status)
    return this.status
  }

  /**
   * Relay tor's live bootstrap ticks into 'change' events so a status surface
   * can show "Connecting… 45% — <phase>". Display-only: the proxy is already
   * pointed at the (still-bootstrapping) SOCKS port, so this changes nothing
   * about leak safety. Guarded by seq so a stale cycle cannot repaint the note.
   */
  _subscribeBootstrap (seq, torSocks) {
    if (!this.tor || typeof this.tor.on !== 'function') return
    this._unsubscribeBootstrap()
    const listener = ({ percent, phase } = {}) => {
      if (seq !== this._switchSeq) return
      if (this.tor.isReady()) return // the 'on' flip owns 100%
      this.status = {
        mode: MODES.TOR,
        rules: torSocks,
        note: connectingNote(percent, phase),
        percent: percent || 0,
        phase: phase || ''
      }
      this.emit('change', this.status)
    }
    this._bootstrapListener = listener
    this.tor.on('bootstrap', listener)
  }

  /** Flip "connecting…" to "on" (or to an honest failure) once tor settles. */
  _awaitReady (seq, torSocks) {
    this.tor.whenReady().then(async (ok) => {
      if (seq !== this._switchSeq) return // the user switched away meanwhile
      this._unsubscribeBootstrap()
      if (ok) {
        this.status = { mode: MODES.TOR, rules: torSocks, note: NOTE_ON, percent: 100, phase: '' }
        this.emit('change', this.status)
        // The circuit is up: let the main process auto-load the tab(s) that
        // failed or waited while connecting (BUG 2). Fires once per cycle.
        this.emit('tor-ready', this.status)
      } else {
        await this._cannotRoute(NOTE_FAILED, NOTE_BLOCKED_FAILED)
      }
    })
  }

  /**
   * TOR was asked for and cannot be had. Direct with an honest note by
   * default; with failClosed, BLOCKED: the sessions are pointed at the
   * blackhole so nothing loads and nothing leaks, and isOn() stays true so
   * every gate that reads it keeps refusing.
   */
  async _cannotRoute (noteDirect, noteBlocked) {
    if (this.failClosed) {
      this.mode = MODES.BLOCKED
      await this._applyRules(BLACKHOLE_RULES)
      this.status = { mode: MODES.BLOCKED, rules: BLACKHOLE_RULES, note: noteBlocked, percent: 0, phase: '' }
    } else {
      this.mode = MODES.OFF
      await this._applyRules(null)
      this.status = { mode: MODES.OFF, rules: null, note: noteDirect, percent: 0, phase: '' }
    }
    this.emit('change', this.status)
    return this.status
  }

  _defaultConfig (rules) {
    return rules
      ? { proxyRules: rules, proxyBypassRules: '<-loopback>' }
      : { mode: 'direct' }
  }

  async _applyRules (rules) {
    for (const s of this.sessions) {
      const base = this._defaultConfig(rules)
      const config = this.proxyConfigFor ? this.proxyConfigFor(s, rules, base) : base
      await s.setProxy(config)
      // Force new sockets so an in-flight direct connection cannot outlive the
      // switch (a leak when turning protection ON).
      if (s.closeAllConnections) await s.closeAllConnections()
    }
  }

  /** Re-apply the current mode through the decorator. Used at startup so the
   *  WS PAC is live from launch — the controller starts OFF and would not call
   *  setProxy until the first IP-Protection toggle otherwise, leaving the WS
   *  routing uninstalled. */
  async reapply () {
    await this._applyRules(this.mode === MODES.OFF ? null : this.status.rules)
  }

  /** Is protection in force — routed through Tor, or blocked because it cannot be? Gates read this. */
  isOn () { return this.mode !== MODES.OFF }

  /**
   * The Tor SOCKS URL, only while traffic is actually routed through it. The
   * raw-socket paths that dial through Tor themselves (the chain resolver's
   * authoritative hop, the WebSocket tunnel, Gemini, Nostr) read this: while
   * BLOCKED it is null, so each of them refuses rather than dialling the
   * blackhole and reporting a network fault.
   */
  torSocks () { return this.mode === MODES.TOR ? (this.status && this.status.rules) || null : null }
}

/**
 * Apply a resolved proxy to Electron sessions without a controller. The
 * app goes through AnonymizeController.setMode (which does the same inline,
 * with the bundled tor's lifecycle around it); this is the controller-free
 * form the pure tests drive. `sessions` is one or many. Returns the resolved
 * descriptor for the caller to surface in the UI.
 */
export async function applyProxy (sessions, mode, opts = {}) {
  const list = Array.isArray(sessions) ? sessions : [sessions]
  const torAvailable = mode === MODES.TOR ? await detectTor(opts.tor || {}) : false
  const torSocks = torAvailable ? `socks5://${EXTERNAL_HOST}:${EXTERNAL_PORT}` : null
  const resolved = resolveProxy(mode, { torAvailable, torSocks })
  for (const s of list) {
    if (resolved.rules) {
      await s.setProxy({ proxyRules: resolved.rules, proxyBypassRules: '<-loopback>' })
    } else {
      await s.setProxy({ mode: 'direct' })
    }
    if (s.closeAllConnections) await s.closeAllConnections()
  }
  return resolved
}
