/*
 * Settings › Content delivery › Mode: Fast / Private — the ONE switch.
 *
 * WHY ONE SWITCH. Privacy and speed pull apart in exactly five places in this
 * browser (docs/MODES.md, the public specification's DIVERGENCE.md); every
 * other divergence was resolved so that the private path is also the fast
 * one. Those five are what a mode is for, and they must move TOGETHER: two
 * controls (IP Protection and a "private lookups" setting, say) would let a
 * person believe they were private while one of them was off. So there is one
 * control, and this module is the single table of what each side decides.
 * Every consumer — the anonymizer, the Handshake DoH resolver, the ICANN
 * transport plan, the Nostr handler, the peer-to-peer gates — reads its
 * answer from policyFor(), never from a flag of its own.
 *
 * What a mode does NOT do: change a trust verdict. The lock and the security
 * panel report what happened for THIS page in both modes; the mode is a
 * policy, the panel is the fact.
 */

import { EventEmitter } from 'node:events'

export const DELIVERY_MODES = Object.freeze(['fast', 'private'])

/**
 * The stored value, normalised. Anything that is not `private` is `fast` —
 * the default, and the one that never refuses a page.
 * @param {unknown} mode
 * @returns {'fast'|'private'}
 */
export function normalizeDeliveryMode (mode) {
  const raw = String(mode ?? '').trim().toLowerCase()
  return raw === 'private' ? 'private' : 'fast'
}

/**
 * What each mode decides, in one place. The row numbers are the public
 * specification's DIVERGENCE.md rows; row 10 (cooperative delivery) is not
 * here because the feature is not shipped.
 * @param {unknown} mode
 */
export function policyFor (mode) {
  const m = normalizeDeliveryMode(mode)
  const priv = m === 'private'
  return Object.freeze({
    mode: m,
    /** Row 7: every session fetch through the device-local Tor, or direct. */
    ipProtection: priv ? 'tor' : 'off',
    /** Row 3: a Handshake name over DoH is looked up obliviously or not at all. */
    strictOblivious: priv,
    /** ICANN names: `secure` with the oblivious bridge as the only server, or the configured `dns.mode`. */
    icannDns: priv ? 'secure' : null,
    /** Row 15: Nostr relays dialled through Tor. */
    nostrThroughTor: priv,
    /** Row 19: hyper / SSB / BitTorrent discovery refused, with the reason on the page. */
    p2pDiscovery: priv ? 'refused' : 'allowed',
    /** Row 8: the local content node runs offline (no swarm, no DHT client) in Private. */
    contentNode: priv ? 'offline' : 'dhtclient'
  })
}

/**
 * The wording the control carries, in full — reviewed in docs/MODES.md and
 * carried here so the settings page cannot drift from it. The `private` line
 * names three protocols, so on the settings page it sits behind the (?)
 * (default-surface-copy.test.js); the surface says the same without them.
 */
export const DISCLOSURE = Object.freeze({
  heading: 'Mode',
  fast: 'Fast — everything loads the quickest way it can. Sites, name servers and relays see this device\'s address. Encrypted DNS is used when it works, and falls back to your network\'s DNS when it does not.',
  private: 'Private — every connection goes through the Tor client on this device, and nothing is looked up in the clear: if a private lookup fails, the page fails rather than falling back. Pages load more slowly; some sites block Tor; peer-to-peer content (hyper, SSB, BitTorrent) is refused, with the reason shown. Handshake names keep their chain proof either way.',
  neither: 'Neither mode changes what the lock says. The lock reports what was verified on this computer and what was taken on someone\'s word; the mode only decides the route.'
})

/** Every refusal page points at the same control, in the same words. */
export const SWITCH_HINT = 'Switch to Fast in Settings › Content delivery to load it directly.'

/**
 * The controller the main process holds: the current mode, its policy, and
 * the anonymizer it drives. `persist(mode)` writes the setting (the config
 * file) so the mode survives a restart; the settings page and the menu both
 * end up in set().
 *
 * Order of operations is the point. Entering Private flips the mode FIRST —
 * every consumer that reads policyFor() is restrictive from that instant —
 * and routes the session through Tor after. Leaving Private takes the
 * anonymizer off first (it closes its own gate before going direct) and
 * flips the mode last, so in both directions the restrictive state is
 * entered before the permissive one.
 */
export class DeliveryMode extends EventEmitter {
  constructor ({ anonymizer = null, mode = 'fast', persist = null } = {}) {
    super()
    this.anonymizer = anonymizer
    this.mode = normalizeDeliveryMode(mode)
    this.persist = typeof persist === 'function' ? persist : null
  }

  get policy () { return policyFor(this.mode) }

  isPrivate () { return this.mode === 'private' }

  /** Drive the anonymizer to what the current mode says (startup, and after set()). */
  async apply () {
    if (this.anonymizer && typeof this.anonymizer.setMode === 'function') {
      await this.anonymizer.setMode(this.policy.ipProtection)
    }
    this.emit('change', { mode: this.mode, policy: this.policy })
    return this.policy
  }

  /** Switch modes: persist, then apply in the safe order. */
  async set (mode) {
    const next = normalizeDeliveryMode(mode)
    if (next === 'private') {
      this.mode = next
      if (this.persist) await this.persist(next)
      return this.apply()
    }
    if (this.anonymizer && typeof this.anonymizer.setMode === 'function') {
      await this.anonymizer.setMode('off')
    }
    this.mode = next
    if (this.persist) await this.persist(next)
    this.emit('change', { mode: this.mode, policy: this.policy })
    return this.policy
  }
}

/**
 * The words a Private-mode refusal or failure page carries — one builder, so
 * the Handshake handler, the peer-to-peer gates and the tests say the same
 * thing. Every one of them: names the mode, says what was NOT done (nothing
 * was sent, no unprotected lookup was made), does not blame the site, and
 * ends with the same pointer at the control.
 *
 * @param {'lookup'|'site'|'relay'|'ipfs'|'p2p'} kind
 * @param {{host?: string, reason?: string, label?: string}} [about]
 * @returns {{title: string, detail: string}}
 */
export function privateRefusal (kind, { host = '', reason = '', label = '' } = {}) {
  const who = host ? `${host} ` : 'This page '
  const why = reason ? ` (${reason})` : ''
  switch (kind) {
    case 'lookup':
      return {
        title: `${host || 'This name'} could not be looked up privately`,
        detail: 'Private mode looks a name up obliviously or not at all. The private ' +
          `lookup failed${why}, and this browser did not fall back to an unprotected one. ` +
          'Nothing is known about the site itself — it may be perfectly fine. Try again in a ' +
          `moment, or ${SWITCH_HINT.replace('load it directly', 'look it up directly')}`
      }
    case 'site':
      return {
        title: `${who.trim()} is not loaded in Private mode`,
        detail: 'This site is served from its own server, and Private mode reaches a server ' +
          `only through the Tor client on this device, which is not connected right now${why}. ` +
          `Nothing was sent to the site. ${SWITCH_HINT}`
      }
    case 'relay':
      return {
        title: 'Relays are not asked in Private mode without the Tor client',
        detail: 'This address is answered by relays, and Private mode asks a relay only ' +
          `through the Tor client on this device, which is not connected right now${why}. ` +
          `Nothing was asked. ${SWITCH_HINT.replace('load it directly', 'ask them directly')}`
      }
    case 'ipfs':
      return {
        title: `${who.trim()} is not loaded in Private mode`,
        detail: 'This name serves its content from the peer-to-peer network, and finding it ' +
          'there means asking strangers directly over a path Private mode cannot route — it ' +
          `would reveal this device's address, so it was not asked${why}. A name that also ` +
          'publishes a stated origin for its content loads from that origin in Private mode. ' +
          SWITCH_HINT
      }
    case 'p2p':
    default:
      return {
        title: host ? `${host} is not loaded in Private mode` : `${label || 'This content'} is refused in Private mode`,
        detail: `${host ? 'This name serves' : label ? `${label} serves` : 'It serves'} its content over a ` +
          'peer-to-peer network, whose peers learn the address of whoever asks; that path cannot be ' +
          `routed through the private connection, so nothing was asked${why}. ` +
          (host ? 'A name that also publishes a stated origin for its content loads from that origin in Private mode. ' : '') +
          SWITCH_HINT
      }
  }
}
