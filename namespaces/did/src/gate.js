/* global Response */

import { privateRefusal } from '../../../src/delivery-mode.js'

/*
 * The IP-Protection gate for handlers that do NOT route through the proxied
 * Electron session. Two classes need it:
 *   - p2p overlays (IPFS/Hyper/BitTorrent/SSB) that dial peers directly, and
 *   - main-process handlers that use Node's global fetch or a raw socket
 *     against an often attacker-chosen host.
 * Both bypass session.setProxy and would reveal the real IP. Anonymization is
 * HTTP-scoped: proxyable traffic rides session.fetch and stays available;
 * everything else is blocked (503), not leaked.
 *
 * 503, not Cloudflare's 523: a protocol handler's Response status goes
 * straight into net::GetHttpReasonPhrase() (ElectronURLLoaderFactory::
 * StartLoading), which NOTREACHEDs on any code Chromium does not know —
 * a crash dump on every gated request today (dumps 2026-08-24 09:32 and
 * 18:06) and a hard crash the day Chromium makes it fatal. Pinned by
 * tests/hns/http-status-known.test.js.
 *
 * Lives in its own Electron-free module so torrent-gate.test.js can pin the
 * behaviour under plain node — src/protocols/index.js imports Electron and
 * cannot be loaded in a test.
 */

/**
 * @param {() => boolean} isAnonymized reads the live anonymizer state per request
 * @returns {(handler: Function, label: string) => Function}
 */
export function createNonProxiedGate (isAnonymized) {
  return (handler, label) => async (request) => {
    if (isAnonymized()) {
      // Private mode (src/hns/delivery-mode.js), row 19: refused, and the
      // page says why and where the switch is.
      const copy = privateRefusal('p2p', { label })
      return new Response(`${copy.title}\n\n${copy.detail}`,
        { status: 503, headers: { 'content-type': 'text/plain; charset=utf-8' } })
    }
    return handler(request)
  }
}
