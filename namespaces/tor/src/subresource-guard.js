// Close the SUBRESOURCE half of the DNS leak the nav-entry rewrites close for
// main frames. Window.loadURL / will-navigate / addTab / loadTabState rewrite
// a top-level http://nathan.woodburn/ to hns://, but an
// <img src="http://foo.woodburn/x.png"> inside ANY page still went straight
// to Chromium's network stack and SYSTEM DNS — which cannot resolve it (blank
// image) and, worse, leaks the name. For a *.onion subresource the request
// itself is the deanonymising leak; for *.eth it hands ENS traffic to system
// DNS. One classifier decides (src/protocols/router.js via hns-host.js), the
// same one the nav entry points use.
//
// decide() is pure and unit-tested (tests/hns/subresource-guard.test.js);
// installSubresourceGuard() is the Electron wiring. NOTE: Electron allows
// exactly ONE webRequest.onBeforeRequest listener per session — if another ever
// becomes necessary, compose it here rather than registering a second one (the
// second silently replaces the first).
//
// That has now happened: the ad blocker (src/adblock/) is the second stage.
// It is passed in as `next` rather than registering its own listener, because
// @ghostery/adblocker-electron's enableBlockingInSession() would have silently
// replaced THIS listener and reopened the *.onion/*.eth leak below.
//
// ORDER MATTERS. The leak guard runs first and wins: a cancel or redirect it
// asks for is a security decision, and a filter list must never be able to
// downgrade it. The blocker only ever sees requests the guard passed through.

import { rewriteToHns } from '../../../src/hns-host.js'

/**
 * The onBeforeRequest verdict for one request.
 * @param {string} url
 * @param {string} resourceType Electron's details.resourceType ('mainFrame',
 *   'subFrame', 'image', 'xhr', …)
 * @returns {{cancel?: boolean, redirectURL?: string}} empty object = proceed
 */
export function decide (url, resourceType) {
  const rewritten = rewriteToHns(url)
  if (!rewritten) return {} // ICANN / IP / localhost / non-http — untouched
  if (resourceType === 'mainFrame') {
    // A top-level load that got here anyway (typically a server-side redirect
    // chain, which never re-enters will-navigate): send it where the nav
    // entry points would have — hns:// resolves; ens:// resolves the name on
    // Ethereum; onion:// routes through Tor or shows its interstitial. Each
    // answers inside its own namespace, never by asking DNS.
    return { redirectURL: rewritten }
  }
  if (!rewritten.startsWith('hns://')) {
    // Reserved-namespace subresource (*.eth, *.onion): there is nothing to
    // render and nothing we may look up. Cancel — zero network, zero DNS.
    return { cancel: true }
  }
  // Handshake-host subresource: serve it through the hns:// handler (chain
  // proof + DANE) exactly like a main-frame load.
  return { redirectURL: rewritten }
}

/**
 * Compose the leak guard with an optional second stage (the ad blocker).
 *
 * The URL filter stays http/https-only, deliberately: routing every scheme
 * through this listener would put hns://, ipfs:// and friends through the
 * blocker's matcher for no benefit — ad networks live on http(s), and the
 * custom-protocol handlers should not have a webRequest hook in their path.
 *
 * @param {import('electron').Session} session
 * @param {{next?: ((details: Electron.OnBeforeRequestListenerDetails) =>
 *   {cancel?: boolean, redirectURL?: string})|null}} [options]
 *   `next` sees only requests the guard passed through.
 */
// A fresh "proceed" verdict. A function, not a shared constant, so no caller
// can mutate the object every allowed request shares — and it keeps
// n/no-callback-literal satisfied without an eslint-disable.
const allow = () => ({})

export function installSubresourceGuard (session, { next = null, chromeApi = null } = {}) {
  session.webRequest.onBeforeRequest(
    // `wildroot://` is here for ONE reason: the Files API is reachable by
    // fetch() from any page, and Electron allows exactly one
    // onBeforeRequest per session — so the gate has to live in this listener
    // or not at all. See chromeApi below.
    { urls: ['http://*/*', 'https://*/*', 'wildroot://*/*'] },
    (details, callback) => {
      // WHO IS ASKING FOR THE FILES API. Answered by the asking WebContents'
      // URL, because a custom-scheme request carries no Origin, no
      // Sec-Fetch-Site and no initiator (measured in Electron 43). A page
      // that is not the Files app gets nothing.
      if (chromeApi) {
        const verdict = chromeApi(details)
        if (verdict) return callback(verdict)
      }
      if (details.url.startsWith('wildroot://')) return callback(allow())
      const verdict = decide(details.url, details.resourceType)
      // The guard spoke: cancel/redirect is a security decision, it is final.
      if (verdict.cancel || verdict.redirectURL) return callback(verdict)
      if (!next) return callback(verdict)
      try {
        return callback(next(details))
      } catch (e) {
        // A blocker fault must never take the network down with it. Fail OPEN
        // here and only here: the guard has already had its say above, so
        // "allow" cannot leak a name — it can only miss an ad.
        console.warn('adblock: match failed, allowing —', e.message)
        return callback(allow())
      }
    })
}
