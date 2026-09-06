/*
 * When IP Protection finishes connecting, some tabs are stuck: the user
 * navigated (often to a .onion) while Tor was still bootstrapping, so the load
 * either errored or rendered a broken app-error page against a proxy that was
 * not ready yet. The moment the circuit comes up they must auto-load — a user
 * should never have to know to hit reload themselves (BUG 2).
 *
 * This is the pure decision: given a snapshot of a window's tabs, which ones
 * to reload. Electron-free so it runs under `node --test` with plain fakes.
 *
 * The rule, deliberately conservative so it does NOT stomp a page the user is
 * happily reading:
 *   - a tab whose last main-frame load ERRORED -> reload (it is stuck);
 *   - a tab on the onion:// scheme -> reload (it needed Tor; even a "successful"
 *     200 from a web app that threw a client-side storage error looks fine to
 *     did-fail-load, so scheme is the honest signal here);
 *   - everything else is left alone.
 * The active tab is covered by these same rules — an errored or onion active
 * tab reloads, a good one does not.
 */

/** Is this a Tor onion address that only resolves once the circuit is up? */
export function isTorScheme (url) {
  return /^onion:\/\//i.test(String(url || ''))
}

/**
 * @param {Array<{ url?: string, loadFailed?: boolean, active?: boolean }>} tabs
 * @returns the subset (same objects) that should be reloaded now Tor is ready.
 */
export function tabsToReloadOnTorReady (tabs) {
  return (Array.isArray(tabs) ? tabs : []).filter(
    (t) => !!t && (t.loadFailed === true || isTorScheme(t.url))
  )
}
