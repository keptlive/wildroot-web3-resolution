// PAC (proxy auto-config) builder for hns:// WebSocket routing.
//
// A secure hns:// page can only open `wss://<name>` (Chromium blocks plaintext
// ws:// from a secure context — see docs/WEBSOCKETS.md). This PAC sends
// ws/wss requests to a HANDSHAKE host through the local HTTP CONNECT ws-proxy
// (which does proxy-side DNS via the SPV resolver and enforces the four
// fences), and sends everything else to `baseDirective` — which is the
// anonymizer's current directive (DIRECT when off, `SOCKS5 <tor>` when IP
// Protection is on), so page/search/DoH traffic keeps riding Tor. One PAC,
// applied through the AnonymizeController's decorator, so there is a single
// proxy authority.
//
// The directive carries NO credential: Chromium ignores `user:pass@` in PAC
// strings (and cannot authenticate to SOCKS5 at all). The proxy's per-session
// credential is supplied by main through Electron's app 'login' event when
// the proxy answers 407 — see src/index.js.
//
// The host rule MIRRORS classifyHost (src/protocols/router.js): a bare label
// or non-ICANN / numeric TLD is Handshake; ICANN TLDs, IP literals, .eth and
// .onion are not. The ICANN set is embedded once here (from icann-tlds.cjs)
// rather than duplicated, so there is a single TLD source.

import reserved from '../../../src/reserved-names.cjs'

const { NEVER_HNS_TLDS } = reserved

/** Turn the anonymizer's proxyRules ('socks5://host:port' or null) into a PAC
 *  directive for all non-ws traffic. */
export function rulesToPacDirective (rules) {
  if (!rules) return 'DIRECT'
  const m = /^socks5?:\/\/([^/]+)$/i.exec(String(rules))
  return m ? `SOCKS5 ${m[1]}` : 'DIRECT'
}

/** Build the PAC script. `icannTlds` is the Set from ui/icann-tlds.cjs. */
export function buildWsPac (icannTlds, { port, baseDirective = 'DIRECT' }) {
  const tlds = JSON.stringify(Object.fromEntries([...icannTlds].map((t) => [t, 1])))
  // The reserved-name list (src/hns/reserved-names.cjs) is embedded the same
  // way, so `nas.local` stays direct for the same reason `localhost` does.
  const reserved = JSON.stringify(Object.fromEntries([...NEVER_HNS_TLDS].map((t) => [t, 1])))
  const socks = `PROXY 127.0.0.1:${port}`
  return `var ICANN = ${tlds};
var RESERVED = ${reserved};
function _isHns(h){
  h = (h||'').toLowerCase().replace(/\\.$/,'');
  if(!h || h === 'localhost') return false;
  if(/^\\d{1,3}(\\.\\d{1,3}){3}$/.test(h)) return false;
  if(h.indexOf(':')>=0 || h.charAt(0)==='[') return false;
  var labels = h.split('.').filter(Boolean);
  if(RESERVED[labels[labels.length-1]]) return false;
  if(labels.length < 2) return true;
  var tld = labels[labels.length-1];
  if(tld === 'eth') return false;
  if(tld === 'onion') return false;
  if(/^\\d+$/.test(tld)) return true;
  return !ICANN[tld];
}
function FindProxyForURL(url, host){
  if(url.substring(0,4) === 'wss:' || url.substring(0,3) === 'ws:'){
    return _isHns(host) ? '${socks}' : 'DIRECT';
  }
  return '${baseDirective}';
}`
}
