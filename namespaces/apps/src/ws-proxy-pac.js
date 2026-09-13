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
// The directive carries no credential: this browser's WebSocket CONNECT path
// cannot answer a proxy-auth challenge. The listener is loopback-only.
//
// The host rule MIRRORS classifyHost (src/protocols/router.js): a bare label
// or non-ICANN / numeric TLD is Handshake; ICANN TLDs, IP literals, .eth and
// .onion are not. The ICANN set is embedded once here (from icann-tlds.cjs)
// rather than duplicated, so there is a single TLD source.

import reserved from '../../../src/reserved-names.cjs'

const { NEVER_HNS_TLDS } = reserved

/** Turn the anonymizer's rules into the base route, including ordinary WS. */
export function rulesToPacDirective (rules) {
  if (!rules) return 'DIRECT'
  const m = /^socks5?:\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+):(\d{1,5})\/?$/i.exec(String(rules))
  if (!m || Number(m[2]) < 1 || Number(m[2]) > 65535) throw new Error('Unsupported WebSocket base proxy rule')
  return `SOCKS5 ${m[1]}:${m[2]}`
}

/** Build the PAC script. `icannTlds` is the Set from ui/icann-tlds.cjs. */
export function buildWsPac (icannTlds, { port, baseDirective = 'DIRECT', numericNames = false }) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid WebSocket proxy port')
  if (typeof baseDirective !== 'string' || !/^(?:DIRECT|SOCKS5 (?:\[[0-9a-f:]+\]|[a-z0-9.-]+):\d{1,5})$/i.test(baseDirective)) throw new Error('Unsupported WebSocket base proxy directive')
  const tlds = JSON.stringify(Object.fromEntries([...icannTlds].map((t) => [t, 1])))
  // Numeric Handshake names are a switch (src/hns/classify-host.cjs); the PAC
  // copy of the rule takes the same answer.
  const numeric = numericNames ? 'true' : 'false'
  // The reserved-name list (src/hns/reserved-names.cjs) is embedded the same
  // way, so `nas.local` is never sent to a Handshake resolver. In Private it
  // follows the base proxy too. Chromium's implicit loopback bypass is gated
  // separately by localWsPolicy, with a same-origin running Local App exception.
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
  var tld = labels[labels.length-1];
  if(/^\\d+$/.test(tld)) return ${numeric};
  if(labels.length < 2) return true;
  if(tld === 'eth') return false;
  if(tld === 'onion') return false;
  return !ICANN[tld];
}
function FindProxyForURL(url, host){
  if(url.substring(0,4) === 'wss:' || url.substring(0,3) === 'ws:'){
    if(_isHns(host)) return '${socks}';
  }
  return '${baseDirective}';
}`
}
