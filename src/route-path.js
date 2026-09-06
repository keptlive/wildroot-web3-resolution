/*
 * The ROUTE a page took — the privacy workup, beside the trust workup.
 *
 * src/hns/trust-path.js answers "what was verified": for each step, whose
 * word was accepted. This module answers the other question the lock has to
 * be honest about: "who saw what" — for each hop, the route it took and what
 * the party at the other end learned, in the mode the page was loaded under,
 * with what the OTHER mode would have done for that hop. Fast is the
 * quickest route; Private is the route through the device-local Tor with no
 * unprotected fallback (docs/MODES.md, the DIVERGENCE rows). Both are
 * described in the same words, per hop, so the switch is a comparison the
 * user can read rather than a promise.
 *
 * Every fact here is decided in main from the resolution record and the
 * mode at the moment the page was loaded; the panel renders and cannot
 * soften. Nothing about the TRUST verdict changes with the mode — a verdict
 * is a fact about the page, the mode is a policy about the route.
 *
 * Routes:
 *   local      nothing about this hop left the computer
 *   oblivious  split between a relay (saw the address) and a target (saw the
 *              question), neither able to link the two
 *   tor        through the device-local Tor: the far end saw a Tor exit
 *   direct     the far end saw this computer's address, with the question
 *   refused    not done in this mode, and nothing was sent instead
 */

/** @typedef {{label: string, route: 'local'|'oblivious'|'tor'|'direct'|'refused', source: string, detail: string, alt: string}} Hop */

const hop = (label, route, source, detail, alt) => ({ label, route, source, detail, alt })

const CONTENT_PEERS = new Set(['ipfs', 'ipns', 'ipld'])
const P2P = new Set(['bittorrent', 'hyper', 'ssb'])

function hostOf (url) {
  try { return new URL(String(url)).host } catch { return String(url || '') }
}

/**
 * The route an hns:// page took.
 * @param {string} host
 * @param {object} resolution the record src/hns/resolver.js (or doh.js) returned
 * @param {{mode?: 'fast'|'private', anonymized?: boolean, transport?: string|null}} [extra]
 *   `anonymized`: the session proxy and every dialer ride the device-local
 *   Tor right now (IP Protection / Private mode). `transport`: what the
 *   connection to an A-record site will be ('https-dane' | 'http' | 'refused').
 * @returns {Hop[]}
 */
export function hnsRoute (host, resolution = {}, extra = {}) {
  const priv = extra.mode === 'private'
  const tor = !!extra.anonymized
  const chain = resolution.trust !== 'doh'
  const steps = []

  // 1. The name lookup. A chain proof is verified HERE, but the proof itself
  //    is asked of a chain peer, and that peer sees the question.
  if (chain) {
    steps.push(tor
      ? hop('Handshake name', 'tor',
        'Chain proof from a chain peer, through Tor',
        `The local node asked a chain peer for the proof of ${host} over Tor: the peer saw a Tor exit and the name, never this computer's address. The proof was checked here.`,
        'In Fast the peer is asked directly and sees this computer\'s address with the name.')
      : hop('Handshake name', 'direct',
        'Chain proof from a chain peer, asked directly',
        `The local node asked a chain peer for the proof of ${host}: that peer saw this computer's address and the name together. The proof was checked here, so the peer could not change the answer.`,
        'In Private the peer is asked through Tor and sees a Tor exit instead.'))
  } else if (resolution.oblivious) {
    steps.push(hop('Handshake name', 'oblivious',
      `Oblivious DoH — relay ${resolution.via || '(unnamed)'} → target ${resolution.target || 'odoh.hns.one'}`,
      'The relay saw this computer\'s address and only ciphertext; the target saw the name and only the relay. Neither alone can link the two.',
      priv
        ? 'Fast takes the same route when it answers, and may fall back to a plain resolver when it does not.'
        : 'In Private this is the only route: if the oblivious lookup fails, the page fails rather than falling back.'))
  } else {
    steps.push(hop('Handshake name', 'direct',
      resolution.endpoint ? `Plain DoH resolver ${resolution.endpoint}` : 'Plain DoH resolver',
      `That resolver saw this computer's address and ${host} together.`,
      'In Private this fallback is never taken: an oblivious lookup, or nothing.'))
  }

  // 2a. A registry contract, read over an RPC.
  if (resolution.op) {
    steps.push(hop('Name records', tor ? 'tor' : 'direct',
      `Optimism registry read via ${resolution.op.rpc || 'a public RPC'}${tor ? ', through Tor' : ', directly'}`,
      tor
        ? 'The RPC endpoint saw a Tor exit and the question.'
        : 'The RPC endpoint saw this computer\'s address and which name was asked.',
      tor ? 'In Fast the endpoint is asked directly.' : 'In Private the endpoint is asked through Tor.'))
  }

  // 2b. The zone's nameserver.
  if (resolution.ns) {
    steps.push(hop('Zone records', tor ? 'tor' : 'direct',
      `Nameserver ${resolution.ns}, asked ${tor ? 'through Tor' : 'directly'}`,
      tor
        ? 'The nameserver saw a Tor exit and the question.'
        : 'The nameserver saw this computer\'s address and which name was asked.',
      tor ? 'In Fast the nameserver is asked directly.' : 'In Private the nameserver is asked through Tor, with the same checks.'))
  }

  // 3. The bytes.
  const kind = resolution.kind
  if (kind === 'site') {
    if (extra.transport === 'refused') {
      steps.push(hop('Connection', 'refused', 'Not connected',
        'No connection was made, so the site learned nothing.',
        'The same in either mode: this is a trust decision, not a route.'))
    } else {
      const scheme = extra.transport === 'http' ? 'Plain HTTP' : 'HTTPS'
      steps.push(hop('Connection', tor ? 'tor' : 'direct',
        `${scheme} to ${resolution.address || 'the site'}, ${tor ? 'through Tor' : 'direct'}`,
        tor
          ? 'The site saw a Tor exit address. Some sites block Tor exits.'
          : 'The site saw this computer\'s address.',
        tor ? 'In Fast the site is reached directly and sees this computer\'s address.' : 'In Private the site is reached through Tor and sees a Tor exit, with the same certificate pin.'))
    }
  } else if (CONTENT_PEERS.has(kind)) {
    const origin = resolution.origin ? hostOf(resolution.origin) : null
    if (priv || tor) {
      steps.push(origin
        ? hop('Content', 'tor',
          `Whole archive from the stated origin ${origin}, through Tor`,
          'No content-network peer was asked. The origin saw a Tor exit and which archive was fetched; the bytes were verified here.',
          'In Fast the local node asks content-network peers, which see this computer\'s address and the address of the content.')
        : hop('Content', 'refused', 'No stated origin — not fetched from peers',
          'Asking content-network peers would show them this computer\'s address and what it wants, so it was not done.',
          'In Fast the local node asks content-network peers directly.'))
    } else {
      steps.push(hop('Content', 'direct',
        origin
          ? `Local node asks content-network peers; also fetched from the stated origin ${origin}`
          : 'Local node asks content-network peers',
        'The peers that answered — and the origin, when there is one — saw this computer\'s address and the address of the content. The bytes were verified here.',
        origin
          ? 'In Private the whole archive is fetched from the stated origin through Tor and no peer is asked.'
          : 'In Private this name is refused: it publishes no stated origin to fetch from through Tor.'))
    }
  } else if (kind === 'arweave') {
    steps.push(hop('Content', tor ? 'tor' : 'direct',
      `Gateway fetch, ${tor ? 'through Tor' : 'direct'}`,
      tor ? 'The gateway saw a Tor exit and which transaction was fetched.' : 'The gateway saw this computer\'s address and which transaction was fetched.',
      tor ? 'In Fast the gateway is reached directly.' : 'In Private the gateway is reached through Tor.'))
  } else if (P2P.has(kind)) {
    steps.push(priv || tor
      ? hop('Content', 'refused', 'Peer-to-peer discovery not done',
        'Finding this content means asking strangers, who would see this computer\'s address and what it wants. It was not done.',
        'In Fast the local client asks peers directly.')
      : hop('Content', 'direct', 'Peer-to-peer discovery, direct',
        'Peers and trackers saw this computer\'s address and what it wants.',
        'In Private this is refused, with the reason on the page.'))
  }
  return steps
}

/**
 * The route for everything that is NOT an hns:// page.
 * @param {string} url
 * @param {{mode?: string, servers?: string[], oblivious?: boolean, failClosed?: boolean}|null} [dns] the ICANN DNS plan the engine was configured with
 * @param {{live: boolean, relay?: string|null, target?: string|null}|null} [bridge] whether the oblivious bridge answered this host
 * @param {{mode?: 'fast'|'private', anonymized?: boolean}} [extra]
 * @returns {Hop[]}
 */
export function schemeRoute (url, dns = null, bridge = null, extra = {}) {
  const priv = extra.mode === 'private'
  const tor = !!extra.anonymized
  let protocol = ''
  let host = ''
  try {
    const u = new URL(url)
    protocol = u.protocol.replace(':', '')
    host = u.hostname
  } catch {
    const named = /^([a-z][a-z0-9+.-]*):/i.exec(String(url || '').trim())
    if (!named) return []
    protocol = named[1].toLowerCase()
  }
  const connection = (what) => hop('Connection', tor ? 'tor' : 'direct',
    `${what}, ${tor ? 'through Tor' : 'direct'}`,
    tor ? 'The far end saw a Tor exit address.' : 'The far end saw this computer\'s address.',
    tor ? 'In Fast it is reached directly.' : 'In Private it is reached through Tor.')
  if (/\.onion$/i.test(host)) protocol = 'onion'
  switch (protocol) {
    case 'https':
    case 'http':
      return [icannNameHop(host, dns, bridge, priv), connection(protocol === 'http' ? 'Plain HTTP' : 'HTTPS')]
    case 'ipfs':
    case 'ipns':
    case 'ipld':
    case 'pubsub':
      return [priv || tor
        ? hop('Content', 'refused', 'Content-network peers not asked',
          'Asking peers would show them this computer\'s address and what it wants, so it was not done.',
          'In Fast the local node asks peers directly.')
        : hop('Content', 'direct', 'Local node asks content-network peers',
          'The peers that answered saw this computer\'s address and the address of the content.',
          'In Private this is refused; a Handshake name with a stated origin is fetched from that origin through Tor instead.')]
    case 'ar':
      return [connection('Gateway fetch')]
    case 'onion':
      return [tor
        ? hop('Connection', 'tor', 'Onion service, through Tor',
          'Reached inside the Tor network: no exit is involved and the service saw no address of yours.',
          'In Fast, without Tor, an onion address cannot be reached at all.')
        : hop('Connection', 'refused', 'Not reachable without Tor',
          'An onion address only exists inside the Tor network; nothing was sent.',
          'In Private it is reached through the device-local Tor.')]
    case 'magnet':
    case 'bittorrent':
    case 'hyper':
    case 'ssb':
      return [priv || tor
        ? hop('Content', 'refused', 'Peer-to-peer discovery not done',
          'Finding this content means asking strangers who would see this computer\'s address. It was not done.',
          'In Fast the local client asks peers directly.')
        : hop('Content', 'direct', 'Peer-to-peer discovery, direct',
          'Peers and trackers saw this computer\'s address and what it wants.',
          'In Private this is refused, with the reason on the page.')]
    case 'wildroot':
    case 'file':
    case 'about':
    case 'blob':
    case 'data':
      return [hop('Page', 'local', 'Built into the browser', 'Nothing left this computer to show this page.', 'The same in either mode.')]
    case 'gemini':
      return [connection('Gemini capsule')]
    case 'nostr':
      return [hop('Relays', tor ? 'tor' : 'direct',
        tor ? 'Relays asked through Tor, by name' : 'Relays asked directly',
        tor ? 'Each relay saw a Tor exit and the question.' : 'Each relay saw this computer\'s address and the question — which notes and whose.',
        tor ? 'In Fast the relays are asked directly.' : 'In Private the relays are asked through Tor.')]
    default:
      return [connection('Lookup and fetch')]
  }
}

function icannNameHop (host, dns, bridge, priv) {
  if (bridge && bridge.live) {
    return hop('Domain name', 'oblivious',
      `Oblivious DoH — relay ${bridge.relay || '(configured relay)'} → target ${bridge.target || 'odoh.hns.one'}`,
      `The relay saw this computer's address and only ciphertext; the target saw ${host} and only the relay.`,
      priv ? 'Fast takes the same route when the bridge answers, and may fall back to an encrypted resolver.' : 'In Private this is the only route: nothing else is asked.')
  }
  const mode = (dns && dns.mode) || 'automatic'
  if (dns && dns.oblivious && mode === 'secure') {
    return hop('Domain name', 'oblivious', 'Oblivious bridge only — this answer may have come from the engine\'s cache',
      `Only the oblivious bridge could have resolved ${host}; unencrypted DNS is refused.`,
      'In Fast an encrypted resolver may answer instead, and sees the name with this computer\'s address.')
  }
  const servers = (dns && dns.servers) || []
  if (!servers.length || mode === 'off') {
    return hop('Domain name', 'direct', 'System DNS, unencrypted',
      `${host} went out in the clear: the router, the ISP and anyone on the path saw the name with this computer's address.`,
      'In Private the name is looked up only through the oblivious bridge.')
  }
  let label = servers[0]
  try { label = new URL(servers[0]).host } catch {}
  return hop('Domain name', 'direct', `Encrypted DNS to ${label}`,
    `Encrypted in transit, but ${label} saw this computer's address and ${host} together.`,
    'In Private the name is looked up only through the oblivious bridge, which splits the two.')
}

/**
 * The heading and the one-liner for a route list.
 * @param {'fast'|'private'|string} mode
 * @param {Hop[]} steps
 */
export function summarizeRoute (mode, steps) {
  const priv = mode === 'private'
  const label = priv ? 'Private — through Tor' : 'Fast — the quickest route'
  if (!steps.length) return { mode: priv ? 'private' : 'fast', label, summary: 'Nothing is known about how this page was reached.' }
  const direct = steps.filter((s) => s.route === 'direct')
  const refused = steps.filter((s) => s.route === 'refused')
  let summary
  if (direct.length) {
    summary = direct.length === steps.length
      ? 'Every step showed someone this computer\'s address.'
      : `${direct.length} of ${steps.length} steps showed someone this computer's address: ${direct.map((s) => s.label.toLowerCase()).join(', ')}.`
  } else if (refused.length) {
    summary = `${refused.length === 1 ? 'One step was' : `${refused.length} steps were`} refused rather than sent unprotected; nothing showed this computer's address.`
  } else {
    summary = 'No step showed anyone this computer\'s address.'
  }
  return { mode: priv ? 'private' : 'fast', label, summary }
}
