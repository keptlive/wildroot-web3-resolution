/*
 * Guard against SSRF through attacker-controlled zone data.
 *
 * Every address the resolver hands back — an A record, an on-chain SYNTH4
 * or GLUE4, or the IP a delegated NS host resolves to — is chosen by
 * whoever registered the name. Without this, visiting hns://evil.tld/ where
 * evil.tld publishes `A 169.254.169.254` (or 127.0.0.1, or 10.x) makes the
 * browser fetch cloud metadata / a loopback admin panel FROM THE MAIN
 * PROCESS over plain HTTP, and same-origin page JS reads the response. So
 * the browser must refuse to connect to any non-public address.
 *
 * This is an allowlist of the public internet by exclusion: reject
 * loopback, private, link-local, CGNAT, and unspecified/reserved ranges.
 */

function ipv4ToInt (addr) {
  const parts = addr.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const b = Number(p)
    if (b > 255) return null
    n = (n << 8 >>> 0) + b
  }
  return n >>> 0
}

const V4_BLOCKS = [
  ['0.0.0.0', 8], // "this host"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local (incl. cloud metadata 169.254.169.254)
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4] // reserved / broadcast
].map(([base, bits]) => {
  const b = ipv4ToInt(base)
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return { net: (b & mask) >>> 0, mask }
})

function isPublicV4 (addr) {
  const n = ipv4ToInt(addr)
  if (n === null) return false
  for (const { net, mask } of V4_BLOCKS) {
    if (((n & mask) >>> 0) === net) return false
  }
  return true
}

// Expand an IPv6 string to its eight 16-bit groups, or null if malformed.
function expandV6 (addr) {
  const a = addr.toLowerCase().split('%')[0]
  const halves = a.split('::')
  if (halves.length > 2) return null
  const parseSide = (s) => s ? s.split(':').filter((x) => x !== '') : []
  // A trailing IPv4 dotted-quad (::ffff:127.0.0.1) becomes two hex groups.
  const embedV4 = (groups) => {
    const out = []
    for (const g of groups) {
      const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(g)
      if (v4) {
        const n = ipv4ToInt(g)
        if (n === null) return null
        out.push((n >>> 16) & 0xffff, n & 0xffff)
      } else if (/^[0-9a-f]{1,4}$/.test(g)) {
        out.push(parseInt(g, 16))
      } else {
        return null
      }
    }
    return out
  }
  const head = embedV4(parseSide(halves[0]))
  const tail = halves.length === 2 ? embedV4(parseSide(halves[1])) : []
  if (head === null || tail === null) return null
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length
    if (fill < 0) return null
    return [...head, ...Array(fill).fill(0), ...tail]
  }
  return head.length === 8 ? head : null
}

function isPublicV6 (addr) {
  const g = expandV6(addr)
  if (!g) return false // unparseable -> fail closed
  // loopback ::1 and unspecified ::
  if (g.every((x, i) => (i < 7 ? x === 0 : true)) &&
      (g[7] === 0 || g[7] === 1)) return false
  const first = g[0]
  if ((first & 0xffc0) === 0xfe80) return false // link-local fe80::/10
  if ((first & 0xfe00) === 0xfc00) return false // unique-local fc00::/7
  // IPv4-mapped ::ffff:0:0/96 and IPv4-compat ::/96 — judge the embedded v4.
  const allZeroTop = g.slice(0, 5).every((x) => x === 0)
  if (allZeroTop && (g[5] === 0xffff || g[5] === 0)) {
    const v4 = `${(g[6] >> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >> 8) & 0xff}.${g[7] & 0xff}`
    return isPublicV4(v4)
  }
  // NAT64 well-known prefix 64:ff9b::/96 embeds a v4 too.
  if (first === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) {
    const v4 = `${(g[6] >> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >> 8) & 0xff}.${g[7] & 0xff}`
    return isPublicV4(v4)
  }
  return true
}

/** True only for a routable public unicast address. */
export function isPublicAddress (addr) {
  if (!addr || typeof addr !== 'string') return false
  return addr.includes(':') ? isPublicV6(addr) : isPublicV4(addr)
}

/** Throw a readable error if an address is not safe to connect to. */
export function assertPublicAddress (addr, context = 'this name') {
  if (!isPublicAddress(addr)) {
    const err = new Error(
      `${context} resolves to ${addr}, a private or reserved address. ` +
      'Refusing to connect — a public name pointing at an internal address ' +
      'is how a malicious site would reach things it should not.')
    err.ssrf = true
    throw err
  }
}
