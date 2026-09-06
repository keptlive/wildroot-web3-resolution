/*
 * Test helper: an on-path attacker for DNS-over-TCP, in its smallest useful
 * forms — a proxy in front of a nameserver that can DROP a query, ANSWER it
 * itself, or REWRITE the reply on its way back.
 *
 * The threat model every DNSSEC test in this directory shares is exactly one
 * party: whoever sits between the browser and the zone's nameserver. It
 * cannot sign anything, but it can delete records, substitute an empty
 * answer, or change bytes and hope nobody checks. So the proofs here are
 * written as that party would attack them.
 */

import net from 'node:net'

/** The qtype of a DNS message (no TCP length prefix), by walking the QNAME. */
export function qtypeOf (msg) {
  let i = 12
  while (i < msg.length && msg[i] !== 0) i += msg[i] + 1
  return i + 2 < msg.length ? msg.readUInt16BE(i + 1) : 0
}

/** The lowercased QNAME of a DNS message. */
export function qnameOf (msg) {
  const labels = []
  let i = 12
  while (i < msg.length && msg[i] !== 0) {
    labels.push(msg.toString('ascii', i + 1, i + 1 + msg[i]))
    i += msg[i] + 1
  }
  return labels.join('.').toLowerCase()
}

/**
 * A synthetic reply to `query` with the question echoed and NO records — the
 * forged "nothing here". `rcode` 0 is NOERROR/NODATA, 3 is NXDOMAIN.
 * @param {Buffer} query the DNS message (no length prefix)
 */
export function emptyReply (query, rcode = 0) {
  let i = 12
  while (i < query.length && query[i] !== 0) i += query[i] + 1
  const question = query.subarray(12, i + 5)
  const header = Buffer.alloc(12)
  header.writeUInt16BE(query.readUInt16BE(0), 0)
  header.writeUInt16BE(0x8400 | (rcode & 0xf), 2) // QR + AA
  header.writeUInt16BE(1, 4)
  return Buffer.concat([header, question])
}

/** Frame a DNS message for TCP. */
const framed = (msg) => {
  const out = Buffer.alloc(2 + msg.length)
  out.writeUInt16BE(msg.length, 0)
  msg.copy(out, 2)
  return out
}

/**
 * A TCP DNS proxy in front of `upstream` (127.0.0.1:port).
 *
 * `onQuery(msg)` may return a Buffer — a reply the proxy sends INSTEAD of
 * asking upstream — or `'drop'` to hang up, or nothing to forward.
 * `onReply(query, reply)` may return a Buffer to send in place of the
 * upstream's reply, or nothing to pass it through.
 *
 * @param {number} upstream
 * @param {{onQuery?: Function, onReply?: Function}} hooks
 */
export async function dnsProxy (upstream, { onQuery = null, onReply = null } = {}) {
  const server = net.createServer((client) => {
    client.on('error', () => {})
    client.once('data', (chunk) => {
      const query = chunk.subarray(2)
      const verdict = onQuery ? onQuery(query) : null
      if (verdict === 'drop') return client.destroy()
      if (Buffer.isBuffer(verdict)) {
        client.end(framed(verdict))
        return
      }
      const up = net.connect({ host: '127.0.0.1', port: upstream }, () => up.write(chunk))
      up.on('error', () => client.destroy())
      const chunks = []
      let expected = null
      up.on('data', (piece) => {
        chunks.push(piece)
        const buf = Buffer.concat(chunks)
        if (expected === null && buf.length >= 2) expected = buf.readUInt16BE(0)
        if (expected === null || buf.length < expected + 2) return
        const reply = buf.subarray(2, expected + 2)
        const changed = onReply ? onReply(query, reply) : null
        client.end(framed(Buffer.isBuffer(changed) ? changed : reply))
        up.destroy()
      })
      up.on('close', () => { if (expected === null) client.destroy() })
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    close: () => new Promise((resolve) => server.close(resolve))
  }
}

/** Replace every occurrence of `from` in `buf` with `to` (same length). */
export function replaceBytes (buf, from, to) {
  if (from.length !== to.length) throw new Error('replaceBytes: lengths differ')
  const out = Buffer.from(buf)
  let at = out.indexOf(from)
  while (at !== -1) {
    to.copy(out, at)
    at = out.indexOf(from, at + from.length)
  }
  return out
}
