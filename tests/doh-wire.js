// Test helper: build RFC 8484 wire-format DoH stubs for DoHResolver tests.
// Decodes the ?dns= query, echoes its question, and appends the answers the
// test map specifies — so tests exercise the REAL wire codec end to end.

import { TYPES } from '../src/dns-query.js'

function fromB64url (s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
}

function readQname (buf, off) {
  const labels = []
  while (buf[off] !== 0) {
    const len = buf[off]
    labels.push(buf.toString('ascii', off + 1, off + 1 + len))
    off += 1 + len
  }
  return { name: labels.join('.'), next: off + 1 }
}

function rdataFor (type, data) {
  if (type === TYPES.A) return Buffer.from(data.split('.').map(Number))
  if (type === TYPES.TXT) {
    const s = Buffer.from(String(data))
    return Buffer.concat([Buffer.from([s.length]), s])
  }
  if (type === TYPES.TLSA) {
    // "usage selector matching <hex>", the presentation form.
    const [usage, sel, mt, hex] = String(data).split(/\s+/)
    return Buffer.concat([Buffer.from([Number(usage), Number(sel), Number(mt)]), Buffer.from(hex, 'hex')])
  }
  throw new Error(`unsupported test rdata type ${type}`)
}

/** Build a wire response answering `query` with `records` [{type, data}]. */
export function wireResponse (queryBuf, records, rcode = 0) {
  const { next } = readQname(queryBuf, 12)
  const question = queryBuf.subarray(12, next + 4)
  const header = Buffer.alloc(12)
  header.writeUInt16BE(queryBuf.readUInt16BE(0), 0)
  header.writeUInt16BE(0x8180 | rcode, 2)
  header.writeUInt16BE(1, 4)
  header.writeUInt16BE(records.length, 6)
  const answers = records.map(({ type, data }) => {
    const rd = rdataFor(type, data)
    const head = Buffer.alloc(12)
    head.writeUInt16BE(0xc00c, 0) // name: pointer to question
    head.writeUInt16BE(type, 2)
    head.writeUInt16BE(1, 4) // IN
    head.writeUInt32BE(60, 6)
    head.writeUInt16BE(rd.length, 10)
    return Buffer.concat([head, rd])
  })
  return Buffer.concat([header, question, ...answers])
}

/**
 * fetchImpl stub: map of 'name:TYPE' -> [{type, data}]. Unknown names get an
 * empty NOERROR answer.
 */
export function stubWireFetch (map) {
  return async (url) => {
    const u = new URL(url)
    const q = fromB64url(u.searchParams.get('dns'))
    const { name } = readQname(q, 12)
    const qtype = q.readUInt16BE(readQname(q, 12).next)
    const typeName = Object.keys(TYPES).find((k) => TYPES[k] === qtype) || qtype
    const records = map[`${name}:${typeName}`] || []
    const body = wireResponse(q, records)
    return {
      ok: true,
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength)
    }
  }
}
