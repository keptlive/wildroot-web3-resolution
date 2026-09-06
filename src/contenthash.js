/*
 * EIP-1577 / ENSIP-7 contenthash decoding.
 *
 * An ENS name's `contenthash` resolver record is a multicodec-prefixed byte
 * string: an unsigned-varint "protocol code" followed by a value whose shape
 * depends on that code. This module turns those bytes into a browser-native
 * content pointer (ipfs:// / ipns:// / ar://) that the existing IPFS and
 * Arweave handlers already know how to render — so ens:// resolution reuses
 * the verified content stack rather than growing a second one.
 *
 * It is deliberately pure (no Electron, no network) so it runs under plain
 * `node --test` with real captured contenthash values.
 *
 * Codes we recognise (from the content-hash library / ENSIP-7 profiles):
 *   ipfs-ns    0xe3      value is a CID              -> ipfs://<cid>
 *   ipns-ns    0xe5      value is a CID (libp2p-key) -> ipns://<cid>
 *   swarm-ns   0xe4      value is a CID (bzz)        -> recognised, unsupported
 *   arweave-ns 0xb29910  value is the raw 32-byte tx -> ar://<txid base64url>
 *
 * Anything else (an empty record, an address-only name, an unknown codec) is
 * reported honestly rather than guessed at — the caller shows a plain "no
 * website content record" page instead of sending the user somewhere.
 */

import { CID } from 'multiformats/cid'

export const CODEC = Object.freeze({
  IPFS: 0xe3,
  IPNS: 0xe5,
  SWARM: 0xe4,
  ARWEAVE: 0xb29910
})

/** Normalise a `0x…` hex string or a byte array to a Uint8Array. */
export function toBytes (input) {
  if (input == null) return new Uint8Array(0)
  if (input instanceof Uint8Array) return input
  if (Array.isArray(input)) return Uint8Array.from(input)
  let hex = String(input).trim()
  if (hex.startsWith('0x') || hex.startsWith('0X')) hex = hex.slice(2)
  if (hex.length === 0) return new Uint8Array(0)
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error('contenthash: not a hex byte string')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/**
 * Read one unsigned varint (LEB128) from `bytes` at `offset`.
 * @returns {{ value: number, length: number }}
 */
export function readVarint (bytes, offset = 0) {
  let value = 0
  let shift = 0
  let i = offset
  for (; i < bytes.length; i++) {
    const byte = bytes[i]
    value += (byte & 0x7f) * Math.pow(2, shift)
    if ((byte & 0x80) === 0) {
      return { value, length: i - offset + 1 }
    }
    shift += 7
    if (shift > 35) throw new Error('contenthash: varint too long')
  }
  throw new Error('contenthash: truncated varint')
}

/**
 * Decode a contenthash byte string into a content pointer.
 *
 * @param {string|Uint8Array|number[]} input `0x…` hex, or raw bytes.
 * @returns {null | {
 *   protocol: 'ipfs'|'ipns'|'arweave'|'swarm'|'unknown',
 *   supported: boolean,
 *   id?: string,      // CID string or Arweave txid
 *   url?: string,     // ipfs:// / ipns:// / ar:// pointer (supported only)
 *   code: number
 * }}  null when there is no record at all.
 */
export function decodeContenthash (input) {
  const bytes = toBytes(input)
  // An empty record (or the ABI zero-length bytes an unset name returns) is
  // "no contenthash", not an error and not a guess.
  if (bytes.length === 0) return null

  const { value: code, length } = readVarint(bytes, 0)
  const rest = bytes.subarray(length)

  if (code === CODEC.IPFS) {
    const cid = CID.decode(rest).toString()
    return { protocol: 'ipfs', supported: true, id: cid, url: `ipfs://${cid}`, code }
  }
  if (code === CODEC.IPNS) {
    const cid = CID.decode(rest).toString()
    return { protocol: 'ipns', supported: true, id: cid, url: `ipns://${cid}`, code }
  }
  if (code === CODEC.ARWEAVE) {
    // The value is the raw 32-byte Arweave transaction id; ar:// wants it in
    // the 43-char base64url form the gateway uses.
    const txid = Buffer.from(rest).toString('base64url')
    return { protocol: 'arweave', supported: true, id: txid, url: `ar://${txid}`, code }
  }
  if (code === CODEC.SWARM) {
    // Recognised, but this build has no Swarm (bzz) transport — decode it so
    // the page can say what it is, and fail closed rather than mis-route it.
    let id = ''
    try { id = CID.decode(rest).toString() } catch { /* keep it nameless */ }
    return { protocol: 'swarm', supported: false, id, code }
  }
  return { protocol: 'unknown', supported: false, code }
}
