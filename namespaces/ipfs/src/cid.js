/*
 * The IPFS CID of a file or folder, computed exactly as the bundled kubo
 * computes it — so a CID we record is the CID kubo will announce when the
 * same bytes are published later, without re-chunking or re-hashing
 * (SIA-STORAGE.md §5b: the identity of a stored thing IS its CID).
 *
 * WHAT "EXACTLY AS KUBO" MEANS. `ipfs add --cid-version=1` with kubo 0.43's
 * defaults: a fixed-size chunker of 256 KiB (`Import.UnixFSChunker` =
 * size-262144), raw leaves (every chunk is its own block under the `raw`
 * codec, no UnixFS wrapper), sha2-256, a balanced DAG with at most 174 links
 * per node (`Import.UnixFSFileMaxLinks`), dag-pb internal nodes carrying a
 * UnixFS `File` message, and a UnixFS `Directory` node for a folder — links
 * sorted by name, each `Tsize` the cumulative size of the child's DAG. The
 * layout is go-unixfs `importer/balanced.Layout` (fill each level left to
 * right, all leaves at the same depth, a single chunk IS the file, an empty
 * file is a single empty raw leaf); the wire form is the dag-pb spec
 * (https://ipld.io/specs/codecs/dag-pb/spec/) and the UnixFS `Data` message
 * (https://github.com/ipfs/specs/blob/main/UNIXFS.md). Both encoders are
 * written out here — they are a few dozen bytes of protobuf — rather than
 * taken from `@ipld/dag-pb` / `ipfs-unixfs`, which are only in the tree as
 * transitive dependencies of the deprecated ipfsd-ctl stack (src/hns/ipfs.js)
 * and would vanish with it. `multiformats` (a direct dependency) does the
 * CID, sha2-256 and varint work. tests/hns/files-cid.test.js runs the real
 * kubo binary over the same fixtures and asserts equality, so "exactly" is a
 * proven property, not a claim.
 *
 * STREAMING. A file is read once, in order, and only the current chunk plus
 * the pending link lists (one per tree level, ≤ 174 entries each) are held —
 * memory is bounded whatever the file size. Nothing here touches a
 * filesystem: callers hand in bytes, a Node `Readable`, a web
 * `ReadableStream` or any async iterable of bytes.
 *
 * NOT COVERED, on purpose: HAMT-sharded directories. kubo shards a folder
 * whose basic directory node would exceed 256 KiB
 * (`Import.UnixFSHAMTDirectorySizeThreshold`); `directoryCid` refuses such a
 * folder with NOT_SUPPORTED rather than answer a CID kubo would not agree
 * with. A library manifest that large is a later problem (SIA-STORAGE.md
 * §5b #4) and gets HAMT then.
 */

import { Readable } from 'node:stream'
import { CID, varint } from 'multiformats'
import { sha256 } from 'multiformats/hashes/sha2'
import * as raw from 'multiformats/codecs/raw'

import { SourceError } from './source-error.js'

/** kubo `Import.UnixFSChunker` default: `size-262144`. */
export const CHUNK_SIZE = 256 * 1024
/** kubo `Import.UnixFSFileMaxLinks` default (go-unixfs `DefaultLinksPerBlock`). */
export const MAX_LINKS = 174
/** kubo `Import.UnixFSHAMTDirectorySizeThreshold` default: `256KiB`. */
export const HAMT_THRESHOLD = 256 * 1024
/** The dag-pb multicodec. `raw` comes from multiformats. */
const DAG_PB = 0x70

/**
 * @typedef {object} FileCidResult
 * @property {string} cid   CIDv1, base32 — what `ipfs add` prints
 * @property {number} size  the file's byte length
 * @property {number} tsize the DAG's cumulative byte length: the `Tsize` a
 *   parent directory link carries, and the size of the CAR minus framing
 */

/**
 * @typedef {object} DirectoryEntry
 * @property {string} name        the child's name in this folder
 * @property {string|CID} cid     the child's root CID (a file's, or a subfolder's)
 * @property {number} tsize       the child's cumulative DAG size (`FileCidResult.tsize`)
 */

// ----------------------------------------------------------------- protobuf

/**
 * Field tags (number << 3 | wire type). Wire type 0 = varint, 2 = bytes.
 * Names follow the two .proto files so a reader can check them line by line.
 */
const TAG = {
  // unixfs.proto `Data`
  UNIXFS_TYPE: 0x08, // 1, varint
  UNIXFS_FILESIZE: 0x18, // 3, varint
  UNIXFS_BLOCKSIZE: 0x20, // 4, varint, repeated (proto2: one tag per element)
  // merkledag.proto `PBLink`
  LINK_HASH: 0x0a, // 1, bytes (the CID's bytes)
  LINK_NAME: 0x12, // 2, string
  LINK_TSIZE: 0x18, // 3, varint
  // merkledag.proto `PBNode` — links are written BEFORE data (dag-pb spec)
  NODE_DATA: 0x0a, // 1, bytes
  NODE_LINK: 0x12 // 2, bytes, repeated
}
const UNIXFS_FILE = 2
const UNIXFS_DIRECTORY = 1

function uvarint (n) {
  const out = new Uint8Array(varint.encodingLength(n))
  varint.encodeTo(n, out, 0)
  return out
}

/** A varint field. */
function vfield (tag, n) {
  return Buffer.concat([uvarint(tag), uvarint(n)])
}

/** A length-delimited field. */
function bfield (tag, payload) {
  return Buffer.concat([uvarint(tag), uvarint(payload.length), payload])
}

/**
 * UnixFS `Data { Type: File, filesize, blocksizes[] }` for an internal node.
 * `Data.Data` is never set: with raw leaves no dag-pb node carries bytes.
 * @param {number[]} blocksizes the file bytes under each child, in order
 */
function unixfsFile (blocksizes) {
  const filesize = blocksizes.reduce((a, b) => a + b, 0)
  return Buffer.concat([
    vfield(TAG.UNIXFS_TYPE, UNIXFS_FILE),
    vfield(TAG.UNIXFS_FILESIZE, filesize),
    ...blocksizes.map((b) => vfield(TAG.UNIXFS_BLOCKSIZE, b))
  ])
}

/** UnixFS `Data { Type: Directory }` — two bytes. */
function unixfsDirectory () {
  return vfield(TAG.UNIXFS_TYPE, UNIXFS_DIRECTORY)
}

/**
 * A dag-pb node: every link (Hash, Name, Tsize — Name always present, empty
 * for a file's children, which is what both kubo and js-ipfs write), then
 * the Data field.
 * @param {Array<{ cid: CID, name: string, tsize: number }>} links
 * @param {Uint8Array} data
 */
function pbNode (links, data) {
  const parts = links.map(({ cid, name, tsize }) => bfield(TAG.NODE_LINK, Buffer.concat([
    bfield(TAG.LINK_HASH, cid.bytes),
    bfield(TAG.LINK_NAME, Buffer.from(name, 'utf8')),
    vfield(TAG.LINK_TSIZE, tsize)
  ])))
  parts.push(bfield(TAG.NODE_DATA, data))
  return Buffer.concat(parts)
}

// --------------------------------------------------------------------- DAG

/**
 * @typedef {object} Node one built block, as its parent needs to know it
 * @property {CID} cid
 * @property {number} tsize    bytes of this block plus everything under it
 * @property {number} filesize file bytes under it (a leaf: its length)
 */

/** A raw leaf: the chunk is the block. @returns {Promise<Node>} */
async function leaf (chunk) {
  const digest = await sha256.digest(chunk)
  return { cid: CID.createV1(raw.code, digest), tsize: chunk.length, filesize: chunk.length }
}

/** An internal file node over `children`. @returns {Promise<Node>} */
async function fileNode (children) {
  const bytes = pbNode(children.map((c) => ({ cid: c.cid, name: '', tsize: c.tsize })), unixfsFile(children.map((c) => c.filesize)))
  const digest = await sha256.digest(bytes)
  return {
    cid: CID.createV1(DAG_PB, digest),
    tsize: bytes.length + children.reduce((a, c) => a + c.tsize, 0),
    filesize: children.reduce((a, c) => a + c.filesize, 0)
  }
}

/**
 * The balanced layout, built bottom-up as chunks arrive: `levels[d]` holds
 * the finished children waiting to become a node at depth `d`; a level that
 * reaches `maxLinks` is committed into a node and pushed one level up, which
 * may cascade. That produces the same tree as go-unixfs's top-down
 * `Layout`/`fillNodeRec` — every internal node full except the rightmost
 * path, all leaves at the same depth — because both fill left to right with
 * the same fan-out; the flush rule below covers the one asymmetry (a
 * single-child level at the top is the root itself, never wrapped).
 */
class BalancedBuilder {
  constructor (maxLinks) {
    this.maxLinks = maxLinks
    /** @type {Node[][]} */
    this.levels = []
  }

  async push (node, depth = 0) {
    const level = this.levels[depth] || (this.levels[depth] = [])
    level.push(node)
    if (level.length === this.maxLinks) {
      this.levels[depth] = []
      await this.push(await fileNode(level), depth + 1)
    }
  }

  /** @returns {Promise<Node>} the root; `null` when nothing was pushed */
  async finish () {
    let carry = null
    for (let d = 0; d < this.levels.length; d++) {
      const level = this.levels[d]
      if (carry) level.push(carry)
      carry = null
      if (level.length === 0) continue
      const above = this.levels.slice(d + 1).some((l) => l.length > 0)
      // A lone node with nothing above it IS the root: a one-chunk file is
      // its raw leaf, a file of exactly maxLinks chunks is that one node.
      if (!above && level.length === 1) return level[0]
      carry = await fileNode(level)
    }
    return carry
  }
}

/**
 * Anything a caller may hand in, as an async iterable of Buffers. Shared
 * with LocalFolderSource.write(), which accepts the same shapes.
 * @param {import('node:stream').Readable|ReadableStream|AsyncIterable<Uint8Array>|Uint8Array|string} body
 * @returns {AsyncIterable<Buffer>}
 */
export async function * bytesOf (body) {
  if (typeof body === 'string') { yield Buffer.from(body, 'utf8'); return }
  if (body instanceof Uint8Array) { yield Buffer.from(body.buffer, body.byteOffset, body.byteLength); return }
  const iterable = typeof body.getReader === 'function' ? Readable.fromWeb(body) : body
  for await (const chunk of iterable) {
    yield typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)
  }
}

/**
 * Re-cut an arbitrary byte stream into exactly `size`-byte chunks (the last
 * one shorter). kubo's `size-N` chunker is this and nothing more. At most one
 * partial chunk plus one incoming piece is held at a time.
 * @param {AsyncIterable<Buffer>} chunks
 * @param {number} size
 */
async function * rechunk (chunks, size) {
  let pending = Buffer.allocUnsafe(size)
  let filled = 0
  for await (const piece of chunks) {
    let offset = 0
    while (offset < piece.length) {
      const take = Math.min(size - filled, piece.length - offset)
      piece.copy(pending, filled, offset, offset + take)
      filled += take
      offset += take
      if (filled === size) {
        yield pending
        pending = Buffer.allocUnsafe(size)
        filled = 0
      }
    }
  }
  if (filled > 0) yield pending.subarray(0, filled)
}

/**
 * The CID of a file's UnixFS DAG, kubo-identical with the defaults. The
 * options exist so the tree shape can be proven against kubo's
 * `--chunker=size-N --max-links=M` on small fixtures; production callers
 * never pass them.
 *
 * @param {import('node:stream').Readable|ReadableStream|AsyncIterable<Uint8Array>|Uint8Array|string} body
 * @param {{ chunkSize?: number, maxLinks?: number }} [opts]
 * @returns {Promise<FileCidResult>}
 */
export async function fileCid (body, { chunkSize = CHUNK_SIZE, maxLinks = MAX_LINKS } = {}) {
  if (!(Number.isInteger(chunkSize) && chunkSize > 0) || !(Number.isInteger(maxLinks) && maxLinks > 1)) {
    throw new SourceError('BAD_PATH', 'CID options must be positive integers')
  }
  const builder = new BalancedBuilder(maxLinks)
  let size = 0
  for await (const chunk of rechunk(bytesOf(body), chunkSize)) {
    size += chunk.length
    await builder.push(await leaf(chunk))
  }
  // go-unixfs: "No data, return just an empty node" — with raw leaves that
  // is a raw block of zero bytes, not a UnixFS file node.
  const root = (await builder.finish()) || (await leaf(Buffer.alloc(0)))
  return { cid: root.cid.toString(), size, tsize: root.tsize }
}

/**
 * The CID of a UnixFS directory node over `entries` — what `ipfs add -r`
 * prints for a folder whose children have those CIDs. Order in is
 * irrelevant: links are sorted bytewise by name, as go-merkledag does. Each
 * entry's `tsize` must be the child's own cumulative size, so a folder of
 * folders is built bottom-up by calling this on each child first.
 *
 * @param {DirectoryEntry[]} entries
 * @returns {Promise<{ cid: string, tsize: number }>}
 */
export async function directoryCid (entries) {
  const links = []
  const seen = new Set()
  for (const { name, cid, tsize } of entries) {
    if (typeof name !== 'string' || name === '' || name.includes('/')) throw new SourceError('BAD_PATH', `Bad folder entry name "${name}"`)
    if (seen.has(name)) throw new SourceError('BAD_PATH', `Folder entry "${name}" appears twice`)
    if (!Number.isInteger(tsize) || tsize < 0) throw new SourceError('BAD_PATH', `Folder entry "${name}" has no DAG size`)
    seen.add(name)
    links.push({ name, cid: typeof cid === 'string' ? CID.parse(cid) : CID.asCID(cid), tsize })
    if (!links[links.length - 1].cid) throw new SourceError('BAD_PATH', `Folder entry "${name}" has no CID`)
  }
  links.sort((a, b) => Buffer.compare(Buffer.from(a.name, 'utf8'), Buffer.from(b.name, 'utf8')))
  const bytes = pbNode(links, unixfsDirectory())
  if (bytes.length >= HAMT_THRESHOLD) {
    throw new SourceError('NOT_SUPPORTED', `This folder has too many entries to hash as one block (${links.length})`)
  }
  const digest = await sha256.digest(bytes)
  return { cid: CID.createV1(DAG_PB, digest).toString(), tsize: bytes.length + links.reduce((a, l) => a + l.tsize, 0) }
}

/** True for a string `fileCid`/`directoryCid` could have produced. */
export function isCidV1 (value) {
  try { return CID.parse(value).version === 1 } catch { return false }
}
