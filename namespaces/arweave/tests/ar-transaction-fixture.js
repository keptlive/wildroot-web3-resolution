// Offline fixtures signed with a newly generated, non-wallet RSA key. The
// signing payload is constructed independently of the handler's verifier.
// The key is RSA-4096 because that is the only size Arweave wallets have and
// the only one src/hns/ar-tx.js will verify.
import { constants, createHash, generateKeyPairSync, sign } from 'node:crypto'
import { dataRootB64 } from '../src/ar-merkle.js'

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 65537 })
const owner = publicKey.export({ format: 'jwk' }).n
const digest = (input) => createHash('sha384').update(input).digest()
const decode = (input) => Buffer.from(input, 'base64url')

function hashItem (item) {
  if (!Array.isArray(item)) return digest(Buffer.concat([digest(Buffer.from('blob' + item.length)), digest(item)]))
  let result = digest(Buffer.from('list' + item.length))
  for (const child of item) result = digest(Buffer.concat([result, hashItem(child)]))
  return result
}

export function transaction (bytes, fields = {}, key = privateKey, saltLength = 32) {
  const header = {
    format: 2,
    owner,
    target: '',
    quantity: '0',
    reward: '1000',
    last_tx: '',
    tags: [],
    data_size: String(bytes.length),
    data_root: bytes.length ? dataRootB64(bytes) : '',
    ...fields
  }
  const payload = [
    Buffer.from(String(header.format)), decode(header.owner), decode(header.target),
    Buffer.from(header.quantity), Buffer.from(header.reward), decode(header.last_tx),
    header.tags.map((tag) => [decode(tag.name), decode(tag.value)]),
    Buffer.from(header.data_size), decode(header.data_root)
  ]
  if (header.denomination !== undefined) payload.unshift(Buffer.from(header.denomination))
  const signature = sign('sha256', hashItem(payload), { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength })
  header.signature = signature.toString('base64url')
  header.id = createHash('sha256').update(signature).digest('base64url')
  return { id: header.id, header }
}

export function tag (name, value) {
  return { name: Buffer.from(name).toString('base64url'), value: Buffer.from(value).toString('base64url') }
}

/**
 * The legacy format: the DATA is inside the signature (a plain concatenation,
 * no deep hash and no Merkle root), and `data_size` is not signed at all.
 */
export function transactionV1 (bytes, fields = {}, key = privateKey, saltLength = 32) {
  const header = {
    format: 1,
    owner,
    target: '',
    quantity: '0',
    reward: '1000',
    last_tx: '',
    tags: [],
    data: bytes.toString('base64url'),
    data_size: String(bytes.length),
    data_root: '',
    ...fields
  }
  const payload = Buffer.concat([
    decode(header.owner), decode(header.target), decode(header.data),
    Buffer.from(header.quantity), Buffer.from(header.reward), decode(header.last_tx),
    ...header.tags.flatMap((tag) => [decode(tag.name), decode(tag.value)])
  ])
  const signature = sign('sha256', payload, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength })
  header.signature = signature.toString('base64url')
  header.id = createHash('sha256').update(signature).digest('base64url')
  return { id: header.id, header }
}
