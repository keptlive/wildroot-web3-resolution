/*
 * CCIP-read (ERC-3668): following an on-chain contract's instruction to go and
 * ask somewhere else.
 *
 * WHY WE NEED IT. Most of the interesting ENS namespace is no longer stored on
 * L1. `.base.eth`, `uni.eth`, `linea.eth`, World's names, and every ICANN
 * domain imported through ENS's gasless DNSSEC path all answer by REVERTING
 * with `OffchainLookup(...)`, which is a contract saying "the data is over
 * there, fetch it and hand it back to me". Without this the browser's ENS
 * support covers a shrinking minority of the names people actually have.
 *
 * WHAT IT IS NOT. It does not make anything trustless. The gateway's answer is
 * handed straight back to the contract, and what the contract DOES with it is
 * the resolver author's choice: some verify a signature from a key they control
 * (so the answer is that operator's word), some verify a Merkle storage proof
 * or a DNSSEC chain on-chain (so the answer is cryptographic). Both are the
 * same protocol and opposite guarantees.
 *
 * It is tempting to grade the padlock by which one happened — payload size and
 * revert message make it observable. We deliberately do NOT, for a reason that
 * outranks the distinction: this browser has no Ethereum light client, so the
 * registry read, the resolver address and the callback result all arrive on the
 * word of an RPC endpoint. A "verified storage proof" that we learned about
 * from an RPC that could equally have made it up is not evidence of anything.
 * Grading would show the user a difference we cannot actually observe. ENS is
 * TRUSTED, all of it, until there is a light client — and the trust panel says
 * exactly that (src/hns/trust-path.js).
 *
 * SECURITY, all of it required by the spec or by not being reckless:
 *   - `sender` MUST equal the contract that reverted (§Client Lookup Protocol).
 *     Without it, any contract could point the browser at any other contract's
 *     callback and have the result attributed to it.
 *   - lookups are CAPPED (spec: MUST, at least 4). A callback may itself revert
 *     with OffchainLookup, so this is a recursion the contract controls.
 *   - the gateway URL comes from a REVERT, i.e. from whoever wrote the
 *     contract. https only, no private or loopback hosts, no redirects
 *     followed, a byte cap and a deadline per attempt. A URL from an untrusted
 *     source pointed at the user's own network is the whole SSRF pattern.
 *   - 4xx stops (the gateway has answered: no), 5xx tries the next URL.
 *
 * ENSIP-21 IS NOT OPTIONAL HERE. The outer URL in a modern ENS lookup is ENS's
 * own batch gateway, so a client without a local implementation discloses every
 * name its user resolves to a third party. The sentinel `x-batch-gateway:true`
 * means "substitute your own", and this module does — see batchLocally.
 */

/** `OffchainLookup(address,string[],bytes,bytes4,bytes)`. */
export const OFFCHAIN_LOOKUP = '0x556f1830'

/** ENSIP-21: "use your own batch gateway; all compliant ones are equivalent". */
export const BATCH_SENTINEL = 'x-batch-gateway:true'

/** ENSIP-21 `query((address,string[],bytes)[])`. */
export const BATCH_SELECTOR = '0xa780bab6'

/** Spec: MUST cap, SHOULD allow at least 4. */
export const MAX_LOOKUPS = 4

/**
 * The most sub-requests one ENSIP-21 batch may carry. The triples are chosen
 * by the same contract that chose the batch, and every one of them is a
 * fetch; without a bound, four rounds of an unbounded batch is a lot of
 * fetching directed by a stranger. A batch over the cap is refused whole
 * rather than truncated, so the callback never sees a silently short array.
 */
export const MAX_BATCH_REQUESTS = 16

/** A gateway answer larger than this is refused rather than buffered. */
export const MAX_RESPONSE_BYTES = 1 << 20

/** How long one gateway request may take. */
export const GATEWAY_TIMEOUT_MS = 8000

const LOOKUP_ARGS = [
  { type: 'address' }, { type: 'string[]' }, { type: 'bytes' },
  { type: 'bytes4' }, { type: 'bytes' }
]
const BATCH_REQUESTS = [{
  type: 'tuple[]',
  components: [{ type: 'address' }, { type: 'string[]' }, { type: 'bytes' }]
}]
const BATCH_RESULTS = [{ type: 'bool[]' }, { type: 'bytes[]' }]

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/**
 * Is this a gateway URL we are willing to fetch?
 *
 * The URL arrives inside a revert, so it is chosen by whoever deployed the
 * contract. Everything below is about not letting that reach the user's own
 * network or their filesystem.
 */
export function isSafeGatewayUrl (raw, { isPublicAddress } = {}) {
  let u
  try {
    u = new URL(String(raw))
  } catch {
    return false
  }
  if (u.protocol !== 'https:') return false
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost')) return false
  if (host.endsWith('.local') || host.endsWith('.internal')) return false
  // An IP literal is checked directly; a hostname cannot be without resolving
  // it, which is the caller's job if it wants to go further.
  if (IPV4.test(host) || host.includes(':')) {
    if (typeof isPublicAddress === 'function' && !isPublicAddress(host)) return false
  }
  return true
}

/** An error that ends the lookup: not a "try the next gateway" condition. */
function fatal (message) {
  const err = new Error(message)
  err.fatal = true
  return err
}

/** ERC-3668 §Client: `{sender}` and `{data}` are lowercase 0x-hex. */
function fillTemplate (template, sender, data) {
  return String(template)
    .replace(/\{sender\}/g, String(sender).toLowerCase())
    .replace(/\{data\}/g, String(data).toLowerCase())
}

/**
 * One gateway request. Returns the `data` hex, or throws.
 *
 * GET when the template carries `{data}`, POST otherwise — the spec makes that
 * the client's decision and not the gateway's.
 */
async function askGateway (template, sender, data, { fetchImpl, timeout, isPublicAddress }) {
  const url = fillTemplate(template, sender, data)
  if (!isSafeGatewayUrl(url, { isPublicAddress })) {
    const err = new Error('gateway URL refused')
    err.fatal = true // not a "try the next one" condition; it is a bad URL
    return Promise.reject(err)
  }
  const hasData = /\{data\}/.test(String(template))
  const res = await fetchImpl(url, {
    method: hasData ? 'GET' : 'POST',
    headers: hasData ? {} : { 'content-type': 'application/json' },
    body: hasData ? undefined : JSON.stringify({ data, sender: String(sender).toLowerCase() }),
    // A gateway that redirects is asking us to fetch a URL nothing checked.
    redirect: 'manual',
    signal: AbortSignal.timeout(timeout)
  })
  if (res.status >= 400 && res.status <= 499) {
    const err = new Error(`gateway refused (HTTP ${res.status})`)
    err.fatal = true // the spec: 4xx returns an error to the caller and stops
    throw err
  }
  if (!res.ok) throw new Error(`gateway error (HTTP ${res.status})`)
  const text = await readCapped(res)
  let body = null
  try {
    body = JSON.parse(text)
  } catch {
    throw new Error('gateway answered with something that is not JSON')
  }
  if (!body || typeof body.data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(body.data)) {
    throw new Error('gateway answer carried no data')
  }
  return body.data
}

/** Read a response body, refusing one that will not fit in memory politely. */
async function readCapped (res) {
  const declared = Number(res.headers.get('content-length') || 0)
  if (declared > MAX_RESPONSE_BYTES) throw new Error('gateway answer too large')
  const text = await res.text()
  if (text.length > MAX_RESPONSE_BYTES) throw new Error('gateway answer too large')
  return text
}

/**
 * The ENSIP-21 batch gateway, implemented here rather than asked of ENS's.
 *
 * The outer URL of a modern ENS lookup is `ccip-v3.ens.xyz`, and using it means
 * telling a third party every name this browser's user resolves. The sentinel
 * says a client may substitute its own; this does the inner requests directly.
 * A sub-request that fails is reported as a failure in the returned array
 * rather than failing the batch — that is the interface's own shape.
 */
async function batchLocally (callData, deps) {
  const data = String(callData || '')
  if (data.slice(0, 10).toLowerCase() !== BATCH_SELECTOR) {
    throw fatal(`batch gateway calldata is not query(): selector ${data.slice(0, 10)}`)
  }
  const [requests] = deps.decodeAbiParameters(BATCH_REQUESTS, `0x${data.slice(10)}`)
  if (requests.length > MAX_BATCH_REQUESTS) {
    throw fatal(`batch of ${requests.length} sub-requests exceeds the cap of ${MAX_BATCH_REQUESTS}`)
  }
  const failures = []
  const responses = []
  for (const req of requests) {
    const [sender, urls, data] = [req[0] ?? req.sender, req[1] ?? req.urls, req[2] ?? req.data]
    let answer = null
    for (const url of urls || []) {
      try {
        answer = await askGateway(url, sender, data, deps)
        break
      } catch (err) {
        if (err && err.fatal) break
      }
    }
    failures.push(answer === null)
    responses.push(answer === null ? '0x' : answer)
  }
  return deps.encodeAbiParameters(BATCH_RESULTS, [failures, responses])
}

/**
 * Perform an `eth_call`, following any OffchainLookup it reverts with.
 *
 * @param {object} req
 * @param {string} req.to                the contract
 * @param {string} req.data              the calldata
 * @param {Function} req.call            (to, data) -> {result} | {revertData}
 * @param {object} req.deps              decodeAbiParameters, encodeAbiParameters,
 *                                       fetchImpl, isPublicAddress, timeout
 * @returns {Promise<string|null>} the result hex, or null for an empty return
 */
export async function ccipCall ({ to, data, call, deps }) {
  const limit = deps.maxLookups || MAX_LOOKUPS
  const timeout = deps.timeout || GATEWAY_TIMEOUT_MS
  let current = data
  for (let round = 0; round <= limit; round++) {
    const out = await call(to, current)
    if (!out || !out.revertData) {
      return out && out.result && out.result !== '0x' ? out.result : null
    }
    const revert = String(out.revertData)
    if (!revert.toLowerCase().startsWith(OFFCHAIN_LOOKUP)) {
      const err = new Error('call reverted')
      err.revertData = revert
      throw err
    }
    if (round === limit) throw new Error(`more than ${limit} offchain lookups`)

    const [sender, urls, callData, callbackFn, extraData] =
      deps.decodeAbiParameters(LOOKUP_ARGS, `0x${revert.slice(10)}`)

    // MUST: the contract may only send us to fetch data for ITSELF.
    if (String(sender).toLowerCase() !== String(to).toLowerCase()) {
      throw new Error('OffchainLookup named a different contract than the one called')
    }

    const list = Array.from(urls || [])
    let answer = null
    if (list.some((u) => String(u) === BATCH_SENTINEL)) {
      // ENSIP-21: all compliant batch gateways are equivalent, so use ours and
      // disclose nothing.
      answer = await batchLocally(callData, { ...deps, timeout })
    } else {
      let lastErr = null
      for (const url of list) {
        try {
          answer = await askGateway(url, sender, callData, { ...deps, timeout })
          break
        } catch (err) {
          lastErr = err
          if (err && err.fatal) break // 4xx or a refused URL: stop, per spec
        }
      }
      if (answer === null) throw lastErr || new Error('no gateway answered')
    }

    current = `${callbackFn}${deps
      .encodeAbiParameters([{ type: 'bytes' }, { type: 'bytes' }], [answer, extraData])
      .slice(2)}`
  }
  throw new Error('offchain lookup did not terminate')
}
