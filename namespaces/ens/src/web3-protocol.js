/* globals Response */
import fetchToHandler from './fetch-to-handler.js'
import { safeStatus } from '../../../src/safe-status.js'

/**
 * The response headers a contract may set. ERC-5219 lets the contract return
 * arbitrary `(string,string)[]` headers; on a standard, secure origin that
 * would let it choose anything from a service-worker-relevant header to a
 * redirect. Only headers that describe the body get through.
 */
const HEADER_ALLOWLIST = new Set([
  'content-type', 'content-length', 'content-disposition', 'cache-control', 'etag', 'last-modified'
])

/**
 * The Response for one ERC-4804 read. The contract chooses the status, the
 * headers and the body; this browser decides which of those it will carry.
 * The status is clamped to one Chromium knows (an unknown code NOTREACHEDs in
 * the protocol loader, so a contract returning 523 would be choosing a
 * crash), and the headers are filtered to the allowlist above.
 * @param {{httpCode?: unknown, httpHeaders?: object, output?: any}} result
 */
export function web3Response ({ httpCode, httpHeaders, output } = {}) {
  const headers = new Headers()
  for (const [k, v] of Object.entries(httpHeaders || {})) {
    if (HEADER_ALLOWLIST.has(String(k).toLowerCase()) && typeof v === 'string') headers.set(k, v)
  }
  return new Response(output, { status: safeStatus(httpCode), headers })
}

export default async function createHandler (options) {
  return fetchToHandler(async () => {
    // web3protocol (its Client plus the full default chain registry) costs
    // roughly half a second to import, for a scheme almost nobody uses — so
    // BOTH imports happen here, on the first web3:// fetch, never at startup
    // (fetchToHandler runs this callback lazily). An rc-supplied
    // web3Options.chainList still takes precedence over the default registry.
    const { chainList, ...opts } = options
    const [{ Client }, list] = await Promise.all([
      import('web3protocol'),
      chainList
        ? Promise.resolve(chainList)
        : import('web3protocol/chains').then(({ getDefaultChainList }) => getDefaultChainList())
    ])
    const web3Client = new Client(list, opts)
    async function fetch ({ url, method }) {
      if (method !== 'GET') {
        return new Response('Method Not Allowed', {
          status: 405
        })
      }
      return web3Response(await web3Client.fetchUrl(url))
    }

    return fetch
  })
}
