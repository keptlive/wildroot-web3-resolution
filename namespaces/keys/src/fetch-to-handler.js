/* global Response, Headers */
export const CORS_HEADERS = [
  'Access-Control-Allow-Origin',
  'Allow-CSP-From',
  'Access-Control-Allow-Headers',
  'Access-Control-Allow-Methods',
  'Access-Control-Request-Headers'
]

export default function fetchToHandler (getFetch, session) {
  let hasFetch = null
  let loadingFetch = null

  async function load () {
    if (hasFetch) return hasFetch
    if (loadingFetch) return loadingFetch

    loadingFetch = Promise.resolve().then(getFetch).then((fetch) => {
      hasFetch = fetch
      loadingFetch = null
      return fetch
    }).catch((e) => {
      loadingFetch = null
      throw e
    })

    return loadingFetch
  }

  const close = async () => {
    if (loadingFetch) {
      await loadingFetch
      await close()
    } else if (hasFetch) {
      if (hasFetch.close) await hasFetch.close()
      else if (hasFetch.destroy) await hasFetch.destroy()
    }
  }

  return { handler: protocolHandler, close }

  async function protocolHandler (request) {
    try {
      // Lazy load fetch implementation
      const fetch = await load()

      const response = await fetch(request)
      try {
        for (const header of CORS_HEADERS) {
          response.headers.set(header, '*')
        }
      } catch {
        // Immutable headers (a Response the fetch did not build itself):
        // rebuild them mutable and set the same CORS headers on the copy.
        const newHeaders = new Headers([...response.headers])
        for (const header of CORS_HEADERS) newHeaders.set(header, '*')

        return new Response(response.body, {
          headers: newHeaders,
          statusText: response.statusText,
          status: response.status
        })
      }

      return response
    } catch (e) {
      // The message, never the stack: a stack carries this installation's
      // absolute paths, and on a scheme with supportFetchAPI and CORS `*` any
      // page could read them by fetching a URL it knows will fail.
      console.error(e)
      return new Response(String((e && e.message) || e), {
        status: 500,
        headers: { 'content-type': 'text/plain; charset=utf-8' }
      })
    }
  }
}
