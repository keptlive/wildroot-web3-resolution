/*
 * The HTTP status codes Chromium knows the reason phrase for.
 *
 * A protocol handler's Response status goes straight into
 * net::GetHttpReasonPhrase() inside ElectronURLLoaderFactory::StartLoading,
 * which NOTREACHEDs on any code Chromium does not define — a crash dump today
 * and a hard crash the day it is made fatal. Cloudflare's 5xx family
 * (520–530) is the usual way a status arrives from outside; nothing in that
 * band is defined. tests/hns/http-status-known.test.js scans the tree for a
 * LITERAL status outside this set; this module is for a status that is a
 * VARIABLE — chosen by a gateway, an upstream server or a contract — which
 * that scan cannot see.
 */

export const CHROMIUM_STATUSES = Object.freeze(new Set([
  100, 101, 103,
  200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
  300, 301, 302, 303, 304, 305, 306, 307, 308,
  400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
  415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451,
  500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511
]))

/**
 * A status Chromium can carry, or `fallback` (502, "bad gateway": the party
 * that chose the code is upstream of this handler) when it cannot.
 * @param {unknown} code
 * @param {number} [fallback]
 */
export function safeStatus (code, fallback = 502) {
  const n = Number(code)
  return CHROMIUM_STATUSES.has(n) ? n : fallback
}
