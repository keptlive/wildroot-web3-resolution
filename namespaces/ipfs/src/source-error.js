// The typed error `cid.js` refuses with, factored out of the Wildroot browser's
// `src/files/source.js` — a 500-line Files-API module of which `cid.js` uses
// exactly this class. Nothing else from that file is in scope here.
//
// The class and the status table are byte-identical to the Wildroot tree.

/**
 * @typedef {'NOT_FOUND'|'EXISTS'|'FORBIDDEN'|'BAD_PATH'|'IS_DIRECTORY'|
 *   'NOT_DIRECTORY'|'NOT_EMPTY'|'READ_ONLY'|'RANGE'|'NOT_SUPPORTED'|
 *   'TOO_LARGE'|'IO'} SourceErrorCode
 */

/** @type {Record<SourceErrorCode, number>} */
export const STATUS_OF = {
  NOT_FOUND: 404,
  EXISTS: 409,
  FORBIDDEN: 403,
  BAD_PATH: 400,
  IS_DIRECTORY: 400,
  NOT_DIRECTORY: 400,
  NOT_EMPTY: 409,
  READ_ONLY: 403,
  RANGE: 416,
  NOT_SUPPORTED: 501,
  TOO_LARGE: 413,
  IO: 500
}

export class SourceError extends Error {
  /**
   * @param {SourceErrorCode} code
   * @param {string} message a sentence the user may see
   * @param {object} [extra] fields the API layer may need (`path`, `size`)
   */
  constructor (code, message, extra = {}) {
    super(message)
    this.name = 'SourceError'
    this.code = code
    this.status = STATUS_OF[code] || 500
    Object.assign(this, extra)
  }

  /** The wire form — never the Error object. */
  toJSON () {
    return { code: this.code, status: this.status, message: this.message, path: this.path }
  }
}
