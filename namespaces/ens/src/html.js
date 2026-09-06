/*
 * The two helpers every protocol handler that renders a PAGE needs.
 *
 * Several handlers answer with HTML they build themselves — an error page, a
 * directory listing, a "this name has no records" explainer — and every one of
 * them was carrying its own copy of the same two functions. ens-protocol.js
 * and onion-protocol.js had byte-identical escapers; torrent-protocol.js added
 * a third, plus a byte formatter that already existed in three page scripts.
 * One copy, here, for the main-process side.
 *
 * Pure and Electron-free, so it unit-tests under plain node.
 */

const ESCAPE = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }

/**
 * Text -> safe HTML text. Escapes the single quote as well as the double, so
 * the result is safe in a single-quoted attribute too.
 * @param {unknown} value
 */
export function escapeHtml (value) {
  return String(value).replace(/[&<>"']/g, (c) => ESCAPE[c])
}

/**
 * Bytes -> the size a person reads ("4.2 MB"), one decimal below 10 so
 * "9.9 MB" keeps its precision and "512 MB" does not pretend to.
 * @param {number} n
 */
export function fmtBytes (n) {
  if (!Number.isFinite(n) || n <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++ }
  return `${n.toFixed(i && n < 10 ? 1 : 0)} ${units[i]}`
}
