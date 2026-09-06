/*
 * search:// URLs — THE one place they are built and the one place they are
 * read. Pure (no Electron), so every form below is unit-tested.
 *
 * WHY A HOST. `search` is a STANDARD scheme (src/main.cjs BROWSER_PRIVILEGES,
 * decision F1), and a standard scheme with no host is an INVALID GURL: the
 * old `search://?q=x` form loads nowhere (loadURL rejects it with
 * ERR_INVALID_URL) and, worse, navigationHistory.restore() creates the entry
 * anyway, after which every getAllEntries() — the session save on each
 * navigation — trips `url/gurl.cc:166 NOTREACHED` and writes a 35 MB dump
 * (Windows 2.57.0; traced in commit 6584613). Restore now filters such
 * entries, but the product kept MINTING them from four places. The fix by
 * construction is here: one builder, one parser, and every legacy spelling
 * accepted as an alias that is rewritten — never a 404.
 *
 * CANONICAL FORM: `search://<category>/?q=<query>`, home `search://<category>/`.
 * The host names the CATEGORY because the metasearch's model (src/hns/search.js,
 * after SearXNG) runs a query against exactly one category's engines — web,
 * academic, code, wiki, or the user's custom blend — so the category is what
 * a search URL is "on", the way a site is what an http URL is on. Chromium
 * lowercases a standard host and adds the slash; the category names are
 * already lowercase, so the string Chromium commits is the one built here.
 *
 * ALIASES (read, rewritten to canonical): `search://?q=x[&cat=y]` (what every
 * old bookmark, history row and saved provider template carries),
 * `search://` (home), and `search://<terms>` (the router's old default, the
 * query in the host). `?cat=` is honoured on an alias; on a canonical URL the
 * host wins. Bang prefixes (`!a query`) stay in the QUERY — the handler's
 * parseBang reads them after this parse, unchanged.
 */

/** The category names the handler knows; `custom` is the user's own blend. */
export const SEARCH_CATEGORIES = Object.freeze(['web', 'academic', 'code', 'wiki', 'custom'])
export const DEFAULT_SEARCH_CATEGORY = 'web'
/** The provider-template placeholder (Config.searchProvider, the omnibox). */
export const QUERY_PLACEHOLDER = '%s'

const SEARCH_SCHEME = /^search:/i

/**
 * Normalise a category name: lowercase, `all` → web (an old spelling), and
 * anything unknown → web, so a caller never has to guard the fallback.
 * @param {unknown} cat
 * @returns {string} a member of SEARCH_CATEGORIES
 */
export function searchCategory (cat) {
  const name = String(cat || '').trim().toLowerCase()
  if (name === 'all') return DEFAULT_SEARCH_CATEGORY
  return SEARCH_CATEGORIES.includes(name) ? name : DEFAULT_SEARCH_CATEGORY
}

/**
 * The provider template for a category — `search://web/?q=%s` — the form
 * Config.searchProvider, the settings dropdown and the omnibox share.
 * @param {string} [cat]
 */
export function searchTemplate (cat = DEFAULT_SEARCH_CATEGORY) {
  return `${searchHome(cat)}?q=${QUERY_PLACEHOLDER}`
}

/**
 * The category's home page (an empty query renders the search box).
 * @param {string} [cat]
 */
export function searchHome (cat = DEFAULT_SEARCH_CATEGORY) {
  return `search://${searchCategory(cat)}/`
}

/**
 * A results URL for a query. The only constructor in the tree: the omnibox
 * fallback, the context menu, the results page's own links and forms, the
 * router's search default all come here.
 * @param {string} query
 * @param {string} [cat]
 */
export function searchURL (query, cat = DEFAULT_SEARCH_CATEGORY) {
  return searchTemplate(cat).replace(QUERY_PLACEHOLDER, encodeURIComponent(String(query ?? '')))
}

function decode (s) {
  try { return decodeURIComponent(s) } catch { return s }
}

/**
 * Read any spelling of a search URL — canonical or alias — into what the
 * handler needs. Null when the URL is not search:// at all; an unparseable
 * search: string reads as the web home rather than throwing, because the
 * scheme was named and the answer to a broken search URL is the search page.
 * @param {unknown} href
 * @returns {{ query: string, cat: string }?}
 */
export function parseSearchURL (href) {
  const raw = String(href || '').trim()
  if (!SEARCH_SCHEME.test(raw)) return null
  let url
  try { url = new URL(raw) } catch { return { query: '', cat: DEFAULT_SEARCH_CATEGORY } }
  // Node's WHATWG parser treats a non-special scheme's host verbatim
  // (percent-escapes kept, case kept); Chromium has already lowercased it.
  const host = decode(url.hostname).toLowerCase()
  const q = url.searchParams.get('q')
  const pathTerms = decode(url.pathname).replace(/^\/+|\/+$/g, '')
  if (SEARCH_CATEGORIES.includes(host) || host === 'all') {
    // Canonical: the host is the category. (A path is tolerated as the query
    // so a hand-typed `search://web/kittens` still searches.)
    return { query: (q ?? pathTerms).trim(), cat: searchCategory(host) }
  }
  if (host === '') {
    // The old `search://?q=x&cat=y` form, and `search://` home.
    return { query: (q ?? pathTerms).trim(), cat: searchCategory(url.searchParams.get('cat')) }
  }
  // The router's old `search://<terms>`: the query IS the host (plus any path).
  const terms = pathTerms ? `${host}/${pathTerms}` : host
  return { query: (q ?? terms).trim(), cat: searchCategory(url.searchParams.get('cat')) }
}

/**
 * The navigation-time rewrite, on the rewriteToWildroot/rewriteToHns contract
 * (callers do `canonicalSearchURL(url) || url`): the canonical string when
 * `href` is a search URL spelled some other way, null when it is not a search
 * URL or is already canonical — so a canonical entry is restored with its
 * history intact and only an alias is re-issued as a fresh load.
 * @param {unknown} href
 * @returns {string?}
 */
export function canonicalSearchURL (href) {
  const parsed = parseSearchURL(href)
  if (!parsed) return null
  const canonical = parsed.query ? searchURL(parsed.query, parsed.cat) : searchHome(parsed.cat)
  return canonical === String(href).trim() ? null : canonical
}

/**
 * The same for a provider TEMPLATE (Config.searchProvider): a legacy
 * `search://?q=%s&cat=academic` from an old rc file becomes
 * `search://academic/?q=%s`; a third-party template (https://…?q=%s) passes
 * through untouched. Applied once where Config is built, so the omnibox, the
 * welcome page and the settings dropdown all see the canonical value.
 * @param {unknown} template
 * @returns {string}
 */
export function canonicalSearchTemplate (template) {
  const parsed = parseSearchURL(template)
  return parsed ? searchTemplate(parsed.cat) : String(template ?? '')
}
