// The Bluesky (AT Protocol) adapter — reads, session auth, and writes.
//
// READS need no account: they go to the public AppView, which serves profile,
// search and author-feed data for the entire network unauthenticated. That is
// what makes "find your Bluesky friends and subscribe" possible with zero
// setup — verified live against public.api.bsky.app (searchActors, getProfile,
// getAuthorFeed, resolveHandle, getPostThread) on 2026-08-22.
//
// WRITES are the user acting AS THEIR OWN existing Bluesky account: a session
// against their own PDS (bsky.social for most people, honored from their DID
// document otherwise), created from handle + app password. The app password
// and both session tokens live in the vault and never reach a renderer; this
// module only ever sees them as arguments from the main process.
//
// EVERYTHING NORMALIZES to the unified post/actor model from
// docs/SOCIAL-MULTIPROTOCOL.md — {id, origin_protocol, author, content,
// created_at, reply_parent_ref, counts, origin_uri} — and every normalized
// object KEEPS its native ref (uri+cid, reply refs, did) so an interaction
// can route back to its origin protocol instead of being faked locally.

import { makeXrpc, PUBLIC_APPVIEW, isExpiredToken } from './xrpc.js'
import { didWebUrl, isSafeDidWebHost } from './did-protocol.js'

export { PUBLIC_APPVIEW, isExpiredToken }

/** The default PDS for accounts whose DID document we cannot resolve. */
export const DEFAULT_PDS = 'https://bsky.social'

/** did:plc directory — the resolver for the DID method most accounts use. */
const PLC_DIRECTORY = 'https://plc.directory'

const iso = (nowMs) => new Date(nowMs).toISOString()
const seconds = (isoString) => {
  const ms = Date.parse(isoString)
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0
}

/** at://did/collection/rkey -> rkey. */
export function rkeyOf (uri) {
  const parts = String(uri || '').split('/')
  return parts.length ? parts[parts.length - 1] : ''
}

/** The canonical web URL for a post — where "open on Bluesky" goes. */
export function postUrl (post) {
  const who = post.author.handle || post.author.did
  return `https://bsky.app/profile/${who}/post/${rkeyOf(post.uri)}`
}

/** A profileView/actor -> the unified actor model. */
export function normalizeActor (actor) {
  return {
    origin_protocol: 'bsky',
    id: actor.did,
    handle: actor.handle || actor.did,
    display: actor.displayName || actor.handle || actor.did,
    about: String(actor.description || '').slice(0, 300),
    avatar: actor.avatar || '',
    url: `https://bsky.app/profile/${actor.handle || actor.did}`,
    ref: { did: actor.did, handle: actor.handle || '' },
    counts: {
      followers: actor.followersCount ?? null,
      posts: actor.postsCount ?? null
    }
  }
}

/**
 * A postView (with or without its feed wrapper) -> the unified post model.
 *
 * The native ref keeps uri, cid AND the record's own reply refs, because a
 * future reply to this post must send `{root, parent}` built from them —
 * replying with only the parent detaches the reply from its thread.
 */
export function normalizePost (item) {
  const post = item.post || item
  const record = post.record || {}
  const reason = item.reason || null
  const author = post.author || {}
  return {
    id: post.uri,
    origin_protocol: 'bsky',
    author: {
      id: author.did,
      handle: author.handle || author.did,
      display: author.displayName || author.handle || author.did,
      avatar: author.avatar || ''
    },
    content: String(record.text || ''),
    created_at: seconds(record.createdAt || post.indexedAt),
    reply_parent_ref: record.reply ? { uri: record.reply.parent && record.reply.parent.uri } : null,
    counts: {
      replies: post.replyCount ?? 0,
      reposts: post.repostCount ?? 0,
      likes: post.likeCount ?? 0
    },
    origin_uri: post.uri,
    open_url: postUrl({ author, uri: post.uri }),
    boosted_by: reason && reason.$type === 'app.bsky.feed.defs#reasonRepost' && reason.by
      ? (reason.by.displayName || reason.by.handle)
      : null,
    ref: {
      protocol: 'bsky',
      uri: post.uri,
      cid: post.cid,
      author_did: author.did,
      reply: record.reply || null
    }
  }
}

/**
 * The `{root, parent}` refs for a reply to `post` (a normalized post).
 *
 * A reply to a THREAD MEMBER keeps that thread's root; a reply to a root
 * starts the thread with root === parent. Getting this wrong is how replies
 * render orphaned in every other client.
 */
export function replyRefs (post) {
  const parent = { uri: post.ref.uri, cid: post.ref.cid }
  const root = post.ref.reply && post.ref.reply.root
    ? { uri: post.ref.reply.root.uri, cid: post.ref.reply.root.cid }
    : parent
  return { root, parent }
}

/**
 * The adapter. All network goes through the injected transport, so tests
 * exercise every path with a fixture fetch and no sockets.
 */
export function makeBsky ({ fetchFn = globalThis.fetch, xrpc = null, now = Date.now } = {}) {
  const rpc = xrpc || makeXrpc({ fetchFn, now })

  async function fetchJson (url) {
    // redirect:'error' — the did:web branch fetches an attacker-influenceable
    // host's /.well-known/did.json; a 302 must not carry it into internal space.
    const res = await fetchFn(url, { redirect: 'error', signal: AbortSignal.timeout(10000) })
    if (!res.ok) throw new Error(`${url} answered ${res.status}`)
    return res.json()
  }

  return {
    // ------------------------------------------------------ public reads

    async searchActors (q, { limit = 12 } = {}) {
      const body = await rpc.get(PUBLIC_APPVIEW, 'app.bsky.actor.searchActors',
        { q, limit })
      return (body.actors || []).map(normalizeActor)
    },

    async getProfile (actor) {
      const body = await rpc.get(PUBLIC_APPVIEW, 'app.bsky.actor.getProfile', { actor })
      return normalizeActor(body)
    },

    async resolveHandle (handle) {
      const body = await rpc.get(PUBLIC_APPVIEW, 'com.atproto.identity.resolveHandle',
        { handle })
      return body.did
    },

    /** An author's recent posts, normalized. `cursor` pages backwards. */
    async getAuthorFeed (actor, { limit = 30, cursor = null } = {}) {
      const body = await rpc.get(PUBLIC_APPVIEW, 'app.bsky.feed.getAuthorFeed',
        { actor, limit, cursor, filter: 'posts_no_replies' })
      return {
        posts: (body.feed || []).map(normalizePost),
        cursor: body.cursor || null
      }
    },

    /** One post's thread from the public AppView; replies normalized, flat. */
    async getPostThread (uri) {
      const body = await rpc.get(PUBLIC_APPVIEW, 'app.bsky.feed.getPostThread',
        { uri, depth: 10 }, { ttl: 30000 })
      const replies = []
      const walk = (node) => {
        if (!node || !node.post) return
        for (const child of node.replies || []) {
          if (child && child.post) replies.push(normalizePost(child))
          walk(child)
        }
      }
      walk(body.thread)
      replies.sort((a, b) => a.created_at - b.created_at)
      return {
        root: body.thread && body.thread.post ? normalizePost(body.thread) : null,
        replies
      }
    },

    // ------------------------------------------------- identity / session

    /**
     * Where this account's PDS lives, from its DID document. Falls back to
     * bsky.social — wrong for self-hosters, correct for almost everyone, and
     * createSession against the wrong host fails loudly rather than silently.
     * A fallback is LEGIBLE: `assumed: true` and a `reason`, so a caller
     * answering "where does this account live" does not present a guess as a
     * resolution. The did:web URL is the ONE reader the browser has
     * (src/protocols/did-protocol.js), host-guarded like it, and the document
     * must be about the DID asked for.
     */
    async resolvePds (didOrHandle) {
      let did = null
      try {
        did = String(didOrHandle).startsWith('did:')
          ? didOrHandle
          : await this.resolveHandle(didOrHandle)
        let url = null
        if (did.startsWith('did:plc:')) {
          url = `${PLC_DIRECTORY}/${did}`
        } else if (did.startsWith('did:web:')) {
          url = didWebUrl(did.slice('did:web:'.length))
          if (!isSafeDidWebHost(new URL(url).host)) {
            return { did, pds: DEFAULT_PDS, assumed: true, reason: 'did:web host is not a public web host' }
          }
        } else {
          return { did, pds: DEFAULT_PDS, assumed: true, reason: `unsupported DID method in ${did}` }
        }
        const doc = await fetchJson(url)
        if (!doc || doc.id !== did) {
          return { did, pds: DEFAULT_PDS, assumed: true, reason: 'the DID document is not about this DID' }
        }
        const service = (doc.service || []).find(
          (s) => String(s.id || '').endsWith('#atproto_pds') &&
            (!s.type || s.type === 'AtprotoPersonalDataServer'))
        if (service && /^https:\/\//.test(service.serviceEndpoint)) {
          return { did, pds: service.serviceEndpoint }
        }
        return { did, pds: DEFAULT_PDS, assumed: true, reason: 'the DID document names no https PDS' }
      } catch (err) {
        return { did, pds: DEFAULT_PDS, assumed: true, reason: (err && err.message) || 'the DID document could not be fetched' }
      }
    },

    /** Log in with handle (or DID) + app password, against the user's own PDS. */
    async createSession ({ pds = DEFAULT_PDS, identifier, password }) {
      const body = await rpc.proc(pds, 'com.atproto.server.createSession',
        { identifier, password })
      return {
        pds,
        did: body.did,
        handle: body.handle,
        accessJwt: body.accessJwt,
        refreshJwt: body.refreshJwt
      }
    },

    /** Trade the refresh token for a fresh pair. */
    async refreshSession ({ pds, refreshJwt }) {
      const body = await rpc.proc(pds, 'com.atproto.server.refreshSession',
        undefined, { accessJwt: refreshJwt })
      return {
        pds,
        did: body.did,
        handle: body.handle,
        accessJwt: body.accessJwt,
        refreshJwt: body.refreshJwt
      }
    },

    // ------------------------------------------------------------ writes

    /** The user's home timeline — an authed read, their own PDS proxies it. */
    async getTimeline (session, { limit = 30 } = {}) {
      const body = await rpc.get(session.pds, 'app.bsky.feed.getTimeline',
        { limit }, { accessJwt: session.accessJwt, ttl: 0 })
      return { posts: (body.feed || []).map(normalizePost), cursor: body.cursor || null }
    },

    async createRecord (session, collection, record) {
      return rpc.proc(session.pds, 'com.atproto.repo.createRecord', {
        repo: session.did, collection, record
      }, { accessJwt: session.accessJwt })
    },

    async deleteRecord (session, collection, rkey) {
      return rpc.proc(session.pds, 'com.atproto.repo.deleteRecord', {
        repo: session.did, collection, rkey
      }, { accessJwt: session.accessJwt })
    },

    /** Follow a DID. Returns the follow record's uri (needed to unfollow). */
    async follow (session, did) {
      const out = await this.createRecord(session, 'app.bsky.graph.follow', {
        $type: 'app.bsky.graph.follow', subject: did, createdAt: iso(now())
      })
      return { uri: out.uri }
    },

    /**
     * Unfollow a DID. The follow RECORD's rkey is required, and the authed
     * profile view is the honest place to learn it: `viewer.following` is the
     * at:// uri of OUR follow record when one exists.
     */
    async unfollow (session, did) {
      const profile = await rpc.get(session.pds, 'app.bsky.actor.getProfile',
        { actor: did }, { accessJwt: session.accessJwt, ttl: 0 })
      const followUri = profile.viewer && profile.viewer.following
      if (!followUri) return { removed: false }
      await this.deleteRecord(session, 'app.bsky.graph.follow', rkeyOf(followUri))
      return { removed: true }
    },

    /** Like a post by its native ref {uri, cid}. */
    async like (session, ref) {
      const out = await this.createRecord(session, 'app.bsky.feed.like', {
        $type: 'app.bsky.feed.like',
        subject: { uri: ref.uri, cid: ref.cid },
        createdAt: iso(now())
      })
      return { uri: out.uri }
    },

    /** Repost a post by its native ref {uri, cid}. */
    async repost (session, ref) {
      const out = await this.createRecord(session, 'app.bsky.feed.repost', {
        $type: 'app.bsky.feed.repost',
        subject: { uri: ref.uri, cid: ref.cid },
        createdAt: iso(now())
      })
      return { uri: out.uri }
    },

    /**
     * Publish a post — a top-level one, or a reply when `replyTo` (a
     * normalized post) is given. Reply refs are built from the ORIGIN post's
     * kept native ref; see replyRefs.
     */
    async post (session, { text, replyTo = null }) {
      const record = {
        $type: 'app.bsky.feed.post',
        text: String(text),
        createdAt: iso(now())
      }
      if (replyTo) record.reply = replyRefs(replyTo)
      const out = await this.createRecord(session, 'app.bsky.feed.post', record)
      return { uri: out.uri, cid: out.cid }
    }
  }
}
