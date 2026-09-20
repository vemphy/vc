import claimsV1 from './claims-v1.json' with { type: 'json' }
import credentialsV2 from './credentials-v2.json' with { type: 'json' }
import { coreContexts, coreSchemaDocuments } from '../schema/core.js'

import { CLAIMS_V1, CREDENTIALS_V2 } from './urls.js'

export { CLAIMS_V1, CREDENTIALS_V2 }

// credentials-v2.json is the W3C file, byte for byte. Its SHA-256 is published in the
// Verifiable Credentials Data Model 2.0 specification:
// 59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734

export type RemoteDocument = { contextUrl: null; documentUrl: string; document: unknown }
export type DocumentLoader = (url: string) => Promise<RemoteDocument>

/** The URL is not on the allowlist, or a static loader does not hold it. Nothing was requested. */
export class UnknownContextError extends Error {
  constructor(readonly url: string) {
    super(`refused to load ${url}: not an allowed origin`)
    this.name = 'UnknownContextError'
  }
}

/** The URL is allowed, but the document is not bundled or cached and could not be fetched. */
export class DocumentUnavailableError extends Error {
  constructor(
    readonly url: string,
    why: string,
  ) {
    super(`cannot load ${url}: ${why}`)
    this.name = 'DocumentUnavailableError'
  }
}

/** The W3C context, `claims/v1`, and every core type context. */
export const BUNDLED_CONTEXTS: Readonly<Record<string, unknown>> = {
  ...coreContexts,
  [CREDENTIALS_V2]: credentialsV2,
  [CLAIMS_V1]: claimsV1,
}

/** The schema document of every core type. */
export const BUNDLED_SCHEMAS: Readonly<Record<string, unknown>> = coreSchemaDocuments

/** An exact URL, or a prefix ending in `*`. */
export const CONTEXT_ALLOWLIST = [CREDENTIALS_V2, 'https://w3id.org/security/*', 'https://vemphy.com/ns/*'] as const
export const SCHEMA_ALLOWLIST = ['https://vemphy.com/schemas/*'] as const

/** Published contexts and schemas never change, so a cache never expires. */
export interface DocumentCache {
  get(url: string): Promise<unknown | undefined>
  set(url: string, document: unknown): Promise<void>
}

export function memoryCache(): DocumentCache {
  const documents = new Map<string, unknown>()
  return {
    get: async (url) => documents.get(url),
    set: async (url, document) => void documents.set(url, document),
  }
}

export type LoaderOptions = {
  /** Defaults to the W3C credentials context, `https://w3id.org/security/*` and `https://vemphy.com/ns/*`. */
  allowlist?: readonly string[]
  cache?: DocumentCache
  /** Documents that need no lookup. Defaults to `BUNDLED_CONTEXTS`. */
  bundled?: Readonly<Record<string, unknown>>
  /** Leave this out to stay offline: a document that is not bundled or cached is then an error. */
  fetch?: typeof globalThis.fetch
  /** A fetched document is kept only if this accepts it. Defaults to requiring an `@context`. */
  accept?: (document: unknown) => boolean
}

const MAX_BYTES = 64 * 1024

const allowed = (url: string, allowlist: readonly string[]) =>
  allowlist.some((entry) => (entry.endsWith('*') ? url.startsWith(entry.slice(0, -1)) : url === entry))

const hasContext = (document: unknown) => typeof document === 'object' && document !== null && '@context' in document

/**
 * Loads contexts for signing and verifying. Bundled documents first, then the
 * cache, then the network, and the network only for a URL on the allowlist:
 * anything else is refused before a request is made. What a signature covers
 * depends on the contexts, so where they may come from is not left open.
 */
export function documentLoader(options: LoaderOptions = {}): DocumentLoader {
  const { allowlist = CONTEXT_ALLOWLIST, cache, bundled = BUNDLED_CONTEXTS, fetch, accept = hasContext } = options
  return async (url) => {
    const found = (document: unknown): RemoteDocument => ({ contextUrl: null, documentUrl: url, document })
    if (Object.hasOwn(bundled, url)) return found(bundled[url])
    if (!allowed(url, allowlist)) throw new UnknownContextError(url)

    const cached = await cache?.get(url)
    if (cached !== undefined) return found(cached)
    if (!fetch) throw new DocumentUnavailableError(url, 'it is not bundled or cached, and this loader is offline')

    let document: unknown
    try {
      const response = await fetch(url, { headers: { accept: 'application/ld+json, application/json' } })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const body = await response.text()
      if (body.length > MAX_BYTES) throw new Error('the document is too large')
      document = JSON.parse(body)
    } catch (error) {
      throw new DocumentUnavailableError(url, (error as Error).message)
    }
    if (!accept(document)) throw new DocumentUnavailableError(url, 'it is not the kind of document expected')
    await cache?.set(url, document)
    return found(document)
  }
}

/**
 * A loader that serves the bundled contexts and nothing else, offline.
 * `extra` adds documents by URL, for tests that use third-party fixtures.
 */
export function staticLoader(extra: Record<string, unknown> = {}): DocumentLoader {
  return documentLoader({ allowlist: [], bundled: { ...extra, ...BUNDLED_CONTEXTS } })
}

/** Loads schema documents the same way: bundled core schemas, then cache, then `https://vemphy.com/schemas/*`. */
export function schemaLoader(options: Omit<LoaderOptions, 'accept'> = {}): (url: string) => Promise<unknown> {
  const load = documentLoader({
    allowlist: SCHEMA_ALLOWLIST,
    bundled: BUNDLED_SCHEMAS,
    ...options,
    accept: (document) => typeof document === 'object' && document !== null && 'properties' in document,
  })
  return async (url) => (await load(url)).document
}
