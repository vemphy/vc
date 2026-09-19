import claimsV1 from './claims-v1.json' with { type: 'json' }
import credentialsV2 from './credentials-v2.json' with { type: 'json' }

import { CLAIMS_V1, CREDENTIALS_V2 } from './urls.js'

export { CLAIMS_V1, CREDENTIALS_V2 }

// credentials-v2.json is the W3C file, byte for byte. Its SHA-256 is published in the
// Verifiable Credentials Data Model 2.0 specification:
// 59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734

export type RemoteDocument = { contextUrl: null; documentUrl: string; document: unknown }
export type DocumentLoader = (url: string) => Promise<RemoteDocument>

export class UnknownContextError extends Error {
  constructor(readonly url: string) {
    super(`unknown context: ${url}`)
    this.name = 'UnknownContextError'
  }
}

const BUNDLED: Record<string, unknown> = {
  [CREDENTIALS_V2]: credentialsV2,
  [CLAIMS_V1]: claimsV1,
}

/**
 * A document loader that serves the bundled contexts and nothing else. It never
 * touches the network, so what a signature covers cannot be changed by whoever
 * serves a context URL, and verification works offline.
 *
 * `extra` adds documents by URL. It exists for tests that use third-party fixtures.
 */
export function staticLoader(extra: Record<string, unknown> = {}): DocumentLoader {
  const documents = { ...extra, ...BUNDLED }
  return async (url) => {
    if (!Object.hasOwn(documents, url)) throw new UnknownContextError(url)
    return { contextUrl: null, documentUrl: url, document: documents[url] }
  }
}
