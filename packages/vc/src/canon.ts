import jsonld from 'jsonld'
import { type DocumentLoader, staticLoader } from './context/loader.js'

const defaultLoader = staticLoader()

// @types/jsonld predates the RDFC-1.0 algorithm name and the safe option.
type CanonizeOptions = {
  algorithm: 'RDFC-1.0'
  format: 'application/n-quads'
  documentLoader: DocumentLoader
  safe: boolean
}
const canonize = jsonld.canonize as unknown as (doc: object, options: CanonizeOptions) => Promise<string>

/**
 * RDFC-1.0 canonical N-Quads for a JSON-LD document.
 *
 * Runs in safe mode: a property or type that no context defines is an error
 * rather than being dropped, because a dropped property would not be signed.
 */
export async function canonicalize(doc: object, loader: DocumentLoader = defaultLoader): Promise<string> {
  return canonize(doc, {
    algorithm: 'RDFC-1.0',
    format: 'application/n-quads',
    documentLoader: loader,
    safe: true,
  })
}
