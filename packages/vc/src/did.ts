import { decodeMultikey } from './multibase.js'
import { type DidDocument, didDocumentSchema } from './schema/credential.js'

const DID_PATTERN = /^did:web:vemphy\.com:i:([a-z]{2,4})$/

/** The issuer slug in a Vemphy DID, lowercase. Throws for any other DID. */
export function slugOf(did: string): string {
  const match = DID_PATTERN.exec(did)
  if (!match) throw new Error(`not a Vemphy issuer DID: ${did}`)
  return match[1]!
}

/** did:web:vemphy.com:i:gcb -> https://vemphy.com/i/gcb/did.json */
export function didToUrl(did: string): string {
  return `https://vemphy.com/i/${slugOf(did)}/did.json`
}

/** Validates a DID document and checks that it describes `did`. */
export function parseDidDocument(input: unknown, did: string): DidDocument {
  const doc = didDocumentSchema.parse(input)
  if (doc.id !== did) throw new Error(`DID document is for ${doc.id}, not ${did}`)
  return doc
}

export type ResolvedKey = {
  publicKey: Uint8Array
  /** Signatures made at or after this instant are not accepted. */
  revoked?: Date
  expires?: Date
  /** Whether the key may sign new claims. Retired and revoked keys may not. */
  inAssertionMethod: boolean
}

/** Finds a key in the issuer's own DID document. A key controlled by anyone else is ignored. */
export function findKey(doc: DidDocument, verificationMethod: string): ResolvedKey | undefined {
  if (!verificationMethod.startsWith(`${doc.id}#`)) return undefined
  const method = doc.verificationMethod.find((m) => m.id === verificationMethod && m.controller === doc.id)
  if (!method) return undefined
  return {
    publicKey: decodeMultikey(method.publicKeyMultibase),
    ...(method.revoked !== undefined && { revoked: new Date(method.revoked) }),
    ...(method.expires !== undefined && { expires: new Date(method.expires) }),
    inAssertionMethod: doc.assertionMethod.includes(verificationMethod),
  }
}
