import { decodeMultikey } from './multibase.js'
import { type DidDocument, isDidDocument } from './envelope.js'
import { envelopeValidator } from './schema/validate.js'

const DID_PATTERN = /^did:web:vemphy\.com:i:([a-z]{2,4})$/

/**
 * Vemphy's own DID, at the apex of vemphy.com. Its key signs the issuer
 * directory and nothing else: Vemphy is not an issuer of claims, so this
 * constant is never accepted by `slugOf` or `didToUrl`, only by
 * `parseApexDidDocument` and `verifyDirectory`.
 */
export const APEX_DID = 'did:web:vemphy.com'

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

/** Where the did:web method resolves `APEX_DID` to: https://vemphy.com/.well-known/did.json */
export function apexDidUrl(): string {
  return 'https://vemphy.com/.well-known/did.json'
}

/** Validates a DID document and checks that it describes `did`. */
export function parseDidDocument(input: unknown, did: string): DidDocument {
  if (!isDidDocument(input)) throw new Error('not a DID document')
  const doc = input
  if (doc.id !== did) throw new Error(`DID document is for ${doc.id}, not ${did}`)
  return doc
}

// Only the verificationMethod entries of the shared envelope schema are reused here.
// Its didDocument definition constrains `id` to an issuer DID
// (did:web:vemphy.com:i:<slug>) and would refuse the apex document outright,
// which is deliberate: an issuer's DID document and Vemphy's own must never
// be read as interchangeable.
const verificationMethodValid = envelopeValidator('verificationMethod')

/**
 * Validates the DID document served at the apex, `apexDidUrl()`. This is a
 * different document from an issuer's: it describes `APEX_DID`, whose key
 * signs the issuer directory, so it is read with this function rather than
 * `parseDidDocument`, whose pattern only ever matches an issuer DID.
 */
export function parseApexDidDocument(raw: unknown): DidDocument {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new Error('not a DID document')
  const doc = raw as Record<string, unknown>
  if (doc['id'] !== APEX_DID) throw new Error(`DID document is for ${String(doc['id'])}, not ${APEX_DID}`)
  if (!Array.isArray(doc['verificationMethod']) || !doc['verificationMethod'].every((m) => verificationMethodValid(m))) {
    throw new Error('not a DID document')
  }
  if (!Array.isArray(doc['assertionMethod']) || !doc['assertionMethod'].every((m) => typeof m === 'string')) {
    throw new Error('not a DID document')
  }
  return doc as unknown as DidDocument
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
