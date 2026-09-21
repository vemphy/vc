import { type DocumentLoader, staticLoader } from './context/loader.js'
import { APEX_DID, findKey, parseApexDidDocument } from './did.js'
import type { Proof } from './envelope.js'
import { verifyProof } from './proof.js'
import { usableAt } from './verify.js'

/** One issuer Vemphy recognises, as it appears in the signed issuer directory. */
export interface DirectoryEntry {
  slug: string
  legalName: string
  did: string
  status: string
}

/** Vemphy's issuer directory, once its issuer, key, signature and validity period have all held. */
export interface Directory {
  entries: DirectoryEntry[]
  /** The instant this directory stops being current. Fetch and verify a fresh copy from then on. */
  validUntil: Date
}

export interface VerifyDirectoryDeps {
  /** The instant to verify at. Defaults to the current time. */
  now?: Date
  /** Returns the document at `apexDidUrl()`. */
  resolveApex(): Promise<unknown>
  /**
   * Loads JSON-LD contexts, the same type `verifyCredential` takes. Left out,
   * the bundled offline loader is used, which is enough here: the
   * directory's own term vocabulary is inline in its `@context`, so
   * canonicalising it needs nothing beyond the W3C credentials context,
   * which is always bundled.
   */
  documentLoader?: DocumentLoader
}

/**
 * Thrown by `verifyDirectory` when the issuer, key, key window and signature
 * all held, but the directory's `validUntil` has passed. Kept apart from
 * every other failure, as a plain subclass rather than a fifth result word,
 * because the two calls for different action: a stale directory means fetch
 * a fresh copy, while any other refusal means the document in hand was never
 * trustworthy as Vemphy's.
 */
export class DirectoryExpiredError extends Error {
  constructor(readonly validUntil: Date) {
    super(`the issuer directory expired at ${validUntil.toISOString()}`)
    this.name = 'DirectoryExpiredError'
  }
}

const DIRECTORY_CREDENTIAL_TYPE = 'VemphyIssuerDirectoryCredential'

type DirectoryCredential = {
  issuer: string
  validUntil: string
  proof: Proof
  credentialSubject: { issuers: DirectoryEntry[] }
}

function isProof(input: unknown): input is Proof {
  if (typeof input !== 'object' || input === null) return false
  const p = input as Record<string, unknown>
  return (
    p['type'] === 'DataIntegrityProof' &&
    p['cryptosuite'] === 'eddsa-rdfc-2022' &&
    typeof p['created'] === 'string' &&
    typeof p['verificationMethod'] === 'string' &&
    p['proofPurpose'] === 'assertionMethod' &&
    typeof p['proofValue'] === 'string'
  )
}

function isDirectoryEntry(input: unknown): input is DirectoryEntry {
  if (typeof input !== 'object' || input === null) return false
  const e = input as Record<string, unknown>
  return typeof e['slug'] === 'string' && typeof e['legalName'] === 'string' && typeof e['did'] === 'string' && typeof e['status'] === 'string'
}

/**
 * Checks everything that can be told without a key: this is a Verifiable
 * Credential, its `type` names the issuer directory, and its `issuer` is
 * exactly `APEX_DID`. Refusing any other issuer here, before a key is ever
 * looked up, is what stops a claim — even a genuine one, from a real Vemphy
 * issuer — from being read as Vemphy's own directory: Vemphy's apex key
 * signs the directory and nothing else.
 */
function asDirectoryCredential(input: unknown): DirectoryCredential {
  const malformed = (): never => {
    throw new Error('not a Vemphy issuer directory')
  }
  if (typeof input !== 'object' || input === null) malformed()
  const c = input as Record<string, unknown>

  if (!Array.isArray(c['type']) || !c['type'].includes('VerifiableCredential') || !c['type'].includes(DIRECTORY_CREDENTIAL_TYPE)) {
    malformed()
  }
  if (c['issuer'] !== APEX_DID) throw new Error(`issuer ${String(c['issuer'])} is not ${APEX_DID}`)
  if (typeof c['validUntil'] !== 'string' || Number.isNaN(Date.parse(c['validUntil']))) malformed()
  if (!isProof(c['proof'])) malformed()

  const subject = c['credentialSubject']
  const issuers = typeof subject === 'object' && subject !== null ? (subject as Record<string, unknown>)['issuers'] : undefined
  if (!Array.isArray(issuers) || !issuers.every(isDirectoryEntry)) malformed()

  return c as unknown as DirectoryCredential
}

/**
 * Verifies Vemphy's signed issuer directory — the list of issuers Vemphy
 * recognises — so a receiver can pin trust to Vemphy rather than to DNS
 * alone.
 *
 * Throws rather than returning a result object: a directory either holds or
 * it does not, and there is no equivalent here to `verifyCredential`'s four
 * results for a caller to act on differently. The one distinction a caller
 * does need — `DirectoryExpiredError` against everything else — is between a
 * directory that has simply gone stale and one that was never Vemphy's. The
 * checks below run in the same order `verifyCredential` uses for a claim, so
 * an altered document is always refused as not trustworthy, never mistaken
 * for merely stale.
 */
export async function verifyDirectory(raw: unknown, deps: VerifyDirectoryDeps): Promise<Directory> {
  // 1. Shape, including that the issuer is exactly Vemphy's own apex DID.
  const credential = asDirectoryCredential(raw)

  // 2. The key, resolved from the apex DID document and matched on the proof's verificationMethod.
  const apexDocument = parseApexDidDocument(await deps.resolveApex())
  const key = findKey(apexDocument, credential.proof.verificationMethod)
  if (!key) throw new Error(`key ${credential.proof.verificationMethod} is not in the apex DID document`)

  // 3. The key must not have been revoked or expired when the proof was made.
  if (!usableAt(key, credential.proof.created)) {
    throw new Error('the key that signed the directory had been revoked or had expired by then')
  }

  // 4. Signature. A canonicalisation failure (an alteration can break the shape
  // a context expects) is a refusal too, exactly as verifyCredential treats it.
  const loader = deps.documentLoader ?? staticLoader()
  let holds: boolean
  try {
    holds = await verifyProof(raw as Record<string, unknown>, key.publicKey, loader)
  } catch {
    holds = false
  }
  if (!holds) throw new Error('the directory signature does not hold: it may have been altered after signing')

  // 5. validUntil, checked last and reported distinctly: a stale directory is the
  // ordinary failure mode of a document that otherwise has every reason to be trusted.
  const validUntil = new Date(credential.validUntil)
  const now = deps.now ?? new Date()
  if (now.getTime() >= validUntil.getTime()) throw new DirectoryExpiredError(validUntil)

  return {
    entries: credential.credentialSubject.issuers.map((entry) => ({
      slug: entry.slug,
      legalName: entry.legalName,
      did: entry.did,
      status: entry.status,
    })),
    validUntil,
  }
}

/** Finds one issuer's entry in a verified directory by slug, or undefined if the directory does not name it. */
export function directoryIssuer(directory: Directory, slug: string): DirectoryEntry | undefined {
  return directory.entries.find((entry) => entry.slug === slug)
}
