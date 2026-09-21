import { type DocumentLoader, schemaLoader, staticLoader } from './context/loader.js'
import { findKey, parseDidDocument, type ResolvedKey } from './did.js'
import { type Credential, credentialProblem, type DidDocument, type StatusListCredential, statusListProblem } from './envelope.js'
import { verifyProof } from './proof.js'
import { coreSchema } from './schema/core.js'
import { subjectSchemaFrom } from './schema/document.js'
import type { ClaimSchema } from './schema/types.js'
import { validateSchema, validateSubject } from './schema/validate.js'
import { decodeList, getBit } from './status.js'

export type Result = 'valid' | 'revoked' | 'expired' | 'unknown'

/**
 * Why a result is `unknown`. This is for operators and alerting. Anything
 * shown to the person checking a claim uses the four result words only.
 */
export type Reason =
  | 'malformed'
  | 'context_unavailable'
  | 'did_unresolvable'
  | 'key_not_found'
  | 'key_window_violation'
  | 'signature_failure'
  | 'status_list_unverifiable'

export type Check = { name: string; ok: boolean }

export type Outcome = {
  result: Result
  reason?: Reason
  checks: Check[]
  /**
   * Whether the subject matches the schema the claim names. Extra information
   * for whoever wants it: it never changes `result`, which signature, status
   * and dates decide. Absent when the signature did not hold or the schema
   * could not be had.
   */
  schemaValid?: boolean
}

export interface VerifyDeps {
  /** The instant to verify at. This function never reads a clock. */
  now: Date
  /** Returns the DID document for an issuer DID. See `didToUrl`. */
  resolveDid(did: string): Promise<unknown>
  /** Returns the status list credential at a URL. */
  fetchStatusList(url: string): Promise<unknown>
  /**
   * Loads JSON-LD contexts. Defaults to the bundled ones, offline: the W3C
   * context and every core type. Pass `documentLoader({ cache, fetch })` to
   * verify claims of an issuer's own types.
   */
  documentLoader?: DocumentLoader
  /** Returns the schema document at a URL. Defaults to the bundled core schemas, offline. */
  fetchSchema?(url: string): Promise<unknown>
}

const bundledContexts = staticLoader()
const bundledSchemas = schemaLoader()

/**
 * Verifies a Vemphy claim. Never throws: whatever goes wrong, the answer is
 * one of the four results.
 *
 * The order matters. The signature is checked before revocation and dates, so
 * a document that has been altered can only ever come back `unknown`.
 */
export async function verifyCredential(input: unknown, deps: VerifyDeps): Promise<Outcome> {
  const checks: Check[] = []
  const pass = (name: string) => void checks.push({ name, ok: true })
  let schemaValid: boolean | undefined
  const stop = (name: string, result: Result, reason?: Reason): Outcome => {
    checks.push({ name, ok: false })
    return { result, ...(reason && { reason }), checks, ...(schemaValid !== undefined && { schemaValid }) }
  }
  const loader = deps.documentLoader ?? bundledContexts

  // 1. Shape.
  if (credentialProblem(input) !== undefined) return stop('shape', 'unknown', 'malformed')
  const credential = input as Credential
  pass('shape')

  // The vocabulary the claim is written in. Without it nothing can be said about the signature.
  try {
    await loader(credential['@context'][1])
  } catch {
    return stop('context', 'unknown', 'context_unavailable')
  }
  pass('context')

  // 2. Issuer key.
  let didDocument: DidDocument
  try {
    didDocument = parseDidDocument(await deps.resolveDid(credential.issuer), credential.issuer)
  } catch {
    return stop('did', 'unknown', 'did_unresolvable')
  }
  pass('did')

  const key = lookUp(didDocument, credential.proof.verificationMethod)
  if (!key) return stop('key', 'unknown', 'key_not_found')
  pass('key')

  // 3. The key must not have been revoked or expired when the proof was made.
  if (!usableAt(key, credential.proof.created)) return stop('key_window', 'unknown', 'key_window_violation')
  pass('key_window')

  // 4. Signature.
  if (!(await signatureHolds(input as Record<string, unknown>, key, loader))) {
    return stop('signature', 'unknown', 'signature_failure')
  }
  pass('signature')
  schemaValid = await matchesSchema(credential, deps.fetchSchema ?? bundledSchemas)

  // 5. The status list is itself a signed, short-lived credential from the same issuer.
  const bits = await loadStatusList(credential.issuer, credential.credentialStatus.statusListCredential, didDocument, deps)
  if (!bits) return stop('status_list', 'unknown', 'status_list_unverifiable')
  pass('status_list')

  // 6. Revocation.
  if (getBit(bits, Number(credential.credentialStatus.statusListIndex))) return stop('not_revoked', 'revoked')
  pass('not_revoked')

  // 7. Validity period.
  const now = deps.now.getTime()
  const from = Date.parse(credential.validFrom)
  const until = credential.validUntil === undefined ? Infinity : Date.parse(credential.validUntil)
  if (now < from || now >= until) return stop('validity_period', 'expired')
  pass('validity_period')

  return { result: 'valid', checks, ...(schemaValid !== undefined && { schemaValid }) }
}

// A claim issued under claims/v1 names no schema; version 1 of the core type of the same name describes it.
async function matchesSchema(credential: Credential, fetchSchema: (url: string) => Promise<unknown>): Promise<boolean | undefined> {
  let schema: unknown
  if (credential.credentialSchema === undefined) {
    schema = coreSchema(credential.type[1], 1)
  } else {
    try {
      schema = subjectSchemaFrom(await fetchSchema(credential.credentialSchema.id))
    } catch {
      return undefined
    }
  }
  if (schema === undefined) return undefined
  try {
    if (validateSchema(schema).length > 0) return false
    return validateSubject(schema as ClaimSchema, credential.credentialSubject).length === 0
  } catch {
    return false
  }
}

function lookUp(doc: DidDocument, verificationMethod: string): ResolvedKey | undefined {
  try {
    return findKey(doc, verificationMethod)
  } catch {
    return undefined
  }
}

/**
 * Whether a key was in good standing when a proof dated `created` was made:
 * not yet revoked, not yet expired. Exported so `verifyDirectory` can apply
 * the same key-window rule to the apex key that signs the issuer directory.
 */
export function usableAt(key: ResolvedKey, created: string): boolean {
  const at = Date.parse(created)
  if (key.revoked && at >= key.revoked.getTime()) return false
  if (key.expires && at >= key.expires.getTime()) return false
  return true
}

async function signatureHolds(document: Record<string, unknown>, key: ResolvedKey, loader?: DocumentLoader) {
  try {
    return await verifyProof(document, key.publicKey, loader)
  } catch {
    return false
  }
}

async function loadStatusList(
  issuer: string,
  url: string,
  didDocument: DidDocument,
  deps: VerifyDeps,
): Promise<Uint8Array | undefined> {
  try {
    const raw = await deps.fetchStatusList(url)
    if (statusListProblem(raw) !== undefined) return undefined
    const list = raw as StatusListCredential
    if (list.id !== url || list.issuer !== issuer) return undefined

    const now = deps.now.getTime()
    if (now < Date.parse(list.validFrom) || now >= Date.parse(list.validUntil)) return undefined

    const key = lookUp(didDocument, list.proof.verificationMethod)
    if (!key || !usableAt(key, list.proof.created)) return undefined
    if (!(await signatureHolds(raw as Record<string, unknown>, key, deps.documentLoader ?? bundledContexts))) return undefined

    return await decodeList(list.credentialSubject.encodedList)
  } catch {
    return undefined
  }
}
