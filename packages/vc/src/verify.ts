import type { DocumentLoader } from './context/loader.js'
import { findKey, parseDidDocument, type ResolvedKey } from './did.js'
import { verifyProof } from './proof.js'
import { credentialSchema, type DidDocument, statusListCredentialSchema } from './schema/credential.js'
import { decodeList, getBit } from './status.js'

export type Result = 'valid' | 'revoked' | 'expired' | 'unknown'

/**
 * Why a result is `unknown`. This is for operators and alerting. Anything
 * shown to the person checking a claim uses the four result words only.
 */
export type Reason =
  | 'malformed'
  | 'did_unresolvable'
  | 'key_not_found'
  | 'key_window_violation'
  | 'signature_failure'
  | 'status_list_unverifiable'

export type Check = { name: string; ok: boolean }

export type Outcome = { result: Result; reason?: Reason; checks: Check[] }

export interface VerifyDeps {
  /** The instant to verify at. This function never reads a clock. */
  now: Date
  /** Returns the DID document for an issuer DID. See `didToUrl`. */
  resolveDid(did: string): Promise<unknown>
  /** Returns the status list credential at a URL. */
  fetchStatusList(url: string): Promise<unknown>
  /** For tests. Defaults to the bundled contexts. */
  documentLoader?: DocumentLoader
}

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
  const stop = (name: string, result: Result, reason?: Reason): Outcome => {
    checks.push({ name, ok: false })
    return reason ? { result, reason, checks } : { result, checks }
  }

  // 1. Shape.
  const parsed = credentialSchema.safeParse(input)
  if (!parsed.success) return stop('shape', 'unknown', 'malformed')
  const credential = parsed.data
  pass('shape')

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
  if (!(await signatureHolds(input as Record<string, unknown>, key, deps.documentLoader))) {
    return stop('signature', 'unknown', 'signature_failure')
  }
  pass('signature')

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

  return { result: 'valid', checks }
}

function lookUp(doc: DidDocument, verificationMethod: string): ResolvedKey | undefined {
  try {
    return findKey(doc, verificationMethod)
  } catch {
    return undefined
  }
}

function usableAt(key: ResolvedKey, created: string): boolean {
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
    const list = statusListCredentialSchema.parse(raw)
    if (list.id !== url || list.issuer !== issuer) return undefined

    const now = deps.now.getTime()
    if (now < Date.parse(list.validFrom) || now >= Date.parse(list.validUntil)) return undefined

    const key = lookUp(didDocument, list.proof.verificationMethod)
    if (!key || !usableAt(key, list.proof.created)) return undefined
    if (!(await signatureHolds(raw as Record<string, unknown>, key, deps.documentLoader))) return undefined

    return await decodeList(list.credentialSubject.encodedList)
  } catch {
    return undefined
  }
}
