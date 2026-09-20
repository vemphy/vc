import { LIST_BITS } from './constants.js'
import { envelopeValidator } from './schema/validate.js'
import { LEGACY_CONTEXT, LEGACY_TYPES, parseContextUrl, schemaUrl } from './schema/urls.js'

// The structure of everything outside credentialSubject is described by
// schemas/envelope/envelope.json, shared with vc-go. The rules below span more
// than one field, which JSON Schema cannot say.

export type Proof = {
  type: 'DataIntegrityProof'
  cryptosuite: 'eddsa-rdfc-2022'
  created: string
  verificationMethod: string
  proofPurpose: 'assertionMethod'
  proofValue: string
}

export type StatusEntry = {
  id: string
  type: 'BitstringStatusListEntry'
  statusPurpose: 'revocation'
  statusListIndex: string
  statusListCredential: string
}

export type UnsignedCredential = {
  '@context': [string, string]
  id: string
  type: ['VerifiableCredential', string]
  issuer: string
  validFrom: string
  validUntil?: string
  credentialSchema?: { id: string; type: 'JsonSchema' }
  credentialSubject: Record<string, unknown>
  credentialStatus: StatusEntry
}

export type Credential = UnsignedCredential & { proof: Proof }

export type StatusListCredential = {
  '@context': [string]
  id: string
  type: ['VerifiableCredential', 'BitstringStatusListCredential']
  issuer: string
  validFrom: string
  validUntil: string
  credentialSubject: { id: string; type: 'BitstringStatusList'; statusPurpose: 'revocation'; encodedList: string }
  proof: Proof
}

export type VerificationMethod = {
  id: string
  type: 'Multikey'
  controller: string
  publicKeyMultibase: string
  revoked?: string
  expires?: string
}

export type DidDocument = { id: string; verificationMethod: VerificationMethod[]; assertionMethod: string[] }

const slugOfDid = (did: string) => did.slice(did.lastIndexOf(':') + 1)

/** Why a claim's envelope is not acceptable, or undefined when it is. */
export function credentialProblem(input: unknown, signed = true): string | undefined {
  const validate = envelopeValidator(signed ? 'credential' : 'unsignedCredential')
  if (!validate(input)) return `${validate.errors?.[0]?.instancePath ?? ''} ${validate.errors?.[0]?.message ?? 'is not valid'}`.trim()
  const c = input as UnsignedCredential & { proof?: Proof }

  // Everything in a claim has to name the same issuer: the slug in the code,
  // the issuer DID, the status list URL, the key that signed it, and the
  // vocabulary it uses when that belongs to an issuer.
  const slug = slugOfDid(c.issuer)
  if (!c.id.startsWith(`urn:vemphy:claim:${slug.toUpperCase()}-`)) return 'code does not belong to the issuer'
  const status = c.credentialStatus
  if (!status.statusListCredential.startsWith(`https://vemphy.com/i/${slug}/status/`)) return 'status list does not belong to the issuer'
  if (status.id !== `${status.statusListCredential}#${status.statusListIndex}`) return 'status id must be the list URL, # and the index'
  if (Number(status.statusListIndex) >= LIST_BITS) return 'status index is past the end of the list'
  if (c.proof && !c.proof.verificationMethod.startsWith(`${c.issuer}#`)) return 'key does not belong to the issuer'
  if (c.validUntil !== undefined && Date.parse(c.validUntil) <= Date.parse(c.validFrom)) return 'validUntil must be after validFrom'

  const [, context] = c['@context']
  const [, type] = c.type
  if (context === LEGACY_CONTEXT) {
    if (!(LEGACY_TYPES as readonly string[]).includes(type)) return 'type is not defined by claims/v1'
    if (c.credentialSchema !== undefined) return 'a claims/v1 claim has no credentialSchema'
    return undefined
  }
  const ref = parseContextUrl(context)
  if (!ref) return 'context is not a Vemphy type context'
  if (ref.name !== type) return 'type does not match its context'
  if (ref.issuer !== undefined && ref.issuer !== slug) return "context belongs to another issuer"
  if (c.credentialSchema?.id !== schemaUrl(ref)) return 'credentialSchema does not match the context'
  return undefined
}

export function statusListProblem(input: unknown): string | undefined {
  const validate = envelopeValidator('statusListCredential')
  if (!validate(input)) return 'is not a status list credential'
  const list = input as StatusListCredential
  if (list.credentialSubject.id !== `${list.id}#list`) return 'subject id must be the list URL followed by #list'
  if (!list.id.startsWith(`https://vemphy.com/i/${slugOfDid(list.issuer)}/status/`)) return 'status list does not belong to the issuer'
  if (!list.proof.verificationMethod.startsWith(`${list.issuer}#`)) return 'key does not belong to the issuer'
  return undefined
}

export function isDidDocument(input: unknown): input is DidDocument {
  return envelopeValidator('didDocument')(input)
}
