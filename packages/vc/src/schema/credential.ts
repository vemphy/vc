import { z } from 'zod'
import { CLAIMS_V1, CREDENTIALS_V2 } from '../context/urls.js'
import { LIST_BITS } from '../status.js'
import { bankReferenceLetter } from './bank-reference-letter.js'
import { instant, issuerDid, SLUG } from './common.js'
import { degreeCertificate } from './degree-certificate.js'
import { employmentLetter } from './employment-letter.js'

export const CLAIM_TYPES = ['BankReferenceLetter', 'DegreeCertificate', 'EmploymentLetter'] as const
export type ClaimType = (typeof CLAIM_TYPES)[number]

export const subjectSchemas = {
  BankReferenceLetter: bankReferenceLetter,
  DegreeCertificate: degreeCertificate,
  EmploymentLetter: employmentLetter,
} as const

export const proofSchema = z.strictObject({
  type: z.literal('DataIntegrityProof'),
  cryptosuite: z.literal('eddsa-rdfc-2022'),
  created: instant,
  verificationMethod: z.string().regex(new RegExp(`^did:web:vemphy\\.com:i:${SLUG}#key-[1-9]\\d*$`)),
  proofPurpose: z.literal('assertionMethod'),
  proofValue: z.string().regex(/^z[1-9A-HJ-NP-Za-km-z]+$/),
})

const statusListUrl = z.string().regex(new RegExp(`^https://vemphy\\.com/i/${SLUG}/status/[1-9]\\d*$`))

export const statusEntrySchema = z
  .strictObject({
    id: z.string(),
    type: z.literal('BitstringStatusListEntry'),
    statusPurpose: z.literal('revocation'),
    statusListIndex: z
      .string()
      .regex(/^(0|[1-9]\d*)$/)
      .refine((s) => Number(s) < LIST_BITS, 'index is past the end of the list'),
    statusListCredential: statusListUrl,
  })
  .refine((s) => s.id === `${s.statusListCredential}#${s.statusListIndex}`, {
    path: ['id'],
    message: 'must be the list URL followed by # and the index',
  })

const claimId = z.string().regex(/^urn:vemphy:claim:[A-Z]{2,4}-[0-9A-Z]{4}-[0-9A-Z]{3}[0-9A-Z*~$=]$/)

const slugOfDid = (did: string) => did.slice(did.lastIndexOf(':') + 1)

function unsignedShape<T extends ClaimType>(type: T) {
  return {
    '@context': z.tuple([z.literal(CREDENTIALS_V2), z.literal(CLAIMS_V1)]),
    id: claimId,
    type: z.tuple([z.literal('VerifiableCredential'), z.literal(type)]),
    issuer: issuerDid,
    validFrom: instant,
    validUntil: instant.optional(),
    credentialSubject: subjectSchemas[type],
    credentialStatus: statusEntrySchema,
  }
}

type Envelope = {
  id: string
  issuer: string
  validFrom: string
  validUntil?: string | undefined
  credentialStatus: { statusListCredential: string }
  proof?: { verificationMethod: string }
}

// Everything in a claim has to name the same issuer: the slug in the code, the
// issuer DID, the status list URL and the key that signed it.
function sameIssuer(value: Envelope, ctx: z.RefinementCtx) {
  const slug = slugOfDid(value.issuer)
  if (!value.id.startsWith(`urn:vemphy:claim:${slug.toUpperCase()}-`)) {
    ctx.addIssue({ code: 'custom', path: ['id'], message: 'code does not belong to the issuer' })
  }
  if (!value.credentialStatus.statusListCredential.startsWith(`https://vemphy.com/i/${slug}/status/`)) {
    ctx.addIssue({ code: 'custom', path: ['credentialStatus'], message: 'status list does not belong to the issuer' })
  }
  if (value.proof && !value.proof.verificationMethod.startsWith(`${value.issuer}#`)) {
    ctx.addIssue({ code: 'custom', path: ['proof', 'verificationMethod'], message: 'key does not belong to the issuer' })
  }
  if (value.validUntil !== undefined && Date.parse(value.validUntil) <= Date.parse(value.validFrom)) {
    ctx.addIssue({ code: 'custom', path: ['validUntil'], message: 'must be after validFrom' })
  }
}

/** A claim of one type, before it is signed. */
export function unsignedCredentialSchemaFor<T extends ClaimType>(type: T) {
  return z.strictObject(unsignedShape(type)).superRefine(sameIssuer)
}

/** A signed claim of one type. */
export function credentialSchemaFor<T extends ClaimType>(type: T) {
  return z.strictObject({ ...unsignedShape(type), proof: proofSchema }).superRefine(sameIssuer)
}

/** A signed claim of any known type. */
export const credentialSchema = z.union([
  credentialSchemaFor('BankReferenceLetter'),
  credentialSchemaFor('DegreeCertificate'),
  credentialSchemaFor('EmploymentLetter'),
])

export const statusListCredentialSchema = z
  .strictObject({
    '@context': z.tuple([z.literal(CREDENTIALS_V2)]),
    id: statusListUrl,
    type: z.tuple([z.literal('VerifiableCredential'), z.literal('BitstringStatusListCredential')]),
    issuer: issuerDid,
    validFrom: instant,
    validUntil: instant,
    credentialSubject: z.strictObject({
      id: z.string(),
      type: z.literal('BitstringStatusList'),
      statusPurpose: z.literal('revocation'),
      encodedList: z.string().regex(/^u[A-Za-z0-9_-]+$/),
    }),
    proof: proofSchema,
  })
  .superRefine((value, ctx) => {
    if (value.credentialSubject.id !== `${value.id}#list`) {
      ctx.addIssue({ code: 'custom', path: ['credentialSubject', 'id'], message: 'must be the list URL followed by #list' })
    }
    if (!value.id.startsWith(`https://vemphy.com/i/${slugOfDid(value.issuer)}/status/`)) {
      ctx.addIssue({ code: 'custom', path: ['id'], message: 'status list does not belong to the issuer' })
    }
    if (!value.proof.verificationMethod.startsWith(`${value.issuer}#`)) {
      ctx.addIssue({ code: 'custom', path: ['proof', 'verificationMethod'], message: 'key does not belong to the issuer' })
    }
  })

// DID documents are read, never signed over, so unknown members are allowed.
export const verificationMethodSchema = z.looseObject({
  id: z.string(),
  type: z.literal('Multikey'),
  controller: z.string(),
  publicKeyMultibase: z.string().regex(/^z[1-9A-HJ-NP-Za-km-z]+$/),
  revoked: instant.optional(),
  expires: instant.optional(),
})

export const didDocumentSchema = z.looseObject({
  id: issuerDid,
  verificationMethod: z.array(verificationMethodSchema),
  assertionMethod: z.array(z.string()),
})

export type Proof = z.infer<typeof proofSchema>
export type Credential = z.infer<typeof credentialSchema>
export type StatusListCredential = z.infer<typeof statusListCredentialSchema>
export type VerificationMethod = z.infer<typeof verificationMethodSchema>
export type DidDocument = z.infer<typeof didDocumentSchema>
