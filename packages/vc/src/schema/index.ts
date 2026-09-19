import { z } from 'zod'
import { bankReferenceLetterDisclosure } from './bank-reference-letter.js'
import { type ClaimType, subjectSchemas } from './credential.js'
import { degreeCertificateDisclosure } from './degree-certificate.js'
import { employmentLetterDisclosure } from './employment-letter.js'

export * from './credential.js'
export { bankReferenceLetter } from './bank-reference-letter.js'
export { degreeCertificate } from './degree-certificate.js'
export { employmentLetter } from './employment-letter.js'

/** The subject fields shown to anyone who verifies a claim, unless the issuer's policy says otherwise. */
export const defaultDisclosure: Record<ClaimType, readonly string[]> = {
  BankReferenceLetter: bankReferenceLetterDisclosure,
  DegreeCertificate: degreeCertificateDisclosure,
  EmploymentLetter: employmentLetterDisclosure,
}

/** JSON Schema (2020-12) for a claim type's subject. Cross-field rules are not expressible and are left out. */
export function jsonSchemaFor(type: ClaimType): Record<string, unknown> {
  return z.toJSONSchema(subjectSchemas[type]) as Record<string, unknown>
}
