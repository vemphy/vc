import attestation from '../../schemas/core/Attestation.v1.json' with { type: 'json' }
import bankBalanceLetter from '../../schemas/core/BankBalanceLetter.v1.json' with { type: 'json' }
import bankReferenceLetter from '../../schemas/core/BankReferenceLetter.v1.json' with { type: 'json' }
import degreeCertificate from '../../schemas/core/DegreeCertificate.v1.json' with { type: 'json' }
import employmentLetter from '../../schemas/core/EmploymentLetter.v1.json' with { type: 'json' }
import insuranceCertificate from '../../schemas/core/InsuranceCertificate.v1.json' with { type: 'json' }
import salaryConfirmation from '../../schemas/core/SalaryConfirmation.v1.json' with { type: 'json' }
import { contextFromSchema } from './context.js'
import { credentialSchemaDocument } from './document.js'
import type { ClaimSchema } from './types.js'
import { contextUrl, namespaceOf, schemaUrl, type TypeRef } from './urls.js'

export type CoreType = { ref: TypeRef; schema: ClaimSchema }

/** Every version of every core type this release knows. Core types are curated by Vemphy and open to every issuer. */
export const coreTypes: readonly CoreType[] = (
  [
    attestation,
    bankBalanceLetter,
    bankReferenceLetter,
    degreeCertificate,
    employmentLetter,
    insuranceCertificate,
    salaryConfirmation,
  ] as unknown as ClaimSchema[]
).map((schema) => ({ ref: { name: schema['x-vemphy'].name, version: 1 }, schema }))

export function coreSchema(name: string, version: number): ClaimSchema | undefined {
  return coreTypes.find((t) => t.ref.name === name && t.ref.version === version)?.schema
}

/** Core contexts by URL. Generated from the schemas, so they cannot drift from them. */
export const coreContexts: Record<string, unknown> = Object.fromEntries(
  coreTypes.map(({ ref, schema }) => [contextUrl(ref), contextFromSchema(schema, namespaceOf(ref))]),
)

/** Core schema documents by URL. */
export const coreSchemaDocuments: Record<string, unknown> = Object.fromEntries(
  coreTypes.map(({ ref, schema }) => [schemaUrl(ref), credentialSchemaDocument(schema, schemaUrl(ref))]),
)
