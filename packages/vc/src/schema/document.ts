import type { ClaimSchema } from './types.js'

const DRAFT = 'https://json-schema.org/draft/2020-12/schema'

/**
 * The document served at a schema URL. A `credentialSchema` of type
 * `JsonSchema` validates the whole credential (W3C, "Verifiable Credentials
 * JSON Schema"), so the claim schema sits under `credentialSubject`.
 */
export function credentialSchemaDocument(schema: ClaimSchema, url: string): Record<string, unknown> {
  const { $schema: _, ...subject } = schema
  return {
    $schema: DRAFT,
    $id: url,
    title: schema['x-vemphy'].displayName.en,
    type: 'object',
    required: ['credentialSubject'],
    properties: { credentialSubject: subject },
  }
}

/** The claim schema inside a schema document, or undefined if the document is not shaped like one. It is not yet checked: see `validateSchema`. */
export function subjectSchemaFrom(document: unknown): unknown {
  const subject = (document as { properties?: { credentialSubject?: unknown } } | null)?.properties?.credentialSubject
  if (typeof subject !== 'object' || subject === null) return undefined
  return { $schema: DRAFT, ...subject }
}
