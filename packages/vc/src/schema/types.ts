/** Text in one or more languages, keyed by language tag. `en` is always present. */
export type Labels = { en: string } & Record<string, string>

export type FieldExtension = {
  label: Labels
  /** Whether the issuer may choose to show this field to someone verifying a claim. */
  disclosable: boolean
  pii: boolean
  order: number
  kind?: 'decimal' | 'multiline'
  enumLabels?: Record<string, Labels>
}

export type Field =
  | { type: 'string'; minLength?: number; maxLength: number; pattern?: string; 'x-vemphy': FieldExtension }
  | { type: 'string'; format: 'date' | 'date-time' | 'email' | 'uri'; 'x-vemphy': FieldExtension }
  | { type: 'string'; enum: string[]; 'x-vemphy': FieldExtension }
  | { type: 'integer'; minimum: number; maximum: number; 'x-vemphy': FieldExtension }
  | { type: 'boolean'; 'x-vemphy': FieldExtension }

/** A Vemphy claim schema: the restricted JSON Schema that describes one version of a claim type's subject. */
export type ClaimSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema'
  type: 'object'
  additionalProperties: false
  'x-vemphy': { name: string; displayName: Labels }
  properties: Record<string, Field>
  required?: string[]
}

/** How a value should be shown. Derived from the schema so that nothing downstream needs schema logic. */
export type Kind = 'text' | 'multiline' | 'decimal' | 'integer' | 'boolean' | 'date' | 'datetime' | 'email' | 'uri' | 'choice'

export type Problem = { field: string; message: string }
