import type { ClaimSchema, Field } from './types.js'

const XSD = 'http://www.w3.org/2001/XMLSchema#'

function datatype(field: Field): string | undefined {
  if (field.type === 'integer') return `${XSD}integer`
  if (field.type === 'boolean') return `${XSD}boolean`
  if ('format' in field && field.format === 'date') return `${XSD}date`
  if ('format' in field && field.format === 'date-time') return `${XSD}dateTime`
  return undefined
}

/**
 * The JSON-LD context for one version of a claim type. `namespace` is the
 * context's own URL followed by `#` (see `namespaceOf`).
 *
 * Every property is defined, by name, with an identifier under the namespace.
 * JSON-LD drops a term that no context defines, and a dropped field is a field
 * the signature does not cover.
 *
 * vc-go's GenerateContext must produce the same bytes from `canonicalJson`.
 */
export function contextFromSchema(schema: ClaimSchema, namespace: string): { '@context': Record<string, unknown> } {
  const name = schema['x-vemphy'].name
  const terms: Record<string, unknown> = { '@protected': true, [name]: `${namespace}${name}` }
  for (const [key, field] of Object.entries(schema.properties)) {
    const type = datatype(field)
    terms[key] = type === undefined ? `${namespace}${key}` : { '@id': `${namespace}${key}`, '@type': type }
  }
  return { '@context': terms }
}

/** JSON with object keys sorted and no whitespace, so two implementations can be compared byte for byte. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`
  }
  return JSON.stringify(value)
}
